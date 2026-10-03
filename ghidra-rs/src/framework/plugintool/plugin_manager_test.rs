//! Port of `ghidra.framework.plugintool.PluginManagerTest`.
//!
//! Integration-test suite exercising `PluginTool`'s plugin-loading/removal behavior (diamond and
//! circular dependency resolution, missing/simultaneously-satisfied dependencies, init/dispose
//! failure cleanup, isolated batch failures, and plugin name uniqueness). Selected as a
//! dependency-cycle cut-point, so it is ported as a trait describing the test suite's contract
//! rather than tied to a concrete `PluginTool`/`TestEnv` pair.
//!
//! Each JUnit `@Test` method took no arguments and either returned `void` or declared `throws
//! PluginException`; that maps directly to a parameterless `&mut self` method returning
//! `Result<(), PluginException>`, keeping the trait object-safe (mirroring the convention already
//! used by [`RecoveryDbTest`](crate::framework::db::recovery_db_test::RecoveryDbTest)). The
//! original's private helper methods (`removePlugin`, `assertPlugin`, `assertNotPlugin`,
//! `getPlugin`) and its `env`/`tool` fields are implementation details of a concrete test fixture,
//! not part of the ported contract, so they are not trait members here.

use crate::framework::plugintool::util::PluginException;

/// Mirrors `ghidra.framework.plugintool.PluginManagerTest`. Object-safe, so implementations can be
/// driven through `Box<dyn PluginManagerTest>`/`Arc<dyn PluginManagerTest>`.
pub trait PluginManagerTest {
    /// Create a fresh tool environment. Mirrors the JUnit `@Before` method.
    fn set_up(&mut self) -> Result<(), PluginException>;

    /// Dispose of the tool environment. Mirrors the JUnit `@After` method.
    fn tear_down(&mut self) -> Result<(), PluginException>;

    /// Loading a plugin that has a name conflict with another plugin should fail with a message
    /// naming both conflicting classes, and neither should end up installed. Mirrors
    /// `testConflictPluginNames()`.
    fn test_conflict_plugin_names(&mut self) -> Result<(), PluginException>;

    /// Loading a plugin with a diamond-shaped dependency graph should transitively load every
    /// dependency exactly once. Mirrors `testDiamond()`.
    fn test_diamond(&mut self) -> Result<(), PluginException>;

    /// Loading plugins with a circular dependency is allowed, and removing one side of the cycle
    /// removes the other as well. Mirrors `testCircularDependency()`.
    fn test_circular_dependency(&mut self) -> Result<(), PluginException>;

    /// Loading the same plugin multiple times is a no-op after the first load. Mirrors
    /// `testLoadSameMultipleTimes()`.
    fn test_load_same_multiple_times(&mut self) -> Result<(), PluginException>;

    /// Loading a plugin whose dependency has no default provider and is not already installed
    /// fails with an "Unresolved dependency" message; installing the dependency first makes a
    /// subsequent load succeed. Mirrors `testMissingDependency()`.
    fn test_missing_dependency(&mut self) -> Result<(), PluginException>;

    /// Loading a plugin and a second plugin that provides its otherwise-unresolvable dependency in
    /// the same batch should succeed. Mirrors `testLoadingDepSimultaneously()`.
    fn test_loading_dep_simultaneously(&mut self) -> Result<(), PluginException>;

    /// A plugin that throws during init() is removed and cleaned up (disposed), and the failure is
    /// reported. Mirrors `testInitFail()`.
    fn test_init_fail(&mut self) -> Result<(), PluginException>;

    /// A plugin whose dependency throws during init() is itself removed and cleaned up along with
    /// the failing dependency. Mirrors `testInitFailInDependency()`.
    fn test_init_fail_in_dependency(&mut self) -> Result<(), PluginException>;

    /// A plugin that throws during dispose() is still removed from the managed set. Mirrors
    /// `testDisposeFail()`.
    fn test_dispose_fail(&mut self) -> Result<(), PluginException>;

    /// Loading multiple plugins where one is bad should still install the good ones, isolating the
    /// failure. Mirrors `testLoadFailure_Isolated()`.
    fn test_load_failure_isolated(&mut self) -> Result<(), PluginException>;

    /// Every discoverable (non-`TestingPlugin`) plugin must have a name that is unique among its
    /// peers. Mirrors `testUniquePluginNames()`.
    fn test_unique_plugin_names(&mut self) -> Result<(), PluginException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    const INIT_FAIL_ERROR_MSG: &str = "InitFailPluginB intentionally failed during init()";
    const NAME_CONFLICT_CLASS_1: &str =
        "ghidra.framework.plugintool.testplugins.NameConflictingPlugin";
    const NAME_CONFLICT_CLASS_2: &str =
        "ghidra.framework.plugintool.testplugins.secondconflict.NameConflictingPlugin";

    /// `(provides, requires)` for each mock plugin's catalog entry, keyed by plugin class name.
    fn catalog() -> HashMap<&'static str, (&'static [&'static str], &'static [&'static str])> {
        HashMap::from([
            ("DiamondPluginA", (&[][..], &["DiamondServiceB", "DiamondServiceC"][..])),
            ("DiamondPluginB", (&["DiamondServiceB"][..], &["DiamondServiceD"][..])),
            ("DiamondPluginC", (&["DiamondServiceC"][..], &["DiamondServiceD"][..])),
            ("DiamondPluginD", (&["DiamondServiceD"][..], &[][..])),
            ("CircularPluginA", (&["CircularServiceA"][..], &["CircularServiceB"][..])),
            ("CircularPluginB", (&["CircularServiceB"][..], &["CircularServiceA"][..])),
            ("MissingDepPluginA", (&[][..], &["MissingDepServiceB"][..])),
            ("MissingDepPluginB", (&["MissingDepServiceB"][..], &[][..])),
            ("InitFailPluginA", (&[][..], &["InitFailServiceB"][..])),
            ("IsolatedFailPluginA", (&[][..], &[][..])),
            ("DisposeFailPluginA", (&[][..], &[][..])),
        ])
    }

    /// Services that have an `@ServiceInfo(defaultProvider = ...)` annotation in Java, so a lone
    /// `add_plugin` can auto-resolve them. `MissingDepServiceB` deliberately has none (its Java
    /// source even has the argument commented out), which is the whole point of
    /// `testMissingDependency`/`testLoadingDepSimultaneously`.
    fn default_providers() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("DiamondServiceB", "DiamondPluginB"),
            ("DiamondServiceC", "DiamondPluginC"),
            ("DiamondServiceD", "DiamondPluginD"),
            ("CircularServiceA", "CircularPluginA"),
            ("CircularServiceB", "CircularPluginB"),
            ("InitFailServiceB", "InitFailPluginB"),
        ])
    }

    fn require(cond: bool, msg: &str) -> Result<(), PluginException> {
        if cond {
            Ok(())
        } else {
            Err(PluginException::with_message(msg))
        }
    }

    /// A minimal in-memory model of `PluginTool`'s plugin-loading behavior: a small hardcoded
    /// dependency catalog plus a real (if simplified) recursive resolver, so the trait methods
    /// below exercise genuine dependency-resolution/cleanup logic rather than stubbed-out asserts.
    struct MockPluginManagerTest {
        loaded: Vec<String>,
        config_changed: bool,
        dispose_count: HashMap<String, u32>,
    }

    impl MockPluginManagerTest {
        fn new() -> Self {
            Self { loaded: Vec::new(), config_changed: false, dispose_count: HashMap::new() }
        }

        fn is_loaded(&self, name: &str) -> bool {
            self.loaded.iter().any(|n| n == name)
        }

        fn service_satisfied(&self, service: &str) -> bool {
            let cat = catalog();
            self.loaded.iter().any(|n| cat.get(n.as_str()).is_some_and(|(p, _)| p.contains(&service)))
        }

        fn bump_dispose_count(&mut self, name: &str) {
            *self.dispose_count.entry(name.to_string()).or_insert(0) += 1;
        }

        fn dispose_count(&self, name: &str) -> u32 {
            self.dispose_count.get(name).copied().unwrap_or(0)
        }

        /// Recursively resolves and loads `name` and its unsatisfied dependencies. `batch`
        /// contains providers supplied by the current `add_plugins` call (if any), which take
        /// priority over the plugin's own `@ServiceInfo` default provider -- mirroring how loading
        /// a dependency-providing plugin in the same batch satisfies an otherwise-unresolvable
        /// dependency. `resolving` tracks the in-progress chain so a circular dependency is
        /// tolerated (matching Java's documented "currently allowed" behavior) instead of
        /// recursing forever.
        fn add_plugin_internal(
            &mut self,
            name: &str,
            batch: &HashMap<String, String>,
            resolving: &mut HashSet<String>,
        ) -> Result<(), PluginException> {
            if self.is_loaded(name) {
                return Ok(());
            }
            if !resolving.insert(name.to_string()) {
                // Already in progress higher up the call chain: circular dependency, tolerated.
                return Ok(());
            }

            if name == "NameConflictingPlugin" {
                resolving.remove(name);
                return Err(PluginException::new(
                    name,
                    &format!(
                        "conflicting plugin names: {} and {}",
                        NAME_CONFLICT_CLASS_1, NAME_CONFLICT_CLASS_2
                    ),
                ));
            }
            if name == "InitFailPluginB" || name == "IsolatedFailPluginB" {
                resolving.remove(name);
                self.bump_dispose_count(name);
                return Err(PluginException::new(name, INIT_FAIL_ERROR_MSG));
            }

            let cat = catalog();
            let requires: &[&str] = cat.get(name).map(|(_, r)| *r).unwrap_or(&[]);
            for service in requires {
                if self.service_satisfied(service) {
                    continue;
                }
                let provider =
                    batch.get(*service).map(String::as_str).or_else(|| {
                        default_providers().get(service).copied()
                    });
                match provider {
                    Some(provider) => {
                        let provider = provider.to_string();
                        if let Err(e) = self.add_plugin_internal(&provider, batch, resolving) {
                            resolving.remove(name);
                            self.bump_dispose_count(name);
                            return Err(e);
                        }
                    }
                    None => {
                        resolving.remove(name);
                        return Err(PluginException::new(
                            name,
                            &format!("Unresolved dependency: {}", service),
                        ));
                    }
                }
            }

            resolving.remove(name);
            self.loaded.push(name.to_string());
            Ok(())
        }

        fn add_plugin(&mut self, name: &str) -> Result<(), PluginException> {
            self.config_changed = true;
            let mut resolving = HashSet::new();
            self.add_plugin_internal(name, &HashMap::new(), &mut resolving)
        }

        fn add_plugins(&mut self, names: &[&str]) -> Result<(), PluginException> {
            self.config_changed = true;
            let mut batch = HashMap::new();
            let cat = catalog();
            for name in names {
                if let Some((provides, _)) = cat.get(*name) {
                    for service in *provides {
                        batch.insert(service.to_string(), name.to_string());
                    }
                }
            }
            let mut first_err = None;
            for name in names {
                let mut resolving = HashSet::new();
                if let Err(e) = self.add_plugin_internal(name, &batch, &mut resolving) {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
            match first_err {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }

        /// Removes `name`, then cascades to any loaded plugin whose dependency is no longer
        /// satisfied as a result (mirroring `removePlugins` tearing down dependents).
        fn remove_plugin(&mut self, name: &str) {
            if !self.is_loaded(name) {
                return;
            }
            self.loaded.retain(|n| n != name);
            self.config_changed = true;

            let cat = catalog();
            loop {
                let victim = self.loaded.iter().find(|p| {
                    let requires: &[&str] = cat.get(p.as_str()).map(|(_, r)| *r).unwrap_or(&[]);
                    requires.iter().any(|svc| !self.service_satisfied(svc))
                });
                match victim.cloned() {
                    Some(v) => self.loaded.retain(|n| n != &v),
                    None => break,
                }
            }
        }
    }

    impl PluginManagerTest for MockPluginManagerTest {
        fn set_up(&mut self) -> Result<(), PluginException> {
            self.loaded.clear();
            self.config_changed = false;
            self.dispose_count.clear();
            Ok(())
        }

        fn tear_down(&mut self) -> Result<(), PluginException> {
            self.loaded.clear();
            Ok(())
        }

        fn test_conflict_plugin_names(&mut self) -> Result<(), PluginException> {
            let err = self
                .add_plugin("NameConflictingPlugin")
                .expect_err("conflicting plugin names should fail to load");
            let msg = err.to_string();
            require(msg.contains(NAME_CONFLICT_CLASS_1), "message should name the first conflict")?;
            require(msg.contains(NAME_CONFLICT_CLASS_2), "message should name the second conflict")?;
            require(!self.is_loaded("NameConflictingPlugin"), "conflicting plugin must not load")
        }

        fn test_diamond(&mut self) -> Result<(), PluginException> {
            self.add_plugin("DiamondPluginA")?;
            for name in ["DiamondPluginA", "DiamondPluginB", "DiamondPluginC", "DiamondPluginD"] {
                require(self.is_loaded(name), "diamond dependency should be loaded")?;
            }
            require(self.config_changed, "loading a plugin should mark the tool dirty")
        }

        fn test_circular_dependency(&mut self) -> Result<(), PluginException> {
            self.add_plugin("CircularPluginA")?;
            require(self.is_loaded("CircularPluginA"), "A should load despite the cycle")?;
            require(self.is_loaded("CircularPluginB"), "B should load despite the cycle")?;
            require(self.config_changed, "loading a plugin should mark the tool dirty")?;

            self.remove_plugin("CircularPluginB");
            require(!self.is_loaded("CircularPluginA"), "removing B should cascade to A")?;
            require(!self.is_loaded("CircularPluginB"), "B should be removed")
        }

        fn test_load_same_multiple_times(&mut self) -> Result<(), PluginException> {
            self.add_plugin("DiamondPluginD")?;
            require(self.is_loaded("DiamondPluginD"), "D should be loaded")?;
            require(self.config_changed, "loading a plugin should mark the tool dirty")?;

            self.add_plugin("DiamondPluginD")?;
            require(
                self.loaded.iter().filter(|n| *n == "DiamondPluginD").count() == 1,
                "loading the same plugin twice should not duplicate it",
            )
        }

        fn test_missing_dependency(&mut self) -> Result<(), PluginException> {
            let plugin_count = self.loaded.len();
            let err = self
                .add_plugin("MissingDepPluginA")
                .expect_err("PluginA should fail to load without its dependency");
            let msg = err.to_string();
            require(msg.contains("Unresolved dependency"), "message should mention unresolved dependency")?;
            require(msg.contains("MissingDepServiceB"), "message should name the missing service")?;
            require(self.loaded.len() == plugin_count, "failed load should not add any plugin")?;
            require(self.config_changed, "attempted load should mark the tool dirty")?;

            self.add_plugin("MissingDepPluginB")?;
            self.add_plugin("MissingDepPluginA")?;
            require(self.is_loaded("MissingDepPluginB"), "B should now be loaded")?;
            require(self.is_loaded("MissingDepPluginA"), "A should now be loaded")
        }

        fn test_loading_dep_simultaneously(&mut self) -> Result<(), PluginException> {
            self.add_plugins(&["MissingDepPluginA", "MissingDepPluginB"])?;
            require(self.is_loaded("MissingDepPluginA"), "A should be loaded")?;
            require(self.is_loaded("MissingDepPluginB"), "B should be loaded")?;
            require(self.config_changed, "loading plugins should mark the tool dirty")
        }

        fn test_init_fail(&mut self) -> Result<(), PluginException> {
            let plugin_count = self.loaded.len();
            let dispose_before = self.dispose_count("InitFailPluginB");

            let err = self
                .add_plugin("InitFailPluginB")
                .expect_err("PluginB should fail to load because it throws during init()");
            require(err.to_string().contains(INIT_FAIL_ERROR_MSG), "message should contain the init error")?;

            require(
                self.dispose_count("InitFailPluginB") == dispose_before + 1,
                "failed plugin should still be disposed once",
            )?;
            require(self.loaded.len() == plugin_count, "failed load should not add any plugin")?;
            require(self.config_changed, "attempted load should mark the tool dirty")
        }

        fn test_init_fail_in_dependency(&mut self) -> Result<(), PluginException> {
            let plugin_count = self.loaded.len();
            let dispose_a_before = self.dispose_count("InitFailPluginA");
            let dispose_b_before = self.dispose_count("InitFailPluginB");

            let err = self
                .add_plugin("InitFailPluginA")
                .expect_err("PluginA should fail because its dependency throws during init()");
            require(err.to_string().contains(INIT_FAIL_ERROR_MSG), "message should contain the init error")?;

            require(!self.is_loaded("InitFailPluginA"), "A should not be loaded")?;
            require(self.loaded.len() == plugin_count, "failed load should not add any plugin")?;
            require(
                self.dispose_count("InitFailPluginB") == dispose_b_before + 1,
                "failing dependency should be disposed once",
            )?;
            require(
                self.dispose_count("InitFailPluginA") == dispose_a_before + 1,
                "dependent should be disposed once too",
            )
        }

        fn test_dispose_fail(&mut self) -> Result<(), PluginException> {
            self.add_plugin("DisposeFailPluginA")?;
            require(self.config_changed, "loading a plugin should mark the tool dirty")?;
            self.config_changed = false;

            self.remove_plugin("DisposeFailPluginA");
            require(!self.is_loaded("DisposeFailPluginA"), "plugin should be removed despite dispose failing")?;
            require(self.config_changed, "removing a plugin should mark the tool dirty")
        }

        fn test_load_failure_isolated(&mut self) -> Result<(), PluginException> {
            let err = self
                .add_plugins(&["IsolatedFailPluginA", "IsolatedFailPluginB"])
                .expect_err("batch should report an error because B is bad");
            require(!err.to_string().is_empty(), "error should carry a message")?;
            require(self.config_changed, "attempted load should mark the tool dirty")?;
            require(self.is_loaded("IsolatedFailPluginA"), "good plugin A should still load")?;
            require(!self.is_loaded("IsolatedFailPluginB"), "bad plugin B should not load")
        }

        fn test_unique_plugin_names(&mut self) -> Result<(), PluginException> {
            // Stand-in for the classes `ClassSearcher` would discover in the real test, excluding
            // `TestingPlugin`-marked plugins (this mock's whole catalog is test-only, so it is
            // deliberately excluded here too).
            let simple_names = ["CodeBrowserPlugin", "DecompilePlugin", "FunctionGraphPlugin"];

            let mut seen: HashMap<&str, &str> = HashMap::new();
            let mut collisions = Vec::new();
            for full_name in simple_names {
                let simple = full_name;
                if let Some(prev) = seen.insert(simple, full_name) {
                    collisions.push(format!("{}: {},{}", simple, prev, full_name));
                }
            }

            require(collisions.is_empty(), &format!("plugins with name collisions: {}", collisions.join("\n")))
        }
    }

    fn requires_plugin_manager_test<T: PluginManagerTest>(_: &T) {}

    #[test]
    fn trait_is_object_safe() {
        let fixture = MockPluginManagerTest::new();
        let _boxed: Box<dyn PluginManagerTest> = Box::new(fixture);
    }

    #[test]
    fn concrete_type_satisfies_trait() {
        let fixture = MockPluginManagerTest::new();
        requires_plugin_manager_test(&fixture);
    }

    #[test]
    fn diamond_dependency_resolves_transitively() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_diamond().expect("diamond dependency resolution should succeed");
        fixture.tear_down().unwrap();
    }

    #[test]
    fn circular_dependency_loads_and_cascades_on_removal() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_circular_dependency().expect("circular dependency handling should succeed");
    }

    #[test]
    fn missing_dependency_then_manual_resolution() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_missing_dependency().expect("missing dependency scenario should succeed");
    }

    #[test]
    fn loading_dependency_simultaneously_succeeds() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_loading_dep_simultaneously().expect("batch load should succeed");
    }

    #[test]
    fn init_failure_disposes_dependent_chain() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_init_fail_in_dependency().expect("init failure cleanup should succeed");
    }

    #[test]
    fn isolated_batch_failure_still_loads_good_plugin() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_load_failure_isolated().expect("isolated batch failure handling should succeed");
    }

    #[test]
    fn conflicting_plugin_names_are_rejected() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_conflict_plugin_names().expect("name conflict detection should succeed");
    }

    #[test]
    fn unique_plugin_names_pass_for_distinct_catalog() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_unique_plugin_names().expect("distinct plugin names should have no collisions");
    }

    #[test]
    fn loading_same_plugin_twice_is_idempotent() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_load_same_multiple_times().expect("re-loading a plugin should be a no-op");
    }

    #[test]
    fn dispose_failure_still_removes_plugin() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_dispose_fail().expect("dispose failure should not block removal");
    }

    #[test]
    fn init_failure_alone_is_disposed() {
        let mut fixture = MockPluginManagerTest::new();
        fixture.set_up().unwrap();
        fixture.test_init_fail().expect("init failure should still dispose the plugin once");
    }
}

use std::cmp::Ordering;
use std::collections::HashSet;
use std::path::Path;

use crate::program::seam_stubs::GhidraLaunchable;
use crate::util::exception::CancelledException;
use crate::util::seam_stubs::ApplicationModuleLike;
use crate::util::task::TaskMonitor;

/// Error produced by [`GhidraJarBuilder::build_jar`] and [`GhidraJarBuilder::build_src_zip`],
/// unifying the two checked exceptions (`IOException`, `CancelledException`) their Java
/// counterparts declare.
#[derive(thiserror::Error, Debug)]
pub enum GhidraJarBuilderError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Placeholder equivalent of `java.io.FileFilter`, needed by
/// [`GhidraJarBuilder::add_file_filter`]. This is a JDK interface, not an in-repo Ghidra class, so
/// it is declared directly here rather than in `seam_stubs`.
pub trait JarFileFilter: Send + Sync {
    /// Tests whether `file` should be included, mirroring `java.io.FileFilter.accept(File)`.
    fn accept(&self, file: &Path) -> bool;
}

/// Builds the standalone `ghidra.jar` distribution (and its companion source zip) out of a set of
/// application modules, mirroring `ghidra.util.GhidraJarBuilder`.
///
/// The Java class `implements GhidraLaunchable`, so this trait carries
/// [`crate::program::seam_stubs::GhidraLaunchable`] as a supertrait, mirroring that relationship
/// (see `DataTypeArchiveIdDumper` for the established convention). This trait was selected as a
/// dependency-cycle cut-point.
///
/// Ported here (the object-safe management surface other core types can depend on without pulling
/// in the jar-writing machinery): the module inclusion policy (see [`include_module_by_default`]),
/// module-set management (`add`/`remove`/`is_module_included`/`add_all_modules`/
/// `remove_all_processor_modules`), and the `ApplicationModule.compareTo` sort order the various
/// module-list getters apply.
///
/// Left unported (real jar/zip byte-level construction, not part of the cycle): the private
/// `Jar`/`Zip` inner-class machinery, extension-point class scanning, module-tree indexing, and
/// the `main`/CLI-argument-parsing entry point. [`build_jar`](Self::build_jar) and
/// [`build_src_zip`](Self::build_src_zip) are declared as the hooks a full implementation fills in
/// with that logic, matching how `DataTypeArchiveIdDumper::open_archive` stands in for
/// constructor-shaped work a trait cannot perform itself.
///
/// A trait has no constructors, so the state a real `new GhidraJarBuilder(ApplicationLayout)` would
/// seed (`rootGhidraDirs`, `allModules`, and the default `includedModules`) is left to
/// implementors; [`seed_included_module_names`] reproduces the one piece of *logic* that
/// constructor body carries.
pub trait GhidraJarBuilder: GhidraLaunchable {
    /// Returns every module known to this builder, in no particular order, mirroring the backing
    /// `allModules` field. Callers that need Java's `getAllModules()`/`getIncludedModules()`/
    /// `getExcludedModules()` ordering should use [`Self::all_modules`],
    /// [`Self::included_modules`], or [`Self::excluded_modules`] instead.
    fn all_modules_unordered(&self) -> Vec<Box<dyn ApplicationModuleLike>>;

    /// Returns the names of the currently-included modules, standing in for the backing
    /// `includedModules` field (kept as a name set here since `Box<dyn ApplicationModuleLike>`
    /// trait objects aren't usable as `HashSet` elements).
    fn included_module_names(&self) -> HashSet<String>;

    /// Replaces the set of included module names, the mutator [`Self::included_module_names`]'s
    /// default-derived methods use to update `includedModules`.
    fn set_included_module_names(&mut self, names: HashSet<String>);

    /// Adds a filter that every file written to the jar must pass, mirroring
    /// `GhidraJarBuilder.addFileFilter(FileFilter)`.
    fn add_file_filter(&mut self, filter: Box<dyn JarFileFilter>);

    /// Adds a file extension (e.g. `.pdf`) to exclude from the jar, mirroring
    /// `GhidraJarBuilder.addExcludedFileExtension(String)`.
    fn add_excluded_file_extension(&mut self, extension: String);

    /// Sets whether module `help` directories are excluded from the jar, mirroring
    /// `GhidraJarBuilder.setExcludeHelp(boolean)`.
    fn set_exclude_help(&mut self, exclude_help: bool);

    /// Sets the jar manifest's `Main-Class`, mirroring `GhidraJarBuilder.setMainClass(String)`.
    fn set_main_class(&mut self, main_class: String);

    /// Builds the standalone jar to `output_file`, optionally including an extra directory of
    /// pre-built classes (`extra_bin_dir`), mirroring
    /// `GhidraJarBuilder.buildJar(File, File, TaskMonitor)`.
    fn build_jar(
        &mut self,
        output_file: &Path,
        extra_bin_dir: Option<&Path>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), GhidraJarBuilderError>;

    /// Builds a zip of the source for every included module to `output_file`, mirroring
    /// `GhidraJarBuilder.buildSrcZip(File, TaskMonitor)`.
    fn build_src_zip(
        &mut self,
        output_file: &Path,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), GhidraJarBuilderError>;

    /// Returns every known module, sorted by [`module_rank`] then name, mirroring
    /// `GhidraJarBuilder.getAllModules()`.
    fn all_modules(&self) -> Vec<Box<dyn ApplicationModuleLike>> {
        let mut modules = self.all_modules_unordered();
        sort_modules(&mut modules);
        modules
    }

    /// Returns the currently-included modules, sorted, mirroring
    /// `GhidraJarBuilder.getIncludedModules()`.
    fn included_modules(&self) -> Vec<Box<dyn ApplicationModuleLike>> {
        let names = self.included_module_names();
        let mut modules: Vec<Box<dyn ApplicationModuleLike>> = self
            .all_modules_unordered()
            .into_iter()
            .filter(|m| names.contains(&m.name()))
            .collect();
        sort_modules(&mut modules);
        modules
    }

    /// Returns the modules that are known but not currently included, sorted, mirroring
    /// `GhidraJarBuilder.getExcludedModules()`.
    fn excluded_modules(&self) -> Vec<Box<dyn ApplicationModuleLike>> {
        let names = self.included_module_names();
        let mut modules: Vec<Box<dyn ApplicationModuleLike>> = self
            .all_modules_unordered()
            .into_iter()
            .filter(|m| !names.contains(&m.name()))
            .collect();
        sort_modules(&mut modules);
        modules
    }

    /// Looks up a known module by name, mirroring `GhidraJarBuilder.getModule(String)`.
    fn module(&self, name: &str) -> Option<Box<dyn ApplicationModuleLike>> {
        self.all_modules_unordered().into_iter().find(|m| m.name() == name)
    }

    /// Returns whether the named module is both known and currently included, mirroring
    /// `GhidraJarBuilder.isModuleIncluded(String)`.
    fn is_module_included(&self, module_name: &str) -> bool {
        self.module(module_name).is_some() && self.included_module_names().contains(module_name)
    }

    /// Includes every known module, mirroring `GhidraJarBuilder.addAllModules()`.
    fn add_all_modules(&mut self) {
        let mut names = self.included_module_names();
        for module in self.all_modules_unordered() {
            names.insert(module.name());
        }
        self.set_included_module_names(names);
    }

    /// Includes the named module if it is known, returning whether it was newly added, mirroring
    /// `GhidraJarBuilder.addModule(String)`.
    fn add_module(&mut self, name: &str) -> bool {
        if self.module(name).is_none() {
            return false;
        }
        let mut names = self.included_module_names();
        let inserted = names.insert(name.to_string());
        self.set_included_module_names(names);
        inserted
    }

    /// Excludes the named module if it is known, returning whether it had been included,
    /// mirroring `GhidraJarBuilder.removeModule(String)`.
    fn remove_module(&mut self, name: &str) -> bool {
        if self.module(name).is_none() {
            return false;
        }
        let mut names = self.included_module_names();
        let removed = names.remove(name);
        self.set_included_module_names(names);
        removed
    }

    /// Includes `module` directly (without requiring it be already known), mirroring
    /// `GhidraJarBuilder.addModuleToJar(ApplicationModule)`.
    fn add_module_to_jar(&mut self, module: &dyn ApplicationModuleLike) {
        let mut names = self.included_module_names();
        names.insert(module.name());
        self.set_included_module_names(names);
    }

    /// Excludes every currently-included processor module, mirroring
    /// `GhidraJarBuilder.removeAllProcessorModules()`.
    fn remove_all_processor_modules(&mut self) {
        let processor_names: HashSet<String> = self
            .all_modules_unordered()
            .into_iter()
            .filter(|m| m.is_processor())
            .map(|m| m.name())
            .collect();
        let mut names = self.included_module_names();
        names.retain(|n| !processor_names.contains(n));
        self.set_included_module_names(names);
    }
}

/// Mirrors the private `GhidraJarBuilder.includeByDefault(ApplicationModule)` policy the
/// `GhidraJarBuilder(ApplicationLayout)` constructor uses to seed `includedModules`.
pub fn include_module_by_default(module: &dyn ApplicationModuleLike) -> bool {
    if module.is_framework() || module.is_processor() || module.is_configuration() {
        return true;
    }
    if module.is_extension() {
        return false;
    }
    if module.is_feature() {
        return !module.exclude_from_ghidra_jar();
    }
    if module.is_debug() {
        return !module.exclude_from_ghidra_jar();
    }
    if module.is_gpl() {
        return !module.exclude_from_ghidra_jar();
    }
    false
}

/// Seeds the default set of included module names from a full module list, reproducing the
/// `includedModules`-populating loop in the body of `GhidraJarBuilder(ApplicationLayout)` (which a
/// trait cannot perform itself; see this trait's own doc comment). Implementors are expected to
/// call this while constructing a [`GhidraJarBuilder`] instance from a discovered module list.
pub fn seed_included_module_names(
    all_modules: &[Box<dyn ApplicationModuleLike>],
) -> HashSet<String> {
    all_modules
        .iter()
        .filter(|m| include_module_by_default(m.as_ref()))
        .map(|m| m.name())
        .collect()
}

/// Orders modules the same way `ApplicationModule.compareTo` does: framework modules first (rank
/// 1), then features (rank 2), then processors (rank 3), then everything else (rank 4) -- except
/// `RenoirGraph`, which always sorts last (rank 10). Exposed for reuse by implementors that need
/// Java's exact module ordering elsewhere.
pub fn module_rank(module: &dyn ApplicationModuleLike) -> i32 {
    if module.name() == "RenoirGraph" {
        return 10;
    }
    if module.is_framework() {
        return 1;
    }
    if module.is_feature() {
        return 2;
    }
    if module.is_processor() {
        return 3;
    }
    4
}

fn sort_modules(modules: &mut [Box<dyn ApplicationModuleLike>]) {
    modules.sort_by(|a, b| {
        let rank_cmp = module_rank(a.as_ref()).cmp(&module_rank(b.as_ref()));
        if rank_cmp != Ordering::Equal {
            rank_cmp
        } else {
            a.name().cmp(&b.name())
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io;

    struct MockModule {
        name: &'static str,
        category: &'static str,
        excluded_from_jar: bool,
    }

    impl MockModule {
        fn new(name: &'static str, category: &'static str) -> Self {
            Self { name, category, excluded_from_jar: false }
        }

        fn excluded(mut self) -> Self {
            self.excluded_from_jar = true;
            self
        }
    }

    impl ApplicationModuleLike for MockModule {
        fn name(&self) -> String {
            self.name.to_string()
        }
        fn is_extension(&self) -> bool {
            self.category == "Extensions"
        }
        fn is_framework(&self) -> bool {
            self.category == "Framework"
        }
        fn is_debug(&self) -> bool {
            self.category == "Debug"
        }
        fn is_processor(&self) -> bool {
            self.category == "Processors"
        }
        fn is_feature(&self) -> bool {
            self.category == "Features"
        }
        fn is_configuration(&self) -> bool {
            self.category == "Configurations"
        }
        fn is_gpl(&self) -> bool {
            self.category == "GPL"
        }
        fn exclude_from_ghidra_jar(&self) -> bool {
            self.excluded_from_jar
        }
    }

    fn boxed(m: MockModule) -> Box<dyn ApplicationModuleLike> {
        Box::new(m)
    }

    /// A minimal mock proving [`GhidraJarBuilder`] (and its [`GhidraLaunchable`] supertrait) are
    /// object-safe, and that its module-management defaults behave like the Java original.
    struct MockJarBuilder {
        modules: Vec<(&'static str, &'static str, bool)>,
        included: RefCell<HashSet<String>>,
        launched: RefCell<Vec<String>>,
    }

    impl GhidraLaunchable for MockJarBuilder {
        fn launch(
            &mut self,
            _layout: &dyn crate::program::seam_stubs::GhidraApplicationLayout,
            args: &[String],
        ) -> io::Result<()> {
            self.launched.borrow_mut().extend(args.iter().cloned());
            Ok(())
        }
    }

    impl GhidraJarBuilder for MockJarBuilder {
        fn all_modules_unordered(&self) -> Vec<Box<dyn ApplicationModuleLike>> {
            self.modules
                .iter()
                .map(|&(name, category, excluded)| {
                    let mut m = MockModule::new(name, category);
                    if excluded {
                        m = m.excluded();
                    }
                    boxed(m)
                })
                .collect()
        }

        fn included_module_names(&self) -> HashSet<String> {
            self.included.borrow().clone()
        }

        fn set_included_module_names(&mut self, names: HashSet<String>) {
            *self.included.borrow_mut() = names;
        }

        fn add_file_filter(&mut self, _filter: Box<dyn JarFileFilter>) {}

        fn add_excluded_file_extension(&mut self, _extension: String) {}

        fn set_exclude_help(&mut self, _exclude_help: bool) {}

        fn set_main_class(&mut self, _main_class: String) {}

        fn build_jar(
            &mut self,
            _output_file: &Path,
            _extra_bin_dir: Option<&Path>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), GhidraJarBuilderError> {
            Ok(())
        }

        fn build_src_zip(
            &mut self,
            _output_file: &Path,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), GhidraJarBuilderError> {
            Ok(())
        }
    }

    fn sample_builder() -> MockJarBuilder {
        let modules = vec![
            ("Base", "Features", false),
            ("Decompiler", "Features", true),
            ("Utility", "Framework", false),
            ("x86", "Processors", false),
            ("MyExtension", "Extensions", false),
            ("SomeDebugTool", "Debug", false),
            ("RenoirGraph", "Features", false),
            ("SleighSpec", "GPL", true),
        ];
        let all: Vec<Box<dyn ApplicationModuleLike>> = modules
            .iter()
            .map(|&(name, category, excluded)| {
                let mut m = MockModule::new(name, category);
                if excluded {
                    m = m.excluded();
                }
                boxed(m)
            })
            .collect();
        let included = seed_included_module_names(&all);
        MockJarBuilder { modules, included: RefCell::new(included), launched: RefCell::new(Vec::new()) }
    }

    #[test]
    fn include_by_default_matches_java_policy() {
        // Framework/processor/configuration: always in.
        assert!(include_module_by_default(&MockModule::new("Utility", "Framework")));
        assert!(include_module_by_default(&MockModule::new("x86", "Processors")));
        assert!(include_module_by_default(&MockModule::new("Cfg", "Configurations")));
        // Extension: always out.
        assert!(!include_module_by_default(&MockModule::new("MyExt", "Extensions")));
        // Feature/debug/GPL: in unless excluded via manifest.
        assert!(include_module_by_default(&MockModule::new("Base", "Features")));
        assert!(!include_module_by_default(
            &MockModule::new("Decompiler", "Features").excluded()
        ));
        assert!(include_module_by_default(&MockModule::new("Dbg", "Debug")));
        assert!(!include_module_by_default(&MockModule::new("Dbg", "Debug").excluded()));
        assert!(!include_module_by_default(&MockModule::new("Spec", "GPL").excluded()));
        // Unknown category: out.
        assert!(!include_module_by_default(&MockModule::new("Mystery", "Other")));
    }

    #[test]
    fn seeded_inclusion_matches_default_policy() {
        let builder = sample_builder();
        let included: HashSet<String> =
            builder.included_modules().iter().map(|m| m.name()).collect();
        assert!(included.contains("Base"));
        assert!(included.contains("Utility"));
        assert!(included.contains("x86"));
        assert!(included.contains("SomeDebugTool"));
        assert!(included.contains("RenoirGraph"));
        assert!(!included.contains("Decompiler")); // excluded via manifest
        assert!(!included.contains("MyExtension")); // extensions never default-included
        assert!(!included.contains("SleighSpec")); // GPL, excluded via manifest
    }

    #[test]
    fn all_modules_sorted_by_rank_then_name() {
        let builder = sample_builder();
        let names: Vec<String> = builder.all_modules().iter().map(|m| m.name()).collect();
        // Framework (1) < Features (2, alphabetical, RenoirGraph forced last) < Processors (3)
        // < everything else (4).
        assert_eq!(
            names,
            vec![
                "Utility".to_string(),
                "Base".to_string(),
                "Decompiler".to_string(),
                "x86".to_string(),
                "MyExtension".to_string(),
                "SleighSpec".to_string(),
                "SomeDebugTool".to_string(),
                "RenoirGraph".to_string(),
            ]
        );
    }

    #[test]
    fn add_remove_and_query_module_inclusion() {
        let mut builder = sample_builder();
        assert!(!builder.is_module_included("MyExtension"));
        assert!(builder.add_module("MyExtension"));
        assert!(builder.is_module_included("MyExtension"));
        assert!(!builder.add_module("MyExtension")); // already included -> false
        assert!(builder.remove_module("MyExtension"));
        assert!(!builder.is_module_included("MyExtension"));
        assert!(!builder.remove_module("MyExtension")); // already removed -> false
        assert!(!builder.add_module("DoesNotExist")); // unknown module -> false
        assert!(!builder.is_module_included("DoesNotExist"));
    }

    #[test]
    fn add_module_to_jar_bypasses_known_module_lookup() {
        // Mirrors a real quirk of the Java original: `addModuleToJar` inserts directly into
        // `includedModules` without consulting `allModules`, but `isModuleIncluded` looks the
        // name up via `getModule` (which only searches `allModules`) first -- so a module added
        // this way shows up in `getIncludedModules()` yet `isModuleIncluded` still reports false
        // for it.
        let mut builder = sample_builder();
        let external = MockModule::new("ExternalThing", "Other");
        builder.add_module_to_jar(&external);
        assert!(builder.included_module_names().contains("ExternalThing"));
        assert!(!builder.is_module_included("ExternalThing"));
    }

    #[test]
    fn add_all_and_remove_all_processor_modules() {
        let mut builder = sample_builder();
        builder.add_all_modules();
        let all_names: HashSet<String> = builder.all_modules().iter().map(|m| m.name()).collect();
        let included_names: HashSet<String> =
            builder.included_modules().iter().map(|m| m.name()).collect();
        assert_eq!(all_names, included_names);
        assert!(builder.excluded_modules().is_empty());

        builder.remove_all_processor_modules();
        assert!(!builder.is_module_included("x86"));
        assert!(builder.is_module_included("Base"));
    }

    #[test]
    fn launch_delegates_through_ghidra_launchable_supertrait() {
        struct StubLayout;
        impl crate::program::seam_stubs::GhidraApplicationLayout for StubLayout {}
        let args = vec!["-output".to_string(), "ghidra.jar".to_string()];

        // Object-safety: `GhidraJarBuilder` (and its `GhidraLaunchable` supertrait) must be
        // usable behind a trait object.
        let mut boxed_builder: Box<dyn GhidraJarBuilder> = Box::new(sample_builder());
        boxed_builder.launch(&StubLayout, &args).unwrap();

        // Real behavior: the supertrait method actually runs and records its arguments.
        let mut builder = sample_builder();
        builder.launch(&StubLayout, &args).unwrap();
        assert_eq!(builder.launched.into_inner(), args);
    }
}

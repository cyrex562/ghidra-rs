use crate::framework::plugintool::ServiceInfo;
use crate::framework::plugintool::util::PluginException;
use crate::framework::seam_stubs::{PluginLike, PluginTool};

/// Utility trait for plugin-related lookups and construction.
///
/// Mirrors `ghidra.framework.plugintool.util.PluginUtils`. In Java this is a static utility class
/// that leans on reflection (`Class<T>` objects, `Constructor.newInstance`) and Ghidra's
/// classpath-scanning `ClassSearcher` to discover and instantiate `Plugin` subclasses. Rust has
/// no reflection or classpath scanning, so — mirroring how other `ClassSearcher`-backed types in
/// this crate are ported (see [`Analyzer`](crate::app::services::Analyzer),
/// [`LanguageProvider`](crate::program::model::lang::LanguageProvider)) — this becomes a registry
/// trait: implementations register known plugin classes (by fully-qualified name) explicitly
/// instead of discovering them via a classpath scan. `Class<? extends Plugin>` is represented by
/// its fully-qualified name as a `String`, matching how
/// [`ServiceInfo`](crate::framework::plugintool::ServiceInfo) and
/// [`PluginInstaller`](crate::framework::plugintool::PluginInstaller) already model
/// `Class<? extends Plugin>` elements. Selected as a dependency-cycle cut-point, so it is ported
/// as an object-safe trait rather than tied to a concrete registry implementation.
///
/// Was selected as a dependency-cycle cut-point.
pub trait PluginUtils {
    /// Returns a new instance of a plugin identified by its fully-qualified class name, mirroring
    /// `instantiatePlugin(Class<T>, PluginTool)`.
    ///
    /// `plugin_class_name` -- fully-qualified name of the plugin class to construct.
    /// `tool` -- the [`PluginTool`] that is the parent of the new plugin.
    ///
    /// Returns an error if `plugin_class_name` does not name a known/constructible plugin class.
    fn instantiate_plugin(
        &self,
        plugin_class_name: &str,
        tool: &dyn PluginTool,
    ) -> Result<Box<dyn PluginLike>, PluginException>;

    /// Returns the fully-qualified name of the registered plugin class matching
    /// `plugin_class_name`, mirroring `forName(String)`.
    ///
    /// Returns an error if no registered plugin class has that name.
    fn for_name(&self, plugin_class_name: &str) -> Result<String, PluginException>;

    /// Returns the fully-qualified plugin class name that is the default provider for a service,
    /// or `None` if no default provider is specified. Mirrors
    /// `getDefaultProviderForServiceClass(Class<?>)`.
    ///
    /// `service_info` -- the service's [`ServiceInfo`] metadata, if the service declares any.
    /// `None` mirrors the Java `@ServiceInfo` annotation being absent from the service class.
    /// The legacy fallback of reading a public static `String defaultProvider` field via
    /// reflection has no Rust equivalent (no field reflection) and is dropped.
    fn default_provider_for_service_class(
        &self,
        service_info: Option<&dyn ServiceInfo>,
    ) -> Option<String>;

    /// Returns the plugin name derived from a fully-qualified plugin class name, mirroring
    /// `getPluginNameFromClass(Class<? extends Plugin>)` (`Class.getSimpleName()`).
    ///
    /// This is a pure string operation that needs no registry lookup, so it has a default
    /// implementation shared by every implementor.
    fn plugin_name_from_class(&self, plugin_class_name: &str) -> String {
        plugin_class_name
            .rsplit(['.', '$'])
            .next()
            .unwrap_or(plugin_class_name)
            .to_string()
    }

    /// Ensures the named plugin class is uniquely named among all registered plugin classes,
    /// mirroring `assertUniquePluginName(Class<? extends Plugin>)`.
    ///
    /// Returns an error if another registered plugin class shares the same simple name (per
    /// [`Self::plugin_name_from_class`]).
    fn assert_unique_plugin_name(&self, plugin_class_name: &str) -> Result<(), PluginException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    struct MockPlugin;

    impl PluginLike for MockPlugin {}

    struct MockTool;

    impl PluginTool for MockTool {}

    struct StubServiceInfo {
        default_provider: Vec<String>,
        default_provider_name: String,
    }

    impl ServiceInfo for StubServiceInfo {
        fn default_provider_name(&self) -> String {
            self.default_provider_name.clone()
        }

        fn default_provider(&self) -> Vec<String> {
            self.default_provider.clone()
        }
    }

    struct MockPluginUtils {
        registered: HashSet<String>,
    }

    impl MockPluginUtils {
        fn new(classes: &[&str]) -> Self {
            Self {
                registered: classes.iter().map(|c| c.to_string()).collect(),
            }
        }
    }

    impl PluginUtils for MockPluginUtils {
        fn instantiate_plugin(
            &self,
            plugin_class_name: &str,
            _tool: &dyn PluginTool,
        ) -> Result<Box<dyn PluginLike>, PluginException> {
            if !self.registered.contains(plugin_class_name) {
                return Err(PluginException::new(
                    plugin_class_name,
                    "Possibly missing plugin constructor",
                ));
            }
            Ok(Box::new(MockPlugin))
        }

        fn for_name(&self, plugin_class_name: &str) -> Result<String, PluginException> {
            if self.registered.contains(plugin_class_name) {
                Ok(plugin_class_name.to_string())
            } else {
                Err(PluginException::with_message(&format!(
                    "Plugin class not found: {}",
                    plugin_class_name
                )))
            }
        }

        fn default_provider_for_service_class(
            &self,
            service_info: Option<&dyn ServiceInfo>,
        ) -> Option<String> {
            let info = service_info?;
            if let Some(first) = info.default_provider().into_iter().next() {
                return Some(first);
            }
            let name = info.default_provider_name();
            if !name.is_empty() {
                return Some(name);
            }
            None
        }

        fn assert_unique_plugin_name(&self, plugin_class_name: &str) -> Result<(), PluginException> {
            let name = self.plugin_name_from_class(plugin_class_name);
            let has_duplicate = self.registered.iter().any(|other| {
                other != plugin_class_name && self.plugin_name_from_class(other) == name
            });
            if has_duplicate {
                Err(PluginException::with_message(&format!(
                    "Duplicate Plugin name: {}",
                    plugin_class_name
                )))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn trait_is_object_safe_and_instantiates_registered_plugin() {
        let utils: Box<dyn PluginUtils> =
            Box::new(MockPluginUtils::new(&["com.example.FooPlugin"]));
        let tool = MockTool;

        let plugin = utils.instantiate_plugin("com.example.FooPlugin", &tool);
        assert!(plugin.is_ok());
    }

    #[test]
    fn instantiate_plugin_fails_for_unregistered_class() {
        let utils = MockPluginUtils::new(&["com.example.FooPlugin"]);
        let tool = MockTool;

        let result = utils.instantiate_plugin("com.example.MissingPlugin", &tool);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected instantiate_plugin to fail for an unregistered class"),
        };
        assert!(err.to_string().contains("MissingPlugin"));
    }

    #[test]
    fn for_name_resolves_registered_class() {
        let utils = MockPluginUtils::new(&["com.example.FooPlugin"]);
        assert_eq!(
            utils.for_name("com.example.FooPlugin").unwrap(),
            "com.example.FooPlugin"
        );
    }

    #[test]
    fn for_name_errors_for_unknown_class() {
        let utils = MockPluginUtils::new(&["com.example.FooPlugin"]);
        assert!(utils.for_name("com.example.Unknown").is_err());
    }

    #[test]
    fn plugin_name_from_class_strips_package_and_outer_class() {
        let utils = MockPluginUtils::new(&[]);
        assert_eq!(
            utils.plugin_name_from_class("com.example.FooPlugin"),
            "FooPlugin"
        );
        assert_eq!(
            utils.plugin_name_from_class("com.example.Outer$InnerPlugin"),
            "InnerPlugin"
        );
    }

    #[test]
    fn assert_unique_plugin_name_detects_duplicates() {
        let utils = MockPluginUtils::new(&["a.pkg.FooPlugin", "b.pkg.FooPlugin"]);
        assert!(utils.assert_unique_plugin_name("a.pkg.FooPlugin").is_err());
    }

    #[test]
    fn assert_unique_plugin_name_allows_unique_names() {
        let utils = MockPluginUtils::new(&["a.pkg.FooPlugin", "b.pkg.BarPlugin"]);
        assert!(utils.assert_unique_plugin_name("a.pkg.FooPlugin").is_ok());
    }

    #[test]
    fn default_provider_for_service_class_prefers_default_provider_list() {
        let utils = MockPluginUtils::new(&[]);
        let info = StubServiceInfo {
            default_provider: vec!["com.example.FooPlugin".to_string()],
            default_provider_name: "com.example.IgnoredPlugin".to_string(),
        };
        assert_eq!(
            utils.default_provider_for_service_class(Some(&info)),
            Some("com.example.FooPlugin".to_string())
        );
    }

    #[test]
    fn default_provider_for_service_class_falls_back_to_name() {
        let utils = MockPluginUtils::new(&[]);
        let info = StubServiceInfo {
            default_provider: Vec::new(),
            default_provider_name: "com.example.FooPlugin".to_string(),
        };
        assert_eq!(
            utils.default_provider_for_service_class(Some(&info)),
            Some("com.example.FooPlugin".to_string())
        );
    }

    #[test]
    fn default_provider_for_service_class_none_when_no_service_info() {
        let utils = MockPluginUtils::new(&[]);
        assert_eq!(utils.default_provider_for_service_class(None), None);
    }
}

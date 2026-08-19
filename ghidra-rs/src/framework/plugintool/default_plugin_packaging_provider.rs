//! Port of `ghidra.framework.plugintool.DefaultPluginPackagingProvider`.
//!
//! The default plugin package provider that uses a `PluginsConfiguration` to supply packages and
//! plugin descriptions. Selected as a dependency-cycle cut-point, so it is ported here as an
//! object-safe trait (mirroring the `PluginPackagingProvider` interface it implements) rather than
//! as a concrete implementation tied to `PluginsConfiguration`.

use crate::framework::plugintool::util::PluginDescription;
use crate::framework::seam_stubs::PluginPackageLike;

/// Provides `PluginPackage`s and plugin descriptions to clients.
///
/// Mirrors `ghidra.framework.plugintool.DefaultPluginPackagingProvider`. Object-safe, so
/// implementations can be stored as `Box<dyn DefaultPluginPackagingProvider>`/
/// `Arc<dyn DefaultPluginPackagingProvider>`.
pub trait DefaultPluginPackagingProvider {
    /// Returns all known plugin packages, mirroring `getPluginPackages()`.
    fn get_plugin_packages(&self) -> Vec<Box<dyn PluginPackageLike>>;

    /// Returns all loaded (non-hidden) plugin descriptions, mirroring `getPluginDescriptions()`.
    fn get_plugin_descriptions(&self) -> Vec<Box<dyn PluginDescription>>;

    /// Returns the plugin description for the given plugin class name, or `None` if there is no
    /// such description, mirroring `getPluginDescription(String)`.
    fn get_plugin_description(&self, plugin_class_name: &str) -> Option<Box<dyn PluginDescription>>;

    /// Gets all plugin descriptions for the given plugin package, mirroring
    /// `getPluginDescriptions(PluginPackage)`.
    fn get_plugin_descriptions_for_package(
        &self,
        plugin_package: &dyn PluginPackageLike,
    ) -> Vec<Box<dyn PluginDescription>>;

    /// Returns the plugin package used to house all unstable plugins, mirroring
    /// `getUnstablePluginPackage()`.
    fn get_unstable_plugin_package(&self) -> Box<dyn PluginPackageLike>;

    /// Returns all unstable plugin package descriptions, mirroring
    /// `getUnstablePluginDescriptions()`.
    fn get_unstable_plugin_descriptions(&self) -> Vec<Box<dyn PluginDescription>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockPackage {
        name: String,
    }

    impl PluginPackageLike for MockPackage {
        fn name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockDescription {
        class_name: String,
        package_name: String,
        unstable: bool,
    }

    impl PluginDescription for MockDescription {
        fn plugin_class_name(&self) -> String {
            self.class_name.clone()
        }

        fn name(&self) -> String {
            self.class_name.rsplit(['.', '$']).next().unwrap_or(&self.class_name).to_string()
        }

        fn short_description(&self) -> String {
            "no description".to_string()
        }

        fn description(&self) -> String {
            "no description".to_string()
        }

        fn category(&self) -> String {
            "NO_CATEGORY".to_string()
        }

        fn status(&self) -> crate::framework::plugintool::util::PluginStatus {
            if self.unstable {
                crate::framework::plugintool::util::PluginStatus::Unstable
            } else {
                crate::framework::plugintool::util::PluginStatus::Released
            }
        }

        fn plugin_package(&self) -> Box<dyn PluginPackageLike> {
            Box::new(MockPackage { name: self.package_name.clone() })
        }

        fn is_slow_installation(&self) -> bool {
            false
        }

        fn services_required(&self) -> Vec<String> {
            Vec::new()
        }

        fn services_provided(&self) -> Vec<String> {
            Vec::new()
        }

        fn events_consumed(&self) -> Vec<String> {
            Vec::new()
        }

        fn events_produced(&self) -> Vec<String> {
            Vec::new()
        }

        fn source_location(&self) -> String {
            String::new()
        }

        fn module_name(&self) -> String {
            String::new()
        }

        fn is_in_extension(&self) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct MockPackagingProvider {
        packages: Vec<MockPackage>,
        descriptions: Vec<MockDescription>,
    }

    impl DefaultPluginPackagingProvider for MockPackagingProvider {
        fn get_plugin_packages(&self) -> Vec<Box<dyn PluginPackageLike>> {
            self.packages
                .iter()
                .cloned()
                .map(|p| Box::new(p) as Box<dyn PluginPackageLike>)
                .collect()
        }

        fn get_plugin_descriptions(&self) -> Vec<Box<dyn PluginDescription>> {
            self.descriptions
                .iter()
                .map(|d| {
                    Box::new(MockDescription {
                        class_name: d.class_name.clone(),
                        package_name: d.package_name.clone(),
                        unstable: d.unstable,
                    }) as Box<dyn PluginDescription>
                })
                .collect()
        }

        fn get_plugin_description(
            &self,
            plugin_class_name: &str,
        ) -> Option<Box<dyn PluginDescription>> {
            self.descriptions
                .iter()
                .find(|d| d.class_name == plugin_class_name)
                .map(|d| {
                    Box::new(MockDescription {
                        class_name: d.class_name.clone(),
                        package_name: d.package_name.clone(),
                        unstable: d.unstable,
                    }) as Box<dyn PluginDescription>
                })
        }

        fn get_plugin_descriptions_for_package(
            &self,
            plugin_package: &dyn PluginPackageLike,
        ) -> Vec<Box<dyn PluginDescription>> {
            let package_name = plugin_package.name();
            self.descriptions
                .iter()
                .filter(|d| d.package_name == package_name)
                .map(|d| {
                    Box::new(MockDescription {
                        class_name: d.class_name.clone(),
                        package_name: d.package_name.clone(),
                        unstable: d.unstable,
                    }) as Box<dyn PluginDescription>
                })
                .collect()
        }

        fn get_unstable_plugin_package(&self) -> Box<dyn PluginPackageLike> {
            Box::new(MockPackage { name: "Experimental".to_string() })
        }

        fn get_unstable_plugin_descriptions(&self) -> Vec<Box<dyn PluginDescription>> {
            self.descriptions
                .iter()
                .filter(|d| d.unstable)
                .map(|d| {
                    Box::new(MockDescription {
                        class_name: d.class_name.clone(),
                        package_name: d.package_name.clone(),
                        unstable: d.unstable,
                    }) as Box<dyn PluginDescription>
                })
                .collect()
        }
    }

    #[test]
    fn get_plugin_description_finds_by_class_name() {
        let provider = MockPackagingProvider {
            packages: vec![MockPackage { name: "Core".to_string() }],
            descriptions: vec![
                MockDescription {
                    class_name: "com.example.FooPlugin".to_string(),
                    package_name: "Core".to_string(),
                    unstable: false,
                },
                MockDescription {
                    class_name: "com.example.BarPlugin".to_string(),
                    package_name: "Core".to_string(),
                    unstable: true,
                },
            ],
        };

        let found = provider.get_plugin_description("com.example.FooPlugin");
        assert!(found.is_some());

        let missing = provider.get_plugin_description("com.example.NoSuchPlugin");
        assert!(missing.is_none());
    }

    #[test]
    fn get_unstable_plugin_descriptions_filters_by_status() {
        let provider = MockPackagingProvider {
            packages: vec![MockPackage { name: "Core".to_string() }],
            descriptions: vec![
                MockDescription {
                    class_name: "com.example.FooPlugin".to_string(),
                    package_name: "Core".to_string(),
                    unstable: false,
                },
                MockDescription {
                    class_name: "com.example.BarPlugin".to_string(),
                    package_name: "Core".to_string(),
                    unstable: true,
                },
            ],
        };

        let unstable = provider.get_unstable_plugin_descriptions();
        assert_eq!(unstable.len(), 1);

        let all = provider.get_plugin_descriptions();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn get_plugin_descriptions_for_package_filters_by_package_name() {
        let provider = MockPackagingProvider {
            packages: vec![
                MockPackage { name: "Core".to_string() },
                MockPackage { name: "Experimental".to_string() },
            ],
            descriptions: vec![
                MockDescription {
                    class_name: "com.example.FooPlugin".to_string(),
                    package_name: "Core".to_string(),
                    unstable: false,
                },
                MockDescription {
                    class_name: "com.example.BarPlugin".to_string(),
                    package_name: "Experimental".to_string(),
                    unstable: true,
                },
            ],
        };

        let core = MockPackage { name: "Core".to_string() };
        let core_descriptions = provider.get_plugin_descriptions_for_package(&core);
        assert_eq!(core_descriptions.len(), 1);

        let empty = MockPackage { name: "NoSuchPackage".to_string() };
        assert!(provider.get_plugin_descriptions_for_package(&empty).is_empty());
    }

    #[test]
    fn trait_is_object_safe() {
        let provider = MockPackagingProvider::default();
        let boxed: Box<dyn DefaultPluginPackagingProvider> = Box::new(provider);
        assert!(boxed.get_plugin_packages().is_empty());
    }
}

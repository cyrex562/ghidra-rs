use std::cmp::Ordering;

use crate::framework::plugintool::util::PluginStatus;
use crate::framework::seam_stubs::PluginPackageLike;

/// Meta information about a plugin, derived from meta-data attached to a `Plugin` using a
/// `PluginInfo` annotation.
///
/// Mirrors `ghidra.framework.plugintool.util.PluginDescription`. Selected as a
/// dependency-cycle cut-point, so it is ported as an object-safe trait rather than a concrete
/// class holding a `Class<? extends Plugin>`.
///
/// `Class<?>`-typed members (`getPluginClass()`, `getServicesRequired()`, `getServicesProvided()`,
/// `getEventsConsumed()`, `getEventsProduced()`) are represented by fully-qualified type name(s),
/// matching how [`PluginInfo`](crate::framework::plugintool::PluginInfo) already models the same
/// annotation elements. `getPluginPackage()` returns the
/// [`PluginPackageLike`](crate::framework::seam_stubs::PluginPackageLike) seam placeholder since
/// `PluginPackage` itself is not yet ported.
///
/// The static factory/cache methods (`getPluginDescription(Class)`, `createPluginDescription(...)`
/// overloads, `createDefaultPluginDescription`) lean on reflection (`Class.getAnnotation`,
/// `Class.getMethod`/`Method.invoke`) and a static `HashMap` cache to build instances from a
/// `Plugin` subclass; Java itself marks the reflection-based overloads `@Deprecated` as legacy
/// candidates for removal. Rust has no reflection, so those are omitted here -- implementations
/// are constructed directly by whatever code discovers/registers plugins, mirroring how
/// [`PluginUtils`](crate::framework::plugintool::util::PluginUtils) replaced classpath scanning
/// with an explicit registry.
///
/// `getSourceLocation()`, `getModuleName()`, and `isInExtension()` are derived in Java from the
/// plugin class's `ClassLoader`-resolved `URL` and `Application`'s module/extension-directory
/// scanning, none of which exist in Rust; implementations are expected to supply these values
/// directly (e.g. from build-time metadata) rather than compute them via reflection.
pub trait PluginDescription {
    /// Fully-qualified name of the plugin class this description was derived from, mirroring
    /// `getPluginClass()` (returning the class's name rather than a `Class` object).
    fn plugin_class_name(&self) -> String;

    /// Return the name of the plugin, mirroring `getName()` (`Class.getSimpleName()`).
    fn name(&self) -> String;

    /// Set the short description for what the plugin does, mirroring `getShortDescription()`.
    fn short_description(&self) -> String;

    /// Return the description of the plugin, mirroring `getDescription()`.
    fn description(&self) -> String;

    /// Return the category for the plugin, mirroring `getCategory()`.
    fn category(&self) -> String;

    /// Returns the development status of the plugin, mirroring `getStatus()`.
    fn status(&self) -> PluginStatus;

    /// Mirrors `getPluginPackage()`.
    fn plugin_package(&self) -> Box<dyn PluginPackageLike>;

    /// Returns true if this plugin requires a noticeable amount of time to load when installed,
    /// mirroring `isSlowInstallation()`.
    fn is_slow_installation(&self) -> bool;

    /// Mirrors `getServicesRequired()`, with each `Class<?>` represented by its fully-qualified
    /// name.
    fn services_required(&self) -> Vec<String>;

    /// Mirrors `getServicesProvided()`, with each `Class<?>` represented by its fully-qualified
    /// name.
    fn services_provided(&self) -> Vec<String>;

    /// Mirrors `getEventsConsumed()`, with each `Class<? extends PluginEvent>` represented by its
    /// fully-qualified name.
    fn events_consumed(&self) -> Vec<String>;

    /// Mirrors `getEventsProduced()`, with each `Class<? extends PluginEvent>` represented by its
    /// fully-qualified name.
    fn events_produced(&self) -> Vec<String>;

    /// Get the location for the source file for the plugin, mirroring `getSourceLocation()`.
    fn source_location(&self) -> String;

    /// Returns the name of the module that contains the plugin, mirroring `getModuleName()`.
    fn module_name(&self) -> String;

    /// Returns true if this plugin is provided by an extension, mirroring `isInExtension()`.
    fn is_in_extension(&self) -> bool;

    /// Return whether the plugin is in the given category, mirroring `isInCategory(String)`.
    fn is_in_category(&self, parent_category: &str) -> bool {
        self.category() == parent_category
    }

    /// Formats this description the same way `toString()` does: `"<package>:<category>:<name>"`.
    fn describe(&self) -> String {
        format!("{}:{}:{}", self.plugin_package().name(), self.category(), self.name())
    }

    /// Compares by plugin name, mirroring `compareTo(PluginDescription)`.
    fn compare_name(&self, other: &dyn PluginDescription) -> Ordering {
        self.name().cmp(&other.name())
    }

    /// Compares by plugin class name, mirroring `equals(Object)` (which compares `pluginClass`).
    fn same_plugin_class(&self, other: &dyn PluginDescription) -> bool {
        self.plugin_class_name() == other.plugin_class_name()
    }
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

    struct MockPluginDescription {
        plugin_class_name: String,
        name: String,
        category: String,
        package: MockPackage,
        status: PluginStatus,
    }

    impl PluginDescription for MockPluginDescription {
        fn plugin_class_name(&self) -> String {
            self.plugin_class_name.clone()
        }

        fn name(&self) -> String {
            self.name.clone()
        }

        fn short_description(&self) -> String {
            "no description".to_string()
        }

        fn description(&self) -> String {
            "no description".to_string()
        }

        fn category(&self) -> String {
            self.category.clone()
        }

        fn status(&self) -> PluginStatus {
            self.status
        }

        fn plugin_package(&self) -> Box<dyn PluginPackageLike> {
            Box::new(self.package.clone())
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
            "/some/module/bin/main".to_string()
        }

        fn module_name(&self) -> String {
            "SomeModule".to_string()
        }

        fn is_in_extension(&self) -> bool {
            false
        }
    }

    fn mock(class_name: &str, name: &str, category: &str, package: &str) -> MockPluginDescription {
        MockPluginDescription {
            plugin_class_name: class_name.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            package: MockPackage { name: package.to_string() },
            status: PluginStatus::Released,
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let pd: Box<dyn PluginDescription> =
            Box::new(mock("com.example.FooPlugin", "FooPlugin", "Common", "Core"));
        assert_eq!(pd.name(), "FooPlugin");
        assert_eq!(pd.status(), PluginStatus::Released);
    }

    #[test]
    fn is_in_category_matches_exact_category() {
        let pd = mock("com.example.FooPlugin", "FooPlugin", "Common", "Core");
        assert!(pd.is_in_category("Common"));
        assert!(!pd.is_in_category("Diagnostic"));
    }

    #[test]
    fn describe_matches_java_tostring_format() {
        let pd = mock("com.example.FooPlugin", "FooPlugin", "Common", "Core");
        assert_eq!(pd.describe(), "Core:Common:FooPlugin");
    }

    #[test]
    fn compare_name_orders_by_name() {
        let a = mock("com.example.AaaPlugin", "AaaPlugin", "Common", "Core");
        let b = mock("com.example.ZzzPlugin", "ZzzPlugin", "Common", "Core");
        assert_eq!(a.compare_name(&b), Ordering::Less);
        assert_eq!(b.compare_name(&a), Ordering::Greater);
        assert_eq!(a.compare_name(&a), Ordering::Equal);
    }

    #[test]
    fn same_plugin_class_compares_by_class_name_not_instance_fields() {
        let a = mock("com.example.FooPlugin", "FooPlugin", "Common", "Core");
        let b = mock("com.example.FooPlugin", "FooPlugin", "Diagnostic", "Experimental");
        let c = mock("com.example.BarPlugin", "BarPlugin", "Common", "Core");

        assert!(a.same_plugin_class(&b));
        assert!(!a.same_plugin_class(&c));
    }
}

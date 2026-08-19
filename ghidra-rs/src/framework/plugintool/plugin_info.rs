use crate::framework::plugintool::util::PluginStatus;

/// Information about a Ghidra `Plugin`.
///
/// Mirrors `ghidra.framework.plugintool.PluginInfo`.
///
/// In Java this is a runtime annotation (`@PluginInfo`) placed on a `Plugin`
/// subclass to declare its metadata. Rust has no reflective annotation system,
/// so the same metadata is exposed here as a trait that a plugin descriptor
/// implements, mirroring each annotation element as a trait method.
///
/// `Class<?>` elements (`eventsConsumed`, `eventsProduced`, `servicesRequired`,
/// `servicesProvided`) are represented by their fully-qualified type name rather
/// than a `Class` object or trait object, matching how this crate already
/// represents `Class<?>` annotation elements (see
/// [`AutoServiceProvided`](crate::framework::plugintool::annotation::AutoServiceProvided)).
pub trait PluginInfo {
    /// The [`PluginStatus`] of this plugin: `Stable`, `Released`, `Hidden`, `Unstable`, etc.
    fn status(&self) -> PluginStatus;

    /// The package name this plugin belongs in.
    fn package_name(&self) -> String;

    /// The plugin category, e.g. `PluginCategoryNames::COMMON`.
    fn category(&self) -> String;

    /// A brief description of what the plugin does.
    ///
    /// This string probably should not end with a "." character.
    fn short_description(&self) -> String;

    /// The long description of what the plugin does.
    ///
    /// This string probably should end with a "." character.
    fn description(&self) -> String;

    /// Signals that this plugin loads slowly.
    ///
    /// Defaults to `false`, matching `isSlowInstallation() default false`.
    fn is_slow_installation(&self) -> bool {
        false
    }

    /// Names of the `PluginEvent` types that this plugin consumes.
    ///
    /// Defaults to empty, matching `eventsConsumed() default {}`.
    fn events_consumed(&self) -> Vec<String> {
        Vec::new()
    }

    /// Names of the `PluginEvent` types that this plugin produces.
    ///
    /// Defaults to empty, matching `eventsProduced() default {}`.
    fn events_produced(&self) -> Vec<String> {
        Vec::new()
    }

    /// Names of the service interface types that this plugin requires (depends on).
    ///
    /// Defaults to empty, matching `servicesRequired() default {}`.
    fn services_required(&self) -> Vec<String> {
        Vec::new()
    }

    /// Names of the service interface types that this plugin provides.
    ///
    /// Defaults to empty, matching `servicesProvided() default {}`.
    fn services_provided(&self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPluginInfo;

    impl PluginInfo for MockPluginInfo {
        fn status(&self) -> PluginStatus {
            PluginStatus::Released
        }

        fn package_name(&self) -> String {
            "CorePluginPackage".to_string()
        }

        fn category(&self) -> String {
            "Common".to_string()
        }

        fn short_description(&self) -> String {
            "Short description of plugin".to_string()
        }

        fn description(&self) -> String {
            "Longer description of plugin.".to_string()
        }

        fn services_provided(&self) -> Vec<String> {
            vec!["ServiceInterfaceThisPluginProvides".to_string()]
        }

        fn services_required(&self) -> Vec<String> {
            vec!["RequiredServiceInterface1".to_string(), "RequiredServiceInterface2".to_string()]
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let info: Box<dyn PluginInfo> = Box::new(MockPluginInfo);
        assert_eq!(info.status(), PluginStatus::Released);
        assert_eq!(info.package_name(), "CorePluginPackage");
        assert_eq!(info.category(), "Common");
    }

    #[test]
    fn defaults_match_java_annotation_defaults() {
        let info = MockPluginInfo;
        assert!(!info.is_slow_installation());
        assert!(info.events_consumed().is_empty());
        assert!(info.events_produced().is_empty());
    }

    #[test]
    fn overridden_service_lists_are_reported() {
        let info = MockPluginInfo;
        assert_eq!(info.services_provided(), vec!["ServiceInterfaceThisPluginProvides"]);
        assert_eq!(
            info.services_required(),
            vec!["RequiredServiceInterface1", "RequiredServiceInterface2"]
        );
    }
}

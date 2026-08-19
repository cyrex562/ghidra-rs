/// Meta-data about a Plugin's Service.
///
/// Mirrors `ghidra.framework.plugintool.ServiceInfo`.
///
/// In Java this is a runtime annotation (`@ServiceInfo`) placed on a service
/// interface to declare its default provider and description, e.g.:
///
/// ```java
/// @ServiceInfo( defaultProvider = MyPlugin.class )
/// public interface MyService {
///     public void foo();
/// }
/// ```
///
/// Rust has no reflective annotation system, so the same metadata is exposed
/// here as a trait that a service descriptor implements, mirroring each
/// annotation element as a trait method. `Class<? extends Plugin>` elements are
/// represented by their fully-qualified type name rather than a `Class` object
/// or trait object, matching how this crate already represents `Class<?>`
/// annotation elements (see
/// [`PluginInfo`](crate::framework::plugintool::PluginInfo)).
pub trait ServiceInfo {
    /// Full package and classname string of the plugin class that provides
    /// this service.
    ///
    /// Use this form instead of [`Self::default_provider`] if you want to
    /// prevent any form of reference between the service class and the
    /// implementation class.
    ///
    /// Defaults to empty, matching `defaultProviderName() default ""`.
    fn default_provider_name(&self) -> String {
        String::new()
    }

    /// Names of the plugin classes that provide the default implementation of
    /// this service.
    ///
    /// Defaults to empty, matching `defaultProvider() default {}`.
    fn default_provider(&self) -> Vec<String> {
        Vec::new()
    }

    /// Description for this service.
    ///
    /// Currently not used.
    ///
    /// Defaults to empty, matching `description() default ""`.
    fn description(&self) -> String {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockServiceInfo;

    impl ServiceInfo for MockServiceInfo {}

    struct CustomServiceInfo;

    impl ServiceInfo for CustomServiceInfo {
        fn default_provider_name(&self) -> String {
            "packageX.subPackageY.SomeClass".to_string()
        }

        fn default_provider(&self) -> Vec<String> {
            vec!["packageX.MyPlugin".to_string()]
        }

        fn description(&self) -> String {
            "Provides MyService".to_string()
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let info: Box<dyn ServiceInfo> = Box::new(MockServiceInfo);
        assert_eq!(info.default_provider_name(), "");
        assert!(info.default_provider().is_empty());
        assert_eq!(info.description(), "");
    }

    #[test]
    fn defaults_match_java_annotation_defaults() {
        let info = MockServiceInfo;
        assert_eq!(info.default_provider_name(), "");
        assert!(info.default_provider().is_empty());
        assert_eq!(info.description(), "");
    }

    #[test]
    fn overridden_elements_are_reported() {
        let info = CustomServiceInfo;
        assert_eq!(info.default_provider_name(), "packageX.subPackageY.SomeClass");
        assert_eq!(info.default_provider(), vec!["packageX.MyPlugin".to_string()]);
        assert_eq!(info.description(), "Provides MyService");
    }
}

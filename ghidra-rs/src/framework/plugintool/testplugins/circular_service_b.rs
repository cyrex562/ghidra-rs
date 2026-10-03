//! Port of `ghidra.framework.plugintool.testplugins.CircularServiceB`.
//!
//! Test-only plugin service used to exercise circular plugin/service dependency resolution (see
//! `PluginManagerTest#testCircularDependency()`). Selected as a dependency-cycle cut-point, so it
//! is ported as a marker trait rather than tied to a concrete implementation.
//!
//! In Java this is annotated `@ServiceInfo(defaultProvider = CircularPluginB.class, description =
//! "Test service")`. `CircularPluginB` has not been ported to Rust yet, so that association is
//! recorded here only as a doc reference rather than a code dependency (mirroring how
//! [`ServiceInfo::default_provider`](crate::framework::plugintool::ServiceInfo::default_provider)
//! stores provider classes as fully-qualified name strings rather than `Class` references).

/// Marker trait for the `CircularServiceB` test service.
///
/// Mirrors `ghidra.framework.plugintool.testplugins.CircularServiceB`, an empty service
/// interface, so this trait declares no methods.
pub trait CircularServiceB {}

#[cfg(test)]
mod tests {
    use super::*;

    struct CircularPluginBService;

    impl CircularServiceB for CircularPluginBService {}

    fn requires_circular_service_b<T: CircularServiceB>(_: &T) {}

    #[test]
    fn concrete_type_satisfies_marker_trait() {
        let service = CircularPluginBService;
        requires_circular_service_b(&service);
    }

    #[test]
    fn trait_is_object_safe() {
        let service = CircularPluginBService;
        let _boxed: Box<dyn CircularServiceB> = Box::new(service);
    }
}

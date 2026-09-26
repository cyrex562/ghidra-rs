//! Port of `ghidra.framework.plugintool.testplugins.InitFailServiceB`.
//!
//! Test plugin service for `PluginManagerTest#testInitFail()` and friends. Selected as a
//! dependency-cycle cut-point, so it is ported as a marker trait rather than tied to a concrete
//! implementation.
//!
//! In Java this is annotated `@ServiceInfo(defaultProvider = InitFailPluginB.class, description =
//! "Test service")`. `InitFailPluginB` has not been ported to Rust yet, so that association is
//! recorded here only as a doc reference rather than a code dependency (mirroring how
//! [`ServiceInfo::default_provider`](crate::framework::plugintool::ServiceInfo::default_provider)
//! stores provider classes as fully-qualified name strings rather than `Class` references).

/// Marker trait for the `InitFailServiceB` test service.
///
/// Mirrors `ghidra.framework.plugintool.testplugins.InitFailServiceB`, an empty service
/// interface, so this trait declares no methods.
pub trait InitFailServiceB {}

#[cfg(test)]
mod tests {
    use super::*;

    struct InitFailPluginBService;

    impl InitFailServiceB for InitFailPluginBService {}

    fn requires_init_fail_service_b<T: InitFailServiceB>(_: &T) {}

    #[test]
    fn concrete_type_satisfies_marker_trait() {
        let service = InitFailPluginBService;
        requires_init_fail_service_b(&service);
    }

    #[test]
    fn trait_is_object_safe() {
        let service = InitFailPluginBService;
        let _boxed: Box<dyn InitFailServiceB> = Box::new(service);
    }
}

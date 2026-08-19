//! Port of `ghidra.framework.plugintool.testplugins.DiamondServiceC`.
//!
//! Test-only plugin service used to exercise diamond-shaped plugin/service dependency resolution
//! (see `PluginManagerTest#testDiamond()`, dependency shape `A -> {B, C} -> D`). Selected as a
//! dependency-cycle cut-point, so it is ported as a marker trait rather than tied to a concrete
//! implementation.
//!
//! In Java this is annotated `@ServiceInfo(defaultProvider = DiamondPluginC.class, description =
//! "Test service")`. `DiamondPluginC` has not been ported to Rust yet, so that association is
//! recorded here only as a doc reference rather than a code dependency (mirroring how
//! [`ServiceInfo::default_provider`](crate::framework::plugintool::ServiceInfo::default_provider)
//! stores provider classes as fully-qualified name strings rather than `Class` references).

/// Marker trait for the `DiamondServiceC` test service.
///
/// Mirrors `ghidra.framework.plugintool.testplugins.DiamondServiceC`, an empty service
/// interface, so this trait declares no methods.
pub trait DiamondServiceC {}

#[cfg(test)]
mod tests {
    use super::*;

    struct DiamondPluginCService;

    impl DiamondServiceC for DiamondPluginCService {}

    fn requires_diamond_service_c<T: DiamondServiceC>(_: &T) {}

    #[test]
    fn concrete_type_satisfies_marker_trait() {
        let service = DiamondPluginCService;
        requires_diamond_service_c(&service);
    }

    #[test]
    fn trait_is_object_safe() {
        let service = DiamondPluginCService;
        let _boxed: Box<dyn DiamondServiceC> = Box::new(service);
    }
}

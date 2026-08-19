//! Port of `ghidra.framework.plugintool.testplugins.DiamondServiceD`.
//!
//! Test-only plugin service used to exercise diamond-shaped plugin/service dependency resolution
//! (see `PluginManagerTest#testDiamond()`, dependency shape `A -> {B, C} -> D`). Selected as a
//! dependency-cycle cut-point, so it is ported as a marker trait rather than tied to a concrete
//! implementation.
//!
//! In Java this is annotated `@ServiceInfo(defaultProvider = DiamondPluginD.class, description =
//! "Test service")`. `DiamondPluginD` has not been ported to Rust yet, so that association is
//! recorded here only as a doc reference rather than a code dependency (mirroring how
//! [`ServiceInfo::default_provider`](crate::framework::plugintool::ServiceInfo::default_provider)
//! stores provider classes as fully-qualified name strings rather than `Class` references).

/// Marker trait for the `DiamondServiceD` test service.
///
/// Mirrors `ghidra.framework.plugintool.testplugins.DiamondServiceD`, an empty service
/// interface, so this trait declares no methods.
pub trait DiamondServiceD {}

#[cfg(test)]
mod tests {
    use super::*;

    struct DiamondPluginDService;

    impl DiamondServiceD for DiamondPluginDService {}

    fn requires_diamond_service_d<T: DiamondServiceD>(_: &T) {}

    #[test]
    fn concrete_type_satisfies_marker_trait() {
        let service = DiamondPluginDService;
        requires_diamond_service_d(&service);
    }

    #[test]
    fn trait_is_object_safe() {
        let service = DiamondPluginDService;
        let _boxed: Box<dyn DiamondServiceD> = Box::new(service);
    }
}

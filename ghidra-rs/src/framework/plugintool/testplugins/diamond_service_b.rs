//! Port of `ghidra.framework.plugintool.testplugins.DiamondServiceB`.
//!
//! Test-only plugin service used to exercise diamond-shaped plugin/service dependency resolution
//! (see `PluginManagerTest#testDiamond()`, dependency shape `A -> {B, C} -> D`). Selected as a
//! dependency-cycle cut-point, so it is ported as a marker trait rather than tied to a concrete
//! implementation.
//!
//! In Java this is annotated `@ServiceInfo(defaultProvider = DiamondPluginB.class, description =
//! "Test service")`. `DiamondPluginB` has not been ported to Rust yet, so that association is
//! recorded here only as a doc reference rather than a code dependency (mirroring how
//! [`ServiceInfo::default_provider`](crate::framework::plugintool::ServiceInfo::default_provider)
//! stores provider classes as fully-qualified name strings rather than `Class` references).

/// Marker trait for the `DiamondServiceB` test service.
///
/// Mirrors `ghidra.framework.plugintool.testplugins.DiamondServiceB`, an empty service
/// interface, so this trait declares no methods.
pub trait DiamondServiceB {}

#[cfg(test)]
mod tests {
    use super::*;

    struct DiamondPluginBService;

    impl DiamondServiceB for DiamondPluginBService {}

    fn requires_diamond_service_b<T: DiamondServiceB>(_: &T) {}

    #[test]
    fn concrete_type_satisfies_marker_trait() {
        let service = DiamondPluginBService;
        requires_diamond_service_b(&service);
    }

    #[test]
    fn trait_is_object_safe() {
        let service = DiamondPluginBService;
        let _boxed: Box<dyn DiamondServiceB> = Box::new(service);
    }
}

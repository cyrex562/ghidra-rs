//! Port of `ghidra.framework.plugintool.testplugins.MissingDepServiceB`.
//!
//! Test plugin service for `PluginManagerTest#testMissingDependency()` and
//! `PluginManagerTest#testLoadingDepSimultaneously()`. Selected as a dependency-cycle
//! cut-point, so it is ported as a marker trait rather than tied to a concrete implementation.
//!
//! In Java this is annotated `@ServiceInfo(description = "Test service")`, with no
//! `defaultProvider` specified (the Java source even has that argument commented out), so unlike
//! sibling test services in this module there is no provider class to reference here.

/// Marker trait for the `MissingDepServiceB` test service.
///
/// Mirrors `ghidra.framework.plugintool.testplugins.MissingDepServiceB`, an empty service
/// interface, so this trait declares no methods.
pub trait MissingDepServiceB {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MissingDepPluginBService;

    impl MissingDepServiceB for MissingDepPluginBService {}

    fn requires_missing_dep_service_b<T: MissingDepServiceB>(_: &T) {}

    #[test]
    fn concrete_type_satisfies_marker_trait() {
        let service = MissingDepPluginBService;
        requires_missing_dep_service_b(&service);
    }

    #[test]
    fn trait_is_object_safe() {
        let service = MissingDepPluginBService;
        let _boxed: Box<dyn MissingDepServiceB> = Box::new(service);
    }
}

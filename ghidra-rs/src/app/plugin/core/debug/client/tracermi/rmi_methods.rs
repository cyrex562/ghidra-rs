/// Marker trait for RMI methods containers.
///
/// Ported from `ghidra.app.plugin.core.debug.client.tracermi.RmiMethods`.
/// In Java this is a marker interface used to identify objects whose methods
/// can be invoked as RMI trace method handlers. Implementors serve as method
/// containers; the framework discovers and dispatches to their methods by
/// reflection/annotation. The Rust equivalent is an empty marker trait.
pub trait RmiMethods {}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyMethods;
    impl RmiMethods for DummyMethods {}

    #[test]
    fn marker_trait_is_implementable() {
        let _: &dyn RmiMethods = &DummyMethods;
    }
}

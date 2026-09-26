/// Marker trait for nodes in the TraceRmi manager tree.
///
/// Corresponds to `ghidra.app.plugin.core.debug.gui.tracermi.connection.tree.TraceRmiManagerNode`.
pub trait TraceRmiManagerNode {}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConcreteNode;
    impl TraceRmiManagerNode for ConcreteNode {}

    #[test]
    fn marker_trait_implementable() {
        let _node = ConcreteNode;
    }
}

/// Marker trait for widgets that participate in function-graph context identification.
///
/// Maps to `ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphContextMarker`.
pub trait FunctionGraphContextMarker {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MarkerWidget;
    impl FunctionGraphContextMarker for MarkerWidget {}

    #[test]
    fn struct_can_implement_marker() {
        let _w = MarkerWidget;
    }

    #[test]
    fn trait_object_is_constructible() {
        let _w: Box<dyn FunctionGraphContextMarker> = Box::new(MarkerWidget);
    }
}

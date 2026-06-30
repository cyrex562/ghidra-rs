/// Marker trait that widgets can implement for identification in action context.
pub trait VisualGraphContextMarker {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockWidget;
    impl VisualGraphContextMarker for MockWidget {}

    #[test]
    fn test_marker_implemented() {
        let _w = MockWidget;
    }

    #[test]
    fn test_marker_trait_object() {
        let w: Box<dyn VisualGraphContextMarker> = Box::new(MockWidget);
        let _ = w;
    }
}

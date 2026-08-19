use crate::graph::seam_stubs::{LayoutProvider, VisualEdge, VisualGraph, VisualVertex};
use crate::util::classfinder::ExtensionPoint;

/// A discoverable layout provider. Layouts that wish to be discoverable at runtime should
/// implement this trait instead of just `LayoutProvider`.
///
/// This is a marker trait combining `LayoutProvider` and `ExtensionPoint` for runtime
/// discovery of layout implementations.
///
/// # Type Parameters
/// - `V`: The vertex type (must implement `VisualVertex`)
/// - `E`: The edge type (must implement `VisualEdge<V>`)
/// - `G`: The graph type (must implement `VisualGraph<V, E>`)
pub trait LayoutProviderExtensionPoint<
    V: VisualVertex + ?Sized,
    E: VisualEdge + ?Sized,
    G: VisualGraph + ?Sized,
>: LayoutProvider<V, E, G> + ExtensionPoint
{
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation for testing the trait bounds
    struct MockVertex;
    impl VisualVertex for MockVertex {
        fn get_component(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn set_focused(&self, _focused: bool) {}
        fn is_focused(&self) -> bool {
            false
        }
        fn set_selected(&self, _selected: bool) {}
        fn is_selected(&self) -> bool {
            false
        }
        fn set_hovered(&self, _hovered: bool) {}
        fn is_hovered(&self) -> bool {
            false
        }
        fn set_location(&self, _p: &dyn std::any::Any) {}
        fn get_location(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn is_grabbable(&self, _c: &dyn std::any::Any) -> bool {
            false
        }
        fn dispose(&self) {}
        fn set_emphasis(&self, _emphasis_level: f64) {}
        fn get_emphasis(&self) -> f64 {
            0.0
        }
        fn set_alpha(&self, _alpha: f64) {}
        fn get_alpha(&self) -> f64 {
            1.0
        }
    }

    struct MockEdge;
    impl VisualEdge for MockEdge {
        fn set_selected(&self, _selected: bool) {}
        fn is_selected(&self) -> bool {
            false
        }
        fn set_in_hovered_vertex_path(&self, _in_path: bool) {}
        fn is_in_hovered_vertex_path(&self) -> bool {
            false
        }
        fn set_in_focused_vertex_path(&self, _in_path: bool) {}
        fn is_in_focused_vertex_path(&self) -> bool {
            false
        }
        fn get_articulation_points(&self) -> Vec<Box<dyn std::any::Any>> {
            vec![]
        }
        fn set_articulation_points(&self, _points: Vec<Box<dyn std::any::Any>>) {}
        fn clone_edge(&self, _start: &dyn std::any::Any, _end: &dyn std::any::Any) -> Box<dyn VisualEdge> {
            Box::new(MockEdge)
        }
        fn set_emphasis(&self, _emphasis_level: f64) {}
        fn get_emphasis(&self) -> f64 {
            0.0
        }
        fn set_alpha(&self, _alpha: f64) {}
        fn get_alpha(&self) -> f64 {
            1.0
        }
    }

    struct MockGraph;
    impl VisualGraph for MockGraph {
        fn vertex_location_changed(&self, _v: &dyn std::any::Any, _point: &dyn std::any::Any, _change_type: &dyn std::any::Any) {}
        fn get_focused_vertex(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn set_vertex_focused(&self, _v: &dyn std::any::Any, _b: bool) {}
        fn clear_selected_vertices(&self) {}
        fn set_selected_vertices(&self, _vertices: Vec<Box<dyn std::any::Any>>) {}
        fn get_selected_vertices(&self) -> Vec<Box<dyn std::any::Any>> {
            vec![]
        }
        fn add_graph_change_listener(&self, _l: &dyn std::any::Any) {}
        fn remove_graph_change_listener(&self, _l: &dyn std::any::Any) {}
        fn get_layout(&self) -> Box<dyn crate::graph::seam_stubs::VisualGraphLayout> {
            Box::new(MockLayout)
        }
        fn copy(&self) -> Box<dyn VisualGraph> {
            Box::new(MockGraph)
        }
    }

    struct MockLayout;
    impl crate::graph::seam_stubs::VisualGraphLayout for MockLayout {
        fn add_layout_listener(&self, _listener: &dyn std::any::Any) {}
        fn remove_layout_listener(&self, _listener: &dyn std::any::Any) {}
        fn uses_edge_articulations(&self) -> bool {
            false
        }
        fn calculate_locations(&self, _graph: &dyn VisualGraph, _monitor: &dyn crate::util::task::TaskMonitor) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn clone_layout(&self, _new_graph: &dyn VisualGraph) -> Box<dyn crate::graph::seam_stubs::VisualGraphLayout> {
            Box::new(MockLayout)
        }
        fn set_location(&self, _v: &dyn std::any::Any, _location: &dyn std::any::Any, _change_type: &dyn std::any::Any) {}
        fn get_visual_graph(&self) -> Box<dyn VisualGraph> {
            Box::new(MockGraph)
        }
        fn get_edge_renderer(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_edge_shape_transformer(&self, _context: &dyn std::any::Any) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_edge_label_renderer(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn dispose(&self) {}
    }

    struct MockLayoutProvider;
    impl LayoutProvider<MockVertex, MockEdge, MockGraph> for MockLayoutProvider {
        fn get_layout(&self, _graph: &MockGraph, _monitor: &dyn crate::util::task::TaskMonitor) -> Result<Box<dyn crate::graph::seam_stubs::VisualGraphLayout>, std::io::Error> {
            Ok(Box::new(MockLayout))
        }
        fn get_layout_name(&self) -> String {
            "Mock Layout".to_string()
        }
        fn get_action_icon(&self) -> Option<Box<dyn std::any::Any>> {
            None
        }
        fn get_priority_level(&self) -> i32 {
            1
        }
    }

    impl ExtensionPoint for MockLayoutProvider {}

    impl LayoutProviderExtensionPoint<MockVertex, MockEdge, MockGraph> for MockLayoutProvider {}

    #[test]
    fn test_layout_provider_extension_point_implementable() {
        let provider = MockLayoutProvider;
        assert_eq!(provider.get_layout_name(), "Mock Layout");
        assert_eq!(provider.get_priority_level(), 1);
        assert!(provider.get_action_icon().is_none());
    }

    #[test]
    fn test_layout_provider_extension_point_as_trait_object() {
        let provider: Box<dyn LayoutProviderExtensionPoint<MockVertex, MockEdge, MockGraph>> =
            Box::new(MockLayoutProvider);
        assert_eq!(provider.get_layout_name(), "Mock Layout");
    }
}

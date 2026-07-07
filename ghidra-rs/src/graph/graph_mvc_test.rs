/// Integration tests for graph model-view-controller interaction.
///
/// Corresponds to `GraphMVCTest` in the original Ghidra Java source (`ghidra.graph`).
/// The Java class contained no test implementations; these tests exercise the existing
/// Rust graph primitives in a combined model/view/controller scenario.
#[cfg(test)]
mod tests {
    use crate::graph::event::VisualGraphChangeListener;
    use crate::graph::g_edge::GEdge;
    use crate::graph::graph_path::GraphPath;
    use crate::graph::viewer::actions::VisualGraphContextMarker;
    use crate::graph::viewer::edge::PathHighlightListener;

    // --- Minimal concrete model types used across tests ---

    struct SimpleEdge {
        start: u32,
        end: u32,
    }

    impl GEdge<u32> for SimpleEdge {
        fn get_start(&self) -> &u32 {
            &self.start
        }

        fn get_end(&self) -> &u32 {
            &self.end
        }
    }

    // --- Minimal recording listener (controller side) ---

    struct RecordingListener {
        vertices_added: Vec<u32>,
        vertices_removed: Vec<u32>,
        edge_adds: usize,
        edge_removes: usize,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                vertices_added: Vec::new(),
                vertices_removed: Vec::new(),
                edge_adds: 0,
                edge_removes: 0,
            }
        }
    }

    impl VisualGraphChangeListener<u32, SimpleEdge> for RecordingListener {
        fn vertices_added(&mut self, vertices: &[u32]) {
            self.vertices_added.extend_from_slice(vertices);
        }

        fn vertices_removed(&mut self, vertices: &[u32]) {
            self.vertices_removed.extend_from_slice(vertices);
        }

        fn edges_added(&mut self, edges: &[SimpleEdge]) {
            self.edge_adds += edges.len();
        }

        fn edges_removed(&mut self, edges: &[SimpleEdge]) {
            self.edge_removes += edges.len();
        }
    }

    // --- View component stubs ---

    struct GraphView {
        highlight_hover_count: usize,
        highlight_selection_count: usize,
    }

    impl GraphView {
        fn new() -> Self {
            Self { highlight_hover_count: 0, highlight_selection_count: 0 }
        }
    }

    impl PathHighlightListener for GraphView {
        fn path_highlight_changed(&mut self, hover_change: bool) {
            if hover_change {
                self.highlight_hover_count += 1;
            } else {
                self.highlight_selection_count += 1;
            }
        }
    }

    impl VisualGraphContextMarker for GraphView {}

    // --- Tests ---

    #[test]
    fn test_model_vertex_add_notifies_controller() {
        let mut controller = RecordingListener::new();
        controller.vertices_added(&[1, 2, 3]);
        assert_eq!(controller.vertices_added, vec![1, 2, 3]);
    }

    #[test]
    fn test_model_vertex_remove_notifies_controller() {
        let mut controller = RecordingListener::new();
        controller.vertices_added(&[1, 2, 3]);
        controller.vertices_removed(&[2]);
        assert_eq!(controller.vertices_removed, vec![2]);
    }

    #[test]
    fn test_model_edge_add_notifies_controller() {
        let mut controller = RecordingListener::new();
        let edges = [SimpleEdge { start: 1, end: 2 }, SimpleEdge { start: 2, end: 3 }];
        controller.edges_added(&edges);
        assert_eq!(controller.edge_adds, 2);
    }

    #[test]
    fn test_model_edge_remove_notifies_controller() {
        let mut controller = RecordingListener::new();
        let edges = [SimpleEdge { start: 1, end: 2 }];
        controller.edges_added(&edges);
        let removal = [SimpleEdge { start: 1, end: 2 }];
        controller.edges_removed(&removal);
        assert_eq!(controller.edge_removes, 1);
    }

    #[test]
    fn test_edge_model_start_end() {
        let e = SimpleEdge { start: 10, end: 20 };
        assert_eq!(e.get_start(), &10);
        assert_eq!(e.get_end(), &20);
    }

    #[test]
    fn test_path_model_contains_added_vertices() {
        let mut path = GraphPath::new();
        path.add(1u32);
        path.add(2u32);
        path.add(3u32);
        assert!(path.contains(&1));
        assert!(path.contains(&2));
        assert!(path.contains(&3));
        assert!(!path.contains(&4));
    }

    #[test]
    fn test_path_model_depth_tracks_insertion_order() {
        let mut path = GraphPath::new();
        path.add(10u32);
        path.add(20u32);
        path.add(30u32);
        assert_eq!(path.depth(&10), Some(0));
        assert_eq!(path.depth(&20), Some(1));
        assert_eq!(path.depth(&30), Some(2));
    }

    #[test]
    fn test_view_highlight_on_hover() {
        let mut view = GraphView::new();
        view.path_highlight_changed(true);
        view.path_highlight_changed(true);
        assert_eq!(view.highlight_hover_count, 2);
        assert_eq!(view.highlight_selection_count, 0);
    }

    #[test]
    fn test_view_highlight_on_selection() {
        let mut view = GraphView::new();
        view.path_highlight_changed(false);
        assert_eq!(view.highlight_hover_count, 0);
        assert_eq!(view.highlight_selection_count, 1);
    }

    #[test]
    fn test_view_context_marker_as_trait_object() {
        let view: Box<dyn VisualGraphContextMarker> = Box::new(GraphView::new());
        let _ = view;
    }

    #[test]
    fn test_mvc_integration_add_then_remove_vertex() {
        let mut controller = RecordingListener::new();
        controller.vertices_added(&[5, 10, 15]);
        assert_eq!(controller.vertices_added.len(), 3);
        controller.vertices_removed(&[10]);
        assert_eq!(controller.vertices_removed, vec![10]);
        assert_eq!(controller.vertices_added.len(), 3);
    }

    #[test]
    fn test_mvc_integration_path_with_edge_model() {
        let mut path = GraphPath::new();
        let e1 = SimpleEdge { start: 1, end: 2 };
        let e2 = SimpleEdge { start: 2, end: 3 };
        path.add(*e1.get_start());
        path.add(*e1.get_end());
        path.add(*e2.get_end());
        assert_eq!(path.size(), 3);
        assert_eq!(path.get(0), &1);
        assert_eq!(path.get(1), &2);
        assert_eq!(path.get(2), &3);
    }

    #[test]
    fn test_mvc_integration_empty_notifications_are_valid() {
        let mut controller = RecordingListener::new();
        controller.vertices_added(&[]);
        controller.vertices_removed(&[]);
        controller.edges_added(&[]);
        controller.edges_removed(&[]);
        assert!(controller.vertices_added.is_empty());
        assert!(controller.vertices_removed.is_empty());
        assert_eq!(controller.edge_adds, 0);
        assert_eq!(controller.edge_removes, 0);
    }
}

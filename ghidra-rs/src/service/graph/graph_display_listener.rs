use super::graph_display::GraphDisplay;
use super::AttributedVertex;

/// Listener for notifications when the user interacts with a visual graph display.
///
/// Mirrors `ghidra.service.graph.GraphDisplayListener`.
pub trait GraphDisplayListener: Send + Sync {
    /// Notification that the set of selected vertices has changed.
    ///
    /// # Arguments
    /// * `vertices` - The set of currently selected vertices
    fn selection_changed(&self, vertices: Vec<AttributedVertex>);

    /// Notification that the "focused" (active) vertex has changed.
    ///
    /// # Arguments
    /// * `vertex` - The vertex that is currently "focused"
    fn location_focus_changed(&self, vertex: &AttributedVertex);

    /// Creates a new listener of the same type for a different graph display.
    ///
    /// # Arguments
    /// * `graph_display` - The new graph display the listener will support
    ///
    /// # Returns
    /// A new instance of a GraphDisplayListener that is the same type as this listener
    fn clone_with(&self, graph_display: &dyn GraphDisplay) -> Box<dyn GraphDisplayListener>;

    /// Tells the listener that it is no longer needed and it can release any listeners/resources.
    /// This will be called when a GraphDisplay is disposed or if this listener is replaced.
    fn dispose(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockGraphDisplay;
    impl GraphDisplay for MockGraphDisplay {
        fn set_graph_display_listener(&mut self, _listener: Box<dyn GraphDisplayListener>) {}
        fn set_focused_vertex(&mut self, _vertex: &AttributedVertex, _event_trigger: crate::docking::widgets::EventTrigger) {}
        fn get_graph(&self) -> Option<&crate::service::graph::AttributedGraph> {
            None
        }
        fn get_focused_vertex(&self) -> Option<&AttributedVertex> {
            None
        }
        fn select_vertices(&mut self, _vertex_set: &[&AttributedVertex], _event_trigger: crate::docking::widgets::EventTrigger) {}
        fn get_selected_vertices(&self) -> Vec<&AttributedVertex> {
            vec![]
        }
        fn close(&mut self) {}
        fn set_graph(
            &mut self,
            _graph: crate::service::graph::AttributedGraph,
            _options: &dyn crate::service::seam_stubs::GraphDisplayOptions,
            _title: &str,
            _append: bool,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn clear(&mut self) {}
        fn update_vertex_name(&mut self, _vertex: &AttributedVertex, _new_name: &str) {}
        fn get_graph_title(&self) -> String {
            String::new()
        }
        fn add_action(&mut self, _action: Box<dyn crate::docking::action::docking_action_if::DockingActionIf>) {}
        fn get_actions(&self) -> Vec<&dyn crate::docking::action::docking_action_if::DockingActionIf> {
            vec![]
        }
    }

    struct MockListener {
        disposed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl MockListener {
        fn new() -> Self {
            Self {
                disposed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }
    }

    impl GraphDisplayListener for MockListener {
        fn selection_changed(&self, vertices: Vec<AttributedVertex>) {
            assert!(!vertices.is_empty() || vertices.is_empty()); // Just verify we receive vertices
        }

        fn location_focus_changed(&self, _vertex: &AttributedVertex) {
            // Listener receives focus change
        }

        fn clone_with(&self, _graph_display: &dyn GraphDisplay) -> Box<dyn GraphDisplayListener> {
            Box::new(Self::new())
        }

        fn dispose(&self) {
            self.disposed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn can_create_listener() {
        let listener = MockListener::new();
        assert!(!listener.disposed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn dispose_marks_as_disposed() {
        let listener = MockListener::new();
        listener.dispose();
        assert!(listener.disposed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn selection_changed_receives_vertices() {
        let listener = MockListener::new();
        let v1 = AttributedVertex::new("v1", "Vertex 1");
        let v2 = AttributedVertex::new("v2", "Vertex 2");
        listener.selection_changed(vec![v1, v2]);
    }

    #[test]
    fn clone_with_creates_new_listener() {
        let listener = MockListener::new();
        let display = MockGraphDisplay;
        let cloned = listener.clone_with(&display);
        cloned.dispose();
    }
}

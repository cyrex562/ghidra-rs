use super::graph_display::GraphDisplay;
use super::graph_display_listener::GraphDisplayListener;
use super::AttributedVertex;

/// A no-op [`GraphDisplayListener`] used when a graph display needs a listener but nothing in
/// particular should happen on selection change, focus change, or disposal.
///
/// Port of `ghidra.service.graph.DummyGraphDisplayListener`.
pub struct DummyGraphDisplayListener;

impl GraphDisplayListener for DummyGraphDisplayListener {
    /// Port of `DummyGraphDisplayListener.cloneWith(GraphDisplay)`.
    fn clone_with(&self, _graph_display: &dyn GraphDisplay) -> Box<dyn GraphDisplayListener> {
        Box::new(DummyGraphDisplayListener)
    }

    /// Port of `DummyGraphDisplayListener.selectionChanged(Set<AttributedVertex>)`. Stub.
    fn selection_changed(&self, _vertices: Vec<AttributedVertex>) {
        // stub
    }

    /// Port of `DummyGraphDisplayListener.locationFocusChanged(AttributedVertex)`. Stub.
    fn location_focus_changed(&self, _vertex: &AttributedVertex) {
        // stub
    }

    /// Port of `DummyGraphDisplayListener.dispose()`. Stub.
    fn dispose(&self) {
        // stub
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockGraphDisplay;
    impl GraphDisplay for MockGraphDisplay {
        fn set_graph_display_listener(&mut self, _listener: Box<dyn GraphDisplayListener>) {}
        fn set_focused_vertex(
            &mut self,
            _vertex: &AttributedVertex,
            _event_trigger: crate::docking::widgets::EventTrigger,
        ) {
        }
        fn get_graph(&self) -> Option<&crate::service::graph::AttributedGraph> {
            None
        }
        fn get_focused_vertex(&self) -> Option<&AttributedVertex> {
            None
        }
        fn select_vertices(
            &mut self,
            _vertex_set: &[&AttributedVertex],
            _event_trigger: crate::docking::widgets::EventTrigger,
        ) {
        }
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

    #[test]
    fn selection_changed_is_a_stub() {
        let listener = DummyGraphDisplayListener;
        let v1 = AttributedVertex::new("v1", "Vertex 1");
        // Must not panic; there's nothing to observe since it's a no-op.
        listener.selection_changed(vec![v1]);
    }

    #[test]
    fn location_focus_changed_is_a_stub() {
        let listener = DummyGraphDisplayListener;
        let v1 = AttributedVertex::new("v1", "Vertex 1");
        listener.location_focus_changed(&v1);
    }

    #[test]
    fn dispose_is_a_stub() {
        let listener = DummyGraphDisplayListener;
        listener.dispose();
    }

    #[test]
    fn clone_with_returns_a_new_dummy_listener() {
        let listener = DummyGraphDisplayListener;
        let display = MockGraphDisplay;
        let cloned = listener.clone_with(&display);
        // The clone is independently usable -- exercise it the same way the original is.
        cloned.dispose();
    }

    #[test]
    fn usable_as_a_trait_object() {
        let listener: Box<dyn GraphDisplayListener> = Box::new(DummyGraphDisplayListener);
        listener.dispose();
    }
}

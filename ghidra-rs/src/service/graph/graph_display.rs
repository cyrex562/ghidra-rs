use crate::docking::action::docking_action_if::DockingActionIf;
use crate::docking::widgets::EventTrigger;
use crate::service::graph::graph_display_listener::GraphDisplayListener;
use crate::service::graph::AttributedGraph;
use crate::service::graph::AttributedVertex;
use crate::service::seam_stubs::GraphDisplayOptions;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Interface for objects that display (or consume) graphs. Normally, a graph display represents
/// a visual component for displaying and interacting with a graph. Some implementations may not
/// be a visual component, but instead consume/process the graph (i.e. a graph exporter). In that
/// case there is no interactive element, and once the graph has been set on the display, it is
/// closed.
///
/// Port of `ghidra.service.graph.GraphDisplay`.
pub trait GraphDisplay: Send + Sync {
    /// Sets a [`GraphDisplayListener`] to be notified when the user changes the vertex focus or
    /// selects one or more nodes in a graph window.
    ///
    /// Port of `GraphDisplay.setGraphDisplayListener(GraphDisplayListener)`.
    fn set_graph_display_listener(&mut self, listener: Box<dyn GraphDisplayListener>);

    /// Tells the graph display window to focus the given vertex.
    ///
    /// `event_trigger` hints at why the graph location is being updated so the display can
    /// decide whether to send out a notification via
    /// [`GraphDisplayListener::location_focus_changed`]. For example, if the location is being
    /// updated due to an event from the main application, the display should not notify the
    /// application back, to avoid event cycles. See [`EventTrigger`] for more information.
    ///
    /// Port of `GraphDisplay.setFocusedVertex(AttributedVertex, EventTrigger)`.
    fn set_focused_vertex(&mut self, vertex: &AttributedVertex, event_trigger: EventTrigger);

    /// Returns the graph for this display, or `None` if no graph has been set yet.
    ///
    /// Port of `GraphDisplay.getGraph()`.
    fn get_graph(&self) -> Option<&AttributedGraph>;

    /// Returns the currently focused vertex, or `None` if no vertex is focused.
    ///
    /// Port of `GraphDisplay.getFocusedVertex()`.
    fn get_focused_vertex(&self) -> Option<&AttributedVertex>;

    /// Tells the graph display window to select the given vertices.
    ///
    /// `event_trigger` hints at why the selection is being updated so the display can decide
    /// whether to send out a notification via [`GraphDisplayListener::selection_changed`]. For
    /// example, if the selection is being updated due to an event from the main application, the
    /// display should not notify the application back, to avoid event cycles. See
    /// [`EventTrigger`] for more information.
    ///
    /// Port of `GraphDisplay.selectVertices(Set<AttributedVertex>, EventTrigger)`.
    fn select_vertices(&mut self, vertex_set: &[&AttributedVertex], event_trigger: EventTrigger);

    /// Returns the currently selected vertices.
    ///
    /// Port of `GraphDisplay.getSelectedVertices()`.
    fn get_selected_vertices(&self) -> Vec<&AttributedVertex>;

    /// Closes this graph display window.
    ///
    /// Port of `GraphDisplay.close()`.
    fn close(&mut self);

    /// Sets the graph to be displayed or consumed by this graph display.
    ///
    /// `options` configures how the display will render vertices and edges based on their
    /// vertex/edge type respectively. `append`, if true, appends the new graph to any existing
    /// graph.
    ///
    /// # Errors
    ///
    /// Returns a [`CancelledException`] if the graphing operation was cancelled.
    ///
    /// Port of `GraphDisplay.setGraph(AttributedGraph, GraphDisplayOptions, String, boolean,
    /// TaskMonitor)`.
    ///
    /// Java also has a deprecated `setGraph(AttributedGraph, String, boolean, TaskMonitor)`
    /// overload with a default body that builds a `new GraphDisplayOptions(graph.getGraphType())`
    /// and delegates to this method. `GraphDisplayOptions` has no Rust port yet (only the
    /// [`GraphDisplayOptions`] seam-stub trait, which has no way to construct a default
    /// instance), so that deprecated convenience overload is dropped rather than faked; callers
    /// should call this method directly with an explicit options value.
    fn set_graph(
        &mut self,
        graph: AttributedGraph,
        options: &dyn GraphDisplayOptions,
        title: &str,
        append: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Clears all graph vertices and edges from this graph display.
    ///
    /// Port of `GraphDisplay.clear()`.
    fn clear(&mut self);

    /// Updates a vertex to a new name.
    ///
    /// Port of `GraphDisplay.updateVertexName(AttributedVertex, String)`.
    fn update_vertex_name(&mut self, vertex: &AttributedVertex, new_name: &str);

    /// Returns the title of the current graph.
    ///
    /// Port of `GraphDisplay.getGraphTitle()`.
    fn get_graph_title(&self) -> String;

    /// Adds the action to the graph display. Not all graph displays support adding custom
    /// actions, so this may have no effect.
    ///
    /// Port of `GraphDisplay.addAction(DockingActionIf)`.
    fn add_action(&mut self, action: Box<dyn DockingActionIf>);

    /// Gets all actions that have been added to this graph display. If this display does not
    /// support actions, an empty collection is returned.
    ///
    /// Port of `GraphDisplay.getActions()`.
    fn get_actions(&self) -> Vec<&dyn DockingActionIf>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingGraphDisplay {
        graph: Option<AttributedGraph>,
        focused: Option<AttributedVertex>,
        selected: Vec<AttributedVertex>,
        title: String,
        closed: bool,
    }

    impl GraphDisplay for RecordingGraphDisplay {
        fn set_graph_display_listener(&mut self, _listener: Box<dyn GraphDisplayListener>) {}

        fn set_focused_vertex(&mut self, vertex: &AttributedVertex, _event_trigger: EventTrigger) {
            self.focused = Some(AttributedVertex::new(
                vertex.get_id().to_string(),
                vertex.get_name().cloned().unwrap_or_default(),
            ));
        }

        fn get_graph(&self) -> Option<&AttributedGraph> {
            self.graph.as_ref()
        }

        fn get_focused_vertex(&self) -> Option<&AttributedVertex> {
            self.focused.as_ref()
        }

        fn select_vertices(&mut self, vertex_set: &[&AttributedVertex], _event_trigger: EventTrigger) {
            self.selected = vertex_set
                .iter()
                .map(|v| AttributedVertex::new(v.get_id().to_string(), v.get_name().cloned().unwrap_or_default()))
                .collect();
        }

        fn get_selected_vertices(&self) -> Vec<&AttributedVertex> {
            self.selected.iter().collect()
        }

        fn close(&mut self) {
            self.closed = true;
        }

        fn set_graph(
            &mut self,
            graph: AttributedGraph,
            _options: &dyn GraphDisplayOptions,
            title: &str,
            _append: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            self.title = title.to_string();
            self.graph = Some(graph);
            Ok(())
        }

        fn clear(&mut self) {
            self.graph = None;
            self.selected.clear();
            self.focused = None;
        }

        fn update_vertex_name(&mut self, vertex: &AttributedVertex, new_name: &str) {
            if let Some(focused) = self.focused.as_mut() {
                if focused.get_id() == vertex.get_id() {
                    focused.set_name(new_name.to_string());
                }
            }
        }

        fn get_graph_title(&self) -> String {
            self.title.clone()
        }

        fn add_action(&mut self, _action: Box<dyn DockingActionIf>) {}

        fn get_actions(&self) -> Vec<&dyn DockingActionIf> {
            Vec::new()
        }
    }

    struct MockOptions;
    impl GraphDisplayOptions for MockOptions {}

    fn sample_graph() -> AttributedGraph {
        let graph_type = crate::service::graph::GraphType::new(
            "test".to_string(),
            "test graph type".to_string(),
            vec![],
            vec![],
        );
        AttributedGraph::new("test", graph_type)
    }

    #[test]
    fn set_graph_stores_title_and_graph() {
        let mut display = RecordingGraphDisplay::default();
        let monitor = crate::util::task::DummyMonitor;
        let result = display.set_graph(sample_graph(), &MockOptions, "My Graph", false, &monitor);

        assert!(result.is_ok());
        assert_eq!(display.get_graph_title(), "My Graph");
        assert!(display.get_graph().is_some());
    }

    #[test]
    fn set_focused_vertex_updates_focus() {
        let mut display = RecordingGraphDisplay::default();
        let vertex = AttributedVertex::new("v1", "Vertex 1");

        assert!(display.get_focused_vertex().is_none());
        display.set_focused_vertex(&vertex, EventTrigger::ApiCall);

        assert_eq!(display.get_focused_vertex().map(|v| v.get_id()), Some("v1"));
    }

    #[test]
    fn select_vertices_updates_selection() {
        let mut display = RecordingGraphDisplay::default();
        let v1 = AttributedVertex::new("v1", "Vertex 1");
        let v2 = AttributedVertex::new("v2", "Vertex 2");

        display.select_vertices(&[&v1, &v2], EventTrigger::GuiAction);

        assert_eq!(display.get_selected_vertices().len(), 2);
    }

    #[test]
    fn clear_resets_state() {
        let mut display = RecordingGraphDisplay::default();
        let monitor = crate::util::task::DummyMonitor;
        display
            .set_graph(sample_graph(), &MockOptions, "title", false, &monitor)
            .unwrap();
        let v1 = AttributedVertex::new("v1", "Vertex 1");
        display.set_focused_vertex(&v1, EventTrigger::ApiCall);

        display.clear();

        assert!(display.get_graph().is_none());
        assert!(display.get_focused_vertex().is_none());
        assert!(display.get_selected_vertices().is_empty());
    }

    #[test]
    fn close_marks_closed() {
        let mut display = RecordingGraphDisplay::default();
        assert!(!display.closed);
        display.close();
        assert!(display.closed);
    }

    #[test]
    fn trait_is_object_safe() {
        let display: Box<dyn GraphDisplay> = Box::new(RecordingGraphDisplay::default());
        assert!(display.get_actions().is_empty());
    }
}

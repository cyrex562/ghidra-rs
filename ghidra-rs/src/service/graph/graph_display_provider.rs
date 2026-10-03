//! Port of `ghidra.service.graph.GraphDisplayProvider`.
//!
//! `PluginTool` and `HelpLocation` are not yet ported, so [`crate::framework::seam_stubs`]'s
//! existing placeholder traits for them are reused here rather than defining new ones. Java's two
//! overloaded `getGraphDisplay` methods are given distinct Rust names, since Rust traits cannot
//! overload on parameter arity alone; the two-argument form keeps the Java default method's
//! `getGraphDisplay(reuseGraph, false, monitor)` delegation.

use crate::framework::options::Options;
use crate::framework::seam_stubs::{HelpLocation, PluginTool};
use crate::service::graph::graph_display::GraphDisplay;
use crate::util::classfinder::ExtensionPoint;
use crate::util::exception::GraphException;
use crate::util::task::TaskMonitor;

/// Basic interface for objects that can display or otherwise consume a generic graph.
///
/// Port of `ghidra.service.graph.GraphDisplayProvider`.
pub trait GraphDisplayProvider: ExtensionPoint {
    /// The name of this provider (for displaying as a menu option when graphing).
    ///
    /// Port of `GraphDisplayProvider.getName()`.
    fn get_name(&self) -> String;

    /// Returns a `GraphDisplay` that can be used to "display" a graph. This form always clears
    /// any reused display's existing graph; if the intention is to append to the graph, use
    /// [`get_graph_display_reuse`](Self::get_graph_display_reuse) instead.
    ///
    /// `reuse_graph`: if true, this provider will attempt to re-use an existing `GraphDisplay`.
    /// `monitor`: the `TaskMonitor` that can be used to monitor and cancel the operation.
    ///
    /// # Errors
    ///
    /// Returns a `GraphException` if there is a problem creating a `GraphDisplay`.
    ///
    /// Port of `GraphDisplayProvider.getGraphDisplay(boolean, TaskMonitor)`. The Java default
    /// body delegates to `getGraphDisplay(reuseGraph, false, monitor)`.
    fn get_graph_display(
        &mut self,
        reuse_graph: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn GraphDisplay>, GraphException> {
        self.get_graph_display_reuse(reuse_graph, false, monitor)
    }

    /// Returns a `GraphDisplay` that can be used to "display" a graph.
    ///
    /// `reuse_graph`: if true, this provider will attempt to re-use an existing `GraphDisplay`.
    /// `append`: if true and there is a graph display to reuse, don't clear the existing graph
    /// so that it can be appended to; otherwise, any reused graph display has its existing graph
    /// cleared.
    /// `monitor`: the `TaskMonitor` that can be used to monitor and cancel the operation.
    ///
    /// # Errors
    ///
    /// Returns a `GraphException` if there is a problem creating a `GraphDisplay`.
    ///
    /// Port of `GraphDisplayProvider.getGraphDisplay(boolean, boolean, TaskMonitor)`.
    fn get_graph_display_reuse(
        &mut self,
        reuse_graph: bool,
        append: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn GraphDisplay>, GraphException>;

    /// Returns the active graph display, or `None` if there is no active graph display. If only
    /// one graph is displayed, that graph is returned. If multiple graphs are being displayed,
    /// the most recently shown graph is returned, regardless of whether that is the active graph
    /// in terms of user interaction.
    ///
    /// Port of `GraphDisplayProvider.getActiveGraphDisplay()`.
    fn get_active_graph_display(&self) -> Option<Box<dyn GraphDisplay>>;

    /// Returns all known graph displays, typically ordered by use, most recently first.
    ///
    /// Port of `GraphDisplayProvider.getAllGraphDisplays()`.
    fn get_all_graph_displays(&self) -> Vec<Box<dyn GraphDisplay>>;

    /// Provides an opportunity for this provider to register and read tool options.
    ///
    /// `tool`: the tool hosting this display.
    /// `options`: the tool options for graphing.
    ///
    /// Port of `GraphDisplayProvider.initialize(PluginTool, Options)`.
    fn initialize(&mut self, tool: &dyn PluginTool, options: &mut dyn Options);

    /// Called if the graph options change.
    ///
    /// Port of `GraphDisplayProvider.optionsChanged(Options)`.
    fn options_changed(&mut self, options: &dyn Options);

    /// Disposes this `GraphDisplayProvider`.
    ///
    /// Port of `GraphDisplayProvider.dispose()`.
    fn dispose(&mut self);

    /// Gets the help location for this `GraphDisplayProvider`.
    ///
    /// Port of `GraphDisplayProvider.getHelpLocation()`.
    fn get_help_location(&self) -> Box<dyn HelpLocation>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::graph::attributed_graph::AttributedGraph;
    use crate::service::graph::graph_type::GraphType;
    use crate::service::seam_stubs::GraphDisplayOptions;
    use crate::util::exception::CancelledException;

    struct StubHelpLocation;
    impl HelpLocation for StubHelpLocation {}

    struct StubPluginTool;
    impl PluginTool for StubPluginTool {}

    struct StubGraphDisplay {
        title: String,
    }

    impl GraphDisplay for StubGraphDisplay {
        fn set_graph_display_listener(
            &mut self,
            _listener: Box<dyn crate::service::graph::graph_display_listener::GraphDisplayListener>,
        ) {
        }
        fn set_focused_vertex(
            &mut self,
            _vertex: &crate::service::graph::AttributedVertex,
            _event_trigger: crate::docking::widgets::EventTrigger,
        ) {
        }
        fn get_graph(&self) -> Option<&AttributedGraph> {
            None
        }
        fn get_focused_vertex(&self) -> Option<&crate::service::graph::AttributedVertex> {
            None
        }
        fn select_vertices(
            &mut self,
            _vertex_set: &[&crate::service::graph::AttributedVertex],
            _event_trigger: crate::docking::widgets::EventTrigger,
        ) {
        }
        fn get_selected_vertices(&self) -> Vec<&crate::service::graph::AttributedVertex> {
            vec![]
        }
        fn close(&mut self) {}
        fn set_graph(
            &mut self,
            _graph: AttributedGraph,
            _options: &dyn GraphDisplayOptions,
            title: &str,
            _append: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            self.title = title.to_string();
            Ok(())
        }
        fn clear(&mut self) {}
        fn update_vertex_name(&mut self, _vertex: &crate::service::graph::AttributedVertex, _new_name: &str) {}
        fn get_graph_title(&self) -> String {
            self.title.clone()
        }
        fn add_action(&mut self, _action: Box<dyn crate::docking::action::docking_action_if::DockingActionIf>) {}
        fn get_actions(&self) -> Vec<&dyn crate::docking::action::docking_action_if::DockingActionIf> {
            vec![]
        }
    }

    struct StubProvider {
        append_seen: Option<bool>,
        disposed: bool,
    }

    impl ExtensionPoint for StubProvider {}

    impl GraphDisplayProvider for StubProvider {
        fn get_name(&self) -> String {
            "Stub Graph Display".to_string()
        }

        fn get_graph_display_reuse(
            &mut self,
            _reuse_graph: bool,
            append: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn GraphDisplay>, GraphException> {
            self.append_seen = Some(append);
            Ok(Box::new(StubGraphDisplay { title: String::new() }))
        }

        fn get_active_graph_display(&self) -> Option<Box<dyn GraphDisplay>> {
            None
        }

        fn get_all_graph_displays(&self) -> Vec<Box<dyn GraphDisplay>> {
            vec![]
        }

        fn initialize(&mut self, _tool: &dyn PluginTool, _options: &mut dyn Options) {}

        fn options_changed(&mut self, _options: &dyn Options) {}

        fn dispose(&mut self) {
            self.disposed = true;
        }

        fn get_help_location(&self) -> Box<dyn HelpLocation> {
            Box::new(StubHelpLocation)
        }
    }

    fn dummy_monitor() -> crate::util::task::DummyMonitor {
        crate::util::task::DummyMonitor
    }

    #[test]
    fn default_get_graph_display_delegates_with_append_false() {
        let mut provider = StubProvider { append_seen: None, disposed: false };
        let monitor = dummy_monitor();

        let display = provider.get_graph_display(true, &monitor).unwrap();

        assert_eq!(provider.append_seen, Some(false));
        assert_eq!(display.get_graph_title(), "");
    }

    #[test]
    fn get_graph_display_reuse_forwards_append_flag() {
        let mut provider = StubProvider { append_seen: None, disposed: false };
        let monitor = dummy_monitor();

        provider.get_graph_display_reuse(true, true, &monitor).unwrap();

        assert_eq!(provider.append_seen, Some(true));
    }

    #[test]
    fn dispose_marks_disposed() {
        let mut provider = StubProvider { append_seen: None, disposed: false };
        provider.dispose();
        assert!(provider.disposed);
    }

    #[test]
    fn trait_is_object_safe() {
        let mut provider: Box<dyn GraphDisplayProvider> =
            Box::new(StubProvider { append_seen: None, disposed: false });

        assert_eq!(provider.get_name(), "Stub Graph Display");
        assert!(provider.get_active_graph_display().is_none());
        assert!(provider.get_all_graph_displays().is_empty());
        let _ = provider.get_help_location();
    }

    #[test]
    fn graph_type_smoke() {
        // Sanity check that AttributedGraph/GraphType construct as expected in this module's
        // test doubles, matching Java's AttributedGraph(GraphType) usage in GraphDisplay tests.
        let graph_type = GraphType::new("test".to_string(), "test graph type".to_string(), vec![], vec![]);
        let graph = AttributedGraph::new("test", graph_type);
        assert_eq!(graph.get_name(), "test");
    }
}

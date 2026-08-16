//! Service for managing and directing graph output.
//!
//! Port of `ghidra.app.services.GraphDisplayBroker`. Its purpose is to discover available
//! graphing display providers and (if more than one) allow the user to select the currently
//! active graph consumer. Clients that generate graphs don't have to worry about how to display
//! them or export graphs. They simply send their graphs to the broker and register for graph
//! events if they want interactive support.
//!
//! The Java `@ServiceInfo` annotation (default provider `GraphDisplayBrokerPlugin`) has no Rust
//! equivalent and is omitted. `GraphDisplayProvider` is not yet ported, so it is represented by a
//! placeholder trait in [`crate::app::seam_stubs`]. Java's two overloaded `getGraphExporters`
//! methods are given distinct Rust names, since Rust traits cannot overload on parameter
//! type/arity alone. `removeGraphDisplayBrokerLisetener` (sic, per the Java source) is spelled
//! correctly here as `remove_graph_display_broker_listener`.

use crate::app::plugin::core::graph::GraphDisplayBrokerListener;
use crate::app::seam_stubs::GraphDisplayProvider;
use crate::service::graph::AttributedGraphExporter;
use crate::service::graph::GraphDisplay;
use crate::util::exception::GraphException;
use crate::util::task::TaskMonitor;

/// Service for managing and directing graph output.
///
/// Port of `ghidra.app.services.GraphDisplayBroker`.
pub trait GraphDisplayBroker {
    /// Gets the currently active `GraphDisplayProvider` that will be used to display/export
    /// graphs, or `None` if no provider is currently active.
    ///
    /// Port of `GraphDisplayBroker.getDefaultGraphDisplayProvider()`.
    fn get_default_graph_display_provider(&self) -> Option<Box<dyn GraphDisplayProvider>>;

    /// Adds a listener for notification when the set of graph display providers change or the
    /// currently active graph display provider changes.
    ///
    /// Port of `GraphDisplayBroker.addGraphDisplayBrokerListener(GraphDisplayBrokerListener)`.
    fn add_graph_display_broker_listener(&mut self, listener: Box<dyn GraphDisplayBrokerListener>);

    /// Removes the given listener.
    ///
    /// Port of `GraphDisplayBroker.removeGraphDisplayBrokerLisetener(GraphDisplayBrokerListener)`.
    fn remove_graph_display_broker_listener(&mut self, listener: &dyn GraphDisplayBrokerListener);

    /// A convenience method for getting a `GraphDisplay` from the currently active provider.
    /// This method is intended to be used to display a new graph.
    ///
    /// `reuse_graph`: if true, the provider will attempt to re-use a current graph display.
    /// `monitor`: the `TaskMonitor` that can be used to cancel the operation.
    ///
    /// # Errors
    ///
    /// Returns a `GraphException` if an error occurs trying to get a graph display.
    ///
    /// Port of `GraphDisplayBroker.getDefaultGraphDisplay(boolean, TaskMonitor)`.
    fn get_default_graph_display(
        &self,
        reuse_graph: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn GraphDisplay>, GraphException>;

    /// Checks if there is at least one `GraphDisplayProvider` in the system.
    ///
    /// Port of `GraphDisplayBroker.hasDefaultGraphDisplayProvider()`.
    fn has_default_graph_display_provider(&self) -> bool;

    /// Gets the `GraphDisplayProvider` with the given name, or `None` if none with that name
    /// exists.
    ///
    /// Port of `GraphDisplayBroker.getGraphDisplayProvider(String)`.
    fn get_graph_display_provider(&self, name: &str) -> Option<Box<dyn GraphDisplayProvider>>;

    /// Returns a list of all discovered `AttributedGraphExporter`s.
    ///
    /// Port of `GraphDisplayBroker.getGraphExporters()`.
    fn get_graph_exporters(&self) -> Vec<Box<dyn AttributedGraphExporter>>;

    /// Returns the `AttributedGraphExporter` with the given name, or `None` if no exporter with
    /// that name is known.
    ///
    /// Port of `GraphDisplayBroker.getGraphExporters(String)`.
    fn get_graph_exporter_by_name(&self, name: &str) -> Option<Box<dyn AttributedGraphExporter>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io;
    use std::path::Path;

    use crate::service::graph::AttributedGraph;
    use crate::util::classfinder::ExtensionPoint;

    struct MockProvider {
        name: String,
    }
    impl GraphDisplayProvider for MockProvider {}

    struct MockDisplay;
    impl GraphDisplay for MockDisplay {
        fn set_graph_display_listener(
            &mut self,
            _listener: Box<dyn crate::service::graph::GraphDisplayListener>,
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
            _options: &dyn crate::service::seam_stubs::GraphDisplayOptions,
            _title: &str,
            _append: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn clear(&mut self) {}
        fn update_vertex_name(&mut self, _vertex: &crate::service::graph::AttributedVertex, _new_name: &str) {}
        fn get_graph_title(&self) -> String {
            String::new()
        }
        fn add_action(&mut self, _action: Box<dyn crate::docking::action::docking_action_if::DockingActionIf>) {}
        fn get_actions(&self) -> Vec<&dyn crate::docking::action::docking_action_if::DockingActionIf> {
            vec![]
        }
    }

    struct MockExporter;
    impl ExtensionPoint for MockExporter {}
    impl AttributedGraphExporter for MockExporter {
        fn export_graph(&self, _graph: &AttributedGraph, _path: &Path) -> io::Result<()> {
            Ok(())
        }
        fn get_file_extension(&self) -> String {
            "dot".to_string()
        }
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_description(&self) -> String {
            "Mock exporter".to_string()
        }
    }

    struct MockListener;
    impl GraphDisplayBrokerListener for MockListener {
        fn providers_changed(&mut self) {}
    }

    struct MockBroker {
        default_provider: Option<String>,
        listener_count: RefCell<usize>,
    }

    impl GraphDisplayBroker for MockBroker {
        fn get_default_graph_display_provider(&self) -> Option<Box<dyn GraphDisplayProvider>> {
            self.default_provider
                .as_ref()
                .map(|name| Box::new(MockProvider { name: name.clone() }) as Box<dyn GraphDisplayProvider>)
        }

        fn add_graph_display_broker_listener(
            &mut self,
            _listener: Box<dyn GraphDisplayBrokerListener>,
        ) {
            *self.listener_count.borrow_mut() += 1;
        }

        fn remove_graph_display_broker_listener(&mut self, _listener: &dyn GraphDisplayBrokerListener) {
            *self.listener_count.borrow_mut() -= 1;
        }

        fn get_default_graph_display(
            &self,
            _reuse_graph: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn GraphDisplay>, GraphException> {
            if self.default_provider.is_none() {
                return Err(GraphException::with_message("no default provider"));
            }
            Ok(Box::new(MockDisplay))
        }

        fn has_default_graph_display_provider(&self) -> bool {
            self.default_provider.is_some()
        }

        fn get_graph_display_provider(&self, name: &str) -> Option<Box<dyn GraphDisplayProvider>> {
            self.default_provider
                .as_deref()
                .filter(|p| *p == name)
                .map(|name| Box::new(MockProvider { name: name.to_string() }) as Box<dyn GraphDisplayProvider>)
        }

        fn get_graph_exporters(&self) -> Vec<Box<dyn AttributedGraphExporter>> {
            vec![Box::new(MockExporter)]
        }

        fn get_graph_exporter_by_name(&self, name: &str) -> Option<Box<dyn AttributedGraphExporter>> {
            if name == "mock" {
                Some(Box::new(MockExporter))
            } else {
                None
            }
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut broker: Box<dyn GraphDisplayBroker> = Box::new(MockBroker {
            default_provider: Some("default".to_string()),
            listener_count: RefCell::new(0),
        });

        assert!(broker.has_default_graph_display_provider());
        assert!(broker.get_default_graph_display_provider().is_some());
        assert!(broker.get_graph_display_provider("default").is_some());
        assert!(broker.get_graph_display_provider("missing").is_none());

        broker.add_graph_display_broker_listener(Box::new(MockListener));
        broker.remove_graph_display_broker_listener(&MockListener);

        let monitor = crate::util::task::DummyMonitor;
        assert!(broker.get_default_graph_display(true, &monitor).is_ok());

        let exporters = broker.get_graph_exporters();
        assert_eq!(exporters.len(), 1);
        assert!(broker.get_graph_exporter_by_name("mock").is_some());
        assert!(broker.get_graph_exporter_by_name("missing").is_none());
    }
}

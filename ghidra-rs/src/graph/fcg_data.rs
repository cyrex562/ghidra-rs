//! Port of `functioncalls.plugin.FcgData`.
//!
//! Allows clients to retrieve and work on a function call graph and its related data, and makes
//! caching that data simple. In Java the two implementers are `ValidFcgData` (the real data for a
//! function) and `EmptyFcgData` (a null object used to avoid null checks).

use std::sync::Arc;

use crate::app::seam_stubs::GraphPerspectiveInfo;
use crate::program::model::listing::Function;

use super::fcg_vertex_expansion_listener::FcgVertexExpansionListener;
use super::function_call_graph::FunctionCallGraph;
use super::function_edge_cache::FunctionEdgeCache;

/// The graph and related cached data for one function in the function call graph plugin.
pub trait FcgData {
    /// The function of this data (`getFunction()`).
    fn get_function(&self) -> Arc<dyn Function>;

    /// The graph of this data (`getGraph()`).
    fn get_graph(&self) -> &FunctionCallGraph;

    /// Mutable access to the graph of this data. Java returns the (mutable) graph object from
    /// `getGraph()`; Rust splits shared and exclusive access.
    fn get_graph_mut(&mut self) -> &mut FunctionCallGraph;

    /// Returns the cache of function edges (`getFunctionEdgeCache()`).
    ///
    /// These edges are not in the graph, but rather are simple edges that represent a link
    /// between two functions. This is used to track existing edges that are not yet in the
    /// graph, which may be added later as the relevant nodes are inserted into the graph.
    fn get_function_edge_cache(&mut self) -> &mut FunctionEdgeCache;

    /// True if this data has a valid function (`hasResults()`).
    fn has_results(&self) -> bool;

    /// False if the graph in this data has not yet been loaded (`isInitialized()`).
    fn is_initialized(&self) -> bool;

    /// Dispose the contents of this data (`dispose()`).
    fn dispose(&mut self);

    /// Returns the view's graph perspective, used by the view to restore itself
    /// (`getGraphPerspective()`). `None` when no perspective has been recorded yet (Java `null`).
    fn get_graph_perspective(&self) -> Option<GraphPerspectiveInfo>;

    /// Sets the view information for this graph data, later used by the view to restore itself
    /// (`setGraphPerspective(GraphPerspectiveInfo)`).
    fn set_graph_perspective(&mut self, info: GraphPerspectiveInfo);

    /// Returns true if this data's function is equal to the given function (`isFunction`).
    fn is_function(&self, f: &Arc<dyn Function>) -> bool;

    /// Clones this data. The graph, the layout, all vertices and all edges will be cloned
    /// (`cloneGraphData(FcgVertexExpansionListener)`).
    fn clone_graph_data(&self, expansion_listener: &dyn FcgVertexExpansionListener) -> Box<dyn FcgData>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::fcg_direction::FcgDirection;
    use crate::graph::fcg_level::FcgLevel;
    use crate::graph::function_call_graph::tests::{MockFunction, MockVertex};
    use crate::graph::seam_stubs::FcgVertex;

    /// Test double mirroring Java's `ValidFcgData`.
    struct ValidData {
        function: Arc<dyn Function>,
        graph: FunctionCallGraph,
        perspective_info: Option<GraphPerspectiveInfo>,
        all_edges_by_function: FunctionEdgeCache,
    }

    impl ValidData {
        fn new(function: Arc<dyn Function>, graph: FunctionCallGraph) -> Self {
            Self { function, graph, perspective_info: None, all_edges_by_function: FunctionEdgeCache::new() }
        }
    }

    impl FcgData for ValidData {
        fn get_function(&self) -> Arc<dyn Function> {
            self.function.clone()
        }
        fn get_graph(&self) -> &FunctionCallGraph {
            &self.graph
        }
        fn get_graph_mut(&mut self) -> &mut FunctionCallGraph {
            &mut self.graph
        }
        fn get_function_edge_cache(&mut self) -> &mut FunctionEdgeCache {
            &mut self.all_edges_by_function
        }
        fn has_results(&self) -> bool {
            true
        }
        fn is_initialized(&self) -> bool {
            self.graph.get_all_vertices().next().is_some()
        }
        fn dispose(&mut self) {
            self.graph = FunctionCallGraph::new();
        }
        fn get_graph_perspective(&self) -> Option<GraphPerspectiveInfo> {
            self.perspective_info
        }
        fn set_graph_perspective(&mut self, info: GraphPerspectiveInfo) {
            self.perspective_info = Some(info);
        }
        fn is_function(&self, f: &Arc<dyn Function>) -> bool {
            Arc::ptr_eq(&self.function, f)
        }
        fn clone_graph_data(&self, expansion_listener: &dyn FcgVertexExpansionListener) -> Box<dyn FcgData> {
            let mut data = ValidData::new(self.function.clone(), self.graph.clone_graph(expansion_listener));
            data.perspective_info = self.perspective_info;
            Box::new(data)
        }
    }

    struct NoopListener;
    impl FcgVertexExpansionListener for NoopListener {
        fn toggle_incoming_vertices(&self, _v: &dyn FcgVertex) {}
        fn toggle_outgoing_vertices(&self, _v: &dyn FcgVertex) {}
    }

    fn function(name: &str, offset: i64) -> Arc<dyn Function> {
        Arc::new(MockFunction::new(name, offset))
    }

    #[test]
    fn valid_data_is_uninitialized_until_graph_has_vertices() {
        let f = function("main", 0x1000);
        let mut data = ValidData::new(f.clone(), FunctionCallGraph::new());
        assert!(data.has_results());
        assert!(!data.is_initialized());

        let v: Arc<dyn FcgVertex> = Arc::new(MockVertex::new(f.clone(), FcgLevel::source_level()));
        data.get_graph_mut().set_source(v);
        assert!(data.is_initialized());
    }

    #[test]
    fn is_function_uses_identity_of_the_data_function() {
        let f = function("main", 0x1000);
        let other = function("main", 0x1000);
        let data = ValidData::new(f.clone(), FunctionCallGraph::new());
        assert!(data.is_function(&f));
        assert!(!data.is_function(&other));
    }

    #[test]
    fn graph_perspective_round_trips_and_is_carried_into_clone() {
        let f = function("main", 0x1000);
        let mut data = ValidData::new(f.clone(), FunctionCallGraph::new());
        assert_eq!(data.get_graph_perspective(), None);

        let v: Arc<dyn FcgVertex> = Arc::new(MockVertex::new(f.clone(), FcgLevel::source_level()));
        data.get_graph_mut().set_source(v);
        let child: Arc<dyn FcgVertex> = Arc::new(MockVertex::new(
            function("callee", 0x2000),
            FcgLevel::new(1, FcgDirection::Out),
        ));
        data.get_graph_mut().add_vertex(child);

        let info = GraphPerspectiveInfo::create_invalid();
        data.set_graph_perspective(info);
        assert_eq!(data.get_graph_perspective(), Some(info));

        let clone = data.clone_graph_data(&NoopListener);
        assert!(clone.is_function(&f));
        assert_eq!(clone.get_graph_perspective(), Some(info));
        assert_eq!(clone.get_graph().get_all_vertices().count(), 2);
    }

    #[test]
    fn function_edge_cache_tracks_functions() {
        let f = function("main", 0x1000);
        let mut data = ValidData::new(f.clone(), FunctionCallGraph::new());
        assert!(!data.get_function_edge_cache().is_tracked(&f));
        data.get_function_edge_cache().set_tracked(f.clone());
        assert!(data.get_function_edge_cache().is_tracked(&f));
    }
}

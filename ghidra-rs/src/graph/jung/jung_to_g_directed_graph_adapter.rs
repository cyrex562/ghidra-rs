//! Port of `ghidra.graph.jung.JungToGDirectedGraphAdapter`.

use crate::graph::g_directed_graph::GDirectedGraph;
use crate::graph::g_edge::GEdge;
use crate::graph::g_implicit_directed_graph::GImplicitDirectedGraph;

/// The type of an edge in a JUNG graph: whether it can only be traversed in one direction, or
/// both.
///
/// Port of `edu.uci.ics.jung.graph.util.EdgeType`, the one piece of JUNG's own API surface
/// [`JungGraph`]'s passthrough methods need. See [`JungGraph`]'s own docs for why the rest of
/// JUNG is out of scope for this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeType {
    Directed,
    Undirected,
}

/// Seam for JUNG's `edu.uci.ics.jung.graph.Graph<V, E>` interface: the subset of methods
/// [`JungToGDirectedGraphAdapter`] needs from *any* JUNG graph implementation.
///
/// JUNG (`edu.uci.ics.jung.graph`) is a third-party graph-visualization library; per
/// [`JungDirectedGraph`](super::jung_directed_graph::JungDirectedGraph)'s own docs, it is out of
/// scope for this port and has no Rust translation. But unlike `JungDirectedGraph` (which only
/// *extends* a JUNG base class for storage, and so owns its `Vec<V>`/`Vec<E>` directly instead),
/// `JungToGDirectedGraphAdapter` exists specifically to *wrap* an arbitrary JUNG `Graph` -- so
/// this trait stands in for that JUNG interface, giving the adapter something concrete to
/// delegate to. [`JungDirectedGraph`](super::jung_directed_graph::JungDirectedGraph) itself
/// implements this trait too (see its `impl JungGraph` block below), so it can stand in as a
/// real, useful delegate; any other graph representation can implement it as well.
///
/// [`as_g_directed_graph`](JungGraph::as_g_directed_graph) mirrors the Java `delegate instanceof
/// GDirectedGraph` check `emptyCopy()` performs; defaults to `None` for delegates that are "just"
/// JUNG graphs.
pub trait JungGraph<V: Clone + PartialEq, E: GEdge<V> + Clone + PartialEq> {
    /// Port of `Graph.addEdge(E, V, V)`.
    fn add_edge(&mut self, e: E, v1: V, v2: V) -> bool;
    /// Port of `Graph.getVertices()`.
    fn get_vertices(&self) -> Vec<V>;
    /// Port of `Graph.getEdges()`.
    fn get_edges(&self) -> Vec<E>;
    /// Port of `Graph.getInEdges(V)`.
    fn get_in_edges(&self, v: &V) -> Vec<E>;
    /// Port of `Graph.getOutEdges(V)`.
    fn get_out_edges(&self, v: &V) -> Vec<E>;
    /// Port of `Graph.containsVertex(V)`.
    fn contains_vertex(&self, v: &V) -> bool;
    /// Port of `Graph.getPredecessors(V)`.
    fn get_predecessors(&self, v: &V) -> Vec<V>;
    /// Port of `Graph.containsEdge(E)`.
    fn contains_edge(&self, e: &E) -> bool;
    /// Port of `Graph.getEdgeCount()`.
    fn get_edge_count(&self) -> usize;
    /// Port of `Graph.getSuccessors(V)`.
    fn get_successors(&self, v: &V) -> Vec<V>;
    /// Port of `Graph.getVertexCount()`.
    fn get_vertex_count(&self) -> usize;
    /// Port of `Graph.getNeighbors(V)`.
    fn get_neighbors(&self, v: &V) -> Vec<V>;
    /// Port of `Graph.inDegree(V)`.
    fn in_degree(&self, v: &V) -> usize;
    /// Port of `Graph.getIncidentEdges(V)`.
    fn get_incident_edges(&self, v: &V) -> Vec<E>;
    /// Port of `Graph.outDegree(V)`.
    fn out_degree(&self, v: &V) -> usize;
    /// Port of `Graph.getIncidentVertices(E)`.
    fn get_incident_vertices(&self, e: &E) -> Vec<V>;
    /// Port of `Graph.isPredecessor(V, V)`.
    fn is_predecessor(&self, v1: &V, v2: &V) -> bool;
    /// Port of `Graph.isSuccessor(V, V)`.
    fn is_successor(&self, v1: &V, v2: &V) -> bool;
    /// Port of `Graph.findEdge(V, V)`.
    fn find_edge(&self, v1: &V, v2: &V) -> Option<E>;
    /// Port of `Graph.getPredecessorCount(V)`.
    fn get_predecessor_count(&self, v: &V) -> usize;
    /// Port of `Graph.getSuccessorCount(V)`.
    fn get_successor_count(&self, v: &V) -> usize;
    /// Port of `Graph.getSource(E)`.
    fn get_source(&self, e: &E) -> V;
    /// Port of `Graph.findEdgeSet(V, V)`.
    fn find_edge_set(&self, v1: &V, v2: &V) -> Vec<E>;
    /// Port of `Graph.getDest(E)`.
    fn get_dest(&self, e: &E) -> V;
    /// Port of `Graph.isSource(V, E)`.
    fn is_source(&self, v: &V, e: &E) -> bool;
    /// Port of `Graph.addVertex(V)`.
    fn add_vertex(&mut self, v: V) -> bool;
    /// Port of `Graph.isDest(V, E)`.
    fn is_dest(&self, v: &V, e: &E) -> bool;
    /// Port of `Graph.addEdge(E, Collection<? extends V>)`.
    fn add_edge_with_vertices(&mut self, e: E, vertices: &[V]) -> bool;
    /// Port of `Graph.addEdge(E, Collection<? extends V>, EdgeType)`.
    fn add_edge_with_vertices_and_type(&mut self, e: E, vertices: &[V], edge_type: EdgeType) -> bool;
    /// Port of `Graph.addEdge(E, V, V, EdgeType)`.
    fn add_edge_with_endpoints_and_type(&mut self, e: E, v1: V, v2: V, edge_type: EdgeType) -> bool;
    /// Port of `Graph.removeVertex(V)`.
    fn remove_vertex(&mut self, v: &V) -> bool;
    /// Port of `Graph.getEndpoints(E)`.
    fn get_endpoints(&self, e: &E) -> (V, V);
    /// Port of `Graph.getOpposite(V, E)`.
    fn get_opposite(&self, v: &V, e: &E) -> V;
    /// Port of `Graph.removeEdge(E)`.
    fn remove_edge(&mut self, e: &E) -> bool;
    /// Port of `Graph.isNeighbor(V, V)`.
    fn is_neighbor(&self, v1: &V, v2: &V) -> bool;
    /// Port of `Graph.isIncident(V, E)`.
    fn is_incident(&self, v: &V, e: &E) -> bool;
    /// Port of `Graph.degree(V)`.
    fn degree(&self, v: &V) -> usize;
    /// Port of `Graph.getNeighborCount(V)`.
    fn get_neighbor_count(&self, v: &V) -> usize;
    /// Port of `Graph.getIncidentCount(E)`.
    fn get_incident_count(&self, e: &E) -> usize;
    /// Port of `Graph.getEdgeType(E)`.
    fn get_edge_type(&self, e: &E) -> EdgeType;
    /// Port of `Graph.getDefaultEdgeType()`.
    fn get_default_edge_type(&self) -> EdgeType;
    /// Port of `Graph.getEdges(EdgeType)`.
    fn get_edges_of_type(&self, edge_type: EdgeType) -> Vec<E>;
    /// Port of `Graph.getEdgeCount(EdgeType)`.
    fn get_edge_count_of_type(&self, edge_type: EdgeType) -> usize;

    /// Mirrors the Java `delegate instanceof GDirectedGraph` check inside `emptyCopy()`. Defaults
    /// to `None`.
    fn as_g_directed_graph(&self) -> Option<&dyn GDirectedGraph<V, E>> {
        None
    }
}

impl<V, E> JungGraph<V, E> for super::jung_directed_graph::JungDirectedGraph<V, E>
where
    V: Clone + PartialEq + 'static,
    E: GEdge<V> + Clone + PartialEq + 'static,
{
    fn add_edge(&mut self, e: E, _v1: V, _v2: V) -> bool {
        GDirectedGraph::add_edge(self, e);
        true
    }
    fn get_vertices(&self) -> Vec<V> {
        GDirectedGraph::get_vertices(self)
    }
    fn get_edges(&self) -> Vec<E> {
        GDirectedGraph::get_edges(self)
    }
    fn get_in_edges(&self, v: &V) -> Vec<E> {
        GImplicitDirectedGraph::get_in_edges(self, v)
    }
    fn get_out_edges(&self, v: &V) -> Vec<E> {
        GImplicitDirectedGraph::get_out_edges(self, v)
    }
    fn contains_vertex(&self, v: &V) -> bool {
        GDirectedGraph::contains_vertex(self, v)
    }
    fn get_predecessors(&self, v: &V) -> Vec<V> {
        GImplicitDirectedGraph::get_predecessors(self, v)
    }
    fn contains_edge(&self, e: &E) -> bool {
        GDirectedGraph::contains_edge(self, e)
    }
    fn get_edge_count(&self) -> usize {
        GDirectedGraph::get_edge_count(self)
    }
    fn get_successors(&self, v: &V) -> Vec<V> {
        GImplicitDirectedGraph::get_successors(self, v)
    }
    fn get_vertex_count(&self) -> usize {
        GDirectedGraph::get_vertex_count(self)
    }
    fn get_neighbors(&self, v: &V) -> Vec<V> {
        let mut result = JungGraph::get_predecessors(self, v);
        for s in JungGraph::get_successors(self, v) {
            if !result.contains(&s) {
                result.push(s);
            }
        }
        result
    }
    fn in_degree(&self, v: &V) -> usize {
        GImplicitDirectedGraph::get_in_edges(self, v).len()
    }
    fn get_incident_edges(&self, v: &V) -> Vec<E> {
        GDirectedGraph::get_incident_edges(self, v)
    }
    fn out_degree(&self, v: &V) -> usize {
        GImplicitDirectedGraph::get_out_edges(self, v).len()
    }
    fn get_incident_vertices(&self, e: &E) -> Vec<V> {
        vec![e.get_start().clone(), e.get_end().clone()]
    }
    fn is_predecessor(&self, v1: &V, v2: &V) -> bool {
        JungGraph::get_predecessors(self, v2).contains(v1)
    }
    fn is_successor(&self, v1: &V, v2: &V) -> bool {
        JungGraph::get_successors(self, v1).contains(v2)
    }
    fn find_edge(&self, v1: &V, v2: &V) -> Option<E> {
        GDirectedGraph::find_edge(self, v1, v2)
    }
    fn get_predecessor_count(&self, v: &V) -> usize {
        JungGraph::get_predecessors(self, v).len()
    }
    fn get_successor_count(&self, v: &V) -> usize {
        JungGraph::get_successors(self, v).len()
    }
    fn get_source(&self, e: &E) -> V {
        e.get_start().clone()
    }
    fn find_edge_set(&self, v1: &V, v2: &V) -> Vec<E> {
        JungGraph::find_edge(self, v1, v2).into_iter().collect()
    }
    fn get_dest(&self, e: &E) -> V {
        e.get_end().clone()
    }
    fn is_source(&self, v: &V, e: &E) -> bool {
        e.get_start() == v
    }
    fn add_vertex(&mut self, v: V) -> bool {
        GDirectedGraph::add_vertex(self, v)
    }
    fn is_dest(&self, v: &V, e: &E) -> bool {
        e.get_end() == v
    }
    fn add_edge_with_vertices(&mut self, e: E, _vertices: &[V]) -> bool {
        GDirectedGraph::add_edge(self, e);
        true
    }
    fn add_edge_with_vertices_and_type(&mut self, e: E, _vertices: &[V], _edge_type: EdgeType) -> bool {
        GDirectedGraph::add_edge(self, e);
        true
    }
    fn add_edge_with_endpoints_and_type(&mut self, e: E, _v1: V, _v2: V, _edge_type: EdgeType) -> bool {
        GDirectedGraph::add_edge(self, e);
        true
    }
    fn remove_vertex(&mut self, v: &V) -> bool {
        GDirectedGraph::remove_vertex(self, v)
    }
    fn get_endpoints(&self, e: &E) -> (V, V) {
        (e.get_start().clone(), e.get_end().clone())
    }
    fn get_opposite(&self, v: &V, e: &E) -> V {
        if e.get_start() == v { e.get_end().clone() } else { e.get_start().clone() }
    }
    fn remove_edge(&mut self, e: &E) -> bool {
        GDirectedGraph::remove_edge(self, e)
    }
    fn is_neighbor(&self, v1: &V, v2: &V) -> bool {
        self.get_neighbors(v1).contains(v2)
    }
    fn is_incident(&self, v: &V, e: &E) -> bool {
        e.get_start() == v || e.get_end() == v
    }
    fn degree(&self, v: &V) -> usize {
        self.in_degree(v) + self.out_degree(v)
    }
    fn get_neighbor_count(&self, v: &V) -> usize {
        self.get_neighbors(v).len()
    }
    fn get_incident_count(&self, _e: &E) -> usize {
        2
    }
    fn get_edge_type(&self, _e: &E) -> EdgeType {
        EdgeType::Directed
    }
    fn get_default_edge_type(&self) -> EdgeType {
        EdgeType::Directed
    }
    fn get_edges_of_type(&self, edge_type: EdgeType) -> Vec<E> {
        if edge_type == EdgeType::Directed { JungGraph::get_edges(self) } else { Vec::new() }
    }
    fn get_edge_count_of_type(&self, edge_type: EdgeType) -> usize {
        self.get_edges_of_type(edge_type).len()
    }

    fn as_g_directed_graph(&self) -> Option<&dyn GDirectedGraph<V, E>> {
        Some(self)
    }
}

/// A class that turns a JUNG graph into a [`GDirectedGraph`].
///
/// Port of `ghidra.graph.jung.JungToGDirectedGraphAdapter<V, E>`. Java's `V`/`E` type parameters
/// are, in principle, fully determined by `D`'s [`JungGraph<V, E>`] implementation; this struct
/// still carries them explicitly (rather than making `D` alone the sole parameter) because Rust's
/// inherent-impl well-formedness rules require every impl type parameter to appear in the self
/// type, and `V`/`E` otherwise only ever appear inside a `where D: JungGraph<V, E>` bound. The
/// `_marker` field carries no runtime data. See [`JungGraph`]'s docs for why JUNG's own `Graph<V,
/// E>` interface is replaced by that trait here.
pub struct JungToGDirectedGraphAdapter<D, V, E> {
    delegate: D,
    _marker: std::marker::PhantomData<fn() -> (V, E)>,
}

impl<D, V, E> JungToGDirectedGraphAdapter<D, V, E> {
    /// Port of the `JungToGDirectedGraphAdapter(Graph<V, E>)` constructor.
    pub fn new(delegate: D) -> Self {
        JungToGDirectedGraphAdapter { delegate, _marker: std::marker::PhantomData }
    }
}

impl<D, V, E> JungToGDirectedGraphAdapter<D, V, E>
where
    D: JungGraph<V, E>,
    V: Clone + PartialEq,
    E: GEdge<V> + Clone + PartialEq,
{
    /// Port of `JungToGDirectedGraphAdapter.getNeighbors(V)` (not part of `GDirectedGraph`).
    pub fn get_neighbors(&self, vertex: &V) -> Vec<V> {
        self.delegate.get_neighbors(vertex)
    }

    /// Port of `JungToGDirectedGraphAdapter.inDegree(V)` (not part of `GDirectedGraph`).
    pub fn in_degree(&self, vertex: &V) -> usize {
        self.delegate.in_degree(vertex)
    }

    /// Port of `JungToGDirectedGraphAdapter.outDegree(V)` (not part of `GDirectedGraph`).
    pub fn out_degree(&self, vertex: &V) -> usize {
        self.delegate.out_degree(vertex)
    }

    /// Port of `JungToGDirectedGraphAdapter.getIncidentVertices(E)`.
    pub fn get_incident_vertices(&self, edge: &E) -> Vec<V> {
        self.delegate.get_incident_vertices(edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.isPredecessor(V, V)`.
    pub fn is_predecessor(&self, v1: &V, v2: &V) -> bool {
        self.delegate.is_predecessor(v1, v2)
    }

    /// Port of `JungToGDirectedGraphAdapter.isSuccessor(V, V)`.
    pub fn is_successor(&self, v1: &V, v2: &V) -> bool {
        self.delegate.is_successor(v1, v2)
    }

    /// Port of `JungToGDirectedGraphAdapter.getPredecessorCount(V)`.
    pub fn get_predecessor_count(&self, vertex: &V) -> usize {
        self.delegate.get_predecessor_count(vertex)
    }

    /// Port of `JungToGDirectedGraphAdapter.getSuccessorCount(V)`.
    pub fn get_successor_count(&self, vertex: &V) -> usize {
        self.delegate.get_successor_count(vertex)
    }

    /// Port of `JungToGDirectedGraphAdapter.getSource(E)`.
    pub fn get_source(&self, directed_edge: &E) -> V {
        self.delegate.get_source(directed_edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.findEdgeSet(V, V)`.
    pub fn find_edge_set(&self, v1: &V, v2: &V) -> Vec<E> {
        self.delegate.find_edge_set(v1, v2)
    }

    /// Port of `JungToGDirectedGraphAdapter.getDest(E)`.
    pub fn get_dest(&self, directed_edge: &E) -> V {
        self.delegate.get_dest(directed_edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.isSource(V, E)`.
    pub fn is_source(&self, vertex: &V, edge: &E) -> bool {
        self.delegate.is_source(vertex, edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.isDest(V, E)`.
    pub fn is_dest(&self, vertex: &V, edge: &E) -> bool {
        self.delegate.is_dest(vertex, edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.addEdge(E, Collection)`.
    pub fn add_edge_with_vertices(&mut self, edge: E, vertices: &[V]) -> bool {
        self.delegate.add_edge_with_vertices(edge, vertices)
    }

    /// Port of `JungToGDirectedGraphAdapter.addEdge(E, V, V)` (the 3-arg overload).
    pub fn add_edge_with_endpoints(&mut self, e: E, v1: V, v2: V) -> bool {
        self.delegate.add_edge(e, v1, v2)
    }

    /// Port of `JungToGDirectedGraphAdapter.addEdge(E, Collection, EdgeType)`.
    pub fn add_edge_with_vertices_and_type(&mut self, edge: E, vertices: &[V], edge_type: EdgeType) -> bool {
        self.delegate.add_edge_with_vertices_and_type(edge, vertices, edge_type)
    }

    /// Port of `JungToGDirectedGraphAdapter.addEdge(E, V, V, EdgeType)`.
    pub fn add_edge_with_endpoints_and_type(&mut self, e: E, v1: V, v2: V, edge_type: EdgeType) -> bool {
        self.delegate.add_edge_with_endpoints_and_type(e, v1, v2, edge_type)
    }

    /// Port of `JungToGDirectedGraphAdapter.getEndpoints(E)`.
    pub fn get_endpoints(&self, edge: &E) -> (V, V) {
        self.delegate.get_endpoints(edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.getOpposite(V, E)`.
    pub fn get_opposite(&self, vertex: &V, edge: &E) -> V {
        self.delegate.get_opposite(vertex, edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.isNeighbor(V, V)`.
    pub fn is_neighbor(&self, v1: &V, v2: &V) -> bool {
        self.delegate.is_neighbor(v1, v2)
    }

    /// Port of `JungToGDirectedGraphAdapter.isIncident(V, E)`.
    pub fn is_incident(&self, vertex: &V, edge: &E) -> bool {
        self.delegate.is_incident(vertex, edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.degree(V)`.
    pub fn degree(&self, vertex: &V) -> usize {
        self.delegate.degree(vertex)
    }

    /// Port of `JungToGDirectedGraphAdapter.getNeighborCount(V)`.
    pub fn get_neighbor_count(&self, vertex: &V) -> usize {
        self.delegate.get_neighbor_count(vertex)
    }

    /// Port of `JungToGDirectedGraphAdapter.getIncidentCount(E)`.
    pub fn get_incident_count(&self, edge: &E) -> usize {
        self.delegate.get_incident_count(edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.getEdgeType(E)`.
    pub fn get_edge_type(&self, edge: &E) -> EdgeType {
        self.delegate.get_edge_type(edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.getDefaultEdgeType()`.
    pub fn get_default_edge_type(&self) -> EdgeType {
        self.delegate.get_default_edge_type()
    }

    /// Port of `JungToGDirectedGraphAdapter.getEdges(EdgeType)`.
    pub fn get_edges_of_type(&self, edge_type: EdgeType) -> Vec<E> {
        self.delegate.get_edges_of_type(edge_type)
    }

    /// Port of `JungToGDirectedGraphAdapter.getEdgeCount(EdgeType)`.
    pub fn get_edge_count_of_type(&self, edge_type: EdgeType) -> usize {
        self.delegate.get_edge_count_of_type(edge_type)
    }
}

impl<D, V, E> GImplicitDirectedGraph<V, E> for JungToGDirectedGraphAdapter<D, V, E>
where
    D: JungGraph<V, E> + Default + 'static,
    V: Clone + PartialEq + 'static,
    E: GEdge<V> + Clone + PartialEq + 'static,
{
    fn get_in_edges(&self, v: &V) -> Vec<E> {
        self.delegate.get_in_edges(v)
    }

    fn get_out_edges(&self, v: &V) -> Vec<E> {
        self.delegate.get_out_edges(v)
    }

    /// Port of `JungToGDirectedGraphAdapter.getPredecessors(V)`, overriding
    /// `GImplicitDirectedGraph`'s in-edges-derived default with a direct delegate call, exactly
    /// as Java's override does.
    fn get_predecessors(&self, v: &V) -> Vec<V> {
        self.delegate.get_predecessors(v)
    }

    /// Port of `JungToGDirectedGraphAdapter.getSuccessors(V)`, overriding the default the same
    /// way as [`get_predecessors`](Self::get_predecessors).
    fn get_successors(&self, v: &V) -> Vec<V> {
        self.delegate.get_successors(v)
    }

    /// Port of `JungToGDirectedGraphAdapter.copy()`.
    ///
    /// # Java quirk (not reproduced): a latent `ClassCastException`
    /// Java's `copy()` force-casts the result of `emptyCopy()` to `JungToGDirectedGraphAdapter<V,
    /// E>` -- but `emptyCopy()` returns `delegate.emptyCopy()` *directly* (skipping the adapter
    /// wrapper) whenever the delegate itself implements `GDirectedGraph` (see
    /// [`empty_copy`](GDirectedGraph::empty_copy) below), meaning `copy()` would throw
    /// `ClassCastException` for any delegate that is *both* a JUNG graph and a `GDirectedGraph`.
    /// This port sidesteps the bug by construction: Rust's static typing means `copy()` always
    /// builds a same-typed `JungToGDirectedGraphAdapter<D>` (via `D::default()`), never routing
    /// through the trait-object-returning `empty_copy`, so there is no cast (and no failure mode)
    /// to reproduce here.
    fn copy(&self) -> Box<dyn GDirectedGraph<V, E>> {
        let mut new_graph = JungToGDirectedGraphAdapter { delegate: D::default(), _marker: std::marker::PhantomData };
        for v in self.delegate.get_vertices() {
            GDirectedGraph::add_vertex(&mut new_graph, v);
        }
        for e in self.delegate.get_edges() {
            let v1 = e.get_start().clone();
            let v2 = e.get_end().clone();
            new_graph.delegate.add_edge(e, v1, v2);
        }
        Box::new(new_graph)
    }
}

impl<D, V, E> GDirectedGraph<V, E> for JungToGDirectedGraphAdapter<D, V, E>
where
    D: JungGraph<V, E> + Default + 'static,
    V: Clone + PartialEq + 'static,
    E: GEdge<V> + Clone + PartialEq + 'static,
{
    /// Port of `JungToGDirectedGraphAdapter.addEdge(E)`.
    fn add_edge(&mut self, e: E) {
        let v1 = e.get_start().clone();
        let v2 = e.get_end().clone();
        self.delegate.add_edge(e, v1, v2);
    }

    fn add_vertex(&mut self, vertex: V) -> bool {
        self.delegate.add_vertex(vertex)
    }

    fn remove_vertex(&mut self, vertex: &V) -> bool {
        self.delegate.remove_vertex(vertex)
    }

    fn remove_edge(&mut self, edge: &E) -> bool {
        self.delegate.remove_edge(edge)
    }

    fn find_edge(&self, start: &V, end: &V) -> Option<E> {
        self.delegate.find_edge(start, end)
    }

    fn get_vertices(&self) -> Vec<V> {
        self.delegate.get_vertices()
    }

    fn get_edges(&self) -> Vec<E> {
        self.delegate.get_edges()
    }

    fn contains_vertex(&self, vertex: &V) -> bool {
        self.delegate.contains_vertex(vertex)
    }

    /// Port of `JungToGDirectedGraphAdapter.containsEdge(E)`.
    fn contains_edge(&self, edge: &E) -> bool {
        self.delegate.contains_edge(edge)
    }

    /// Port of `JungToGDirectedGraphAdapter.containsEdge(V, V)`: `findEdge(from, to) != null`.
    fn contains_edge_between(&self, from: &V, to: &V) -> bool {
        self.find_edge(from, to).is_some()
    }

    /// Port of `JungToGDirectedGraphAdapter.isEmpty()`: `getVertexCount() == 0`.
    fn is_empty(&self) -> bool {
        self.get_vertex_count() == 0
    }

    fn get_vertex_count(&self) -> usize {
        self.delegate.get_vertex_count()
    }

    fn get_edge_count(&self) -> usize {
        self.delegate.get_edge_count()
    }

    /// Port of `JungToGDirectedGraphAdapter.getIncidentEdges(V)`, overriding `GDirectedGraph`'s
    /// in/out-edge-union default with a direct delegate call, exactly as Java's override does.
    fn get_incident_edges(&self, vertex: &V) -> Vec<E> {
        self.delegate.get_incident_edges(vertex)
    }

    /// Port of `JungToGDirectedGraphAdapter.emptyCopy()`.
    fn empty_copy(&self) -> Box<dyn GDirectedGraph<V, E>> {
        if let Some(g) = self.delegate.as_g_directed_graph() {
            return g.empty_copy();
        }
        Box::new(JungToGDirectedGraphAdapter { delegate: D::default(), _marker: std::marker::PhantomData })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::jung_directed_graph::JungDirectedGraph;

    #[derive(Clone, PartialEq, Debug)]
    struct Edge {
        start: i32,
        end: i32,
    }

    impl GEdge<i32> for Edge {
        fn get_start(&self) -> &i32 {
            &self.start
        }
        fn get_end(&self) -> &i32 {
            &self.end
        }
    }

    fn edge(start: i32, end: i32) -> Edge {
        Edge { start, end }
    }

    fn built_graph() -> JungDirectedGraph<i32, Edge> {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2));
        GDirectedGraph::add_edge(&mut g, edge(1, 3));
        GDirectedGraph::add_edge(&mut g, edge(2, 3));
        g
    }

    #[test]
    fn add_edge_delegates_with_start_and_end() {
        let mut adapter = JungToGDirectedGraphAdapter::new(JungDirectedGraph::<i32, Edge>::new());
        GDirectedGraph::add_edge(&mut adapter, edge(1, 2));

        assert_eq!(adapter.get_vertex_count(), 2);
        assert!(adapter.contains_vertex(&1));
        assert!(adapter.contains_vertex(&2));
        assert_eq!(adapter.get_edge_count(), 1);
    }

    #[test]
    fn contains_edge_between_uses_find_edge() {
        let adapter = JungToGDirectedGraphAdapter::new(built_graph());
        assert!(adapter.contains_edge_between(&1, &2));
        assert!(!adapter.contains_edge_between(&2, &1));
    }

    #[test]
    fn find_edge_and_contains_edge_delegate_through() {
        let adapter = JungToGDirectedGraphAdapter::new(built_graph());
        assert_eq!(adapter.find_edge(&1, &2), Some(edge(1, 2)));
        assert!(adapter.contains_edge(&edge(1, 2)));
        assert!(!adapter.contains_edge(&edge(9, 9)));
    }

    #[test]
    fn get_vertices_and_edges_delegate_through() {
        let adapter = JungToGDirectedGraphAdapter::new(built_graph());
        assert_eq!(adapter.get_vertices().len(), 3);
        assert_eq!(adapter.get_edges().len(), 3);
    }

    #[test]
    fn get_in_and_out_edges_delegate_through() {
        let adapter = JungToGDirectedGraphAdapter::new(built_graph());
        assert_eq!(adapter.get_out_edges(&1), vec![edge(1, 2), edge(1, 3)]);
        assert_eq!(adapter.get_in_edges(&3), vec![edge(1, 3), edge(2, 3)]);
    }

    #[test]
    fn get_predecessors_and_successors_override_defaults_via_delegate() {
        let adapter = JungToGDirectedGraphAdapter::new(built_graph());
        assert_eq!(adapter.get_successors(&1), vec![2, 3]);
        assert_eq!(adapter.get_predecessors(&3), vec![1, 2]);
    }

    #[test]
    fn is_empty_checks_vertex_count_only() {
        let adapter: JungToGDirectedGraphAdapter<JungDirectedGraph<i32, Edge>, i32, Edge> =
            JungToGDirectedGraphAdapter::new(JungDirectedGraph::new());
        assert!(adapter.is_empty());

        let mut adapter = adapter;
        adapter.add_vertex(1);
        assert!(!adapter.is_empty());
    }

    #[test]
    fn get_incident_edges_delegates_through_not_the_union_default() {
        let adapter = JungToGDirectedGraphAdapter::new(built_graph());
        let incident = adapter.get_incident_edges(&1);
        assert_eq!(incident.len(), 2);
        assert!(incident.contains(&edge(1, 2)));
        assert!(incident.contains(&edge(1, 3)));
    }

    #[test]
    fn remove_vertex_and_remove_edge_delegate_through() {
        let mut adapter = JungToGDirectedGraphAdapter::new(built_graph());
        assert!(adapter.remove_edge(&edge(1, 2)));
        assert_eq!(adapter.get_edge_count(), 2);
        assert!(adapter.remove_vertex(&3));
        assert_eq!(adapter.get_vertex_count(), 2);
    }

    #[test]
    fn empty_copy_uses_the_delegates_g_directed_graph_path_when_available() {
        // JungDirectedGraph implements both JungGraph and GDirectedGraph, so
        // as_g_directed_graph() is Some -- emptyCopy() should route through the delegate's own
        // emptyCopy(), matching Java's `delegate instanceof GDirectedGraph` fast path.
        let adapter = JungToGDirectedGraphAdapter::new(built_graph());
        let empty = adapter.empty_copy();
        assert!(empty.is_empty());
    }

    #[test]
    fn copy_duplicates_vertices_and_edges_into_a_fresh_adapter() {
        let adapter = JungToGDirectedGraphAdapter::new(built_graph());
        let copy = GImplicitDirectedGraph::copy(&adapter);
        assert_eq!(copy.get_vertex_count(), 3);
        assert_eq!(copy.get_edge_count(), 3);
        assert!(copy.contains_edge_between(&1, &2));
        assert!(copy.contains_edge_between(&2, &3));
    }

    #[test]
    fn inherent_jung_passthrough_methods_delegate_correctly() {
        let mut adapter = JungToGDirectedGraphAdapter::new(built_graph());

        assert_eq!(adapter.get_source(&edge(1, 2)), 1);
        assert_eq!(adapter.get_dest(&edge(1, 2)), 2);
        assert!(adapter.is_source(&1, &edge(1, 2)));
        assert!(adapter.is_dest(&2, &edge(1, 2)));
        assert!(!adapter.is_source(&2, &edge(1, 2)));

        assert_eq!(adapter.get_endpoints(&edge(1, 2)), (1, 2));
        assert_eq!(adapter.get_opposite(&1, &edge(1, 2)), 2);
        assert_eq!(adapter.get_opposite(&2, &edge(1, 2)), 1);

        assert!(adapter.is_incident(&1, &edge(1, 2)));
        assert!(!adapter.is_incident(&9, &edge(1, 2)));
        assert_eq!(adapter.get_incident_vertices(&edge(1, 2)), vec![1, 2]);

        assert_eq!(adapter.get_predecessor_count(&3), 2);
        assert_eq!(adapter.get_successor_count(&1), 2);
        assert!(adapter.is_predecessor(&1, &2));
        assert!(adapter.is_successor(&2, &3));

        assert_eq!(adapter.in_degree(&3), 2);
        assert_eq!(adapter.out_degree(&1), 2);
        assert_eq!(adapter.degree(&1), 2);

        assert_eq!(adapter.get_edge_type(&edge(1, 2)), EdgeType::Directed);
        assert_eq!(adapter.get_default_edge_type(), EdgeType::Directed);
        assert_eq!(adapter.get_edges_of_type(EdgeType::Directed).len(), 3);
        assert_eq!(adapter.get_edge_count_of_type(EdgeType::Directed), 3);
        assert!(adapter.get_edges_of_type(EdgeType::Undirected).is_empty());

        assert!(adapter.add_edge_with_endpoints(edge(3, 1), 3, 1));
        assert_eq!(adapter.get_edge_count(), 4);
    }

    #[test]
    fn get_neighbors_unions_predecessors_and_successors_without_duplicates() {
        let adapter = JungToGDirectedGraphAdapter::new(built_graph());
        // Vertex 2 has predecessor 1 and successor 3.
        let mut neighbors = adapter.get_neighbors(&2);
        neighbors.sort();
        assert_eq!(neighbors, vec![1, 3]);
        assert_eq!(adapter.get_neighbor_count(&2), 2);
        assert!(adapter.is_neighbor(&2, &1));
    }

    #[test]
    fn object_safety_as_g_directed_graph_trait_object() {
        let adapter = JungToGDirectedGraphAdapter::new(built_graph());
        let dyn_graph: &dyn GDirectedGraph<i32, Edge> = &adapter;
        assert_eq!(dyn_graph.get_vertex_count(), 3);
    }
}

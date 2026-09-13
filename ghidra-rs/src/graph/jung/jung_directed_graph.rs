//! Port of `ghidra.graph.jung.JungDirectedGraph`.

use crate::graph::g_directed_graph::GDirectedGraph;
use crate::graph::g_edge::GEdge;
use crate::graph::g_implicit_directed_graph::GImplicitDirectedGraph;

/// A concrete, explicitly-constructed directed graph.
///
/// Port of `ghidra.graph.jung.JungDirectedGraph`. Java's version `extends
/// DirectedSparseGraph<V, E>` (from the third-party JUNG graph library) purely for its storage --
/// every method this class actually implements is [`GDirectedGraph`]/[`GImplicitDirectedGraph`]
/// behavior. JUNG is not ported (and, being a third-party visualization library, is out of
/// scope), so following this crate's composition-over-inheritance convention, this port owns its
/// vertex/edge storage directly (`Vec<V>` / `Vec<E>`) rather than composing an unported base.
/// This mirrors the exact storage shape [`GDirectedGraph`]'s own doc-test `SimpleGraph` already
/// establishes as this trait's natural minimal backing.
pub struct JungDirectedGraph<V, E> {
    vertices: Vec<V>,
    edges: Vec<E>,
}

impl<V, E> JungDirectedGraph<V, E>
where
    V: Clone + PartialEq,
    E: GEdge<V> + Clone + PartialEq,
{
    /// Creates a new, empty `JungDirectedGraph`.
    pub fn new() -> Self {
        JungDirectedGraph { vertices: Vec::new(), edges: Vec::new() }
    }
}

impl<V, E> Default for JungDirectedGraph<V, E>
where
    V: Clone + PartialEq,
    E: GEdge<V> + Clone + PartialEq,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<V, E> GImplicitDirectedGraph<V, E> for JungDirectedGraph<V, E>
where
    V: Clone + PartialEq + 'static,
    E: GEdge<V> + Clone + PartialEq + 'static,
{
    fn get_in_edges(&self, v: &V) -> Vec<E> {
        self.edges.iter().filter(|e| e.get_end() == v).cloned().collect()
    }

    fn get_out_edges(&self, v: &V) -> Vec<E> {
        self.edges.iter().filter(|e| e.get_start() == v).cloned().collect()
    }

    /// Port of `JungDirectedGraph.copy()`. Java iterates its own (inherited, JUNG-managed)
    /// `vertices`/`edges` fields directly; this port iterates the equivalent own-storage fields.
    fn copy(&self) -> Box<dyn GDirectedGraph<V, E>> {
        let mut new_graph = JungDirectedGraph::new();
        for v in &self.vertices {
            new_graph.add_vertex(v.clone());
        }
        for e in &self.edges {
            GDirectedGraph::add_edge(&mut new_graph, e.clone());
        }
        Box::new(new_graph)
    }
}

impl<V, E> GDirectedGraph<V, E> for JungDirectedGraph<V, E>
where
    V: Clone + PartialEq + 'static,
    E: GEdge<V> + Clone + PartialEq + 'static,
{
    fn add_vertex(&mut self, v: V) -> bool {
        if self.vertices.contains(&v) {
            return false;
        }
        self.vertices.push(v);
        true
    }

    /// Port of `JungDirectedGraph.removeVertices(Iterable<V>)`, which JUNG's `removeVertex` (via
    /// the inherited `super.removeVertex(v)`) also drops incident edges for -- reproduced here by
    /// discarding any edge touching `v` alongside the vertex itself.
    fn remove_vertex(&mut self, v: &V) -> bool {
        let before = self.vertices.len();
        self.vertices.retain(|x| x != v);
        self.edges.retain(|e| e.get_start() != v && e.get_end() != v);
        self.vertices.len() != before
    }

    /// Port of `JungDirectedGraph.addEdge(E)`, which delegates to
    /// `super.addEdge(e, e.getStart(), e.getEnd())` -- JUNG's `addEdge(edge, v1, v2)` implicitly
    /// registers `v1`/`v2` as vertices if they aren't already present, reproduced here directly.
    fn add_edge(&mut self, e: E) {
        let start = e.get_start().clone();
        let end = e.get_end().clone();
        if !self.vertices.contains(&start) {
            self.vertices.push(start);
        }
        if !self.vertices.contains(&end) {
            self.vertices.push(end);
        }
        self.edges.push(e);
    }

    fn remove_edge(&mut self, e: &E) -> bool {
        let before = self.edges.len();
        self.edges.retain(|x| x != e);
        self.edges.len() != before
    }

    fn find_edge(&self, start: &V, end: &V) -> Option<E> {
        self.edges.iter().find(|e| e.get_start() == start && e.get_end() == end).cloned()
    }

    fn get_vertices(&self) -> Vec<V> {
        self.vertices.clone()
    }

    fn get_edges(&self) -> Vec<E> {
        self.edges.clone()
    }

    fn contains_vertex(&self, v: &V) -> bool {
        self.vertices.contains(v)
    }

    fn contains_edge(&self, e: &E) -> bool {
        self.edges.contains(e)
    }

    /// Port of `JungDirectedGraph.containsEdge(V, V)`.
    fn contains_edge_between(&self, from: &V, to: &V) -> bool {
        self.find_edge(from, to).is_some()
    }

    /// Port of `JungDirectedGraph.isEmpty()`. Faithfully mirrors the Java quirk that this checks
    /// *only* the vertex count (`getVertexCount() == 0`), never the edge count -- harmless in
    /// practice since [`add_edge`](Self::add_edge) always registers its endpoints as vertices
    /// too, so a non-empty edge set can never coexist with an empty vertex set.
    fn is_empty(&self) -> bool {
        self.get_vertex_count() == 0
    }

    fn get_vertex_count(&self) -> usize {
        self.vertices.len()
    }

    fn get_edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Port of `JungDirectedGraph.emptyCopy()`.
    fn empty_copy(&self) -> Box<dyn GDirectedGraph<V, E>> {
        Box::new(JungDirectedGraph::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn new_graph_is_empty() {
        let g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        assert!(g.is_empty());
        assert_eq!(g.get_vertex_count(), 0);
        assert_eq!(g.get_edge_count(), 0);
    }

    #[test]
    fn add_vertex_rejects_duplicates() {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        assert!(g.add_vertex(1));
        assert!(!g.add_vertex(1));
        assert_eq!(g.get_vertex_count(), 1);
    }

    #[test]
    fn add_edge_auto_registers_endpoint_vertices() {
        // Mirrors the Java `addEdge` override delegating to JUNG's
        // `addEdge(e, e.getStart(), e.getEnd())`, which implicitly adds missing endpoints.
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2));

        assert_eq!(g.get_vertex_count(), 2);
        assert!(g.contains_vertex(&1));
        assert!(g.contains_vertex(&2));
        assert_eq!(g.get_edge_count(), 1);
    }

    #[test]
    fn remove_vertex_cascades_to_incident_edges() {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2));
        GDirectedGraph::add_edge(&mut g, edge(2, 3));

        assert!(g.remove_vertex(&2));

        assert_eq!(g.get_vertex_count(), 2);
        assert_eq!(g.get_edge_count(), 0);
        assert!(g.contains_vertex(&1));
        assert!(g.contains_vertex(&3));
    }

    #[test]
    fn contains_edge_between_uses_find_edge() {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2));

        assert!(g.contains_edge_between(&1, &2));
        assert!(!g.contains_edge_between(&2, &1));
    }

    #[test]
    fn find_edge_locates_by_endpoints() {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2));
        GDirectedGraph::add_edge(&mut g, edge(1, 3));

        assert_eq!(g.find_edge(&1, &2), Some(edge(1, 2)));
        assert_eq!(g.find_edge(&1, &3), Some(edge(1, 3)));
        assert_eq!(g.find_edge(&2, &1), None);
    }

    #[test]
    fn is_empty_checks_vertex_count_only() {
        // Faithful to the Java quirk: isEmpty() delegates to getVertexCount() == 0. A lone
        // vertex with no edges still makes the graph non-empty.
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        g.add_vertex(1);
        assert!(!g.is_empty());
        assert_eq!(g.get_edge_count(), 0);
    }

    #[test]
    fn copy_duplicates_vertices_and_edges_independently() {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2));
        GDirectedGraph::add_edge(&mut g, edge(2, 3));

        let copy = GImplicitDirectedGraph::copy(&g);
        assert_eq!(copy.get_vertex_count(), 3);
        assert_eq!(copy.get_edge_count(), 2);
        assert!(copy.contains_edge_between(&1, &2));
        assert!(copy.contains_edge_between(&2, &3));
    }

    #[test]
    fn empty_copy_yields_truly_empty_graph() {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2));

        let empty = g.empty_copy();
        assert!(empty.is_empty());
        assert_eq!(empty.get_edge_count(), 0);
    }

    #[test]
    fn remove_edge_leaves_vertices_intact() {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2));

        assert!(g.remove_edge(&edge(1, 2)));
        assert!(!g.remove_edge(&edge(1, 2)));
        assert_eq!(g.get_edge_count(), 0);
        assert_eq!(g.get_vertex_count(), 2);
    }

    #[test]
    fn default_matches_new() {
        let g: JungDirectedGraph<i32, Edge> = Default::default();
        assert!(g.is_empty());
    }

    #[test]
    fn object_safety_as_trait_objects() {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2));

        let dyn_graph: &dyn GDirectedGraph<i32, Edge> = &g;
        assert_eq!(dyn_graph.get_vertex_count(), 2);

        let dyn_implicit: &dyn GImplicitDirectedGraph<i32, Edge> = &g;
        assert_eq!(dyn_implicit.get_successors(&1), vec![2]);
    }
}

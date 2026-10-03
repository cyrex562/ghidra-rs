use super::g_edge::GEdge;
use super::g_implicit_directed_graph::GImplicitDirectedGraph;

/// A directed graph.
///
/// Unlike [`GImplicitDirectedGraph`], this graph is constructed explicitly in memory. Edges and
/// vertices are added and removed like any other collection, and these elements represent the
/// entirety of the graph at any given time.
pub trait GDirectedGraph<V: Clone + PartialEq, E: GEdge<V> + Clone + PartialEq>:
    GImplicitDirectedGraph<V, E>
{
    /// Adds a vertex. Returns `true` if the add was successful, `false` otherwise.
    fn add_vertex(&mut self, v: V) -> bool;

    /// Removes a vertex. Returns `true` if the vertex was present.
    fn remove_vertex(&mut self, v: &V) -> bool;

    /// Removes the given vertices from the graph.
    fn remove_vertices(&mut self, vertices: &[V]) {
        for v in vertices {
            self.remove_vertex(v);
        }
    }

    /// Adds an edge.
    fn add_edge(&mut self, e: E);

    /// Removes an edge. Returns `true` if the graph contained the given edge.
    fn remove_edge(&mut self, e: &E) -> bool;

    /// Removes the given edges from the graph.
    fn remove_edges(&mut self, edges: &[E]) {
        for e in edges {
            self.remove_edge(e);
        }
    }

    /// Locates the edge object for the two vertices.
    fn find_edge(&self, start: &V, end: &V) -> Option<E>;

    /// Retrieves all the vertices.
    fn get_vertices(&self) -> Vec<V>;

    /// Retrieves all the edges.
    fn get_edges(&self) -> Vec<E>;

    /// Tests if the graph contains a given vertex.
    fn contains_vertex(&self, v: &V) -> bool;

    /// Tests if the graph contains a given edge.
    fn contains_edge(&self, e: &E) -> bool;

    /// Tests if the graph contains an edge from one given vertex to another.
    fn contains_edge_between(&self, from: &V, to: &V) -> bool;

    /// Tests if the graph is empty, i.e., contains no vertices or edges.
    fn is_empty(&self) -> bool;

    /// Counts the number of vertices in the graph.
    fn get_vertex_count(&self) -> usize;

    /// Counts the number of edges in the graph.
    fn get_edge_count(&self) -> usize;

    /// Returns all edges connected to the given vertex.
    ///
    /// The default implementation combines the in-edges and out-edges, deduplicated.
    fn get_incident_edges(&self, v: &V) -> Vec<E> {
        let mut result = self.get_in_edges(v);
        for e in self.get_out_edges(v) {
            if !result.contains(&e) {
                result.push(e);
            }
        }
        result
    }

    /// Creates a new instance of this graph with no vertices or edges. This is useful when you
    /// wish to build a new graph using the same type as this graph.
    fn empty_copy(&self) -> Box<dyn GDirectedGraph<V, E>>;
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

    #[derive(Default, Clone)]
    struct SimpleGraph {
        vertices: Vec<i32>,
        edges: Vec<Edge>,
    }

    impl GImplicitDirectedGraph<i32, Edge> for SimpleGraph {
        fn get_in_edges(&self, v: &i32) -> Vec<Edge> {
            self.edges.iter().filter(|e| &e.end == v).cloned().collect()
        }

        fn get_out_edges(&self, v: &i32) -> Vec<Edge> {
            self.edges.iter().filter(|e| &e.start == v).cloned().collect()
        }

        fn copy(&self) -> Box<dyn GDirectedGraph<i32, Edge>> {
            Box::new(self.clone())
        }
    }

    impl GDirectedGraph<i32, Edge> for SimpleGraph {
        fn add_vertex(&mut self, v: i32) -> bool {
            if self.vertices.contains(&v) {
                return false;
            }
            self.vertices.push(v);
            true
        }

        fn remove_vertex(&mut self, v: &i32) -> bool {
            let before = self.vertices.len();
            self.vertices.retain(|x| x != v);
            self.edges.retain(|e| &e.start != v && &e.end != v);
            self.vertices.len() != before
        }

        fn add_edge(&mut self, e: Edge) {
            if !self.vertices.contains(&e.start) {
                self.vertices.push(e.start);
            }
            if !self.vertices.contains(&e.end) {
                self.vertices.push(e.end);
            }
            self.edges.push(e);
        }

        fn remove_edge(&mut self, e: &Edge) -> bool {
            let before = self.edges.len();
            self.edges.retain(|x| x != e);
            self.edges.len() != before
        }

        fn find_edge(&self, start: &i32, end: &i32) -> Option<Edge> {
            self.edges.iter().find(|e| &e.start == start && &e.end == end).cloned()
        }

        fn get_vertices(&self) -> Vec<i32> {
            self.vertices.clone()
        }

        fn get_edges(&self) -> Vec<Edge> {
            self.edges.clone()
        }

        fn contains_vertex(&self, v: &i32) -> bool {
            self.vertices.contains(v)
        }

        fn contains_edge(&self, e: &Edge) -> bool {
            self.edges.contains(e)
        }

        fn contains_edge_between(&self, from: &i32, to: &i32) -> bool {
            self.edges.iter().any(|e| &e.start == from && &e.end == to)
        }

        fn is_empty(&self) -> bool {
            self.vertices.is_empty() && self.edges.is_empty()
        }

        fn get_vertex_count(&self) -> usize {
            self.vertices.len()
        }

        fn get_edge_count(&self) -> usize {
            self.edges.len()
        }

        fn empty_copy(&self) -> Box<dyn GDirectedGraph<i32, Edge>> {
            Box::new(SimpleGraph::default())
        }
    }

    fn build_graph() -> SimpleGraph {
        let mut g = SimpleGraph::default();
        g.add_edge(Edge { start: 1, end: 2 });
        g.add_edge(Edge { start: 1, end: 3 });
        g.add_edge(Edge { start: 2, end: 3 });
        g
    }

    #[test]
    fn test_add_and_contains_vertex() {
        let mut g = SimpleGraph::default();
        assert!(g.add_vertex(1));
        assert!(!g.add_vertex(1));
        assert!(g.contains_vertex(&1));
        assert!(!g.contains_vertex(&2));
    }

    #[test]
    fn test_add_edge_registers_vertices() {
        let g = build_graph();
        assert_eq!(g.get_vertex_count(), 3);
        assert_eq!(g.get_edge_count(), 3);
        assert!(g.contains_edge_between(&1, &2));
        assert!(!g.contains_edge_between(&2, &1));
    }

    #[test]
    fn test_find_edge() {
        let g = build_graph();
        assert_eq!(g.find_edge(&1, &2), Some(Edge { start: 1, end: 2 }));
        assert_eq!(g.find_edge(&2, &1), None);
    }

    #[test]
    fn test_remove_vertex_drops_incident_edges() {
        let mut g = build_graph();
        assert!(g.remove_vertex(&1));
        assert_eq!(g.get_vertex_count(), 2);
        assert_eq!(g.get_edges(), vec![Edge { start: 2, end: 3 }]);
    }

    #[test]
    fn test_remove_vertices_bulk() {
        let mut g = build_graph();
        g.remove_vertices(&[1, 2]);
        assert_eq!(g.get_vertex_count(), 1);
        assert!(g.is_empty() == false);
        assert!(g.get_edges().is_empty());
    }

    #[test]
    fn test_remove_edge_and_remove_edges() {
        let mut g = build_graph();
        assert!(g.remove_edge(&Edge { start: 1, end: 2 }));
        assert!(!g.remove_edge(&Edge { start: 1, end: 2 }));
        g.remove_edges(&[Edge { start: 1, end: 3 }, Edge { start: 2, end: 3 }]);
        assert_eq!(g.get_edge_count(), 0);
    }

    #[test]
    fn test_is_empty() {
        let g = SimpleGraph::default();
        assert!(g.is_empty());
        let g2 = build_graph();
        assert!(!g2.is_empty());
    }

    #[test]
    fn test_get_incident_edges_combines_in_and_out() {
        let g = build_graph();
        let incident = g.get_incident_edges(&1);
        assert_eq!(incident.len(), 2);
        assert!(incident.contains(&Edge { start: 1, end: 2 }));
        assert!(incident.contains(&Edge { start: 1, end: 3 }));
    }

    #[test]
    fn test_default_predecessors_and_successors_from_supertrait() {
        let g = build_graph();
        assert_eq!(g.get_successors(&1), vec![2, 3]);
        assert_eq!(g.get_predecessors(&3), vec![1, 2]);
    }

    #[test]
    fn test_empty_copy_yields_empty_graph_of_same_type() {
        let g = build_graph();
        let empty = g.empty_copy();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_copy_produces_dyn_directed_graph() {
        let g = build_graph();
        let copy: Box<dyn GDirectedGraph<i32, Edge>> = GImplicitDirectedGraph::copy(&g);
        assert_eq!(copy.get_edge_count(), 3);
    }

    #[test]
    fn test_object_safety_as_trait_object() {
        let g = build_graph();
        let dyn_graph: &dyn GDirectedGraph<i32, Edge> = &g;
        assert_eq!(dyn_graph.get_vertex_count(), 3);
    }
}

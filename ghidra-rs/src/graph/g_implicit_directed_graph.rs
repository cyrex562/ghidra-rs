use super::g_edge::GEdge;
use super::seam_stubs::GDirectedGraph;

/// A directed graph that need not be constructed explicitly.
///
/// Instead, the graph is constructed (and usually cached) as it is explored. For instance, if
/// a path searching algorithm is being applied, incident edges and neighboring nodes need not
/// be computed if they're never visited. This allows conceptually large (even infinite) graphs
/// to be represented. A graph algorithm can be applied so long as it supports this trait, and
/// does not attempt to exhaust an infinite graph.
pub trait GImplicitDirectedGraph<V: Clone + PartialEq, E: GEdge<V>> {
    /// Computes the incident edges that end at the given vertex.
    ///
    /// (Optional operation)
    ///
    /// This ought to return cached results if available. As part of computing in-edges, this
    /// also provides predecessors.
    fn get_in_edges(&self, v: &V) -> Vec<E>;

    /// Computes the incident edges that start at the given vertex.
    ///
    /// This ought to return cached results if available. As part of computing out-edges, this
    /// also provides successors.
    fn get_out_edges(&self, v: &V) -> Vec<E>;

    /// Computes a vertex's predecessors.
    ///
    /// The default implementation computes this from the in-edges. If a non-default
    /// implementation is provided, it ought to return cached results if available.
    fn get_predecessors(&self, v: &V) -> Vec<V> {
        let mut result: Vec<V> = Vec::new();
        for edge in self.get_in_edges(v) {
            let start = edge.get_start().clone();
            if !result.contains(&start) {
                result.push(start);
            }
        }
        result
    }

    /// Computes a vertex's successors.
    ///
    /// The default implementation computes this from the out-edges. If a non-default
    /// implementation is provided, it ought to return cached results if available.
    fn get_successors(&self, v: &V) -> Vec<V> {
        let mut result: Vec<V> = Vec::new();
        for edge in self.get_out_edges(v) {
            let end = edge.get_end().clone();
            if !result.contains(&end) {
                result.push(end);
            }
        }
        result
    }

    /// Copies some portion of the implicit graph to an explicit graph.
    ///
    /// Usually, this returns the cached (explored) portion of the graph.
    fn copy(&self) -> Box<dyn GDirectedGraph<V, E>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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

    struct ExplicitCopy {
        edges: Vec<Edge>,
    }

    impl GDirectedGraph<i32, Edge> for ExplicitCopy {}

    /// A tiny implicit graph over a fixed adjacency map, computed lazily on demand.
    struct MockGraph {
        out: HashMap<i32, Vec<Edge>>,
        in_: HashMap<i32, Vec<Edge>>,
    }

    impl GImplicitDirectedGraph<i32, Edge> for MockGraph {
        fn get_in_edges(&self, v: &i32) -> Vec<Edge> {
            self.in_.get(v).cloned().unwrap_or_default()
        }

        fn get_out_edges(&self, v: &i32) -> Vec<Edge> {
            self.out.get(v).cloned().unwrap_or_default()
        }

        fn copy(&self) -> Box<dyn GDirectedGraph<i32, Edge>> {
            let edges = self.out.values().flatten().cloned().collect();
            Box::new(ExplicitCopy { edges })
        }
    }

    fn build_graph() -> MockGraph {
        // 1 -> 2, 1 -> 3, 2 -> 3
        let e12 = Edge { start: 1, end: 2 };
        let e13 = Edge { start: 1, end: 3 };
        let e23 = Edge { start: 2, end: 3 };

        let mut out = HashMap::new();
        out.insert(1, vec![e12.clone(), e13.clone()]);
        out.insert(2, vec![e23.clone()]);

        let mut in_ = HashMap::new();
        in_.insert(2, vec![e12]);
        in_.insert(3, vec![e13, e23]);

        MockGraph { out, in_ }
    }

    #[test]
    fn test_get_out_edges() {
        let graph = build_graph();
        let edges = graph.get_out_edges(&1);
        assert_eq!(edges.len(), 2);
        assert!(edges.contains(&Edge { start: 1, end: 2 }));
        assert!(edges.contains(&Edge { start: 1, end: 3 }));
    }

    #[test]
    fn test_get_in_edges() {
        let graph = build_graph();
        let edges = graph.get_in_edges(&3);
        assert_eq!(edges.len(), 2);
        assert!(edges.contains(&Edge { start: 1, end: 3 }));
        assert!(edges.contains(&Edge { start: 2, end: 3 }));
    }

    #[test]
    fn test_default_successors_dedups_and_preserves_order() {
        let graph = build_graph();
        assert_eq!(graph.get_successors(&1), vec![2, 3]);
    }

    #[test]
    fn test_default_predecessors() {
        let graph = build_graph();
        assert_eq!(graph.get_predecessors(&3), vec![1, 2]);
    }

    #[test]
    fn test_no_edges_yields_empty() {
        let graph = build_graph();
        assert!(graph.get_successors(&3).is_empty());
        assert!(graph.get_predecessors(&1).is_empty());
    }

    #[test]
    fn test_copy_produces_dyn_explicit_graph() {
        let graph = build_graph();
        let copy: Box<dyn GDirectedGraph<i32, Edge>> = graph.copy();
        // Object-safety smoke check: the trait object can be constructed and moved around.
        let _kept: Box<dyn GDirectedGraph<i32, Edge>> = copy;
    }

    #[test]
    fn test_object_safety_as_trait_object() {
        let graph = build_graph();
        let dyn_graph: &dyn GImplicitDirectedGraph<i32, Edge> = &graph;
        assert_eq!(dyn_graph.get_successors(&1), vec![2, 3]);
    }
}

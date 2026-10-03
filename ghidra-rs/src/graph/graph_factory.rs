//! Port of `ghidra.graph.GraphFactory`.

use crate::graph::g_directed_graph::GDirectedGraph;
use crate::graph::g_edge::GEdge;
use crate::graph::jung::jung_directed_graph::JungDirectedGraph;

/// Creates a new, empty directed graph.
///
/// Port of `ghidra.graph.GraphFactory.createDirectedGraph()`. Java is a utility class with a
/// private constructor (`private GraphFactory() { // can't create this; }`) holding a single
/// static factory method; ported as a free function rather than a zero-sized "namespace" struct,
/// since there is no instance state and no other members to group it with.
///
/// The concrete graph handed back is a [`JungDirectedGraph`] (mirroring Java's `new
/// JungDirectedGraph<V, E>()`), but boxed behind the [`GDirectedGraph`] trait object, matching
/// Java's declared return type of the `GDirectedGraph<V, E>` interface rather than the concrete
/// implementation -- callers should not depend on the concrete type.
pub fn create_directed_graph<V, E>() -> Box<dyn GDirectedGraph<V, E>>
where
    V: Clone + PartialEq + 'static,
    E: GEdge<V> + Clone + PartialEq + 'static,
{
    Box::new(JungDirectedGraph::new())
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

    #[test]
    fn creates_empty_directed_graph() {
        let graph = create_directed_graph::<i32, Edge>();
        assert!(graph.is_empty());
        assert_eq!(graph.get_vertex_count(), 0);
        assert_eq!(graph.get_edge_count(), 0);
    }

    #[test]
    fn each_call_creates_an_independent_graph() {
        let mut a = create_directed_graph::<i32, Edge>();
        let b = create_directed_graph::<i32, Edge>();

        a.add_vertex(1);
        assert_eq!(a.get_vertex_count(), 1);
        assert_eq!(b.get_vertex_count(), 0, "a fresh graph per call, not a shared singleton");
    }

    #[test]
    fn returned_graph_behaves_like_a_full_gdirectedgraph() {
        let mut graph = create_directed_graph::<i32, Edge>();
        graph.add_edge(Edge { start: 1, end: 2 });

        assert_eq!(graph.get_vertex_count(), 2);
        assert_eq!(graph.get_edge_count(), 1);
        assert!(graph.contains_edge_between(&1, &2));
    }
}

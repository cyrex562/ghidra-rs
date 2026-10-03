use std::hash::Hash;

use crate::util::graph::directed_graph::DirectedGraph;
use crate::util::graph::edge::Edge;
use crate::util::graph::vertex::Vertex;

/// Provides a depth first search service to directed graphs. Once a search has finished,
/// information about the search can be obtained.
///
/// Port of `ghidra.util.graph.DepthFirstSearch` (deprecated since Ghidra 10.2), cut to a trait to
/// break a dependency cycle at this node in the port graph. The Java class performs the entire
/// search inside its constructor (over `DirectedGraph`/`Vertex`/`Edge`, all already ported as
/// traits) and exposes only query methods on the finished result; that constructor-time traversal
/// (the `pending` stack of mixed `Vertex`/`Edge` `KeyedObject`s, the `unseen`/`finished`
/// bookkeeping, and the three `goForward`/`goBackward` traversal variants) is therefore an
/// implementation detail of *how* an implementer computes the fields below, not part of the
/// public surface described here. `seedsUsed()`, package-private in Java, is included since Rust
/// trait methods have no package-private equivalent.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
#[allow(deprecated)]
pub trait DepthFirstSearch<V: Vertex + Eq + Hash, E: Edge + Eq + Hash> {
    /// Returns true if the vertex has not yet been discovered in the depth first search.
    fn is_unseen(&self, v: &V) -> bool;

    /// Returns true if the vertex has completed its role in the depth first search.
    fn is_completed(&self, v: &V) -> bool;

    /// Returns the back edges found in this depth first search.
    fn back_edges(&self) -> Vec<&E>;

    /// Returns the tree edges found in this depth first search.
    fn tree_edges(&self) -> Vec<&E>;

    /// Returns a topological sort of the directed graph: the vertices in the explored portion of
    /// the graph such that, if the graph is acyclic, `v[i] -> v[j] => i < j`; if the graph
    /// contains cycles, the same holds except when `(v[i], v[j])` is a back edge.
    fn topological_sort(&self) -> Vec<&V>;

    /// Returns the seeds used in the depth first search.
    fn seeds_used(&self) -> Vec<&V>;

    /// Returns true iff every edge in the searched graph is a tree edge. Will always be false if
    /// the entire graph is not explored.
    ///
    /// Unlike [`is_acyclic`](DepthFirstSearch::is_acyclic), this cannot be derived from
    /// [`tree_edges`](DepthFirstSearch::tree_edges) alone: the Java method also compares against
    /// `graph.numEdges()`, so implementers must retain that count (or the graph itself) to
    /// answer this.
    fn is_tree(&self) -> bool;

    /// Returns a spanning tree of the searched graph, made up of this search's tree edges. No
    /// claims are made about any special properties of the spanning tree returned.
    fn spanning_tree(&self) -> Box<dyn DirectedGraph<V, E>>;

    /// Returns true iff no back edges were found.
    ///
    /// Note that if the graph is not completely explored, the answer is only for the portion of
    /// the graph explored.
    fn is_acyclic(&self) -> bool {
        self.back_edges().is_empty()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::util::graph::keyed_object::KeyedObject;
    use std::collections::HashSet;
    use std::hash::Hasher;

    #[derive(Clone)]
    struct MockVertex {
        key: i64,
    }

    impl KeyedObject for MockVertex {
        fn key(&self) -> i64 {
            self.key
        }
    }

    impl Vertex for MockVertex {
        fn referent(&self) -> Option<&dyn std::fmt::Display> {
            None
        }
    }

    impl PartialEq for MockVertex {
        fn eq(&self, other: &Self) -> bool {
            self.key == other.key
        }
    }

    impl Eq for MockVertex {}

    impl Hash for MockVertex {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.key.hash(state);
        }
    }

    #[derive(Clone)]
    struct MockEdge {
        key: i64,
        from: MockVertex,
        to: MockVertex,
    }

    impl KeyedObject for MockEdge {
        fn key(&self) -> i64 {
            self.key
        }
    }

    impl Edge for MockEdge {
        fn from(&self) -> &dyn Vertex {
            &self.from
        }

        fn to(&self) -> &dyn Vertex {
            &self.to
        }
    }

    impl PartialEq for MockEdge {
        fn eq(&self, other: &Self) -> bool {
            self.key == other.key
        }
    }

    impl Eq for MockEdge {}

    impl Hash for MockEdge {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.key.hash(state);
        }
    }

    /// A trivial finished-search result over two vertices joined by one tree edge, proving the
    /// trait is object-safe and its accessors behave as expected.
    struct MockSearch {
        seeds_used: Vec<MockVertex>,
        finished: HashSet<i64>,
        tree_edges: Vec<MockEdge>,
        back_edges: Vec<MockEdge>,
        order: Vec<MockVertex>,
        total_edges: usize,
    }

    impl DepthFirstSearch<MockVertex, MockEdge> for MockSearch {
        fn is_unseen(&self, v: &MockVertex) -> bool {
            !self.finished.contains(&v.key)
        }

        fn is_completed(&self, v: &MockVertex) -> bool {
            self.finished.contains(&v.key)
        }

        fn back_edges(&self) -> Vec<&MockEdge> {
            self.back_edges.iter().collect()
        }

        fn tree_edges(&self) -> Vec<&MockEdge> {
            self.tree_edges.iter().collect()
        }

        fn topological_sort(&self) -> Vec<&MockVertex> {
            self.order.iter().collect()
        }

        fn seeds_used(&self) -> Vec<&MockVertex> {
            self.seeds_used.iter().collect()
        }

        fn is_tree(&self) -> bool {
            self.tree_edges.len() == self.total_edges
        }

        fn spanning_tree(&self) -> Box<dyn DirectedGraph<MockVertex, MockEdge>> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let v1 = MockVertex { key: 1 };
        let v2 = MockVertex { key: 2 };
        let e = MockEdge { key: 100, from: v1.clone(), to: v2.clone() };

        let mut finished = HashSet::new();
        finished.insert(v1.key);
        finished.insert(v2.key);

        let search: Box<dyn DepthFirstSearch<MockVertex, MockEdge>> = Box::new(MockSearch {
            seeds_used: vec![v1.clone()],
            finished,
            tree_edges: vec![e.clone()],
            back_edges: Vec::new(),
            order: vec![v2.clone(), v1.clone()],
            total_edges: 1,
        });

        assert!(!search.is_unseen(&v1));
        assert!(search.is_completed(&v2));
        assert_eq!(search.back_edges().len(), 0);
        assert_eq!(search.tree_edges().len(), 1);
        assert!(search.is_acyclic());
        assert!(search.is_tree());
        assert_eq!(search.seeds_used().len(), 1);

        let order = search.topological_sort();
        assert_eq!(order[0].key(), 2);
        assert_eq!(order[1].key(), 1);
    }
}

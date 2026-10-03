//! Port of `ghidra.graph.GraphToTreeAlgorithm`.
//!
//! This provides an algorithm for topological graph sorting and an algorithm for using that
//! topological sort to create a tree structure from the graph.
//!
//! In general topological sorting and converting to a tree require an acyclic graph. However, by
//! supplying a root vertex, the graph can be made acyclic by traversing the graph from that root
//! and discarding any edges that return to an already-visited vertex. This has a side effect of
//! ignoring any vertices that are not reachable from the root vertex. Also, this algorithm is
//! constructed with an edge comparator which can also determine the order vertices are
//! traversed, thereby affecting the final ordering/tree structure: higher-priority edges are
//! processed first, making those edges least likely to be removed as "back" edges.
//!
//! ## Composition, not inheritance
//!
//! Java holds `graph` as the `GDirectedGraph<V, E>` interface type (any concrete implementation
//! the caller supplies) and `edgeComparator` as a `Comparator<E>`. This port borrows both rather
//! than owning them (`&'a dyn GDirectedGraph<V, E>` / `&'a dyn Fn(&E, &E) -> Ordering`), matching
//! this crate's "trait seam, not a pervasive concrete type" convention -- the algorithm operates
//! on *any* graph implementing [`GDirectedGraph`], exactly like the Java interface-typed field.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use crate::graph::g_directed_graph::GDirectedGraph;
use crate::graph::g_edge::GEdge;
use crate::graph::jung::jung_directed_graph::JungDirectedGraph;

/// Tracks the longest-path distance from the root of the tree. Port of the private nested
/// `GraphToTreeAlgorithm.Depth` class.
#[derive(Default, Clone, Copy)]
struct Depth {
    depth: i64,
}

impl Depth {
    fn new() -> Self {
        Depth { depth: 0 }
    }

    /// Port of `Depth.adjustDepth(Depth)`.
    fn adjust_depth(&mut self, parent_depth: i64) {
        self.depth = self.depth.max(parent_depth + 1);
    }

    /// Port of `Depth.isDirectChildOf(Depth)`.
    fn is_direct_child_of(&self, parent_depth: i64) -> bool {
        self.depth == parent_depth + 1
    }
}

/// Port of `ghidra.graph.GraphToTreeAlgorithm`. See the module docs for the composition
/// strategy.
pub struct GraphToTreeAlgorithm<'a, V, E> {
    graph: &'a dyn GDirectedGraph<V, E>,
    edge_comparator: &'a dyn Fn(&E, &E) -> Ordering,
}

impl<'a, V, E> GraphToTreeAlgorithm<'a, V, E>
where
    V: Clone + PartialEq + Eq + Hash + 'static,
    E: GEdge<V> + Clone + PartialEq + 'static,
{
    /// Port of `GraphToTreeAlgorithm(GDirectedGraph<V, E>, Comparator<E>)`.
    ///
    /// `edge_comparator` provides a priority ordering of edges, with higher-priority edges
    /// getting first shot at claiming children for its sub-tree.
    pub fn new(
        graph: &'a dyn GDirectedGraph<V, E>,
        edge_comparator: &'a dyn Fn(&E, &E) -> Ordering,
    ) -> Self {
        Self { graph, edge_comparator }
    }

    /// Creates a tree graph with the given vertex as the root from this object's graph. Port of
    /// `GraphToTreeAlgorithm.toTree(V)`.
    pub fn to_tree(&self, root: V) -> JungDirectedGraph<V, E> {
        // First sort the vertices topologically.
        let sorted = self.topolocigal_sort(root.clone());

        // Visit vertices in the sorted order and track the longest path to each vertex from the
        // root.
        let depth_map = self.assign_depths(&root, &sorted);

        // Assign vertices to the tree in the sorted order, and only using edges where the "from"
        // vertex (parent) is at a depth one less than the depth of the "to" vertex. This ensures
        // that the tree is ordered such that if all the original forward edges are added back
        // in, they would always flow down the tree.
        self.create_tree(&root, &sorted, &depth_map)
    }

    /// Sorts the vertices in this graph topologically. Returns a list of vertices reachable from
    /// `root`, sorted topologically, with `root` always first.
    ///
    /// Port of `GraphToTreeAlgorithm.topolocigalSort(V)`. Named (and misspelled, "topolocigal"
    /// rather than "topological") to match the real Java method name verbatim -- a genuine typo
    /// in the upstream public API, faithfully preserved rather than silently corrected.
    pub fn topolocigal_sort(&self, root: V) -> Vec<V> {
        struct Frame<V, E> {
            parent: V,
            /// Out-edges of `parent`, ascending by `edge_comparator`. Consumed back-to-front
            /// (highest priority first), mirroring Java's `outEdges.reversed().iterator()` over
            /// the same ascending sort.
            children: Vec<E>,
            /// Number of not-yet-consumed elements at the front of `children` (i.e. the next
            /// element to yield is `children[remaining - 1]`).
            remaining: usize,
        }

        let mut visited: HashSet<V> = HashSet::new();
        let mut ordered: Vec<V> = Vec::new();
        let mut stack: Vec<Frame<V, E>> = Vec::new();

        let make_frame = |parent: V| -> Frame<V, E> {
            let mut out_edges = self.graph.get_out_edges(&parent);
            out_edges.sort_by(|a, b| (self.edge_comparator)(a, b));
            let remaining = out_edges.len();
            Frame { parent, children: out_edges, remaining }
        };

        stack.push(make_frame(root.clone()));
        visited.insert(root);

        // Indexed access throughout (rather than holding a `&mut Frame` from `stack.last_mut()`
        // across the loop body) since a new frame may need to be pushed onto `stack` -- which a
        // live mutable borrow of an existing element would forbid.
        while !stack.is_empty() {
            let top = stack.len() - 1;
            if stack[top].remaining > 0 {
                stack[top].remaining -= 1;
                let next_idx = stack[top].remaining;
                let child = stack[top].children[next_idx].get_end().clone();

                // Only process the child if never seen before; otherwise it is a loop back.
                if !visited.contains(&child) {
                    visited.insert(child.clone());
                    stack.push(make_frame(child));
                }
            } else {
                let frame = stack.pop().unwrap();
                ordered.push(frame.parent);
            }
        }
        ordered.reverse();
        ordered
    }

    fn create_tree(
        &self,
        root: &V,
        sorted: &[V],
        depth_map: &HashMap<V, Depth>,
    ) -> JungDirectedGraph<V, E> {
        let mut visited: HashSet<V> = HashSet::new();
        visited.insert(root.clone());

        let mut tree: JungDirectedGraph<V, E> = JungDirectedGraph::new();
        for v in sorted {
            GDirectedGraph::add_vertex(&mut tree, v.clone());
        }

        for parent in sorted {
            let parent_depth = depth_map.get(parent).map(|d| d.depth).unwrap_or(0);
            let out_edges = self.graph.get_out_edges(parent);
            for e in out_edges {
                let child = e.get_end().clone();
                if visited.contains(&child) {
                    continue; // already assigned
                }
                let child_depth = depth_map.get(&child).copied().unwrap_or_else(Depth::new);
                if child_depth.is_direct_child_of(parent_depth) {
                    GDirectedGraph::add_edge(&mut tree, e);
                    visited.insert(child);
                }
            }
        }
        tree
    }

    fn assign_depths(&self, root: &V, sorted: &[V]) -> HashMap<V, Depth> {
        let mut visited: HashSet<V> = HashSet::new();
        // Port of Java's `LazyMap.lazyMap(new HashMap<>(), k -> new Depth())`: any `get` on a
        // missing key auto-vivifies a zero `Depth` and inserts it. `HashMap::entry(..).or_insert`
        // reproduces the same "lazily materialize on first access" semantics.
        let mut depth_map: HashMap<V, Depth> = HashMap::new();

        depth_map.insert(root.clone(), Depth::new());
        for parent in sorted {
            visited.insert(parent.clone());
            let parent_depth = depth_map.entry(parent.clone()).or_insert_with(Depth::new).depth;
            let mut edges = self.graph.get_out_edges(parent);
            edges.sort_by(|a, b| (self.edge_comparator)(a, b));
            for e in &edges {
                let child = e.get_end().clone();
                if visited.contains(&child) {
                    continue; // loop backs are ignored
                }
                let child_depth = depth_map.entry(child).or_insert_with(Depth::new);
                child_depth.adjust_depth(parent_depth);
            }
        }
        depth_map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::g_directed_graph::GDirectedGraph;

    #[derive(Clone, PartialEq, Debug)]
    struct Edge {
        start: i32,
        end: i32,
        priority: i32,
    }

    impl GEdge<i32> for Edge {
        fn get_start(&self) -> &i32 {
            &self.start
        }
        fn get_end(&self) -> &i32 {
            &self.end
        }
    }

    fn edge(start: i32, end: i32, priority: i32) -> Edge {
        Edge { start, end, priority }
    }

    fn by_priority(a: &Edge, b: &Edge) -> Ordering {
        a.priority.cmp(&b.priority)
    }

    /// Builds:
    /// ```text
    /// 1 -> 2 -> 4
    /// 1 -> 3
    /// 2 -> 3
    /// ```
    fn build_graph() -> JungDirectedGraph<i32, Edge> {
        let mut g = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2, 1));
        GDirectedGraph::add_edge(&mut g, edge(1, 3, 0));
        GDirectedGraph::add_edge(&mut g, edge(2, 3, 0));
        GDirectedGraph::add_edge(&mut g, edge(2, 4, 0));
        g
    }

    #[test]
    fn topological_sort_places_root_first_and_respects_reachability() {
        let g = build_graph();
        let algo = GraphToTreeAlgorithm::new(&g, &by_priority);
        let sorted = algo.topolocigal_sort(1);

        assert_eq!(sorted[0], 1);
        assert_eq!(sorted.len(), 4);
        // Every vertex reachable from 1 appears exactly once.
        let mut copy = sorted.clone();
        copy.sort();
        assert_eq!(copy, vec![1, 2, 3, 4]);
    }

    #[test]
    fn topological_sort_ignores_unreachable_vertices() {
        let mut g = build_graph();
        GDirectedGraph::add_vertex(&mut g, 99); // unreachable from root 1
        let algo = GraphToTreeAlgorithm::new(&g, &by_priority);
        let sorted = algo.topolocigal_sort(1);

        assert!(!sorted.contains(&99));
    }

    #[test]
    fn topological_sort_handles_cycles_by_discarding_back_edges() {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2, 0));
        GDirectedGraph::add_edge(&mut g, edge(2, 1, 0)); // back edge to root
        let algo = GraphToTreeAlgorithm::new(&g, &by_priority);

        let sorted = algo.topolocigal_sort(1);
        assert_eq!(sorted, vec![1, 2]);
    }

    #[test]
    fn to_tree_produces_a_tree_where_forward_edges_flow_downward() {
        let g = build_graph();
        let algo = GraphToTreeAlgorithm::new(&g, &by_priority);
        let tree = algo.to_tree(1);

        assert_eq!(tree.get_vertex_count(), 4);
        // `assignDepths` (verified against GraphToTreeAlgorithm.java) walks vertices in
        // topological order and takes the *longest* path from root for each vertex's depth,
        // via `childDepth.adjustDepth(parentDepth)` = `max(current, parentDepth + 1)`. Vertex 3
        // is reachable both directly from 1 (depth candidate 1) and via 2 (depth candidate 2,
        // since depth(2) = 1); the longest-path rule settles depth(3) = 2, not 1. So in the
        // later `createTree` pass, only edges landing on a vertex exactly one depth below their
        // source survive: 1->2 (0->1, kept) and 2->3 (1->2, kept), but NOT 1->3 (0->2 is not
        // "direct"). 2->4 is likewise a depth-1-to-2 edge and is kept.
        assert!(tree.contains_edge_between(&1, &2));
        assert!(!tree.contains_edge_between(&1, &3));
        assert!(tree.contains_edge_between(&2, &3));
        assert!(tree.contains_edge_between(&2, &4));
        assert_eq!(tree.get_edge_count(), 3);
    }

    #[test]
    fn to_tree_single_vertex_graph_is_a_single_node_tree() {
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_vertex(&mut g, 1);
        let algo = GraphToTreeAlgorithm::new(&g, &by_priority);
        let tree = algo.to_tree(1);

        assert_eq!(tree.get_vertex_count(), 1);
        assert_eq!(tree.get_edge_count(), 0);
    }

    /// Higher-priority edges are processed first during the topological sort's DFS, making them
    /// least likely to be discarded as "back" edges: with two edges into the same vertex from
    /// different depths, the higher-priority parent should win claiming the child in the tree.
    #[test]
    fn higher_priority_edges_win_in_topological_sort_dfs_order() {
        // 1 -> 2 (priority 5), 1 -> 3 (priority 0), 2 -> 3 (priority 0)
        // DFS from 1 visits the highest-priority out-edge first (1->2, priority 5), descends
        // into 2 immediately, and claims 3 via 2->3 before ever trying 1->3.
        let mut g: JungDirectedGraph<i32, Edge> = JungDirectedGraph::new();
        GDirectedGraph::add_edge(&mut g, edge(1, 2, 5));
        GDirectedGraph::add_edge(&mut g, edge(1, 3, 0));
        GDirectedGraph::add_edge(&mut g, edge(2, 3, 0));
        let algo = GraphToTreeAlgorithm::new(&g, &by_priority);

        let sorted = algo.topolocigal_sort(1);
        // DFS descends into 2 before considering 3 as a direct child of 1.
        assert_eq!(sorted, vec![1, 2, 3]);

        let tree = algo.to_tree(1);
        assert!(tree.contains_edge_between(&2, &3), "2 claims 3 since DFS reached it first");
        assert!(!tree.contains_edge_between(&1, &3));
    }
}

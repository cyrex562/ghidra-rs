//! Port of `ghidra.graph.algo.TarjanStronglyConnectedAlgorthm`.
//!
//! The Java class name misspells "Algorithm" as "Algorthm"; that spelling is preserved verbatim
//! here (including in the file name) for a faithful, greppable 1:1 identifier mapping, matching
//! this crate's convention of not silently "fixing" the original names.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicI64, Ordering};

use crate::graph::g_directed_graph::GDirectedGraph;
use crate::graph::g_edge::GEdge;

/// Process-wide counter backing [`TarjanVertexInfo::index`].
///
/// Port of the nested `TarjanVertexInfo`'s `private static int nextIndex`. Java's field is a
/// genuinely process-wide (JVM-wide) `static` counter shared by *every* `TarjanVertexInfo` ever
/// constructed by *any* [`TarjanStronglyConnectedAlgorthm`] instance -- it is never reset between
/// separate algorithm runs. This is very likely an unintentional bug (a plain instance field, or a
/// counter reset per `compute()` call, would be the expected design for an algorithm meant to be
/// re-run independently), but it is faithfully reproduced here via a `static` atomic rather than
/// "fixed" into per-instance state -- see
/// [`indices_keep_increasing_across_separate_algorithm_instances`](tests::indices_keep_increasing_across_separate_algorithm_instances)
/// for a dedicated test pinning this down.
static NEXT_INDEX: AtomicI64 = AtomicI64::new(0);

/// Per-vertex bookkeeping used while running Tarjan's algorithm.
///
/// Port of the nested `TarjanStronglyConnectedAlgorthm.TarjanVertexInfo`.
struct TarjanVertexInfo {
    index: i64,
    low_link: i64,
}

impl TarjanVertexInfo {
    /// Port of `new TarjanVertexInfo()`, which assigns `index` from the shared
    /// [`NEXT_INDEX`] counter (see that static's own docs) and initializes `lowLink` to the same
    /// value.
    fn new() -> Self {
        let index = NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
        TarjanVertexInfo { index, low_link: index }
    }
}

/// Computes the strongly connected components of a directed graph via Tarjan's algorithm.
///
/// Port of `ghidra.graph.algo.TarjanStronglyConnectedAlgorthm<V, E extends GEdge<V>>`.
///
/// # Adaptations
///
/// * The `graph` field is not retained after construction: Java stores it but only ever reads it
///   from within `compute()`/`strongConnect()`, both of which run entirely during construction
///   (`compute()` is called from the constructor, and nothing else touches `this.graph`
///   afterward). Keeping a borrowed `&dyn GDirectedGraph<V, E>` field alongside the other fields
///   this struct mutates recursively during `strong_connect` would require either an owned
///   `Box<dyn GDirectedGraph<V, E>>` (a bigger divergence: Java holds a reference, not ownership)
///   or a lifetime parameter threaded through the whole struct for no behavioral benefit. Instead,
///   the graph is passed as a parameter to [`new`](Self::new) and to the private recursive helper,
///   exactly mirroring its only real uses.
/// * `strongConnect(V)` returns the vertex's whole `TarjanVertexInfo`, but every call site (both
///   the recursive call in `strongConnect` itself and the top-level loop in `compute()`) only
///   ever reads the returned object's `lowLink` field. This port's private `strong_connect`
///   therefore returns just that `i64` low-link value directly, rather than a bespoke struct with
///   a single meaningful field.
/// * `stronglyConnectedList` is a `Set<Set<V>>` in Java. Tarjan's algorithm can never discover the
///   same strongly connected component twice (every vertex is assigned to exactly one component,
///   the first time it is discovered), so a `HashSet` wrapper adds no deduplication value here --
///   this port uses `Vec<HashSet<V>>` instead, sidestepping the need for `HashSet<V>: Hash` (which
///   `std` does not provide), with no observable behavior difference.
/// * Java's inner `for (V w = pop(); v != w; w = pop())` loop compares `v != w` by **reference**
///   identity. A generic Rust `V` has no notion of identity separate from its value, so this port
///   compares by value (`V: Eq`) instead -- the only comparison a bare generic type parameter can
///   offer. For every `V`/`GDirectedGraph` combination actually used in this crate (a vertex
///   value uniquely denotes one graph node), value and reference identity coincide, so this is a
///   necessary generic-Rust adaptation rather than a behavior change.
pub struct TarjanStronglyConnectedAlgorthm<V, E>
where
    V: Clone + Eq + Hash,
    E: GEdge<V> + Clone + PartialEq,
{
    vertex_to_infos: HashMap<V, TarjanVertexInfo>,
    stack: Vec<V>,
    set: HashSet<V>,
    strongly_connected_list: Vec<HashSet<V>>,
    /// `E` (the edge type) never appears in any field's type -- every field only ever stores
    /// vertices -- so it needs an explicit marker to remain a type parameter of this struct,
    /// matching Java's `TarjanStronglyConnectedAlgorthm<V, E extends GEdge<V>>` (whose `graph`
    /// field, the only place `E` appeared, is not retained here -- see the struct's own docs).
    _edge_type: PhantomData<fn(E)>,
}

impl<V, E> TarjanStronglyConnectedAlgorthm<V, E>
where
    V: Clone + Eq + Hash,
    E: GEdge<V> + Clone + PartialEq,
{
    /// Run Tarjan's algorithm over `graph`, computing its strongly connected components.
    ///
    /// Port of `TarjanStronglyConnectedAlgorthm(GDirectedGraph<V, E> g)`, which calls the private
    /// `compute()` before returning.
    pub fn new(graph: &dyn GDirectedGraph<V, E>) -> Self {
        let mut this = TarjanStronglyConnectedAlgorthm {
            vertex_to_infos: HashMap::new(),
            stack: Vec::new(),
            set: HashSet::new(),
            strongly_connected_list: Vec::new(),
            _edge_type: PhantomData,
        };
        this.compute(graph);
        this
    }

    /// Port of the private `compute()`.
    fn compute(&mut self, graph: &dyn GDirectedGraph<V, E>) {
        for v in graph.get_vertices() {
            if !self.vertex_to_infos.contains_key(&v) {
                self.strong_connect(graph, v);
            }
        }
    }

    /// Port of the private `TarjanVertexInfo strongConnect(V v)`. Returns the newly-assigned
    /// vertex's low-link value; see the struct's own docs for why the full `TarjanVertexInfo` is
    /// not returned.
    fn strong_connect(&mut self, graph: &dyn GDirectedGraph<V, E>, v: V) -> i64 {
        let info = TarjanVertexInfo::new();
        let v_index = info.index;
        self.vertex_to_infos.insert(v.clone(), info);
        self.push(v.clone());

        for edge in graph.get_out_edges(&v) {
            let w = edge.get_end().clone();
            if !self.vertex_to_infos.contains_key(&w) {
                let w_low_link = self.strong_connect(graph, w);
                let v_info = self.vertex_to_infos.get_mut(&v).expect("just inserted above");
                v_info.low_link = v_info.low_link.min(w_low_link);
            } else if self.set.contains(&w) {
                let w_index = self.vertex_to_infos.get(&w).expect("checked above").index;
                let v_info = self.vertex_to_infos.get_mut(&v).expect("just inserted above");
                v_info.low_link = v_info.low_link.min(w_index);
            }
        }

        let v_info = self.vertex_to_infos.get(&v).expect("just inserted above");
        let (v_low_link, matches_index) = (v_info.low_link, v_info.low_link == v_index);
        if matches_index {
            let mut connected_set = HashSet::new();
            connected_set.insert(v.clone());
            loop {
                let w = self.pop();
                if w == v {
                    break;
                }
                connected_set.insert(w);
            }
            self.strongly_connected_list.push(connected_set);
        }

        v_low_link
    }

    /// Port of the private `push(V v)`.
    fn push(&mut self, v: V) {
        self.stack.push(v.clone());
        self.set.insert(v);
    }

    /// Port of the private `V pop()`.
    fn pop(&mut self) -> V {
        let v = self.stack.pop().expect("INTERNAL: pop() called on an empty stack");
        self.set.remove(&v);
        v
    }

    /// Returns the strongly connected components discovered.
    ///
    /// Port of `getConnectedComponents()`. See the struct's own docs for why this returns
    /// `Vec<HashSet<V>>` rather than `Set<Set<V>>`.
    pub fn get_connected_components(&self) -> Vec<HashSet<V>> {
        self.strongly_connected_list.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::g_implicit_directed_graph::GImplicitDirectedGraph;

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

    impl SimpleGraph {
        fn edge(&mut self, from: i32, to: i32) {
            if !self.vertices.contains(&from) {
                self.vertices.push(from);
            }
            if !self.vertices.contains(&to) {
                self.vertices.push(to);
            }
            self.edges.push(Edge { start: from, end: to });
        }
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
            before != self.vertices.len()
        }
        fn add_edge(&mut self, e: Edge) {
            self.edges.push(e);
        }
        fn remove_edge(&mut self, e: &Edge) -> bool {
            let before = self.edges.len();
            self.edges.retain(|x| x != e);
            before != self.edges.len()
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
            self.vertices.is_empty()
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

    /// A single cycle `1 -> 2 -> 3 -> 1` is one strongly connected component containing all three
    /// vertices.
    #[test]
    fn single_cycle_is_one_component() {
        let mut g = SimpleGraph::default();
        g.edge(1, 2);
        g.edge(2, 3);
        g.edge(3, 1);

        let tarjan = TarjanStronglyConnectedAlgorthm::new(&g);
        let components = tarjan.get_connected_components();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0], HashSet::from([1, 2, 3]));
    }

    /// A DAG with no cycles: every vertex is its own singleton strongly connected component.
    #[test]
    fn acyclic_graph_has_one_singleton_component_per_vertex() {
        let mut g = SimpleGraph::default();
        g.edge(1, 2);
        g.edge(2, 3);

        let tarjan = TarjanStronglyConnectedAlgorthm::new(&g);
        let components = tarjan.get_connected_components();
        assert_eq!(components.len(), 3);
        for v in [1, 2, 3] {
            assert!(components.contains(&HashSet::from([v])));
        }
    }

    /// Two disjoint cycles connected by a one-way bridge edge: two distinct non-trivial
    /// components, and the bridge itself does not merge them.
    #[test]
    fn two_cycles_joined_by_a_bridge_are_separate_components() {
        let mut g = SimpleGraph::default();
        // Cycle A: 1 <-> 2
        g.edge(1, 2);
        g.edge(2, 1);
        // Cycle B: 3 <-> 4
        g.edge(3, 4);
        g.edge(4, 3);
        // One-way bridge from A into B.
        g.edge(2, 3);

        let tarjan = TarjanStronglyConnectedAlgorthm::new(&g);
        let components = tarjan.get_connected_components();
        assert_eq!(components.len(), 2);
        assert!(components.contains(&HashSet::from([1, 2])));
        assert!(components.contains(&HashSet::from([3, 4])));
    }

    /// A graph with no edges at all: every vertex is a singleton component of its own.
    #[test]
    fn empty_edge_set_gives_a_singleton_component_per_vertex() {
        let mut g = SimpleGraph::default();
        g.vertices = vec![10, 20];

        let tarjan = TarjanStronglyConnectedAlgorthm::new(&g);
        let components = tarjan.get_connected_components();
        assert_eq!(components.len(), 2);
        assert!(components.contains(&HashSet::from([10])));
        assert!(components.contains(&HashSet::from([20])));
    }

    /// A self-loop `1 -> 1` is its own strongly connected component (of size one, but discovered
    /// via the "low_link == index" check rather than trivially).
    #[test]
    fn self_loop_is_its_own_component() {
        let mut g = SimpleGraph::default();
        g.edge(1, 1);

        let tarjan = TarjanStronglyConnectedAlgorthm::new(&g);
        let components = tarjan.get_connected_components();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0], HashSet::from([1]));
    }

    /// Preserved Java quirk: `TarjanVertexInfo.nextIndex` is a `static` counter shared by every
    /// `TarjanStronglyConnectedAlgorthm` instance ever constructed in the process, not reset per
    /// algorithm run. Running the algorithm twice therefore never reuses indices between runs --
    /// pinned down here via the shared [`NEXT_INDEX`] counter's monotonically-increasing value
    /// across two independent instances.
    #[test]
    fn indices_keep_increasing_across_separate_algorithm_instances() {
        let mut g1 = SimpleGraph::default();
        g1.edge(1, 2);
        let before = NEXT_INDEX.load(Ordering::SeqCst);
        let _first = TarjanStronglyConnectedAlgorthm::new(&g1);
        let after_first = NEXT_INDEX.load(Ordering::SeqCst);
        assert!(after_first > before, "first run must have consumed indices");

        let mut g2 = SimpleGraph::default();
        g2.edge(3, 4);
        let _second = TarjanStronglyConnectedAlgorthm::new(&g2);
        let after_second = NEXT_INDEX.load(Ordering::SeqCst);
        // The second run's vertices get indices continuing on from the first run's, never
        // resetting back to 0 -- the process-wide counter is never reset between instances.
        assert!(after_second > after_first, "second run must continue the shared counter");
    }
}

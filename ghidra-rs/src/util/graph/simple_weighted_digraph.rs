//! Port of `ghidra.util.graph.SimpleWeightedDigraph`.

use std::hash::Hash;

use crate::util::graph::directed_graph::DirectedGraph;
use crate::util::graph::edge::Edge;
use crate::util::graph::vertex::Vertex;
use crate::util::graph::weighted_digraph::WeightedDigraph;

/// A simple digraph -- a digraph with no parallel edges (but loops are still allowed if
/// [`allow_loops`](Self::allow_loops) is true). Edges are directed and a single edge may go from
/// any vertex to any other vertex; edges A->B and B->A may both exist. Attempting to add an edge
/// from A to B when an edge from A to B already exists causes the existing edge's weight to be
/// increased by the default edge weight (or the weight specified), rather than inserting a
/// parallel edge.
///
/// This type may be used when simple unweighted graphs are desired (simply ignore edge weights).
///
/// Port of `ghidra.util.graph.SimpleWeightedDigraph` (deprecated since Ghidra 10.2, "no longer
/// used or tested. Use GraphAlgorithms"), a concrete class extending the (now-trait)
/// [`WeightedDigraph`]. Following the precedent [`WeightedDigraph`] itself set for the very same
/// reason -- breaking a dependency cycle -- this becomes a trait extending [`WeightedDigraph`]
/// rather than a struct holding a `base` field. The private `allowLoops` field (set once at
/// construction, from whichever of the three Java constructors is used, and never mutated
/// afterward) becomes the required accessor hook [`allow_loops`](Self::allow_loops), exactly
/// mirroring how [`WeightedDigraph::default_edge_weight`] already stands in for the analogous
/// `defaultValue` field. No constructor is modeled, for the same reason [`WeightedDigraph`]
/// itself models none: implementers supply their own storage and report these two accessor hooks.
///
/// # Same-named methods, shadowing `WeightedDigraph`/`DirectedGraph`
///
/// [`add`](Self::add), [`add_with_weight`](Self::add_with_weight), [`remove`](Self::remove), and
/// [`get_weight`](Self::get_weight) reuse the exact names of [`WeightedDigraph`]'s own
/// (`add`/`add_with_weight`/`get_weight`) and [`DirectedGraph`]'s own (`remove_edge`, ported here
/// under the Java name `remove` to keep the override pairing obvious) methods. As with
/// [`WeightedDigraph`]'s own shadowing of [`DirectedGraph`] (see that trait's own docs), Rust does
/// not let a subtrait's default method replace a supertrait's by name for dispatch purposes -- a
/// type implementing both traits must disambiguate with fully-qualified syntax, e.g.
/// `WeightedDigraph::add(&mut g, e)` versus `SimpleWeightedDigraph::add(&mut g, e)`.
///
/// # Adaptation: no vertex-identity-based loop check
///
/// Java's `add`/`add(Edge,double)` test `e.from() == e.to()` -- Java reference identity, not
/// `.equals()`. [`Edge::from`]/[`Edge::to`] here return `&dyn` [`Vertex`], and a bare generic
/// vertex type has no notion of identity distinct from its value, so this port compares by
/// [`KeyedObject::key`](crate::util::graph::keyed_object::KeyedObject::key) instead -- the
/// intuitive, value-based interpretation of "is this a loop edge", and the only comparison a
/// generic Rust type can offer. For every vertex actually used in this crate (a vertex value
/// uniquely denotes one graph node), key equality and Java's reference equality coincide.
///
/// # Not ported: `copy()`
///
/// Java's `copy()` override constructs a new `SimpleWeightedDigraph` and calls the protected
/// `copyAll(DirectedGraph)` helper -- one of the "protected/private helper methods used internally
/// by `copy`/`join`" that [`DirectedGraph`]'s own docs already note were dropped as subclassing
/// implementation details. [`WeightedDigraph`] itself already declined to give `copy()` a default
/// for the identical reason; this trait follows the same precedent. Implementers still satisfy
/// `copy()` via [`DirectedGraph::copy`] directly, same as any other `DirectedGraph`.
pub trait SimpleWeightedDigraph<V: Vertex + Eq + Hash + Clone, E: Edge + Eq + Hash + Clone>:
    WeightedDigraph<V, E>
{
    /// Whether loops (an edge from a vertex to itself) are permitted.
    ///
    /// Stands in for the private `allowLoops` field. Mirrors what
    /// `SimpleWeightedDigraph`'s three constructors would have stored (`false` unless the
    /// four-argument constructor explicitly passes `true`).
    fn allow_loops(&self) -> bool;

    /// Returns every edge already in the graph sharing `e`'s endpoints (from and to, by key).
    ///
    /// Stands in for `this.getEdges(e.from(), e.to())`, called from within this trait's own
    /// overrides. [`DirectedGraph::get_edges_between`] is not reused directly: it takes `&V`
    /// parameters, but `e.from()`/`e.to()` only ever hand back `&dyn` [`Vertex`] (no way to
    /// recover the concrete `V` from a trait object without registry lookups this trait has no
    /// need for) -- so this filters [`DirectedGraph::edges`] directly by endpoint key instead,
    /// which is exactly what [`DirectedGraph::get_edges_between`]'s own default does internally.
    fn edges_sharing_endpoints_with(&self, e: &E) -> Vec<&E> {
        let from_key = e.from().key();
        let to_key = e.to().key();
        self.edges()
            .to_array()
            .into_iter()
            .filter(|existing| existing.from().key() == from_key && existing.to().key() == to_key)
            .collect()
    }

    /// Add an edge with the default edge weight.
    ///
    /// If an edge between the same two vertices already exists in the graph, the existing edge's
    /// weight is increased by [`WeightedDigraph::default_edge_weight`] instead of inserting a new
    /// edge.
    ///
    /// Mirrors `SimpleWeightedDigraph.add(Edge)`.
    ///
    /// # Preserved quirk: always returns `true`
    /// Like [`WeightedDigraph::add`], this always returns `true` when not rejected as a loop --
    /// even the "merge into existing edge" branch, whose own `setWeight` call result is returned
    /// directly in Java but is itself unconditionally `true` per [`WeightedDigraph::set_weight`]'s
    /// own always-`true` contract.
    fn add(&mut self, e: E) -> bool {
        if !self.allow_loops() && e.from().key() == e.to().key() {
            return false;
        }
        let existing: Vec<E> = self.edges_sharing_endpoints_with(&e).into_iter().cloned().collect();
        if existing.is_empty() {
            return WeightedDigraph::add(self, e);
        }
        let target = existing[0].clone();
        let new_weight = WeightedDigraph::get_weight(self, &target) + self.default_edge_weight();
        WeightedDigraph::set_weight(self, &target, new_weight)
    }

    /// Add an edge with the specified edge weight.
    ///
    /// If an edge between the same two vertices already exists in the graph, `weight` is added to
    /// the existing edge's weight instead of inserting a new edge.
    ///
    /// Mirrors `SimpleWeightedDigraph.add(Edge, double)`.
    fn add_with_weight(&mut self, e: E, weight: f64) -> bool {
        if !self.allow_loops() && e.from().key() == e.to().key() {
            return false;
        }
        let existing: Vec<E> = self.edges_sharing_endpoints_with(&e).into_iter().cloned().collect();
        if existing.is_empty() {
            return WeightedDigraph::add_with_weight(self, e, weight);
        }
        let target = existing[0].clone();
        let new_weight = WeightedDigraph::get_weight(self, &target) + weight;
        WeightedDigraph::set_weight(self, &target, new_weight)
    }

    /// Remove the edge between `e`'s endpoints, if one exists.
    ///
    /// Mirrors `SimpleWeightedDigraph.remove(Edge)`, which delegates to the inherited
    /// `DirectedGraph.remove(Edge)` (there is no `WeightedDigraph.remove` override to call
    /// through to).
    fn remove(&mut self, e: &E) -> bool {
        let existing: Vec<E> = self.edges_sharing_endpoints_with(e).into_iter().cloned().collect();
        let Some(target) = existing.into_iter().next() else {
            return false;
        };
        DirectedGraph::remove_edge(self, &target)
    }

    /// Returns the weight of the edge between `e`'s endpoints, or `0.0` if no such edge exists.
    ///
    /// Mirrors `SimpleWeightedDigraph.getWeight(Edge)`, an override of
    /// [`WeightedDigraph::get_weight`]. See the trait docs for the same-name shadowing this
    /// implies.
    fn get_weight(&self, e: &E) -> f64 {
        let existing = self.edges_sharing_endpoints_with(e);
        let Some(target) = existing.into_iter().next() else {
            return 0.0;
        };
        WeightedDigraph::get_weight(self, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::graph::edge_set::EdgeSet;
    use crate::util::graph::graph_iterator::{ConcurrentModificationError, GraphIterator};
    use crate::util::graph::key_indexable_set::KeyIndexableSet;
    use crate::util::graph::keyed_object::KeyedObject;
    use crate::util::seam_stubs::{AttributeLike, IntegerAttributeLike, VertexSetLike};
    use std::collections::{HashMap, HashSet};
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

    struct MockGraphIter<T: Clone> {
        items: Vec<T>,
        pos: usize,
    }
    impl<T: Clone + KeyedObject> GraphIterator<T> for MockGraphIter<T> {
        fn has_next(&self) -> bool {
            self.pos < self.items.len()
        }
        fn next(&mut self) -> Result<T, ConcurrentModificationError> {
            if self.pos >= self.items.len() {
                return Err(ConcurrentModificationError);
            }
            let item = self.items[self.pos].clone();
            self.pos += 1;
            Ok(item)
        }
        fn remove(&mut self) -> bool {
            if self.pos == 0 || self.pos > self.items.len() {
                return false;
            }
            self.items.remove(self.pos - 1);
            self.pos -= 1;
            true
        }
    }

    struct MockVertexSet {
        items: Vec<MockVertex>,
        modification_number: i64,
    }
    struct MockVertexIter<'a> {
        remaining: std::slice::Iter<'a, MockVertex>,
    }
    impl<'a> crate::util::seam_stubs::GraphIteratorLike<MockVertex> for MockVertexIter<'a> {
        fn has_next(&self) -> bool {
            self.remaining.clone().next().is_some()
        }
        fn next(&mut self) -> Option<MockVertex> {
            self.remaining.next().cloned()
        }
        fn remove(&mut self) -> bool {
            false
        }
    }
    impl KeyIndexableSet<MockVertex> for MockVertexSet {
        fn modification_number(&self) -> i64 {
            self.modification_number
        }
        fn size(&self) -> usize {
            self.items.len()
        }
        fn capacity(&self) -> usize {
            self.items.capacity()
        }
        fn add(&mut self, obj: MockVertex) -> bool {
            if self.contains(&obj) {
                return false;
            }
            self.items.push(obj);
            self.modification_number += 1;
            true
        }
        fn remove(&mut self, obj: &MockVertex) -> bool {
            let before = self.items.len();
            self.items.retain(|v| v.key != obj.key);
            let removed = self.items.len() != before;
            if removed {
                self.modification_number += 1;
            }
            removed
        }
        fn contains(&self, obj: &MockVertex) -> bool {
            self.items.iter().any(|v| v.key == obj.key)
        }
        fn iterator(&self) -> Box<dyn crate::util::seam_stubs::GraphIteratorLike<MockVertex> + '_> {
            Box::new(MockVertexIter { remaining: self.items.iter() })
        }
        fn to_array(&self) -> Vec<&MockVertex> {
            self.items.iter().collect()
        }
        fn get_keyed_object(&self, key: i64) -> Option<&MockVertex> {
            self.items.iter().find(|v| v.key == key)
        }
    }
    impl VertexSetLike<MockVertex> for MockVertexSet {
        fn clear(&mut self) {
            self.items.clear();
            self.modification_number += 1;
        }
    }

    struct MockEdgeSet {
        items: Vec<MockEdge>,
        modification_number: i64,
    }
    struct MockEdgeIter<'a> {
        remaining: std::slice::Iter<'a, MockEdge>,
    }
    impl<'a> crate::util::seam_stubs::GraphIteratorLike<MockEdge> for MockEdgeIter<'a> {
        fn has_next(&self) -> bool {
            self.remaining.clone().next().is_some()
        }
        fn next(&mut self) -> Option<MockEdge> {
            self.remaining.next().cloned()
        }
        fn remove(&mut self) -> bool {
            false
        }
    }
    impl KeyIndexableSet<MockEdge> for MockEdgeSet {
        fn modification_number(&self) -> i64 {
            self.modification_number
        }
        fn size(&self) -> usize {
            self.items.len()
        }
        fn capacity(&self) -> usize {
            self.items.capacity()
        }
        fn add(&mut self, obj: MockEdge) -> bool {
            if self.contains(&obj) {
                return false;
            }
            self.items.push(obj);
            self.modification_number += 1;
            true
        }
        fn remove(&mut self, obj: &MockEdge) -> bool {
            let before = self.items.len();
            self.items.retain(|e| e.key != obj.key);
            let removed = self.items.len() != before;
            if removed {
                self.modification_number += 1;
            }
            removed
        }
        fn contains(&self, obj: &MockEdge) -> bool {
            self.items.iter().any(|e| e.key == obj.key)
        }
        fn iterator(&self) -> Box<dyn crate::util::seam_stubs::GraphIteratorLike<MockEdge> + '_> {
            Box::new(MockEdgeIter { remaining: self.items.iter() })
        }
        fn to_array(&self) -> Vec<&MockEdge> {
            self.items.iter().collect()
        }
        fn get_keyed_object(&self, key: i64) -> Option<&MockEdge> {
            self.items.iter().find(|e| e.key == key)
        }
    }
    impl EdgeSet<MockEdge> for MockEdgeSet {
        fn get_by_index(&self, index: usize) -> Option<&MockEdge> {
            self.items.get(index)
        }
        fn index(&self, e: &MockEdge) -> Option<usize> {
            self.items.iter().position(|edge| edge.key == e.key)
        }
        fn get_next_edge_with_same_from(&self, _e: &MockEdge) -> Option<&MockEdge> {
            None
        }
        fn get_next_edge_with_same_to(&self, _e: &MockEdge) -> Option<&MockEdge> {
            None
        }
        fn get_previous_edge_with_same_from(&self, _e: &MockEdge) -> Option<&MockEdge> {
            None
        }
        fn get_previous_edge_with_same_to(&self, _e: &MockEdge) -> Option<&MockEdge> {
            None
        }
        fn clear(&mut self) {
            self.items.clear();
            self.modification_number += 1;
        }
        fn grow(&mut self) {
            self.items.reserve(self.items.len() + 1);
        }
    }

    struct MockAttributeManager<T> {
        _marker: std::marker::PhantomData<T>,
    }
    impl<T> Default for MockAttributeManager<T> {
        fn default() -> Self {
            MockAttributeManager { _marker: std::marker::PhantomData }
        }
    }
    impl<T: KeyedObject> crate::util::graph::attributes::AttributeManager<T> for MockAttributeManager<T> {
        fn create_attribute(
            &mut self,
            _attribute_name: &str,
            _attribute_type: &str,
        ) -> Option<Box<dyn AttributeLike<T>>> {
            None
        }
        fn remove_attribute(&mut self, _attribute_name: &str) {}
        fn has_attribute_named(&self, _attribute_name: &str) -> bool {
            false
        }
        fn get_attribute(&self, _attribute_name: &str) -> Option<&dyn AttributeLike<T>> {
            None
        }
        fn get_attribute_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn clear(&mut self) {}
    }

    struct MockIntegerAttribute<T> {
        _marker: std::marker::PhantomData<T>,
    }
    impl<T> Default for MockIntegerAttribute<T> {
        fn default() -> Self {
            MockIntegerAttribute { _marker: std::marker::PhantomData }
        }
    }
    impl<T: KeyedObject> AttributeLike<T> for MockIntegerAttribute<T> {
        fn clear(&mut self) {}
    }
    impl<T: KeyedObject> IntegerAttributeLike<T> for MockIntegerAttribute<T> {
        fn get_value(&self, _obj: &T) -> Result<i32, crate::util::exception::NoValueException> {
            Err(crate::util::exception::NoValueException("mock: no value".to_string()))
        }
        fn set_value(&mut self, _obj: &T, _value: i32) {}
    }

    /// A real, working `SimpleWeightedDigraph` implementor, backed by plain `HashMap<i64, f64>`
    /// weight storage (see [`WeightedDigraph`]'s own docs on why `DoubleAttribute` itself can't be
    /// stored as a field).
    struct MockSimpleWeightedDigraph {
        vertices: MockVertexSet,
        edges: MockEdgeSet,
        vertex_attrs: MockAttributeManager<MockVertex>,
        edge_attrs: MockAttributeManager<MockEdge>,
        weights: HashMap<i64, f64>,
        default_value: f64,
        allow_loops: bool,
    }

    impl MockSimpleWeightedDigraph {
        fn new(default_value: f64, allow_loops: bool) -> Self {
            MockSimpleWeightedDigraph {
                vertices: MockVertexSet { items: Vec::new(), modification_number: 0 },
                edges: MockEdgeSet { items: Vec::new(), modification_number: 0 },
                vertex_attrs: MockAttributeManager::default(),
                edge_attrs: MockAttributeManager::default(),
                weights: HashMap::new(),
                default_value,
                allow_loops,
            }
        }
    }

    #[allow(deprecated)]
    impl DirectedGraph<MockVertex, MockEdge> for MockSimpleWeightedDigraph {
        fn vertices(&self) -> &dyn VertexSetLike<MockVertex> {
            &self.vertices
        }
        fn vertices_mut(&mut self) -> &mut dyn VertexSetLike<MockVertex> {
            &mut self.vertices
        }
        fn edges(&self) -> &dyn EdgeSet<MockEdge> {
            &self.edges
        }
        fn edges_mut(&mut self) -> &mut dyn EdgeSet<MockEdge> {
            &mut self.edges
        }
        fn vertex_attributes(&self) -> &dyn crate::util::graph::attributes::AttributeManager<MockVertex> {
            &self.vertex_attrs
        }
        fn vertex_attributes_mut(
            &mut self,
        ) -> &mut dyn crate::util::graph::attributes::AttributeManager<MockVertex> {
            &mut self.vertex_attrs
        }
        fn edge_attributes(&self) -> &dyn crate::util::graph::attributes::AttributeManager<MockEdge> {
            &self.edge_attrs
        }
        fn edge_attributes_mut(
            &mut self,
        ) -> &mut dyn crate::util::graph::attributes::AttributeManager<MockEdge> {
            &mut self.edge_attrs
        }
        fn edge_iterator(&self) -> Box<dyn GraphIterator<MockEdge> + '_> {
            Box::new(MockGraphIter { items: self.edges.items.clone(), pos: 0 })
        }
        fn vertex_iterator(&self) -> Box<dyn GraphIterator<MockVertex> + '_> {
            Box::new(MockGraphIter { items: self.vertices.items.clone(), pos: 0 })
        }
        fn assign_vertices_to_strong_components(&self) -> Vec<HashSet<&MockVertex>> {
            self.vertices.items.iter().map(|v| HashSet::from([v])).collect()
        }
        fn get_entry_points(&self) -> Vec<&MockVertex> {
            self.get_sources()
        }
        fn get_levels(&self) -> Box<dyn IntegerAttributeLike<MockVertex>> {
            Box::new(MockIntegerAttribute::default())
        }
        fn complexity_depth(&self) -> Box<dyn IntegerAttributeLike<MockVertex>> {
            Box::new(MockIntegerAttribute::default())
        }
        fn copy(&self) -> Box<dyn DirectedGraph<MockVertex, MockEdge>> {
            let mut copy = MockSimpleWeightedDigraph::new(self.default_value, self.allow_loops);
            copy.vertices.items = self.vertices.items.clone();
            copy.edges.items = self.edges.items.clone();
            copy.weights = self.weights.clone();
            Box::new(copy)
        }
        fn induced_subgraph(
            &self,
            vertex_set: &[&MockVertex],
        ) -> Box<dyn DirectedGraph<MockVertex, MockEdge>> {
            let verts: Vec<MockVertex> = vertex_set.iter().map(|v| (*v).clone()).collect();
            let mut copy = MockSimpleWeightedDigraph::new(self.default_value, self.allow_loops);
            copy.vertices.items = verts;
            Box::new(copy)
        }
        fn get_component_containing(
            &self,
            _v: &MockVertex,
        ) -> Box<dyn DirectedGraph<MockVertex, MockEdge>> {
            self.copy()
        }
        fn get_components(&self) -> Vec<Box<dyn DirectedGraph<MockVertex, MockEdge>>> {
            vec![self.copy()]
        }
        fn descendants_graph(
            &self,
            seeds: &[&MockVertex],
        ) -> Box<dyn DirectedGraph<MockVertex, MockEdge>> {
            self.induced_subgraph(seeds)
        }
    }

    #[allow(deprecated)]
    impl WeightedDigraph<MockVertex, MockEdge> for MockSimpleWeightedDigraph {
        fn default_edge_weight(&self) -> f64 {
            self.default_value
        }
        fn raw_weight(&self, e: &MockEdge) -> Option<f64> {
            self.weights.get(&e.key).copied()
        }
        fn set_raw_weight(&mut self, e: &MockEdge, value: f64) -> bool {
            if !self.edges.contains(e) {
                return false;
            }
            self.weights.insert(e.key, value);
            true
        }
    }

    #[allow(deprecated)]
    impl SimpleWeightedDigraph<MockVertex, MockEdge> for MockSimpleWeightedDigraph {
        fn allow_loops(&self) -> bool {
            self.allow_loops
        }
    }

    fn v(key: i64) -> MockVertex {
        MockVertex { key }
    }
    fn e(key: i64, from: i64, to: i64) -> MockEdge {
        MockEdge { key, from: v(from), to: v(to) }
    }

    #[test]
    fn add_inserts_a_new_edge_at_the_default_weight() {
        let mut g = MockSimpleWeightedDigraph::new(2.0, false);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let edge = e(100, 1, 2);
        assert!(SimpleWeightedDigraph::add(&mut g, edge.clone()));
        assert!(g.contains_edge(&edge));
        assert_eq!(SimpleWeightedDigraph::get_weight(&g, &edge), 2.0);
    }

    #[test]
    fn add_merges_into_an_existing_edge_between_the_same_endpoints_instead_of_duplicating() {
        let mut g = MockSimpleWeightedDigraph::new(3.0, false);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let first = e(100, 1, 2);
        let second = e(101, 1, 2); // Different key, same endpoints.
        assert!(SimpleWeightedDigraph::add(&mut g, first.clone()));
        assert!(SimpleWeightedDigraph::add(&mut g, second.clone()));

        // Only the first edge (by key) was ever actually inserted into the graph.
        assert!(g.contains_edge(&first));
        assert!(!g.contains_edge(&second));
        // Its weight accumulated the default twice: once on insert, once on the "duplicate".
        assert_eq!(SimpleWeightedDigraph::get_weight(&g, &first), 6.0);
    }

    #[test]
    fn add_rejects_a_loop_when_loops_are_disallowed() {
        let mut g = MockSimpleWeightedDigraph::new(1.0, false);
        g.add_vertex(v(1));
        let loop_edge = e(100, 1, 1);
        assert!(!SimpleWeightedDigraph::add(&mut g, loop_edge.clone()));
        assert!(!g.contains_edge(&loop_edge));
    }

    #[test]
    fn add_permits_a_loop_when_loops_are_allowed() {
        let mut g = MockSimpleWeightedDigraph::new(1.0, true);
        g.add_vertex(v(1));
        let loop_edge = e(100, 1, 1);
        assert!(SimpleWeightedDigraph::add(&mut g, loop_edge.clone()));
        assert!(g.contains_edge(&loop_edge));
    }

    #[test]
    fn add_with_weight_merges_by_accumulating_the_specified_weight() {
        let mut g = MockSimpleWeightedDigraph::new(1.0, false);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let first = e(100, 1, 2);
        let second = e(101, 1, 2);
        assert!(SimpleWeightedDigraph::add_with_weight(&mut g, first.clone(), 5.0));
        assert!(SimpleWeightedDigraph::add_with_weight(&mut g, second, 10.0));
        assert_eq!(SimpleWeightedDigraph::get_weight(&g, &first), 15.0);
    }

    #[test]
    fn add_with_weight_rejects_a_loop_when_disallowed() {
        let mut g = MockSimpleWeightedDigraph::new(1.0, false);
        g.add_vertex(v(1));
        let loop_edge = e(100, 1, 1);
        assert!(!SimpleWeightedDigraph::add_with_weight(&mut g, loop_edge, 9.0));
    }

    #[test]
    fn get_weight_is_zero_for_a_pair_with_no_edge() {
        let g = MockSimpleWeightedDigraph::new(4.0, false);
        let edge = e(100, 1, 2);
        assert_eq!(SimpleWeightedDigraph::get_weight(&g, &edge), 0.0);
    }

    #[test]
    fn get_weight_finds_the_edge_by_endpoints_even_with_a_different_key() {
        let mut g = MockSimpleWeightedDigraph::new(1.0, false);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let stored = e(100, 1, 2);
        assert!(SimpleWeightedDigraph::add(&mut g, stored.clone()));
        WeightedDigraph::set_weight(&mut g, &stored, 42.0);

        let query = e(999, 1, 2); // Same endpoints, unrelated key -- never inserted.
        assert_eq!(SimpleWeightedDigraph::get_weight(&g, &query), 42.0);
    }

    #[test]
    fn remove_deletes_the_edge_matching_the_endpoints() {
        let mut g = MockSimpleWeightedDigraph::new(1.0, false);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let stored = e(100, 1, 2);
        assert!(SimpleWeightedDigraph::add(&mut g, stored.clone()));

        let query = e(999, 1, 2);
        assert!(SimpleWeightedDigraph::remove(&mut g, &query));
        assert!(!g.contains_edge(&stored));
    }

    #[test]
    fn remove_returns_false_when_no_edge_matches() {
        let mut g = MockSimpleWeightedDigraph::new(1.0, false);
        let query = e(999, 1, 2);
        assert!(!SimpleWeightedDigraph::remove(&mut g, &query));
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut g: Box<dyn SimpleWeightedDigraph<MockVertex, MockEdge>> =
            Box::new(MockSimpleWeightedDigraph::new(5.0, false));
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let edge = e(100, 1, 2);
        assert!(SimpleWeightedDigraph::add(g.as_mut(), edge.clone()));
        assert_eq!(SimpleWeightedDigraph::get_weight(g.as_ref(), &edge), 5.0);
        assert!(!g.allow_loops());
    }
}

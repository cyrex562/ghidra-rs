//! Mirrors `ghidra.util.graph.WeightedDigraph`.

use std::hash::Hash;

use crate::util::graph::directed_graph::DirectedGraph;
use crate::util::graph::edge::Edge;
use crate::util::graph::vertex::Vertex;

/// A [`DirectedGraph`] with edge weights. Weights are assumed to be the graph's
/// [`default_edge_weight`](WeightedDigraph::default_edge_weight) unless explicitly set.
///
/// Port of `ghidra.util.graph.WeightedDigraph` (deprecated since Ghidra 10.2, "no longer used or
/// tested. Use GraphAlgorithms"), a concrete class extending the (now-trait) [`DirectedGraph`].
/// Following the precedent [`DirectedGraph`] itself set for the very same reason -- breaking a
/// dependency cycle -- this becomes a trait extending [`DirectedGraph`] rather than a struct
/// holding a `base` field: `WeightedDigraph` only overrides/adds a handful of methods, and every
/// one of them is expressible as a default method built on [`DirectedGraph`]'s own accessors plus
/// one small new pair of hooks this trait adds,
/// [`raw_weight`](WeightedDigraph::raw_weight)/[`set_raw_weight`](WeightedDigraph::set_raw_weight),
/// standing in for the private `weights()` helper
/// (`(DoubleAttribute<Edge>) edgeAttributes().getAttribute("weight")`) and its
/// `DoubleAttribute.getValue`/`setValue` calls. A [`DoubleAttribute`
/// ](crate::util::graph::attributes::DoubleAttribute) itself cannot be stored as a field here: it
/// borrows its owning [`KeyIndexableSet`](crate::util::graph::key_indexable_set::KeyIndexableSet)
/// by reference for its whole lifetime, which is incompatible with a graph struct that would also
/// need to own that same set -- so weight storage is left to the implementer's own hooks, exactly
/// as [`DirectedGraph`] itself already leaves vertex/edge storage to
/// [`vertices`](DirectedGraph::vertices)/[`edges`](DirectedGraph::edges).
///
/// # Same-named methods, shadowing `DirectedGraph`
///
/// [`in_degree`](Self::in_degree), [`out_degree`](Self::out_degree), [`degree`](Self::degree), and
/// [`union_with`](Self::union_with) reuse the exact names of [`DirectedGraph`]'s own same-named
/// default methods (mirroring Java's `@Override`s of the identically-named inherited methods).
/// Rust does not let a subtrait's default method replace a supertrait's default method by name for
/// dispatch purposes -- both remain independently callable -- so a type implementing both traits
/// must disambiguate with fully-qualified syntax, e.g. `WeightedDigraph::in_degree(&g, v)` versus
/// `DirectedGraph::in_degree(&g, v)`. This is the same shadowing pattern already used by
/// [`SwiftSourceLanguage::get_id`](crate::app::util::sourcelanguage::swift_source_language::SwiftSourceLanguage::get_id)
/// (see that trait's own docs), kept here for consistency rather than inventing differently-named
/// methods.
///
/// # Not ported: `copy()`, `intersectionWith`, and `getEdgeWeights`
///
/// Java's `copy()` override constructs a new `WeightedDigraph` and calls the protected
/// `copyAll(DirectedGraph)` helper -- one of the "protected/private helper methods used internally
/// by `copy`/`join`" that [`DirectedGraph`]'s own docs already note were dropped as subclassing
/// implementation details, not part of the public surface being cut across. Since `copyAll` has no
/// port, `copy()` cannot be given a default here either; implementers still satisfy it via
/// [`DirectedGraph::copy`] directly, same as any other `DirectedGraph`. `intersectionWith`'s
/// override is not reproduced as a distinct default because its body is structurally identical to
/// [`DirectedGraph::intersection_with`]'s already-ported default (remove from `other` every
/// vertex/edge not in `self`) -- it does not touch weights at all, so the inherited default
/// already behaves exactly like it. `getEdgeWeights()` returned the same private `weights()`
/// `DoubleAttribute` object wholesale; since that object cannot be reproduced here (see above),
/// and every operation it would support is already exposed piecewise via
/// [`raw_weight`](Self::raw_weight)/[`set_raw_weight`](Self::set_raw_weight), it has no separate
/// port.
pub trait WeightedDigraph<V: Vertex + Eq + Hash, E: Edge + Eq + Hash + Clone>:
    DirectedGraph<V, E>
{
    /// The default weight for edges whose weight has not been explicitly set.
    ///
    /// Stands in for the private `defaultValue` field. Mirrors
    /// `WeightedDigraph.getDefaultEdgeWeight()`.
    fn default_edge_weight(&self) -> f64;

    /// Get the raw stored weight of `e`, or `None` if it has never been set.
    ///
    /// Stands in for `weights().getValue(e)`'s `NoValueException` case, i.e. the private
    /// `weights()` accessor plus `DoubleAttribute.getValue`.
    fn raw_weight(&self, e: &E) -> Option<f64>;

    /// Set the raw stored weight of `e`.
    ///
    /// Stands in for `weights().setValue(e, value)`, i.e. the private `weights()` accessor plus
    /// `DoubleAttribute.setValue`. Returns `true` if the value was stored; Java's
    /// `DoubleAttribute.setValue` returns `false` when `e` is not a member of the attribute's
    /// owning edge set, and implementers are expected to reproduce that same containment check.
    fn set_raw_weight(&mut self, e: &E, value: f64) -> bool;

    /// Get the weight of `e`, falling back to `0.0` (*not*
    /// [`default_edge_weight`](Self::default_edge_weight)) if unset.
    ///
    /// Mirrors `WeightedDigraph.getWeight(Edge)`, which catches `NoValueException` and returns
    /// the literal `0.0`.
    ///
    /// # Preserved quirk: inconsistent fallback with `in_degree`/`out_degree`
    /// Unlike this method, [`in_degree`](Self::in_degree) and [`out_degree`](Self::out_degree)
    /// fall back to [`default_edge_weight`](Self::default_edge_weight) (not `0.0`) for an edge
    /// with no explicit weight -- a real inconsistency in the Java class, faithfully reproduced
    /// as-is rather than unified. See `in_degree_falls_back_to_default_while_get_weight_falls_back_to_zero`
    /// in this module's tests.
    fn get_weight(&self, e: &E) -> f64 {
        self.raw_weight(e).unwrap_or(0.0)
    }

    /// Set the weight of `e`.
    ///
    /// Mirrors `WeightedDigraph.setWeight(Edge, double)`.
    fn set_weight(&mut self, e: &E, value: f64) -> bool {
        self.set_raw_weight(e, value)
    }

    /// Returns the weighted in-degree of `v`: the sum of weights of all edges entering `v`,
    /// falling back to [`default_edge_weight`](Self::default_edge_weight) for any edge with no
    /// explicit weight.
    ///
    /// Mirrors `WeightedDigraph.inDegree(Vertex)`, an override of the unweighted
    /// [`DirectedGraph::in_degree`]. See the trait docs for the same-name shadowing this implies.
    fn in_degree(&self, v: &V) -> f64 {
        self.incoming_edges(v)
            .into_iter()
            .map(|e| self.raw_weight(e).unwrap_or_else(|| self.default_edge_weight()))
            .sum()
    }

    /// Returns the weighted out-degree of `v`: the sum of weights of all edges leaving `v`,
    /// falling back to [`default_edge_weight`](Self::default_edge_weight) for any edge with no
    /// explicit weight.
    ///
    /// Mirrors `WeightedDigraph.outDegree(Vertex)`, an override of the unweighted
    /// [`DirectedGraph::out_degree`]. See the trait docs for the same-name shadowing this implies.
    fn out_degree(&self, v: &V) -> f64 {
        self.outgoing_edges(v)
            .into_iter()
            .map(|e| self.raw_weight(e).unwrap_or_else(|| self.default_edge_weight()))
            .sum()
    }

    /// Returns the weighted self-degree of `v`: the sum of weights of all loops at `v`, falling
    /// back to `0.0` for any loop with no explicit weight.
    ///
    /// Mirrors `WeightedDigraph.selfDegree(Vertex)`. Unlike [`in_degree`](Self::in_degree)/
    /// [`out_degree`](Self::out_degree), this is a new method with no unweighted counterpart on
    /// [`DirectedGraph`], so it needs no shadowing disambiguation.
    fn self_degree(&self, v: &V) -> f64 {
        self.self_edges(v).into_iter().map(|e| self.raw_weight(e).unwrap_or(0.0)).sum()
    }

    /// Returns the weighted degree of `v`: [`in_degree`](Self::in_degree) plus
    /// [`out_degree`](Self::out_degree) minus [`self_degree`](Self::self_degree) (loops are
    /// counted once, not twice).
    ///
    /// Mirrors `WeightedDigraph.degree(Vertex)`, an override of the unweighted
    /// [`DirectedGraph::degree`]. See the trait docs for the same-name shadowing this implies.
    fn degree(&self, v: &V) -> f64 {
        WeightedDigraph::in_degree(self, v) + WeightedDigraph::out_degree(self, v)
            - self.self_degree(v)
    }

    /// Add an edge. If successful (the edge did not already appear in the graph), its weight is
    /// set to [`default_edge_weight`](Self::default_edge_weight); otherwise its existing weight
    /// is incremented by [`default_edge_weight`](Self::default_edge_weight).
    ///
    /// Mirrors `WeightedDigraph.add(Edge)`, an override of the inherited `DirectedGraph.add(Edge)`
    /// (this crate's [`DirectedGraph::add_edge`] is used for the actual insertion).
    ///
    /// # Preserved quirk: always returns `true`
    /// Faithfully reproduces the Java method's `return true;`, which ignores the actual insertion
    /// success/failure (`returnValue`) for its return value -- even when the edge already existed
    /// and was *not* newly inserted, this reports success. `returnValue` is still used internally
    /// to decide which weight-update branch to take.
    fn add(&mut self, e: E) -> bool {
        let wt = self.get_weight(&e);
        let default_value = self.default_edge_weight();
        let inserted = self.add_edge(e.clone());
        if inserted {
            self.set_raw_weight(&e, default_value);
        } else {
            self.set_raw_weight(&e, wt + default_value);
        }
        true
    }

    /// Add an edge with an explicit weight. If successful (the edge did not already appear in the
    /// graph), its weight is set to `weight`; otherwise `weight` is added to its existing weight.
    ///
    /// Mirrors `WeightedDigraph.add(Edge, double)`.
    ///
    /// # Preserved quirk: unconditional weight update, and always returns `true`
    /// Faithfully reproduces the Java method's structure: unlike [`add`](Self::add), this never
    /// even branches on whether the edge was newly inserted -- `wt + weight` (the prior weight,
    /// `0.0` via [`get_weight`](Self::get_weight) if the edge is new, plus `weight`) is stored
    /// regardless. The return value is likewise always `true`.
    fn add_with_weight(&mut self, e: E, weight: f64) -> bool {
        let wt = self.get_weight(&e);
        self.add_edge(e.clone());
        self.set_raw_weight(&e, wt + weight);
        true
    }

    /// Adds all vertices and edges of `other` to this graph in place, carrying over `other`'s
    /// edge weights where set (via [`add_with_weight`](Self::add_with_weight)), and this graph's
    /// own [`default_edge_weight`](Self::default_edge_weight) otherwise (via
    /// [`add`](Self::add)).
    ///
    /// Mirrors `WeightedDigraph.unionWith(DirectedGraph)`, an override of the unweighted
    /// [`DirectedGraph::union_with`]. See the trait docs for the same-name shadowing this implies.
    ///
    /// # Divergence: `other` must itself be a `WeightedDigraph`
    /// Java's override keeps the inherited `unionWith(DirectedGraph otherGraph)` signature, then
    /// unconditionally casts `otherGraph.edgeAttributes().getAttribute("weight")` to
    /// `DoubleAttribute<Edge>` -- a `ClassCastException` risk if `otherGraph` is not actually a
    /// `WeightedDigraph`. This port instead requires `other: &dyn WeightedDigraph<V, E>`,
    /// eliminating that risk at the type level (a genuine strengthening over Java, not merely a
    /// cosmetic rename) while preserving the same observable weight-merging behavior when it is
    /// one.
    fn union_with(&mut self, other: &dyn WeightedDigraph<V, E>) {
        let mut vi = other.vertex_iterator();
        while vi.has_next() {
            match vi.next() {
                Ok(v) => {
                    self.add_vertex(v);
                }
                Err(_) => break,
            }
        }
        drop(vi);
        let mut ei = other.edge_iterator();
        while ei.has_next() {
            match ei.next() {
                Ok(e) => match other.raw_weight(&e) {
                    Some(w) => {
                        self.add_with_weight(e, w);
                    }
                    None => {
                        self.add(e);
                    }
                },
                Err(_) => break,
            }
        }
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

    /// A real, working `WeightedDigraph` implementor: a plain `HashMap<i64, f64>` backs the
    /// weight hooks, sidestepping `DoubleAttribute`'s borrowed-owning-set lifetime issue (see the
    /// trait's own docs).
    struct MockWeightedDigraph {
        vertices: MockVertexSet,
        edges: MockEdgeSet,
        vertex_attrs: MockAttributeManager<MockVertex>,
        edge_attrs: MockAttributeManager<MockEdge>,
        weights: HashMap<i64, f64>,
        default_value: f64,
    }

    impl MockWeightedDigraph {
        fn new(default_value: f64) -> Self {
            MockWeightedDigraph {
                vertices: MockVertexSet { items: Vec::new(), modification_number: 0 },
                edges: MockEdgeSet { items: Vec::new(), modification_number: 0 },
                vertex_attrs: MockAttributeManager::default(),
                edge_attrs: MockAttributeManager::default(),
                weights: HashMap::new(),
                default_value,
            }
        }
    }

    #[allow(deprecated)]
    impl DirectedGraph<MockVertex, MockEdge> for MockWeightedDigraph {
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
            self.vertices
                .items
                .iter()
                .map(|v| {
                    let mut s = HashSet::new();
                    s.insert(v);
                    s
                })
                .collect()
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
            let mut copy = MockWeightedDigraph::new(self.default_value);
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
            let mut copy = MockWeightedDigraph::new(self.default_value);
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

    impl WeightedDigraph<MockVertex, MockEdge> for MockWeightedDigraph {
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

    fn v(key: i64) -> MockVertex {
        MockVertex { key }
    }

    fn e(key: i64, from: i64, to: i64) -> MockEdge {
        MockEdge { key, from: v(from), to: v(to) }
    }

    #[test]
    fn get_weight_falls_back_to_zero_not_default() {
        let mut g = MockWeightedDigraph::new(7.0);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let edge = e(100, 1, 2);
        g.add_edge(edge.clone());
        // Never explicitly weighted.
        assert_eq!(g.get_weight(&edge), 0.0);
    }

    #[test]
    fn in_degree_falls_back_to_default_while_get_weight_falls_back_to_zero() {
        let mut g = MockWeightedDigraph::new(7.0);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let edge = e(100, 1, 2);
        g.add_edge(edge.clone());

        // Preserved Java quirk: in_degree/out_degree use defaultValue for unweighted edges, but
        // getWeight itself uses 0.0.
        assert_eq!(g.get_weight(&edge), 0.0);
        assert_eq!(WeightedDigraph::in_degree(&g, &v(2)), 7.0);
        assert_eq!(WeightedDigraph::out_degree(&g, &v(1)), 7.0);
    }

    #[test]
    fn set_weight_then_get_weight_round_trips() {
        let mut g = MockWeightedDigraph::new(1.0);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let edge = e(100, 1, 2);
        g.add_edge(edge.clone());
        assert!(g.set_weight(&edge, 3.5));
        assert_eq!(g.get_weight(&edge), 3.5);
    }

    #[test]
    fn add_sets_default_weight_on_first_insert_and_increments_on_repeat() {
        let mut g = MockWeightedDigraph::new(2.0);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let edge = e(100, 1, 2);

        assert!(WeightedDigraph::add(&mut g, edge.clone()));
        assert_eq!(g.get_weight(&edge), 2.0);

        // Edge with the same key already exists (per KeyIndexableSet::add's containment check),
        // so the second add() increments the existing weight by default_value instead.
        assert!(WeightedDigraph::add(&mut g, edge.clone()));
        assert_eq!(g.get_weight(&edge), 4.0);
    }

    #[test]
    fn add_with_weight_unconditionally_accumulates() {
        let mut g = MockWeightedDigraph::new(1.0);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let edge = e(100, 1, 2);

        assert!(g.add_with_weight(edge.clone(), 5.0));
        assert_eq!(g.get_weight(&edge), 5.0);

        // Preserved quirk: unlike add(), this always accumulates regardless of whether the edge
        // was already present.
        assert!(g.add_with_weight(edge.clone(), 5.0));
        assert_eq!(g.get_weight(&edge), 10.0);
    }

    #[test]
    fn self_degree_sums_loop_weights_falling_back_to_zero() {
        let mut g = MockWeightedDigraph::new(9.0);
        g.add_vertex(v(1));
        let loop_edge = e(100, 1, 1);
        g.add_edge(loop_edge.clone());
        // Unweighted loop: self_degree falls back to 0.0, not default_edge_weight.
        assert_eq!(g.self_degree(&v(1)), 0.0);

        g.set_weight(&loop_edge, 3.0);
        assert_eq!(g.self_degree(&v(1)), 3.0);
    }

    #[test]
    fn degree_combines_in_out_and_self_degree() {
        let mut g = MockWeightedDigraph::new(1.0);
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let incoming = e(100, 2, 1);
        let outgoing = e(101, 1, 2);
        let loop_edge = e(102, 1, 1);
        g.add_edge(incoming.clone());
        g.add_edge(outgoing.clone());
        g.add_edge(loop_edge.clone());
        g.set_weight(&incoming, 2.0);
        g.set_weight(&outgoing, 3.0);
        g.set_weight(&loop_edge, 4.0);

        // in_degree(1) = incoming(2.0) + loop(4.0) = 6.0
        // out_degree(1) = outgoing(3.0) + loop(4.0) = 7.0
        // self_degree(1) = loop(4.0)
        // degree(1) = 6.0 + 7.0 - 4.0 = 9.0
        assert_eq!(WeightedDigraph::degree(&g, &v(1)), 9.0);
    }

    #[test]
    fn union_with_carries_over_explicit_weights_and_uses_default_for_unweighted() {
        let mut g1 = MockWeightedDigraph::new(1.0);
        g1.add_vertex(v(1));
        g1.add_vertex(v(2));

        let mut g2 = MockWeightedDigraph::new(1.0);
        g2.add_vertex(v(1));
        g2.add_vertex(v(2));
        g2.add_vertex(v(3));
        let weighted = e(200, 1, 2);
        let unweighted = e(201, 2, 3);
        g2.add_edge(weighted.clone());
        g2.add_edge(unweighted.clone());
        g2.set_weight(&weighted, 42.0);

        WeightedDigraph::union_with(&mut g1, &g2);

        assert!(g1.contains_vertex(&v(3)));
        assert!(g1.contains_edge(&weighted));
        assert!(g1.contains_edge(&unweighted));
        // Carried over from g2's explicit weight.
        assert_eq!(g1.get_weight(&weighted), 42.0);
        // g2's unweighted edge went through add(), so it picked up g1's default_edge_weight.
        assert_eq!(g1.get_weight(&unweighted), 1.0);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut g: Box<dyn WeightedDigraph<MockVertex, MockEdge>> =
            Box::new(MockWeightedDigraph::new(5.0));
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let edge = e(100, 1, 2);
        assert!(WeightedDigraph::add(g.as_mut(), edge.clone()));
        assert_eq!(g.get_weight(&edge), 5.0);
        assert_eq!(g.default_edge_weight(), 5.0);
    }
}

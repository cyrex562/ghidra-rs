use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;

use crate::util::graph::attributes::AttributeManager;
use crate::util::graph::edge::Edge;
use crate::util::graph::edge_set::EdgeSet;
use crate::util::graph::graph_iterator::GraphIterator;
use crate::util::graph::vertex::Vertex;
use crate::util::seam_stubs::{IntegerAttributeLike, VertexSetLike};

/// Base implementation of a directed graph. A directed graph consists of a set of vertices and
/// a set of edges joining ordered pairs of vertices. Parallel edges and loops are allowed.
///
/// Port of `ghidra.util.graph.DirectedGraph` (deprecated since Ghidra 10.2; use `GraphFactory`),
/// cut to a trait to break a dependency cycle at this node in the port graph.
///
/// The class's four fields (`vertices: VertexSet`, `edges: EdgeSet`, `vertexAttributes` and
/// `edgeAttributes: AttributeManager`) become the abstract accessor methods below (doubled into
/// `_mut` variants, since Rust cannot hand out one reference usable for both reads and the
/// mutations Java performs through the same getter); every other public method is given a
/// default implementation built from those four accessors plus [`Vertex`]/[`Edge`] key equality,
/// mirroring the original delegation-heavy Java implementation. `ghidra.util.graph.VertexSet` is
/// not yet ported; since every default here only needs its container/clear semantics (adjacency
/// is instead recovered by scanning [`edges`](DirectedGraph::edges)), it is represented by the
/// minimal [`VertexSetLike`] placeholder rather than a full port. `ghidra.util.graph.DepthFirstSearch`
/// is not yet ported either, but it never appears in this trait's surface: it is purely an
/// implementation detail of `assignVerticesToStrongComponents`/`getEntryPoints`/`getLevels`/
/// `complexityDepth`, which stay abstract here for implementers to provide. The `protected`/
/// `private` helper methods used internally by `copy`/`join` to duplicate object-attribute
/// values (`copyVertex`, `copyEdge`, `copy(Vertex|Edge)AttributeValues`, `CopyVertexAttributes`,
/// `CopyEdgeAttributes`, `get/setVertexProperty`, `get/setEdgeProperty`, `get(Vertex|Edge)Attribute`)
/// are subclassing implementation details, not part of the public surface, and are dropped; as a
/// result the default [`join`](DirectedGraph::join) only copies structure (like
/// [`union_with`](DirectedGraph::union_with)), not attribute values. The `public static`
/// `verts2referentSet` utility is ported as the free function [`verts_to_referent_set`] instead
/// of a trait method, since it does not operate on a particular graph instance.
#[deprecated(note = "Deprecated since Ghidra 10.2; use GraphFactory")]
#[allow(deprecated)]
pub trait DirectedGraph<V: Vertex + Eq + Hash, E: Edge + Eq + Hash> {
    /// Returns the VertexSet-like container of this graph.
    fn vertices(&self) -> &dyn VertexSetLike<V>;

    /// Returns the VertexSet-like container of this graph, mutably.
    fn vertices_mut(&mut self) -> &mut dyn VertexSetLike<V>;

    /// Returns the EdgeSet of this graph.
    fn edges(&self) -> &dyn EdgeSet<E>;

    /// Returns the EdgeSet of this graph, mutably.
    fn edges_mut(&mut self) -> &mut dyn EdgeSet<E>;

    /// Returns the AttributeManager for the vertices of this graph.
    fn vertex_attributes(&self) -> &dyn AttributeManager<V>;

    /// Returns the AttributeManager for the vertices of this graph, mutably.
    fn vertex_attributes_mut(&mut self) -> &mut dyn AttributeManager<V>;

    /// Returns the AttributeManager for the edges of this graph.
    fn edge_attributes(&self) -> &dyn AttributeManager<E>;

    /// Returns the AttributeManager for the edges of this graph, mutably.
    fn edge_attributes_mut(&mut self) -> &mut dyn AttributeManager<E>;

    /// Returns an iterator over the edges of this graph.
    fn edge_iterator(&self) -> Box<dyn GraphIterator<E> + '_>;

    /// Returns an iterator over the vertices of this graph.
    fn vertex_iterator(&self) -> Box<dyn GraphIterator<V> + '_>;

    /// Returns the vertices of each strongly connected component of this graph.
    fn assign_vertices_to_strong_components(&self) -> Vec<HashSet<&V>>;

    /// Returns the entry points to this graph: sources, plus the least vertex (by key) in every
    /// strongly connected component that is unreachable from any vertex outside it.
    fn get_entry_points(&self) -> Vec<&V>;

    /// Assigns levels in a top-down manner. Sources are on level 0.
    fn get_levels(&self) -> Box<dyn IntegerAttributeLike<V>>;

    /// Assigns levels in a bottom-up manner. All sinks have the same level.
    fn complexity_depth(&self) -> Box<dyn IntegerAttributeLike<V>>;

    /// Returns a graph with the same vertices, edges, and attributes as this one.
    fn copy(&self) -> Box<dyn DirectedGraph<V, E>>;

    /// Returns the subgraph induced by the given vertices: contains those of the given vertices
    /// which belong to this graph, plus every edge of this graph whose endpoints are both in
    /// that set.
    fn induced_subgraph(&self, vertex_set: &[&V]) -> Box<dyn DirectedGraph<V, E>>;

    /// Returns the subgraph which is the connected component containing `v`.
    fn get_component_containing(&self, v: &V) -> Box<dyn DirectedGraph<V, E>>;

    /// Returns one graph per connected component of this graph.
    fn get_components(&self) -> Vec<Box<dyn DirectedGraph<V, E>>>;

    /// Returns the graph induced by the seed vertices and their descendants.
    fn descendants_graph(&self, seeds: &[&V]) -> Box<dyn DirectedGraph<V, E>>;

    /// The number of edges having `v` as their "to" vertex.
    fn in_valence(&self, v: &V) -> usize {
        self.edges().to_array().into_iter().filter(|e| e.to().key() == v.key()).count()
    }

    /// The number of edges having `v` as their "from" vertex.
    fn out_valence(&self, v: &V) -> usize {
        self.edges().to_array().into_iter().filter(|e| e.from().key() == v.key()).count()
    }

    /// The number of edges having `v` as both their "from" and "to" vertex.
    fn num_loops(&self, v: &V) -> usize {
        self.edges()
            .to_array()
            .into_iter()
            .filter(|e| e.from().key() == v.key() && e.to().key() == v.key())
            .count()
    }

    /// The number of edges incident with `v`.
    fn valence(&self, v: &V) -> usize {
        self.in_valence(v) + self.out_valence(v) - self.num_loops(v)
    }

    /// Returns [`in_valence`](DirectedGraph::in_valence) as a double.
    fn in_degree(&self, v: &V) -> f64 {
        self.in_valence(v) as f64
    }

    /// Returns [`out_valence`](DirectedGraph::out_valence) as a double.
    fn out_degree(&self, v: &V) -> f64 {
        self.out_valence(v) as f64
    }

    /// Returns [`num_loops`](DirectedGraph::num_loops) as a double.
    fn loop_degree(&self, v: &V) -> f64 {
        self.num_loops(v) as f64
    }

    /// Returns [`valence`](DirectedGraph::valence) as a double.
    fn degree(&self, v: &V) -> f64 {
        self.valence(v) as f64
    }

    /// Returns the edge in the graph with the specified key, or `None`.
    fn get_edge_with_key(&self, key: i64) -> Option<&E> {
        self.edges().get_keyed_object(key)
    }

    /// Returns the vertex in the graph with the specified key, or `None`.
    fn get_vertex_with_key(&self, key: i64) -> Option<&V> {
        self.vertices().get_keyed_object(key)
    }

    /// Returns the tos of the outgoing edges of `v`.
    fn get_children<'a>(&'a self, v: &'a V) -> HashSet<&'a V> {
        let mut children = HashSet::new();
        for e in self.edges().to_array() {
            if e.from().key() == v.key() {
                if let Some(child) = self.vertices().get_keyed_object(e.to().key()) {
                    children.insert(child);
                }
            }
        }
        children
    }

    /// Returns the outgoing edges from `v`.
    fn get_outgoing_edges<'a>(&'a self, v: &'a V) -> HashSet<&'a E> {
        self.edges().to_array().into_iter().filter(|e| e.from().key() == v.key()).collect()
    }

    /// Returns the froms of the incoming edges of `v`.
    fn get_parents<'a>(&'a self, v: &'a V) -> HashSet<&'a V> {
        let mut parents = HashSet::new();
        for e in self.edges().to_array() {
            if e.to().key() == v.key() {
                if let Some(parent) = self.vertices().get_keyed_object(e.from().key()) {
                    parents.insert(parent);
                }
            }
        }
        parents
    }

    /// Returns the incoming edges of `v`.
    fn get_incoming_edges<'a>(&'a self, v: &'a V) -> HashSet<&'a E> {
        self.edges().to_array().into_iter().filter(|e| e.to().key() == v.key()).collect()
    }

    /// Returns all children of the vertices in `vs`.
    fn get_children_of_set<'a>(&'a self, vs: &HashSet<&'a V>) -> HashSet<&'a V> {
        let mut children = HashSet::new();
        for v in vs {
            children.extend(self.get_children(*v));
        }
        children
    }

    /// Returns all parents of the vertices in `vs`.
    fn get_parents_of_set<'a>(&'a self, vs: &HashSet<&'a V>) -> HashSet<&'a V> {
        let mut parents = HashSet::new();
        for v in vs {
            parents.extend(self.get_parents(*v));
        }
        parents
    }

    /// Returns all descendants of `v`. A vertex is defined to be a descendant of itself.
    fn get_descendants<'a>(&'a self, v: &'a V) -> HashSet<&'a V> {
        let mut descendants = HashSet::new();
        descendants.insert(v);
        let mut pending = vec![v];
        while let Some(cur) = pending.pop() {
            for child in self.get_children(cur) {
                if descendants.insert(child) {
                    pending.push(child);
                }
            }
        }
        descendants
    }

    /// Returns all vertices descended from a vertex in `seeds`.
    fn get_descendants_from_seeds<'a>(&'a self, seeds: &[&'a V]) -> HashSet<&'a V> {
        let mut descendants = HashSet::new();
        for seed in seeds {
            descendants.extend(self.get_descendants(seed));
        }
        descendants
    }

    /// Returns all ancestors of `v`. A vertex is defined to be one of its own ancestors.
    fn get_ancestors<'a>(&'a self, v: &'a V) -> HashSet<&'a V> {
        let mut ancestors = HashSet::new();
        ancestors.insert(v);
        let mut pending = vec![v];
        while let Some(cur) = pending.pop() {
            for parent in self.get_parents(cur) {
                if ancestors.insert(parent) {
                    pending.push(parent);
                }
            }
        }
        ancestors
    }

    /// Returns all incoming edges of `v`.
    fn incoming_edges<'a>(&'a self, v: &'a V) -> Vec<&'a E> {
        self.edges().to_array().into_iter().filter(|e| e.to().key() == v.key()).collect()
    }

    /// Returns all outgoing edges of `v`.
    fn outgoing_edges<'a>(&'a self, v: &'a V) -> Vec<&'a E> {
        self.edges().to_array().into_iter().filter(|e| e.from().key() == v.key()).collect()
    }

    /// Returns all edges with `v` as both the from and to.
    fn self_edges<'a>(&'a self, v: &'a V) -> Vec<&'a E> {
        self.edges()
            .to_array()
            .into_iter()
            .filter(|e| e.from().key() == v.key() && e.to().key() == v.key())
            .collect()
    }

    /// Returns all vertices unreachable from a source: vertices descending only from a
    /// non-trivial strongly connected component.
    fn vertices_unreachable_from_sources(&self) -> Vec<&V> {
        let sources = self.get_sources();
        let mut reachable: HashSet<&V> = HashSet::new();
        for s in &sources {
            reachable.extend(self.get_descendants(s));
        }
        self.vertices().to_array().into_iter().filter(|v| !reachable.contains(*v)).collect()
    }

    /// Returns the vertices in this graph.
    fn get_vertices(&self) -> HashSet<&V> {
        self.vertices().to_array().into_iter().collect()
    }

    /// Returns the vertices in this graph as a `Vec`.
    fn get_vertex_array(&self) -> Vec<&V> {
        self.vertices().to_array()
    }

    /// Returns the edges in this graph.
    fn get_edges(&self) -> HashSet<&E> {
        self.edges().to_array().into_iter().collect()
    }

    /// Returns the edges in this graph as a `Vec`.
    fn get_edge_array(&self) -> Vec<&E> {
        self.edges().to_array()
    }

    /// Returns the number of vertices in the graph.
    fn num_vertices(&self) -> usize {
        self.vertices().size()
    }

    /// Returns the number of edges in the graph.
    fn num_edges(&self) -> usize {
        self.edges().size()
    }

    /// Adds the specified vertex to the graph.
    fn add_vertex(&mut self, v: V) -> bool {
        self.vertices_mut().add(v)
    }

    /// Adds the specified edge to the graph.
    fn add_edge(&mut self, e: E) -> bool {
        self.edges_mut().add(e)
    }

    /// Removes `v` and all edges incident with it from the graph. Does nothing if `v` is not in
    /// the graph.
    fn remove_vertex(&mut self, v: &V) -> bool {
        self.vertices_mut().remove(v)
    }

    /// Removes `e` from the graph. No effect if `e` is not in the graph.
    fn remove_edge(&mut self, e: &E) -> bool {
        self.edges_mut().remove(e)
    }

    /// Returns true iff `v` is in the graph.
    fn contains_vertex(&self, v: &V) -> bool {
        self.vertices().contains(v)
    }

    /// Returns true iff the graph contains `e`.
    fn contains_edge(&self, e: &E) -> bool {
        self.edges().contains(e)
    }

    /// Returns the number of vertices with out valence zero.
    fn num_sinks(&self) -> usize {
        self.get_sinks().len()
    }

    /// Returns the number of vertices with in valence zero.
    fn num_sources(&self) -> usize {
        self.get_sources().len()
    }

    /// Returns the vertices with no incoming edges.
    fn get_sources(&self) -> Vec<&V> {
        self.vertices().to_array().into_iter().filter(|v| self.in_valence(*v) == 0).collect()
    }

    /// Returns the vertices with no outgoing edges.
    fn get_sinks(&self) -> Vec<&V> {
        self.vertices().to_array().into_iter().filter(|v| self.out_valence(*v) == 0).collect()
    }

    /// Returns all vertices within the same connected component as `v` (including `v` itself).
    fn get_vertices_in_containing_component<'a>(&'a self, v: &'a V) -> HashSet<&'a V> {
        let mut in_component = HashSet::new();
        let mut pending = vec![v];
        while let Some(cur) = pending.pop() {
            for u in self.get_neighborhood(cur) {
                if in_component.insert(u) {
                    pending.push(u);
                }
            }
        }
        in_component
    }

    /// Removes from `other` every vertex and edge that is not also in this graph, leaving
    /// `other` as the intersection.
    fn intersection_with(&self, other: &mut dyn DirectedGraph<V, E>) {
        let mut vi = other.vertex_iterator();
        while vi.has_next() {
            match vi.next() {
                Ok(v) => {
                    if !self.contains_vertex(&v) {
                        vi.remove();
                    }
                }
                Err(_) => break,
            }
        }
        drop(vi);
        let mut ei = other.edge_iterator();
        while ei.has_next() {
            match ei.next() {
                Ok(e) => {
                    if !self.contains_edge(&e) {
                        ei.remove();
                    }
                }
                Err(_) => break,
            }
        }
    }

    /// Adds all vertices and edges of `other` to this graph in place.
    fn union_with(&mut self, other: &dyn DirectedGraph<V, E>) {
        let mut vi = other.vertex_iterator();
        while vi.has_next() {
            match vi.next() {
                Ok(v) => {
                    self.add_vertex(v);
                }
                Err(_) => break,
            }
        }
        let mut ei = other.edge_iterator();
        while ei.has_next() {
            match ei.next() {
                Ok(e) => {
                    self.add_edge(e);
                }
                Err(_) => break,
            }
        }
    }

    /// Returns `v` and its neighbors (parents and children).
    fn get_neighborhood<'a>(&'a self, v: &'a V) -> HashSet<&'a V> {
        let mut neighborhood = self.get_children(v);
        neighborhood.extend(self.get_parents(v));
        neighborhood.insert(v);
        neighborhood
    }

    /// Returns the vertices in `vs` and their neighbors.
    fn get_neighborhood_of_set<'a>(&'a self, vs: &HashSet<&'a V>) -> HashSet<&'a V> {
        let mut neighborhood = HashSet::new();
        for v in vs {
            neighborhood.extend(self.get_neighborhood(*v));
        }
        neighborhood
    }

    /// Returns the referent of the object used to create `v`, if any.
    fn get_referent<'a>(&self, v: &'a V) -> Option<&'a dyn fmt::Display> {
        v.referent()
    }

    /// Returns all edges joining `from` to `to`. Recall that parallel edges are allowed.
    fn get_edges_between<'a>(&'a self, from: &'a V, to: &'a V) -> Vec<&'a E> {
        self.get_outgoing_edges(from).into_iter().filter(|e| e.to().key() == to.key()).collect()
    }

    /// Returns true iff the graph contains an edge from `parent` to `child`.
    fn are_related_as(&self, parent: &V, child: &V) -> bool {
        self.get_outgoing_edges(parent).into_iter().any(|e| e.to().key() == child.key())
    }

    /// Removes all vertices and edges from the graph without changing the space allocated.
    fn clear(&mut self) {
        self.edges_mut().clear();
        self.vertices_mut().clear();
        self.edge_attributes_mut().clear();
        self.vertex_attributes_mut().clear();
    }

    /// Returns the vertices having `o` as a referent.
    fn get_vertices_having_referent<'a>(&'a self, o: &dyn fmt::Display) -> Vec<&'a V> {
        let target = o.to_string();
        let mut result = Vec::new();
        let mut iter = self.vertex_iterator();
        while iter.has_next() {
            match iter.next() {
                Ok(v) => {
                    if v.referent().map(|r| r.to_string()) == Some(target.clone()) {
                        if let Some(actual) = self.vertices().get_keyed_object(v.key()) {
                            result.push(actual);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        result
    }

    /// Returns true iff all vertices and edges of `g` are in this graph.
    fn contains_as_subgraph(&self, g: &dyn DirectedGraph<V, E>) -> bool {
        let mut ei = g.edge_iterator();
        while ei.has_next() {
            match ei.next() {
                Ok(e) => {
                    if !self.contains_edge(&e) {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        let mut vi = g.vertex_iterator();
        while vi.has_next() {
            match vi.next() {
                Ok(v) => {
                    if !self.contains_vertex(&v) {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        true
    }

    /// Joins `other`'s vertices and edges into this graph. Unlike Java's `join`, this does not
    /// copy object-attribute values (see the trait-level doc comment); it behaves like
    /// [`union_with`](DirectedGraph::union_with).
    fn join(&mut self, other: &dyn DirectedGraph<V, E>) {
        self.union_with(other);
    }
}

/// Converts a collection of vertices into the set of their referents' display forms.
///
/// Port of `DirectedGraph#verts2referentSet(Collection<Vertex>)` (a `public static` utility, so
/// it is not tied to any particular graph instance). The original returns a `Set<Object>` relying
/// on `Object.equals`/`hashCode`; since [`Vertex::referent`] only exposes `Display`, referents are
/// compared and deduplicated by their string form instead. A vertex with no referent contributes
/// `None` to the set, matching the original's use of `null`.
#[allow(deprecated)]
pub fn verts_to_referent_set<'a, I>(verts: I) -> HashSet<Option<String>>
where
    I: IntoIterator<Item = &'a dyn Vertex>,
{
    verts.into_iter().map(|v| v.referent().map(|r| r.to_string())).collect()
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::util::exception::NoValueException;
    use crate::util::graph::graph_iterator::ConcurrentModificationError;
    use crate::util::graph::key_indexable_set::KeyIndexableSet;
    use crate::util::graph::keyed_object::KeyedObject;
    use crate::util::seam_stubs::AttributeLike;
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
        fn referent(&self) -> Option<&dyn fmt::Display> {
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

    impl<T: KeyedObject> AttributeManager<T> for MockAttributeManager<T> {
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
        fn get_value(&self, _obj: &T) -> Result<i32, NoValueException> {
            Err(NoValueException("mock: no value".to_string()))
        }

        fn set_value(&mut self, _obj: &T, _value: i32) {}
    }

    struct MockDirectedGraph {
        vertices: MockVertexSet,
        edges: MockEdgeSet,
        vertex_attrs: MockAttributeManager<MockVertex>,
        edge_attrs: MockAttributeManager<MockEdge>,
    }

    impl MockDirectedGraph {
        fn empty() -> Self {
            MockDirectedGraph {
                vertices: MockVertexSet { items: Vec::new(), modification_number: 0 },
                edges: MockEdgeSet { items: Vec::new(), modification_number: 0 },
                vertex_attrs: MockAttributeManager::default(),
                edge_attrs: MockAttributeManager::default(),
            }
        }
    }

    impl DirectedGraph<MockVertex, MockEdge> for MockDirectedGraph {
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

        fn vertex_attributes(&self) -> &dyn AttributeManager<MockVertex> {
            &self.vertex_attrs
        }

        fn vertex_attributes_mut(&mut self) -> &mut dyn AttributeManager<MockVertex> {
            &mut self.vertex_attrs
        }

        fn edge_attributes(&self) -> &dyn AttributeManager<MockEdge> {
            &self.edge_attrs
        }

        fn edge_attributes_mut(&mut self) -> &mut dyn AttributeManager<MockEdge> {
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
            Box::new(MockDirectedGraph {
                vertices: MockVertexSet {
                    items: self.vertices.items.clone(),
                    modification_number: 0,
                },
                edges: MockEdgeSet { items: self.edges.items.clone(), modification_number: 0 },
                vertex_attrs: MockAttributeManager::default(),
                edge_attrs: MockAttributeManager::default(),
            })
        }

        fn induced_subgraph(
            &self,
            vertex_set: &[&MockVertex],
        ) -> Box<dyn DirectedGraph<MockVertex, MockEdge>> {
            let verts: Vec<MockVertex> = vertex_set.iter().map(|v| (*v).clone()).collect();
            Box::new(MockDirectedGraph {
                vertices: MockVertexSet { items: verts, modification_number: 0 },
                edges: MockEdgeSet { items: Vec::new(), modification_number: 0 },
                vertex_attrs: MockAttributeManager::default(),
                edge_attrs: MockAttributeManager::default(),
            })
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

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut g: Box<dyn DirectedGraph<MockVertex, MockEdge>> = Box::new(MockDirectedGraph::empty());

        let v1 = MockVertex { key: 1 };
        let v2 = MockVertex { key: 2 };
        assert!(g.add_vertex(v1.clone()));
        assert!(g.add_vertex(v2.clone()));
        assert_eq!(g.num_vertices(), 2);

        let e = MockEdge { key: 100, from: v1.clone(), to: v2.clone() };
        assert!(g.add_edge(e));
        assert_eq!(g.num_edges(), 1);

        assert_eq!(g.in_valence(&v2), 1);
        assert_eq!(g.out_valence(&v1), 1);
        assert_eq!(g.num_loops(&v1), 0);
        assert_eq!(g.valence(&v1), 1);

        let children = g.get_children(&v1);
        assert!(children.iter().any(|c| c.key() == v2.key()));

        assert!(g.contains_vertex(&v1));
        assert!(g.are_related_as(&v1, &v2));
        assert!(!g.are_related_as(&v2, &v1));

        assert!(g.contains_as_subgraph(g.copy().as_ref()));

        g.clear();
        assert_eq!(g.num_vertices(), 0);
        assert_eq!(g.num_edges(), 0);
    }
}

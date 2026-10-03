//! Port of `ghidra.util.graph.Dominator`.
//!
//! This class contains the functions necessary to build the dominance graph of a directed graph.

use std::hash::Hash;
use std::sync::Arc;

use crate::util::graph::directed_graph::DirectedGraph;
use crate::util::graph::edge::Edge;
use crate::util::graph::path::Path;
use crate::util::graph::vertex::Vertex;
use crate::util::msg::Msg;

const WHITE: i32 = 0;
const GRAY: i32 = 1;

/// Builds the dominance graph of a directed graph.
///
/// Port of `ghidra.util.graph.Dominator` (deprecated since Ghidra 10.2, "no longer used or
/// tested. Use GraphAlgorithms"), a concrete class `extends DirectedGraph`. Following the
/// precedent [`DirectedGraph`] itself set for the same reason -- breaking a dependency cycle at
/// this node in the port graph -- this becomes a trait extending [`DirectedGraph`] rather than a
/// struct holding a `base` field, exactly like the sibling [`WeightedDigraph`
/// ](crate::util::graph::weighted_digraph::WeightedDigraph) already did for its own analogous
/// situation.
///
/// # Hooks standing in for five per-vertex/edge `Attribute`s and one `Path` field
///
/// Java's constructor allocates five `Attribute`s from the inherited `vertexAttributes()`/
/// `edgeAttributes()` machinery (`vertexColor: IntegerAttribute`, `callingParent:
/// ObjectAttribute`, `vertexWeight`/`edgeWeight: DoubleAttribute`, `vertexType: StringAttribute`)
/// plus a fresh `paths: Path` field. As [`WeightedDigraph`]'s own docs already explain for its
/// single `DoubleAttribute` field, none of these concrete `Attribute` types can be stored
/// directly as a field here: each borrows its owning `KeyIndexableSet` by reference for its whole
/// lifetime, incompatible with a struct that would also need to own that same set. This trait
/// therefore models all six as required hooks instead --
/// [`vertex_color`](Self::vertex_color)/[`set_vertex_color`](Self::set_vertex_color),
/// [`calling_parent_of`](Self::calling_parent_of)/
/// [`set_calling_parent_of`](Self::set_calling_parent_of),
/// [`vertex_weight_of`](Self::vertex_weight_of)/[`set_vertex_weight_of`
/// ](Self::set_vertex_weight_of), [`edge_weight_of`](Self::edge_weight_of)/
/// [`set_edge_weight_of`](Self::set_edge_weight_of), [`vertex_type_of`](Self::vertex_type_of)/
/// [`set_vertex_type_of`](Self::set_vertex_type_of), and [`paths`](Self::paths)/
/// [`paths_mut`](Self::paths_mut) -- an implementer supplies real backing storage for each
/// (plain `HashMap`s keyed by [`KeyedObject::key`](crate::util::graph::keyed_object::KeyedObject::key)
/// suffice; see this module's own tests for a working example), the same convention
/// [`WeightedDigraph::raw_weight`]/[`set_raw_weight`](crate::util::graph::weighted_digraph::WeightedDigraph::set_raw_weight)
/// already established.
///
/// # Hook standing in for canonical `Arc` identity within `paths`
///
/// [`Path`] compares its stored elements by `Arc::ptr_eq` (pointer identity), mirroring the *same*
/// reference-identity semantics Java's own `Path` class uses on its `Vector<Vertex>` object
/// references (see [`Path`]'s own docs). For that comparison to behave correctly, every time a
/// given graph vertex is pushed into a path, it must be wrapped in the *same* `Arc` used the
/// previous time -- exactly how Java repeatedly pushes the very same `Vertex` object reference.
/// [`vertex_handle`](Self::vertex_handle) is the hook that supplies this: an implementer caches
/// one `Arc<V>` per vertex key (by
/// [`KeyedObject::key`](crate::util::graph::keyed_object::KeyedObject::key)) and hands back the
/// same one on every call. Every *other* comparison in this class (`Vector.indexOf`,
/// `Vector.contains`, `Vertex.equals`) is Java value equality, not reference equality, and is
/// reproduced here via plain `V: Eq` comparisons on the `Arc`'s pointee -- only the one call to
/// `paths.containsInSomeElement(singlePath)` inside [`set_dominance`](Self::set_dominance)
/// actually needs the identity-preserving handles.
///
/// # Hooks standing in for two constructor-only capabilities
///
/// [`get_dominance_graph`](Self::get_dominance_graph) needs to construct a fresh, empty
/// `DirectedGraph` to populate and return (Java: `DirectedGraph dom = new Dominator();`, used
/// purely as an empty container -- the caller never calls a `Dominator`-specific method on it) and
/// to construct new `Edge`s to insert into it (Java: `new Edge(parent, next)`). Neither is
/// expressible generically inside a default trait method (there is no way to conjure a fresh
/// `Self` or a fresh `E` from nothing), so [`new_dominance_result`](Self::new_dominance_result)
/// and [`new_dominance_edge`](Self::new_dominance_edge) are two more required hooks.
///
/// # Not ported: the three constructors themselves
///
/// As with [`DirectedGraph`] and [`WeightedDigraph`], no constructor is modeled: allocating the
/// six pieces of storage above is an implementer's own responsibility. The two no-argument-ish
/// constructors (`Dominator(int, int)`, `Dominator()`) are pure allocation with no portable
/// default-method equivalent. The third, `Dominator(DirectedGraph cg)`, mixes allocation with
/// genuine traversal *logic* (copying vertices/edges from `cg`, skipping loops, resetting every
/// vertex to white); that logic is ported as the default method [`copy_from`](Self::copy_from),
/// which an implementer calls after constructing itself, reproducing the constructor's own body
/// exactly.
pub trait Dominator<V, E>: DirectedGraph<V, E>
where
    V: Vertex + Eq + Hash + Clone,
    E: Edge + Eq + Hash + Clone,
{
    // ---- Hooks: paths ----

    /// The list of complete root-to-leaf paths discovered so far by [`set_dominance`
    /// ](Self::set_dominance). Stands in for the private `paths: Path` field.
    fn paths(&self) -> &Path<V>;
    /// Mutable access to [`paths`](Self::paths).
    fn paths_mut(&mut self) -> &mut Path<V>;

    // ---- Hook: canonical per-vertex Arc handle, for Path's identity-based comparisons ----

    /// Returns the canonical [`Arc`] handle for `v`, creating and caching one on first use if
    /// necessary. See the trait's own docs on why this is needed for [`Path`]'s identity-based
    /// membership checks to behave correctly.
    fn vertex_handle(&mut self, v: &V) -> Arc<V>;

    // ---- Hooks: vertex color (IntegerAttribute) ----

    /// Get the raw stored color of `v`, or `None` if never set. Stands in for `vertexColor`.
    fn vertex_color(&self, v: &V) -> Option<i32>;
    /// Set the raw stored color of `v`. Stands in for `vertexColor`.
    fn set_vertex_color(&mut self, v: &V, color: i32);

    // ---- Hooks: calling parent (ObjectAttribute) ----

    /// Get the raw stored calling parent of `v`, or `None` if never set. Stands in for
    /// `callingParent`.
    fn calling_parent_of(&self, v: &V) -> Option<V>;
    /// Set the raw stored calling parent of `v`. Stands in for `callingParent`.
    fn set_calling_parent_of(&mut self, v: &V, parent: V);

    // ---- Hooks: vertex weight (DoubleAttribute) ----

    /// Get the raw stored weight of `v`, or `None` if never set. Stands in for `vertexWeight`.
    fn vertex_weight_of(&self, v: &V) -> Option<f64>;
    /// Set the raw stored weight of `v`. Stands in for `vertexWeight`.
    fn set_vertex_weight_of(&mut self, v: &V, weight: f64);

    // ---- Hooks: edge weight (DoubleAttribute) ----

    /// Get the raw stored weight of `e`, or `None` if never set. Stands in for `edgeWeight`.
    fn edge_weight_of(&self, e: &E) -> Option<f64>;
    /// Set the raw stored weight of `e`. Stands in for `edgeWeight`.
    fn set_edge_weight_of(&mut self, e: &E, weight: f64);

    // ---- Hooks: vertex type (StringAttribute) ----

    /// Get the raw stored type of `v`, or `None` if never set. Stands in for `vertexType`.
    fn vertex_type_of(&self, v: &V) -> Option<String>;
    /// Set the raw stored type of `v`. Stands in for `vertexType`.
    fn set_vertex_type_of(&mut self, v: &V, type_name: String);

    // ---- Hooks: constructing fresh results ----

    /// Construct a fresh, empty `DirectedGraph` for [`get_dominance_graph`
    /// ](Self::get_dominance_graph) to populate and return. Stands in for `new Dominator()` used
    /// purely as an empty container.
    fn new_dominance_result(&self) -> Box<dyn DirectedGraph<V, E>>;

    /// Construct a new edge from `from` to `to`. Stands in for `new Edge(parent, next)`.
    fn new_dominance_edge(&self, from: V, to: V) -> E;

    // ---- Default methods: the ported algorithm ----

    /// This aids in going back to the parent from which a vertex was accessed in the depth-first
    /// search.
    ///
    /// Port of `backTrack(Vertex)`.
    fn back_track(&self, v: &V) -> V {
        self.get_calling_parent(v)
    }

    /// Returns the vertex that is the dominator of `v`.
    ///
    /// Port of `getDominator(Vertex)`.
    fn get_dominator(&self, v: &V) -> V {
        let path_set = self.all_paths_containing(v);
        if path_set.is_empty() {
            return v.clone();
        }
        let path = path_set[0].clone();
        self.all_paths_contain(&path_set, v, &path)
    }

    /// Returns all paths that contain `v` which need to be considered when looking for the
    /// dominator of `v`. The longest path is placed first.
    ///
    /// Port of `allPathsContaining(Vertex)`.
    fn all_paths_containing(&self, v: &V) -> Vec<Vec<Arc<V>>> {
        let mut path_set: Vec<Vec<Arc<V>>> = Vec::new();
        let mut maxsize = 0usize;
        for tmp_path in self.paths().iter() {
            if tmp_path.iter().any(|arc| arc.as_ref() == v) {
                if tmp_path.len() > maxsize {
                    maxsize = tmp_path.len();
                    path_set.insert(0, tmp_path.clone());
                } else {
                    path_set.push(tmp_path.clone());
                }
            }
        }
        path_set
    }

    /// This takes the longest path that contains vertex `v` and looks to see if any of `v`'s
    /// ancestors from that path are contained in all other paths that contain `v`.
    ///
    /// Port of `allPathsContain(Vector, Vertex, Vector)`.
    ///
    /// # Panics
    /// Mirrors Java's `ArrayIndexOutOfBoundsException` (`Vector.elementAt(-1)`): if repeatedly
    /// walking backward through `path` exhausts every candidate ancestor without finding one
    /// contained in every element of `path_set`, this panics rather than looping forever or
    /// silently returning a wrong answer.
    fn all_paths_contain(&self, path_set: &[Vec<Arc<V>>], v: &V, path: &[Arc<V>]) -> V {
        let pos = path.iter().position(|arc| arc.as_ref() == v);
        let cand_index_start: i64 = match pos {
            Some(p) => p as i64 - 1,
            None => -2,
        };
        if cand_index_start < 0 {
            return v.clone();
        }
        let mut cand_index = cand_index_start as usize;
        let mut candidate = path[cand_index].as_ref().clone();
        loop {
            let all_contain =
                path_set.iter().all(|p| p.iter().any(|arc| arc.as_ref() == &candidate));
            if all_contain {
                return candidate;
            }
            cand_index = cand_index.checked_sub(1).expect(
                "INTERNAL: all_paths_contain ran out of candidate predecessors (mirrors Java's \
                 ArrayIndexOutOfBoundsException from Vector.elementAt(-1))",
            );
            candidate = path[cand_index].as_ref().clone();
        }
    }

    /// Goes to the next child of `v` that has not been visited and sets the calling parent to be
    /// `v` so that we can backtrack. Returns `None` if `v` has no white child.
    ///
    /// Port of `goToNextWhiteChild(Vertex)`.
    fn go_to_next_white_child(&mut self, v: &V) -> Option<V> {
        if self.has_white_child(v) {
            let children: Vec<V> = self.get_children(v).into_iter().cloned().collect();
            for next_child in children {
                if self.get_color(&next_child) == WHITE {
                    self.set_calling_parent(&next_child, v.clone());
                    return Some(next_child);
                }
            }
        }
        None
    }

    /// This makes a list of all the paths in the graph that terminate either because of a
    /// repeated vertex or hitting a sink. It then calls [`get_dominance_graph`
    /// ](Self::get_dominance_graph), which gets the dominator for every vertex and builds a
    /// dominance graph.
    ///
    /// Returns `None` if the graph does not have exactly one root (logging an error, matching
    /// Java's `return null`).
    ///
    /// Port of `setDominance()`.
    fn set_dominance(&mut self) -> Option<Box<dyn DirectedGraph<V, E>>> {
        let roots: Vec<V> = self.get_sources().into_iter().cloned().collect();

        // Check to make sure we have only one root. Java's own `else` branch here
        // (`roots.length` being neither >1 nor ==0) is unreachable dead code (a `usize` length
        // that is `!= 1` is always either `> 1` or `== 0`), so it is not reproduced.
        if roots.len() != 1 {
            if roots.len() > 1 {
                Msg::error(
                    "Dominator",
                    &"this should not print because it means you have more than 1 root",
                );
            } else {
                Msg::error("Dominator", &"You need a root,no root provided");
            }
            return None;
        }

        let root = roots[0].clone();
        let mut v = root.clone();
        let mut single_path: Vec<Arc<V>> = Vec::new();

        // set the dominance on a graph
        while self.has_white_child(&v) || v != root {
            v = self.add_to_paths(v, &mut single_path);
            if !self.paths().contains_in_some_element(&single_path) {
                self.paths_mut().push(single_path.clone());
                single_path =
                    self.paths().last().expect("just pushed above").clone();
            }
            self.whiten_children(&v);
            v = self.back_track(&v);
            single_path.pop();
        }
        Some(self.get_dominance_graph())
    }

    /// This iterates through the vertices of the graph and gets the dominator for each. In a new
    /// graph, it adds each vertex and an edge between the vertex and its dominator.
    ///
    /// Port of `getDominanceGraph()`.
    ///
    /// # Panics
    /// Mirrors Java's `ArrayIndexOutOfBoundsException` from `getSources()[0]`: panics if the
    /// graph has no source at all (e.g. every vertex has an incoming edge, as with a graph
    /// consisting only of cycles).
    fn get_dominance_graph(&self) -> Box<dyn DirectedGraph<V, E>> {
        let mut dom = self.new_dominance_result();

        if self.num_vertices() == 1 {
            let only = self.get_sources().first().cloned().cloned().expect(
                "INTERNAL: single-vertex graph has no source (mirrors Java's \
                 ArrayIndexOutOfBoundsException from getSources()[0])",
            );
            dom.add_vertex(only);
            return dom;
        }

        // Java re-fetches `getSources()[0]` on every loop iteration; this graph is never mutated
        // during the loop (only the separate `dom` result is), so caching it once is behaviorally
        // identical.
        let first_source = self.get_sources().first().cloned().cloned().expect(
            "INTERNAL: graph has no source (mirrors Java's ArrayIndexOutOfBoundsException from \
             getSources()[0])",
        );
        let all_vertices: Vec<V> = self.get_vertex_array().into_iter().cloned().collect();
        for next in all_vertices {
            if next != first_source {
                let parent = self.get_dominator(&next);
                dom.add_vertex(next.clone());
                dom.add_vertex(parent.clone());
                let edge = self.new_dominance_edge(parent, next);
                dom.add_edge(edge);
            }
        }
        dom
    }

    /// Adds vertices to `single_path` starting from `v`, descending through white children until
    /// none remain (a sink) or the remaining children are all already visited (a loop).
    ///
    /// Port of `addToPaths(Vertex, Vector)`.
    fn add_to_paths(&mut self, v: V, single_path: &mut Vec<Arc<V>>) -> V {
        let mut v = v;
        self.set_color(&v, GRAY);
        if !single_path.iter().any(|arc| arc.as_ref() == &v) {
            let handle = self.vertex_handle(&v);
            single_path.push(handle);
        }
        while self.has_white_child(&v) {
            v = self
                .go_to_next_white_child(&v)
                .expect("has_white_child guarantees a white child exists");
            self.set_color(&v, GRAY);
            let handle = self.vertex_handle(&v);
            single_path.push(handle);
        }
        v
    }

    /// Checks to see if there are any children of `v` not yet visited.
    ///
    /// Port of the private `hasWhiteChild(Vertex)`.
    fn has_white_child(&self, v: &V) -> bool {
        self.get_children(v).into_iter().any(|c| self.get_color(c) == WHITE)
    }

    /// Whitens the children of `v`. Only called after `v` has no more children left and we have
    /// backtracked to the calling parent of `v`, to ensure we don't miss out on any paths that
    /// contain a child of `v` which has other parents.
    ///
    /// Port of `whitenChildren(Vertex)`.
    ///
    /// # Panics
    /// Mirrors Java's uncaught `NoValueException` (from `getCallingParent`): panics if any child
    /// of `v` was never assigned a calling parent at all (e.g. an isolated vertex that happens to
    /// be adjacent to `v` but was never actually reached by the traversal).
    fn whiten_children(&mut self, v: &V) {
        let children: Vec<V> = self.get_children(v).into_iter().cloned().collect();
        for next in children {
            if self.get_calling_parent(&next) == *v {
                self.set_color(&next, WHITE);
            }
        }
    }

    /// Sets the color of a vertex, if it is in the graph.
    ///
    /// Port of `setColor(Vertex, int)`.
    fn set_color(&mut self, v: &V, color: i32) {
        if self.contains_vertex(v) {
            self.set_vertex_color(v, color);
        }
    }

    /// Gets the color of a vertex, defaulting to white if never set.
    ///
    /// Port of `getColor(Vertex)`, which catches `NoValueException` and returns `white`.
    fn get_color(&self, v: &V) -> i32 {
        self.vertex_color(v).unwrap_or(WHITE)
    }

    /// Sets the calling parent of a vertex, if it is in the graph.
    ///
    /// Port of `setCallingParent(Vertex, Vertex)`.
    fn set_calling_parent(&mut self, v: &V, parent: V) {
        if self.contains_vertex(v) {
            self.set_calling_parent_of(v, parent);
        }
    }

    /// Gets the calling parent of a vertex.
    ///
    /// Port of `getCallingParent(Vertex)`.
    ///
    /// # Panics
    /// Unlike [`get_color`](Self::get_color)/[`get_vertex_weight`](Self::get_vertex_weight)/
    /// [`get_edge_weight`](Self::get_edge_weight), Java's `getCallingParent` does *not* catch
    /// `NoValueException` -- a real inconsistency in the Java class, faithfully preserved here as
    /// a panic when no calling parent has ever been set for `v`.
    fn get_calling_parent(&self, v: &V) -> V {
        self.calling_parent_of(v).expect(
            "INTERNAL: no calling parent set for vertex (mirrors Java's uncaught \
             NoValueException from ObjectAttribute.getValue)",
        )
    }

    /// Sets the type of a vertex, if it is in the graph.
    ///
    /// Port of `setType(Vertex, String)`.
    fn set_type(&mut self, v: &V, type_name: String) {
        if self.contains_vertex(v) {
            self.set_vertex_type_of(v, type_name);
        }
    }

    /// Gets the type of a vertex.
    ///
    /// Port of `getType(KeyedObject)`, narrowed to `V` (see this trait's own docs -- Dominator
    /// never calls it with anything but a `Vertex` of its own graph).
    ///
    /// # Panics
    /// Like [`get_calling_parent`](Self::get_calling_parent), Java's `getType` does *not* catch
    /// `NoValueException` either -- faithfully preserved here as a panic when no type has ever
    /// been set for `v`.
    fn get_type(&self, v: &V) -> String {
        self.vertex_type_of(v).expect(
            "INTERNAL: no type set for vertex (mirrors Java's uncaught NoValueException from \
             StringAttribute.getValue)",
        )
    }

    /// Sets the weight of a vertex, if it is in the graph.
    ///
    /// Port of `setWeight(Vertex, double)`.
    fn set_vertex_weight(&mut self, v: &V, weight: f64) {
        if self.contains_vertex(v) {
            self.set_vertex_weight_of(v, weight);
        }
    }

    /// Gets the weight of a vertex, defaulting to `0.0` if never set.
    ///
    /// Port of `getWeight(Vertex)`, which catches `NoValueException` and returns `0.0`.
    fn get_vertex_weight(&self, v: &V) -> f64 {
        self.vertex_weight_of(v).unwrap_or(0.0)
    }

    /// Sets the weight of an edge, if it is in the graph.
    ///
    /// Port of `setWeight(Edge, double)`.
    fn set_edge_weight(&mut self, e: &E, weight: f64) {
        if self.contains_edge(e) {
            self.set_edge_weight_of(e, weight);
        }
    }

    /// Gets the weight of an edge, defaulting to `0.0` if never set.
    ///
    /// Port of `getWeight(Edge)`, which catches `NoValueException` and returns `0.0`.
    fn get_edge_weight(&self, e: &E) -> f64 {
        self.edge_weight_of(e).unwrap_or(0.0)
    }

    /// Copies the vertices and non-loop edges of `cg` into this (already-constructed, empty)
    /// graph, resetting every copied vertex's color to white.
    ///
    /// Port of the traversal logic inside the third constructor, `Dominator(DirectedGraph cg)`
    /// (`this()` first, i.e. fresh storage allocation -- an implementer's own responsibility, not
    /// modeled here; see the trait's own docs). Callers invoke this immediately after
    /// constructing a fresh, empty implementer instance.
    fn copy_from(&mut self, cg: &dyn DirectedGraph<V, E>) {
        let mut vi = cg.vertex_iterator();
        while vi.has_next() {
            match vi.next() {
                Ok(v) => {
                    self.add_vertex(v.clone());
                    self.set_color(&v, WHITE);
                }
                Err(_) => break,
            }
        }
        drop(vi);
        let mut ei = cg.edge_iterator();
        while ei.has_next() {
            match ei.next() {
                Ok(e) => {
                    if e.to().key() != e.from().key() {
                        self.add_edge(e);
                    }
                }
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

    #[derive(Clone, Debug)]
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

    /// A real, working `Dominator` implementor. Every hook is backed by a plain `HashMap` keyed
    /// by vertex/edge key, matching the trait's own docs on why the real `Attribute` types can't
    /// be stored directly.
    #[derive(Default)]
    struct MockDominator {
        vertices: MockVertexSet,
        edges: MockEdgeSet,
        vertex_attrs: MockAttributeManager<MockVertex>,
        edge_attrs: MockAttributeManager<MockEdge>,
        paths: Path<MockVertex>,
        vertex_handles: HashMap<i64, Arc<MockVertex>>,
        colors: HashMap<i64, i32>,
        calling_parents: HashMap<i64, MockVertex>,
        vertex_weights: HashMap<i64, f64>,
        edge_weights: HashMap<i64, f64>,
        vertex_types: HashMap<i64, String>,
    }

    impl Default for MockVertexSet {
        fn default() -> Self {
            MockVertexSet { items: Vec::new(), modification_number: 0 }
        }
    }
    impl Default for MockEdgeSet {
        fn default() -> Self {
            MockEdgeSet { items: Vec::new(), modification_number: 0 }
        }
    }

    #[allow(deprecated)]
    impl DirectedGraph<MockVertex, MockEdge> for MockDominator {
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
            let mut copy = MockDominator::default();
            copy.vertices.items = self.vertices.items.clone();
            copy.edges.items = self.edges.items.clone();
            Box::new(copy)
        }
        fn induced_subgraph(
            &self,
            vertex_set: &[&MockVertex],
        ) -> Box<dyn DirectedGraph<MockVertex, MockEdge>> {
            let mut copy = MockDominator::default();
            copy.vertices.items = vertex_set.iter().map(|v| (*v).clone()).collect();
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

    impl Dominator<MockVertex, MockEdge> for MockDominator {
        fn paths(&self) -> &Path<MockVertex> {
            &self.paths
        }
        fn paths_mut(&mut self) -> &mut Path<MockVertex> {
            &mut self.paths
        }
        fn vertex_handle(&mut self, v: &MockVertex) -> Arc<MockVertex> {
            self.vertex_handles.entry(v.key).or_insert_with(|| Arc::new(v.clone())).clone()
        }
        fn vertex_color(&self, v: &MockVertex) -> Option<i32> {
            self.colors.get(&v.key).copied()
        }
        fn set_vertex_color(&mut self, v: &MockVertex, color: i32) {
            self.colors.insert(v.key, color);
        }
        fn calling_parent_of(&self, v: &MockVertex) -> Option<MockVertex> {
            self.calling_parents.get(&v.key).cloned()
        }
        fn set_calling_parent_of(&mut self, v: &MockVertex, parent: MockVertex) {
            self.calling_parents.insert(v.key, parent);
        }
        fn vertex_weight_of(&self, v: &MockVertex) -> Option<f64> {
            self.vertex_weights.get(&v.key).copied()
        }
        fn set_vertex_weight_of(&mut self, v: &MockVertex, weight: f64) {
            self.vertex_weights.insert(v.key, weight);
        }
        fn edge_weight_of(&self, e: &MockEdge) -> Option<f64> {
            self.edge_weights.get(&e.key).copied()
        }
        fn set_edge_weight_of(&mut self, e: &MockEdge, weight: f64) {
            self.edge_weights.insert(e.key, weight);
        }
        fn vertex_type_of(&self, v: &MockVertex) -> Option<String> {
            self.vertex_types.get(&v.key).cloned()
        }
        fn set_vertex_type_of(&mut self, v: &MockVertex, type_name: String) {
            self.vertex_types.insert(v.key, type_name);
        }
        fn new_dominance_result(&self) -> Box<dyn DirectedGraph<MockVertex, MockEdge>> {
            Box::new(MockDominator::default())
        }
        fn new_dominance_edge(&self, from: MockVertex, to: MockVertex) -> MockEdge {
            // A fresh, arbitrary key -- mirrors Java's `new Edge(parent, next)` picking up the
            // next `KeyedObjectFactory` key.
            MockEdge { key: 1_000_000 + from.key * 1000 + to.key, from, to }
        }
    }

    fn v(key: i64) -> MockVertex {
        MockVertex { key }
    }
    fn e(key: i64, from: i64, to: i64) -> MockEdge {
        MockEdge { key, from: v(from), to: v(to) }
    }

    #[test]
    fn get_color_defaults_to_white() {
        let g = MockDominator::default();
        assert_eq!(Dominator::get_color(&g, &v(1)), WHITE);
    }

    #[test]
    fn set_color_then_get_color_round_trips() {
        let mut g = MockDominator::default();
        g.add_vertex(v(1));
        g.set_color(&v(1), GRAY);
        assert_eq!(Dominator::get_color(&g, &v(1)), GRAY);
    }

    #[test]
    fn set_color_is_a_no_op_for_a_vertex_not_in_the_graph() {
        let mut g = MockDominator::default();
        g.set_color(&v(99), GRAY);
        assert_eq!(Dominator::get_color(&g, &v(99)), WHITE);
    }

    #[test]
    fn get_vertex_weight_and_edge_weight_default_to_zero() {
        let g = MockDominator::default();
        assert_eq!(g.get_vertex_weight(&v(1)), 0.0);
        assert_eq!(g.get_edge_weight(&e(1, 1, 2)), 0.0);
    }

    #[test]
    fn set_vertex_weight_then_get_round_trips() {
        let mut g = MockDominator::default();
        g.add_vertex(v(1));
        g.set_vertex_weight(&v(1), 4.5);
        assert_eq!(g.get_vertex_weight(&v(1)), 4.5);
    }

    #[test]
    fn get_calling_parent_panics_when_never_set() {
        // Preserved Java quirk: getCallingParent doesn't catch NoValueException.
        let g = MockDominator::default();
        let result = std::panic::catch_unwind(|| g.get_calling_parent(&v(1)));
        assert!(result.is_err());
    }

    #[test]
    fn get_type_panics_when_never_set() {
        let g = MockDominator::default();
        let result = std::panic::catch_unwind(|| g.get_type(&v(1)));
        assert!(result.is_err());
    }

    #[test]
    fn set_type_then_get_type_round_trips() {
        let mut g = MockDominator::default();
        g.add_vertex(v(1));
        g.set_type(&v(1), "block".to_string());
        assert_eq!(g.get_type(&v(1)), "block");
    }

    #[test]
    fn set_dominance_fails_with_no_roots() {
        let mut g = MockDominator::default();
        g.add_vertex(v(1));
        g.add_edge(e(1, 1, 1)); // Self-loop: v(1) has an incoming edge, so it's not a source.
        assert!(g.set_dominance().is_none());
    }

    #[test]
    fn set_dominance_fails_with_more_than_one_root() {
        let mut g = MockDominator::default();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        // No edges at all: both are sources.
        assert!(g.set_dominance().is_none());
    }

    /// A linear chain root -> a -> b: each vertex's immediate dominator is its unique
    /// predecessor.
    #[test]
    fn linear_chain_dominance() {
        let mut g = MockDominator::default();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.add_vertex(v(3));
        g.add_edge(e(10, 1, 2));
        g.add_edge(e(11, 2, 3));

        let dom = g.set_dominance().expect("single root");
        assert!(dom.contains_vertex(&v(1)));
        assert!(dom.contains_vertex(&v(2)));
        assert!(dom.contains_vertex(&v(3)));
        // dominator(2) == 1, dominator(3) == 2.
        assert!(dom.get_edges_between(&v(1), &v(2)).into_iter().any(|_| true));
        assert!(dom.get_edges_between(&v(2), &v(3)).into_iter().any(|_| true));
    }

    /// A diamond: root -> a, root -> b, a -> c, b -> c. `c` is reachable via two different paths,
    /// so its dominator is the common ancestor of both: root.
    #[test]
    fn diamond_dominance_finds_the_common_ancestor() {
        let mut g = MockDominator::default();
        g.add_vertex(v(1)); // root
        g.add_vertex(v(2)); // a
        g.add_vertex(v(3)); // b
        g.add_vertex(v(4)); // c
        g.add_edge(e(10, 1, 2));
        g.add_edge(e(11, 1, 3));
        g.add_edge(e(12, 2, 4));
        g.add_edge(e(13, 3, 4));

        let dom = g.set_dominance().expect("single root");
        // c's dominator must be the root (1), not a (2) or b (3).
        assert!(!dom.get_edges_between(&v(2), &v(4)).into_iter().any(|_| true));
        assert!(!dom.get_edges_between(&v(3), &v(4)).into_iter().any(|_| true));
        assert!(dom.get_edges_between(&v(1), &v(4)).into_iter().any(|_| true));
    }

    #[test]
    fn get_dominance_graph_single_vertex() {
        let mut g = MockDominator::default();
        g.add_vertex(v(1));
        let dom = g.get_dominance_graph();
        assert_eq!(dom.num_vertices(), 1);
        assert!(dom.contains_vertex(&v(1)));
    }

    #[test]
    #[should_panic]
    fn get_dominance_graph_panics_when_graph_has_no_source() {
        // A graph consisting only of a cycle has no source at all.
        let mut g = MockDominator::default();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.add_edge(e(1, 1, 2));
        g.add_edge(e(2, 2, 1));
        let _ = g.get_dominance_graph();
    }

    #[test]
    fn copy_from_copies_vertices_and_skips_loop_edges() {
        let mut source = MockDominator::default();
        source.add_vertex(v(1));
        source.add_vertex(v(2));
        source.add_edge(e(1, 1, 2));
        source.add_edge(e(2, 2, 2)); // Loop -- should be skipped.

        let mut dest = MockDominator::default();
        dest.copy_from(&source);

        assert!(dest.contains_vertex(&v(1)));
        assert!(dest.contains_vertex(&v(2)));
        assert!(dest.contains_edge(&e(1, 1, 2)));
        assert!(!dest.contains_edge(&e(2, 2, 2)));
        // Every copied vertex's color is reset to white.
        assert_eq!(Dominator::get_color(&dest, &v(1)), WHITE);
        assert_eq!(Dominator::get_color(&dest, &v(2)), WHITE);
    }

    #[test]
    fn back_track_delegates_to_get_calling_parent() {
        let mut g = MockDominator::default();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.set_calling_parent(&v(2), v(1));
        assert_eq!(g.back_track(&v(2)), v(1));
    }

    #[test]
    fn get_dominator_of_a_vertex_with_no_recorded_paths_is_itself() {
        let g = MockDominator::default();
        assert_eq!(g.get_dominator(&v(42)), v(42));
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let mut g: Box<dyn Dominator<MockVertex, MockEdge>> = Box::new(MockDominator::default());
        g.add_vertex(v(1));
        assert_eq!(Dominator::get_color(g.as_ref(), &v(1)), WHITE);
    }
}

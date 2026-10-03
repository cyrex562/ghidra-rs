//! Port of `ghidra.util.graph.VertexSet`.

use crate::util::datastruct::LongIntHashtable;
use crate::util::graph::edge::Edge;
use crate::util::graph::edge_set::EdgeSet;
use crate::util::graph::graph_iterator::{ConcurrentModificationError, GraphIterator};
use crate::util::graph::keyed_object::KeyedObject;
use crate::util::graph::vertex::Vertex;
use crate::util::msg::Msg;

/// `VertexSet` is a container class for objects of type `Vertex`. It is designed to be used in
/// conjunction with `EdgeSet` as part of `DirectedGraph`.
///
/// Port of `ghidra.util.graph.VertexSet` (deprecated since Ghidra 10.2, package-private).
///
/// # Adaptation: no stored `parentGraph`
///
/// The Java class stores a reference to its owning, *concrete* `ghidra.util.graph.DirectedGraph`
/// (`private final DirectedGraph parentGraph`), assigned in its constructor from a
/// partially-constructed `this` (`DirectedGraph`'s own constructor does `vertices = new
/// VertexSet(this, vertexCapacity); edges = new EdgeSet(this, edgeCapacity);`) -- an ownership
/// cycle (`VertexSet` <-> `EdgeSet`, both back-referencing their shared owner) Rust cannot express
/// directly, and which this crate's [`DirectedGraph`](crate::util::graph::DirectedGraph) trait
/// sidesteps entirely by never holding a real `VertexSet` (see that trait's own module docs).
/// Inspecting every real use of `parentGraph` in the Java source shows it is reached only two
/// ways, both of which resolve to the sibling `EdgeSet`:
/// - `parentGraph.remove(Edge)` is exactly `this.edges().remove(e)` (see
///   `DirectedGraph#remove(Edge)`);
/// - `parentGraph.edges()` is the `EdgeSet` itself.
///
/// So every method that used `parentGraph` here instead takes the owning [`EdgeSet`] as an
/// explicit parameter ([`remove`](VertexSet::remove), [`clear`](VertexSet::clear),
/// [`get_last_outgoing_edge`](VertexSet::get_last_outgoing_edge),
/// [`get_last_incoming_edge`](VertexSet::get_last_incoming_edge)) rather than storing it
/// permanently -- a mechanical adaptation for Rust's ownership rules, not a behavior change. The
/// real Java `EdgeSet#remove`/`#add` also mutate the *caller's* `VertexSet` first/last-edge
/// pointers as a side effect (via `vertices.setFirstOutgoingEdge(...)` etc., reached through the
/// same `parentGraph` back-reference on the `EdgeSet` side); since the [`EdgeSet`] trait here
/// carries no such back-reference either (see its own module docs), [`remove`](VertexSet::remove)
/// reproduces that bookkeeping explicitly by querying
/// [`EdgeSet::get_next_edge_with_same_from`]/[`EdgeSet::get_next_edge_with_same_to`] before each
/// edge removal, exactly mirroring what `EdgeSet#remove` computes internally
/// (`oldNextEdgeWithSameFrom`/`oldNextEdgeWithSameTo`) before mutating `VertexSet`'s pointers.
///
/// # Adaptation: `V: Clone`, `E: Clone`
///
/// Java stores `Vertex`/`Edge` *object references*: the same edge object can be pointed to by up
/// to four slots across this class's `first`/`lastOutgoingEdge`/`first`/`lastIncomingEdge` arrays
/// (aliased with the copy the owning `EdgeSet` holds), and the same vertex reference can be handed
/// out repeatedly by accessors. Rust has no shared-reference equivalent that also satisfies
/// [`KeyIndexableSet`](crate::util::graph::KeyIndexableSet)'s existing by-value `add` convention
/// (see that trait, which this class predates as a real implementation of), so `V`/`E` are
/// required to be small, cheaply-cloned handle types (as every `Vertex`/`Edge` implementor in this
/// crate's own tests already is) and are cloned wherever Java would alias an existing reference.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub struct VertexSet<V: Vertex + Clone, E: Edge + Clone> {
    modification_number: i64,
    capacity: usize,
    next_index: usize,
    key_indices: LongIntHashtable,
    first_outgoing_edge: Vec<Option<E>>,
    first_incoming_edge: Vec<Option<E>>,
    last_outgoing_edge: Vec<Option<E>>,
    last_incoming_edge: Vec<Option<E>>,
    vertices: Vec<Option<V>>,
}

#[allow(deprecated)]
impl<V: Vertex + Clone, E: Edge + Clone> VertexSet<V, E> {
    /// Constructor.
    ///
    /// `capacity` is the number of vertices that may be held without invoking [`grow`](Self::grow).
    ///
    /// Java: `public VertexSet(DirectedGraph parent, int capacity)`. The `parent` parameter is
    /// dropped; see the struct-level docs.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(10);
        VertexSet {
            modification_number: 0,
            capacity,
            next_index: 0,
            key_indices: LongIntHashtable::with_capacity(capacity as i32),
            first_outgoing_edge: (0..capacity).map(|_| None).collect(),
            first_incoming_edge: (0..capacity).map(|_| None).collect(),
            last_outgoing_edge: (0..capacity).map(|_| None).collect(),
            last_incoming_edge: (0..capacity).map(|_| None).collect(),
            vertices: (0..capacity).map(|_| None).collect(),
        }
    }

    /// Return the internal index of the given vertex within this vertex set, or `None` if the
    /// `KeyedObject` is not in the `VertexSet`.
    ///
    /// Java: `int index(Vertex v)` (returns `-1` on `NoValueException` instead of `None`).
    fn index(&self, v: &V) -> Option<usize> {
        self.key_indices.get(v.key()).ok().map(|i| i as usize)
    }

    /// Adds the given vertex to the vertex set, if it does not already contain it.
    ///
    /// Returns true if and only if the vertex was successfully added.
    ///
    /// Java: `public boolean add(Vertex v)`.
    pub fn add(&mut self, v: V) -> bool {
        let key = v.key();
        if self.key_indices.contains(key) {
            return false;
        }
        if self.next_index >= self.capacity {
            self.grow();
        }
        self.key_indices.put(key, self.next_index as i32);
        self.vertices[self.next_index] = Some(v);
        self.next_index += 1;
        self.modification_number += 1;
        true
    }

    /// Removes the given vertex from this vertex set if it contains it, cascading removal to
    /// every edge incident with it. `edges` is the [`EdgeSet`] of the owning graph (see the
    /// struct-level docs for why this is a parameter rather than a stored `parentGraph`).
    ///
    /// Returns true if and only if the vertex was successfully removed.
    ///
    /// Java: `public boolean remove(Vertex v)`.
    pub fn remove(&mut self, v: &V, edges: &mut dyn EdgeSet<E>) -> bool {
        let Some(index) = self.index(v) else {
            return false;
        };

        while let Some(e) = self.first_outgoing_edge[index].clone() {
            let next = edges.get_next_edge_with_same_from(&e).cloned();
            edges.remove(&e);
            self.first_outgoing_edge[index] = next;
        }
        while let Some(e) = self.first_incoming_edge[index].clone() {
            let next = edges.get_next_edge_with_same_to(&e).cloned();
            edges.remove(&e);
            self.first_incoming_edge[index] = next;
        }
        // Once every incident edge is gone, the last-edge pointers converge to None too (matching
        // the end state Java's EdgeSet#remove side effects would leave them in).
        self.last_outgoing_edge[index] = None;
        self.last_incoming_edge[index] = None;

        self.key_indices.remove(v.key());
        self.vertices[index] = None;
        self.modification_number += 1;
        true
    }

    /// Return the number of vertices in this `VertexSet`.
    ///
    /// Java: `public int size()`.
    pub fn size(&self) -> usize {
        self.key_indices.size() as usize
    }

    /// Return true iff the specified `Vertex` is contained in this `VertexSet`.
    ///
    /// Java: `public boolean contains(Vertex v)`.
    pub fn contains(&self, v: &V) -> bool {
        self.key_indices.contains(v.key())
    }

    /// Return the `Vertex` at the specified index. May be `None`.
    ///
    /// Java: `private Vertex getByIndex(int index)`.
    fn get_by_index(&self, index: usize) -> Option<&V> {
        self.vertices.get(index).and_then(|o| o.as_ref())
    }

    /// Return the number of sources: vertices with no incoming edges in the `VertexSet`.
    ///
    /// Java: `public int numSources()`.
    pub fn num_sources(&self) -> usize {
        (0..self.next_index)
            .filter(|&i| self.first_incoming_edge[i].is_none() && self.vertices[i].is_some())
            .count()
    }

    /// Return the number of sinks: vertices with no outgoing edges in the `VertexSet`.
    ///
    /// Java: `public int numSinks()`.
    pub fn num_sinks(&self) -> usize {
        (0..self.next_index)
            .filter(|&i| self.first_outgoing_edge[i].is_none() && self.vertices[i].is_some())
            .count()
    }

    /// Return all vertices in the `VertexSet` that have no incoming edges.
    ///
    /// Java: `Vertex[] getSources()`.
    pub fn get_sources(&self) -> Vec<&V> {
        (0..self.next_index)
            .filter(|&i| self.first_incoming_edge[i].is_none() && self.vertices[i].is_some())
            .map(|i| self.vertices[i].as_ref().unwrap())
            .collect()
    }

    /// Return all vertices in the `VertexSet` that have no outgoing edges.
    ///
    /// Java: `Vertex[] getSinks()`.
    pub fn get_sinks(&self) -> Vec<&V> {
        (0..self.next_index)
            .filter(|&i| self.first_outgoing_edge[i].is_none() && self.vertices[i].is_some())
            .map(|i| self.vertices[i].as_ref().unwrap())
            .collect()
    }

    /// Get the first outgoing edge in the internal structures for this `VertexSet`.
    ///
    /// Java: `Edge getFirstOutgoingEdge(Vertex v)`.
    pub fn get_first_outgoing_edge(&self, v: &V) -> Option<&E> {
        self.index(v).and_then(|i| self.first_outgoing_edge[i].as_ref())
    }

    /// Get the first incoming edge in the internal structures for this `VertexSet`.
    ///
    /// Java: `Edge getFirstIncomingEdge(Vertex v)`.
    pub fn get_first_incoming_edge(&self, v: &V) -> Option<&E> {
        self.index(v).and_then(|i| self.first_incoming_edge[i].as_ref())
    }

    /// Get the last outgoing edge for `v`, by walking the "next edge with same from" chain
    /// starting at [`get_first_outgoing_edge`](Self::get_first_outgoing_edge).
    ///
    /// Java: `Edge getLastOutgoingEdge(Vertex v)`. Rather than returning `lastOutgoingEdge[index]`
    /// directly (an O(1) lookup this class already maintains via
    /// [`set_last_outgoing_edge`](Self::set_last_outgoing_edge)), the real Java method
    /// recomputes the answer with an O(n) walk -- faithfully reproduced here rather than "fixed"
    /// into the cheaper lookup.
    pub fn get_last_outgoing_edge(&self, v: &V, edges: &dyn EdgeSet<E>) -> Option<E> {
        let index = self.index(v)?;
        let mut re = self.first_outgoing_edge[index].clone();
        let mut e = re.clone();
        while let Some(cur) = e.take() {
            re = Some(cur.clone());
            e = edges.get_next_edge_with_same_from(&cur).cloned();
        }
        re
    }

    /// Get the last incoming edge for `v`, by walking the "next edge with same to" chain starting
    /// at [`get_first_incoming_edge`](Self::get_first_incoming_edge).
    ///
    /// Java: `Edge getLastIncomingEdge(Vertex v)`. See
    /// [`get_last_outgoing_edge`](Self::get_last_outgoing_edge) for why this walks rather than
    /// returning the maintained `lastIncomingEdge[index]` directly.
    pub fn get_last_incoming_edge(&self, v: &V, edges: &dyn EdgeSet<E>) -> Option<E> {
        let index = self.index(v)?;
        let mut re = self.first_incoming_edge[index].clone();
        let mut e = re.clone();
        while let Some(cur) = e.take() {
            re = Some(cur.clone());
            e = edges.get_next_edge_with_same_to(&cur).cloned();
        }
        re
    }

    /// Set the first outgoing edge of `v` to be `e`. It is assumed that `v` has already been
    /// added to the graph.
    ///
    /// Java: `void setFirstOutgoingEdge(Vertex v, Edge e)`.
    pub fn set_first_outgoing_edge(&mut self, v: &V, e: Option<E>) {
        match self.index(v) {
            Some(i) => self.first_outgoing_edge[i] = e,
            None => log_no_value("setFirstOutgoingEdge", v, &e),
        }
    }

    /// Set the last outgoing edge of `v` to be `e`. It is assumed that `v` has already been added
    /// to the graph.
    ///
    /// Java: `void setLastOutgoingEdge(Vertex v, Edge e)`.
    pub fn set_last_outgoing_edge(&mut self, v: &V, e: Option<E>) {
        match self.index(v) {
            Some(i) => self.last_outgoing_edge[i] = e,
            None => log_no_value("setLastOutgoingEdge", v, &e),
        }
    }

    /// Set the first incoming edge of `v` to be `e`. It is assumed that `v` has already been added
    /// to the graph.
    ///
    /// Java: `void setFirstIncomingEdge(Vertex v, Edge e)`.
    pub fn set_first_incoming_edge(&mut self, v: &V, e: Option<E>) {
        match self.index(v) {
            Some(i) => self.first_incoming_edge[i] = e,
            None => log_no_value("setFirstIncomingEdge", v, &e),
        }
    }

    /// Set the last incoming edge of `v` to be `e`. It is assumed that `v` has already been added
    /// to the graph.
    ///
    /// Java: `void setLastIncomingEdge(Vertex v, Edge e)`.
    pub fn set_last_incoming_edge(&mut self, v: &V, e: Option<E>) {
        match self.index(v) {
            Some(i) => self.last_incoming_edge[i] = e,
            None => log_no_value("setLastIncomingEdge", v, &e),
        }
    }

    /// Remove all of the vertices from this `VertexSet` without changing the capacity. Much
    /// faster than removing each vertex individually. The `EdgeSet` for this graph gets cleared
    /// first.
    ///
    /// Java: `void clear()`.
    pub fn clear(&mut self, edges: &mut dyn EdgeSet<E>) {
        self.modification_number += 1;
        if edges.size() > 0 {
            edges.clear();
        }
        if self.size() > 0 {
            self.next_index = 0;
            self.key_indices.remove_all();
            for i in 0..self.capacity {
                self.first_outgoing_edge[i] = None;
                self.first_incoming_edge[i] = None;
                self.last_outgoing_edge[i] = None;
                self.last_incoming_edge[i] = None;
                self.vertices[i] = None;
            }
        }
    }

    /// Java: `Vertex getKeyedObject(long key)`.
    pub fn get_keyed_object(&self, key: i64) -> Option<&V> {
        if !self.key_indices.contains(key) {
            return None;
        }
        self.key_indices.get(key).ok().and_then(|i| self.vertices.get(i as usize)?.as_ref())
    }

    /// Return the number of vertices this `VertexSet` may hold without growing.
    ///
    /// Java: `public int capacity()`.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Increases the capacity of the `VertexSet` so additional vertices can be added.
    ///
    /// Java: `void grow()`.
    fn grow(&mut self) {
        self.modification_number += 1;
        if (self.key_indices.size() as i64 * 13) > (self.capacity as i64 * 9) {
            let new_capacity = ((self.key_indices.size() as f64 * 1.7).round() as usize) + 7;

            let mut new_first_outgoing: Vec<Option<E>> = (0..new_capacity).map(|_| None).collect();
            let mut new_first_incoming: Vec<Option<E>> = (0..new_capacity).map(|_| None).collect();
            let mut new_last_outgoing: Vec<Option<E>> = (0..new_capacity).map(|_| None).collect();
            let mut new_last_incoming: Vec<Option<E>> = (0..new_capacity).map(|_| None).collect();
            let mut new_vertices: Vec<Option<V>> = (0..new_capacity).map(|_| None).collect();

            self.next_index = 0;
            for i in 0..self.capacity {
                if self.vertices[i].is_some() {
                    let key = self.vertices[i].as_ref().unwrap().key();
                    new_vertices[self.next_index] = self.vertices[i].take();
                    new_first_outgoing[self.next_index] = self.first_outgoing_edge[i].take();
                    new_first_incoming[self.next_index] = self.first_incoming_edge[i].take();
                    new_last_outgoing[self.next_index] = self.last_outgoing_edge[i].take();
                    new_last_incoming[self.next_index] = self.last_incoming_edge[i].take();
                    self.key_indices.remove(key);
                    self.key_indices.put(key, self.next_index as i32);
                    self.next_index += 1;
                }
            }
            self.capacity = new_capacity;
            self.vertices = new_vertices;
            self.first_outgoing_edge = new_first_outgoing;
            self.first_incoming_edge = new_first_incoming;
            self.last_outgoing_edge = new_last_outgoing;
            self.last_incoming_edge = new_last_incoming;
        } else {
            self.tighten();
        }
    }

    /// Clean up the internal storage of the `VertexSet`.
    ///
    /// Java: `private void tighten()`.
    fn tighten(&mut self) {
        self.modification_number += 1;
        self.next_index = 0;
        for i in 0..self.capacity {
            if self.vertices[i].is_some() {
                if i > self.next_index {
                    let key = self.vertices[i].as_ref().unwrap().key();
                    self.vertices[self.next_index] = self.vertices[i].take();
                    self.first_outgoing_edge[self.next_index] = self.first_outgoing_edge[i].take();
                    self.first_incoming_edge[self.next_index] = self.first_incoming_edge[i].take();
                    self.last_outgoing_edge[self.next_index] = self.last_outgoing_edge[i].take();
                    self.last_incoming_edge[self.next_index] = self.last_incoming_edge[i].take();
                    self.key_indices.remove(key);
                    self.key_indices.put(key, self.next_index as i32);
                }
                self.next_index += 1;
            }
        }
    }

    /// Get the number of times this `VertexSet` has changed.
    ///
    /// Java: `public long getModificationNumber()`.
    pub fn get_modification_number(&self) -> i64 {
        self.modification_number
    }

    /// Return an iterator over all of the vertices in this `VertexSet`. The iterator becomes
    /// invalid and reports [`ConcurrentModificationError`] if any changes are made to the
    /// `VertexSet` after the iterator is created.
    ///
    /// Java: `public GraphIterator<Vertex> iterator()`. Returns a read-only iterator: its
    /// [`GraphIterator::remove`] always reports `false`, since removing a vertex through the
    /// iterator would need to cascade edge removal through the owning graph's `EdgeSet` (see
    /// [`remove`](Self::remove)), which this borrow-only iterator has no access to -- matching the
    /// same limitation this whole package's other placeholder/mock `GraphIterator` implementations
    /// already accept for the analogous situation (e.g. `KeyIndexableSet`'s and `EdgeSet`'s own
    /// doc-tests).
    pub fn iterator(&self) -> VertexSetIterator<'_, V, E> {
        VertexSetIterator::new(self)
    }

    /// Return the elements of this `VertexSet` as a `HashSet`.
    ///
    /// Java: `public Set<Vertex> toSet()`.
    pub fn to_set(&self) -> std::collections::HashSet<&V>
    where
        V: Eq + std::hash::Hash,
    {
        self.to_array().into_iter().collect()
    }

    /// Return the elements of this `VertexSet` as a `Vec`.
    ///
    /// Java: `public Vertex[] toArray()`.
    pub fn to_array(&self) -> Vec<&V> {
        self.vertices.iter().filter_map(|o| o.as_ref()).collect()
    }
}

/// Port of the `catch (ArrayIndexOutOfBoundsException exc)` handlers in
/// `setFirst/LastOutgoing/IncomingEdge`, which log via `Msg.error` (rather than propagating) when
/// `v` is not (yet) a member of this `VertexSet`.
#[allow(deprecated)]
fn log_no_value<V: Vertex, E: Edge>(method: &str, v: &V, e: &Option<E>) {
    Msg::error(
        "VertexSet",
        &format!(
            "No Value Exception in {method}()\tVertex: {}\tEdge: {}",
            v.key(),
            e.as_ref().map(|edge| edge.key()).map(|k| k.to_string()).unwrap_or_else(|| "null".to_string())
        ),
    );
}

/// Implements an `Iterator` for a [`VertexSet`].
///
/// Port of the private inner class `VertexSet.VertexSetIterator`.
#[allow(deprecated)]
pub struct VertexSetIterator<'a, V: Vertex + Clone, E: Edge + Clone> {
    set: &'a VertexSet<V, E>,
    current_position: Option<usize>,
    next_position: usize,
    set_modification_number: i64,
}

#[allow(deprecated)]
impl<'a, V: Vertex + Clone, E: Edge + Clone> VertexSetIterator<'a, V, E> {
    fn new(set: &'a VertexSet<V, E>) -> Self {
        let next_position = Self::find_next(set, 0);
        VertexSetIterator {
            set,
            current_position: None,
            next_position,
            set_modification_number: set.get_modification_number(),
        }
    }

    /// Java: `private void getNextPosition()`, restructured to compute the next occupied index
    /// starting at `from` rather than mutating `nextPosition` in place (this port doesn't start
    /// the search at `-1` the way Java's field does, since `usize` cannot represent that).
    fn find_next(set: &VertexSet<V, E>, mut from: usize) -> usize {
        while from < set.capacity() && set.get_by_index(from).is_none() {
            from += 1;
        }
        from
    }
}

#[allow(deprecated)]
impl<'a, V: Vertex + Clone, E: Edge + Clone> GraphIterator<V> for VertexSetIterator<'a, V, E> {
    /// Return true if there is another vertex in this iteration.
    ///
    /// Java: `public boolean hasNext() throws ConcurrentModificationException`.
    fn has_next(&self) -> bool {
        self.next_position < self.set.capacity()
    }

    /// Return the next `Vertex` in the iteration.
    ///
    /// Java: `public Vertex next() throws ConcurrentModificationException`.
    ///
    /// # Panics
    ///
    /// Panics once the iteration is exhausted, mirroring Java's unchecked
    /// `NoSuchElementException`.
    fn next(&mut self) -> Result<V, ConcurrentModificationError> {
        if self.set_modification_number != self.set.get_modification_number() {
            return Err(ConcurrentModificationError);
        }
        if self.next_position < self.set.capacity() {
            let pos = self.next_position;
            self.current_position = Some(pos);
            self.next_position = Self::find_next(self.set, pos + 1);
            return Ok(self.set.get_by_index(pos).expect("iterator position must be occupied").clone());
        }
        panic!("NoSuchElementException: VertexSet iterator has no more elements")
    }

    /// Remove the vertex returned by the most recent call to `next()`. Always returns `false`;
    /// see [`VertexSet::iterator`]'s doc comment for why.
    ///
    /// Java: `public boolean remove() throws ConcurrentModificationException`.
    fn remove(&mut self) -> bool {
        false
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::util::graph::key_indexable_set::KeyIndexableSet;
    use crate::util::seam_stubs::GraphIteratorLike;

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MockEdge {
        key: i64,
        from: i64,
        to: i64,
    }

    impl KeyedObject for MockEdge {
        fn key(&self) -> i64 {
            self.key
        }
    }

    impl Edge for MockEdge {
        fn from(&self) -> &dyn Vertex {
            unimplemented!("tests key MockEdge endpoints via from_key/to_key instead")
        }
        fn to(&self) -> &dyn Vertex {
            unimplemented!("tests key MockEdge endpoints via from_key/to_key instead")
        }
    }

    /// A minimal in-memory [`EdgeSet`] backing store, threaded through the same/next/previous
    /// pointers a real one would maintain, sufficient to exercise [`VertexSet::remove`]'s
    /// edge-cascading behavior and [`VertexSet::get_last_outgoing_edge`]/`get_last_incoming_edge`'s
    /// chain walk.
    #[derive(Default)]
    struct MockEdgeSet {
        edges: Vec<MockEdge>,
        modification_number: i64,
    }

    impl MockEdgeSet {
        fn add_edge(&mut self, key: i64, from: i64, to: i64) -> MockEdge {
            let e = MockEdge { key, from, to };
            self.edges.push(e.clone());
            self.modification_number += 1;
            e
        }
    }

    struct MockEdgeIter<'a> {
        remaining: std::slice::Iter<'a, MockEdge>,
    }
    impl<'a> GraphIteratorLike<MockEdge> for MockEdgeIter<'a> {
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
            self.edges.len()
        }
        fn capacity(&self) -> usize {
            self.edges.capacity()
        }
        fn add(&mut self, obj: MockEdge) -> bool {
            if self.contains(&obj) {
                return false;
            }
            self.edges.push(obj);
            self.modification_number += 1;
            true
        }
        fn remove(&mut self, obj: &MockEdge) -> bool {
            let before = self.edges.len();
            self.edges.retain(|e| e.key != obj.key);
            let removed = self.edges.len() != before;
            if removed {
                self.modification_number += 1;
            }
            removed
        }
        fn contains(&self, obj: &MockEdge) -> bool {
            self.edges.iter().any(|e| e.key == obj.key)
        }
        fn iterator(&self) -> Box<dyn GraphIteratorLike<MockEdge> + '_> {
            Box::new(MockEdgeIter { remaining: self.edges.iter() })
        }
        fn to_array(&self) -> Vec<&MockEdge> {
            self.edges.iter().collect()
        }
        fn get_keyed_object(&self, key: i64) -> Option<&MockEdge> {
            self.edges.iter().find(|e| e.key == key)
        }
    }

    impl EdgeSet<MockEdge> for MockEdgeSet {
        fn get_by_index(&self, index: usize) -> Option<&MockEdge> {
            self.edges.get(index)
        }
        fn index(&self, e: &MockEdge) -> Option<usize> {
            self.edges.iter().position(|edge| edge.key == e.key)
        }
        fn get_next_edge_with_same_from(&self, e: &MockEdge) -> Option<&MockEdge> {
            let i = self.index(e)?;
            self.edges[i + 1..].iter().find(|other| other.from == e.from)
        }
        fn get_next_edge_with_same_to(&self, e: &MockEdge) -> Option<&MockEdge> {
            let i = self.index(e)?;
            self.edges[i + 1..].iter().find(|other| other.to == e.to)
        }
        fn get_previous_edge_with_same_from(&self, e: &MockEdge) -> Option<&MockEdge> {
            let i = self.index(e)?;
            self.edges[..i].iter().rev().find(|other| other.from == e.from)
        }
        fn get_previous_edge_with_same_to(&self, e: &MockEdge) -> Option<&MockEdge> {
            let i = self.index(e)?;
            self.edges[..i].iter().rev().find(|other| other.to == e.to)
        }
        fn clear(&mut self) {
            self.edges.clear();
            self.modification_number += 1;
        }
        fn grow(&mut self) {
            self.edges.reserve(self.edges.len() + 1);
        }
    }

    fn v(key: i64) -> MockVertex {
        MockVertex { key }
    }

    #[test]
    fn new_clamps_capacity_to_a_minimum_of_ten() {
        let set: VertexSet<MockVertex, MockEdge> = VertexSet::new(2);
        assert_eq!(set.capacity(), 10);
        let set: VertexSet<MockVertex, MockEdge> = VertexSet::new(50);
        assert_eq!(set.capacity(), 50);
    }

    #[test]
    fn add_and_contains_and_size() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        assert!(set.add(v(1)));
        assert!(set.contains(&v(1)));
        assert_eq!(set.size(), 1);
        assert_eq!(set.get_modification_number(), 1);
    }

    #[test]
    fn add_duplicate_key_returns_false_and_does_not_bump_modification_number() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        assert!(set.add(v(1)));
        assert!(!set.add(v(1)));
        assert_eq!(set.size(), 1);
        assert_eq!(set.get_modification_number(), 1);
    }

    #[test]
    fn get_keyed_object_and_to_array() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        set.add(v(2));
        assert_eq!(set.get_keyed_object(1), Some(&v(1)));
        assert_eq!(set.get_keyed_object(99), None);
        let mut arr: Vec<i64> = set.to_array().into_iter().map(|x| x.key).collect();
        arr.sort();
        assert_eq!(arr, vec![1, 2]);
    }

    #[test]
    fn to_set_deduplicates_by_key() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        set.add(v(2));
        let s = set.to_set();
        assert_eq!(s.len(), 2);
        assert!(s.contains(&v(1)));
    }

    #[test]
    fn first_and_last_edge_pointers_round_trip() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        let e1 = MockEdge { key: 100, from: 1, to: 2 };
        set.set_first_outgoing_edge(&v(1), Some(e1.clone()));
        assert_eq!(set.get_first_outgoing_edge(&v(1)), Some(&e1));

        set.set_first_incoming_edge(&v(1), Some(e1.clone()));
        assert_eq!(set.get_first_incoming_edge(&v(1)), Some(&e1));
    }

    #[test]
    fn set_edge_pointer_on_absent_vertex_logs_and_does_not_panic() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        // v(99) was never added; Java catches ArrayIndexOutOfBoundsException and logs via
        // Msg.error instead of throwing. This should not panic.
        set.set_first_outgoing_edge(&v(99), None);
    }

    #[test]
    fn num_sources_and_sinks_and_get_sources_and_sinks() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        set.add(v(2));
        // v1 -> v2 via edge 100: v1 has no incoming edge (source), v2 has no outgoing edge (sink).
        let e = MockEdge { key: 100, from: 1, to: 2 };
        set.set_first_outgoing_edge(&v(1), Some(e.clone()));
        set.set_first_incoming_edge(&v(2), Some(e));

        assert_eq!(set.num_sources(), 1);
        assert_eq!(set.num_sinks(), 1);
        let sources: Vec<i64> = set.get_sources().into_iter().map(|x| x.key).collect();
        assert_eq!(sources, vec![1]);
        let sinks: Vec<i64> = set.get_sinks().into_iter().map(|x| x.key).collect();
        assert_eq!(sinks, vec![2]);
    }

    #[test]
    fn get_last_outgoing_edge_walks_the_same_from_chain() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        set.add(v(2));
        set.add(v(3));
        let mut edges = MockEdgeSet::default();
        let e1 = edges.add_edge(100, 1, 2);
        let e2 = edges.add_edge(101, 1, 3);
        set.set_first_outgoing_edge(&v(1), Some(e1));
        set.set_last_outgoing_edge(&v(1), Some(e2.clone()));

        let last = set.get_last_outgoing_edge(&v(1), &edges);
        assert_eq!(last, Some(e2));
    }

    #[test]
    fn get_last_incoming_edge_walks_the_same_to_chain() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        set.add(v(2));
        let mut edges = MockEdgeSet::default();
        let e1 = edges.add_edge(100, 1, 2);
        let e2 = edges.add_edge(101, 3, 2);
        set.set_first_incoming_edge(&v(2), Some(e1));

        let last = set.get_last_incoming_edge(&v(2), &edges);
        assert_eq!(last, Some(e2));
    }

    #[test]
    fn remove_cascades_to_incident_edges_via_the_edge_set() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        set.add(v(2));
        set.add(v(3));

        let mut edges = MockEdgeSet::default();
        let e1 = edges.add_edge(100, 1, 2); // 1 -> 2
        let e2 = edges.add_edge(101, 1, 3); // 1 -> 3 (also from 1)
        set.set_first_outgoing_edge(&v(1), Some(e1.clone()));
        set.set_first_incoming_edge(&v(2), Some(e1));
        set.set_first_incoming_edge(&v(3), Some(e2.clone()));

        assert!(set.remove(&v(1), &mut edges));
        assert!(!set.contains(&v(1)));
        // Both edges incident to v1 were removed from the edge set too.
        assert_eq!(edges.size(), 0);
    }

    #[test]
    fn remove_missing_vertex_returns_false() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        let mut edges = MockEdgeSet::default();
        assert!(!set.remove(&v(1), &mut edges));
    }

    #[test]
    fn clear_empties_vertices_and_clears_a_non_empty_edge_set() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        set.add(v(2));
        let mut edges = MockEdgeSet::default();
        edges.add_edge(100, 1, 2);

        set.clear(&mut edges);
        assert_eq!(set.size(), 0);
        assert_eq!(edges.size(), 0);
        assert!(!set.contains(&v(1)));
    }

    #[test]
    fn grow_rebuilds_storage_and_preserves_membership() {
        // `grow()` is only invoked from `add()` once `next_index >= capacity`; with capacity 10,
        // that's the 11th `add`. At that point size == 11, so `(11*13=143) > (10*9=90)` takes the
        // reallocating branch (not `tighten()`).
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        for i in 0..11 {
            set.add(v(i));
        }
        assert!(set.capacity() > 10);
        assert_eq!(set.size(), 11);
        for i in 0..11 {
            assert!(set.contains(&v(i)), "expected vertex {i} to survive growth");
        }
    }

    #[test]
    fn grow_tightens_instead_of_reallocating_when_sparsely_filled() {
        // Fill a capacity-100 set to next_index == 90, remove 80 of those (size drops to 10 but
        // `next_index` -- the high-water mark of used slots -- is untouched by `remove()`), then
        // add 10 more (next_index climbs 90 -> 100, still without triggering `grow()`). The next
        // `add()` finally sees `next_index(100) >= capacity(100)` and calls `grow()`; at that
        // point size is 20 (the 10 survivors + the 10 just added), so `(20*13=260) <= (100*9=900)`
        // takes the `tighten()` branch: capacity stays 100, but the used slots are compacted.
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(100);
        for i in 0..90 {
            set.add(v(i));
        }
        let mut edges = MockEdgeSet::default();
        for i in 0..80 {
            set.remove(&v(i), &mut edges);
        }
        assert_eq!(set.size(), 10);
        for i in 90..100 {
            set.add(v(i));
        }
        assert_eq!(set.size(), 20);

        set.add(v(200)); // triggers grow() -> tighten() (capacity unchanged)

        assert_eq!(set.capacity(), 100);
        assert_eq!(set.size(), 21);
        for i in 80..90 {
            assert!(set.contains(&v(i)), "expected surviving vertex {i} after tighten");
        }
        for i in 90..100 {
            assert!(set.contains(&v(i)), "expected newly-added vertex {i} after tighten");
        }
        assert!(set.contains(&v(200)));
        for i in 0..80 {
            assert!(!set.contains(&v(i)), "removed vertex {i} should stay gone after tighten");
        }
    }

    #[test]
    fn iterator_visits_every_vertex_exactly_once() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        set.add(v(2));
        set.add(v(3));

        let mut iter = set.iterator();
        let mut seen = Vec::new();
        while iter.has_next() {
            seen.push(iter.next().unwrap().key);
        }
        seen.sort();
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn iterator_over_empty_set_has_no_next() {
        let set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        let iter = set.iterator();
        assert!(!iter.has_next());
    }

    #[test]
    fn iterator_reports_concurrent_modification() {
        // `VertexSetIterator::new` (via `VertexSet::iterator`) ties the iterator's lifetime to an
        // immutable borrow of the set, so a *live* mutation while an iterator is held would not
        // even borrow-check (matching Rust's stricter aliasing rules vs. Java's, where the same
        // scenario is only caught at runtime). Instead, construct the iterator directly (its
        // fields are visible to this child module) with a stale `set_modification_number`,
        // simulating "the set changed after this snapshot was taken" -- the same technique this
        // package's own `GraphIterator` doc-tests use for the identical situation (see
        // `graph_iterator.rs`'s `next_reports_concurrent_modification`).
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        let stale_number = set.get_modification_number() - 1;
        let mut iter = VertexSetIterator {
            set: &set,
            current_position: None,
            next_position: 0,
            set_modification_number: stale_number,
        };
        assert!(matches!(iter.next(), Err(ConcurrentModificationError)));
    }

    #[test]
    fn iterator_remove_is_a_documented_no_op() {
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        let mut iter = set.iterator();
        iter.next().unwrap();
        assert!(!iter.remove());
        assert!(set.contains(&v(1)));
    }

    #[test]
    #[should_panic(expected = "NoSuchElementException")]
    fn iterator_next_past_the_end_panics() {
        let set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        let mut iter = set.iterator();
        let _ = iter.next();
    }

    #[test]
    fn boxed_use_via_key_indexable_style_accessors_is_usable() {
        // Smoke test proving VertexSet is usable behind a plain reference the way DirectedGraph's
        // default methods use VertexSetLike, without requiring a real KeyIndexableSet impl.
        let mut set: VertexSet<MockVertex, MockEdge> = VertexSet::new(10);
        set.add(v(1));
        let set_ref: &VertexSet<MockVertex, MockEdge> = &set;
        assert_eq!(set_ref.size(), 1);
    }
}

//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use super::datastruct::NoSuchIndexException;
use super::exception::NoValueException;
use super::graph::key_indexable_set::KeyIndexableSet;
use super::graph::keyed_object::KeyedObject;
use super::graph::vertex::Vertex;

/// Placeholder for `ghidra.util.task.Task`, needed by [`crate::util::TrackedTaskListener`].
pub trait Task: Send + Sync {}

/// Placeholder for `ghidra.util.Location`, needed by [`crate::util::Issue`].
pub trait Location: Send + Sync {}

/// Placeholder for `ghidra.util.datastruct.WeakSet`, needed by
/// [`crate::util::datastruct::WeakDataStructureFactory`].
///
/// The factory only creates and returns these; no accessors are called on them here, so
/// this is a marker trait until the real `WeakSet` family is ported.
pub trait WeakSet<T>: Send + Sync {}

/// Placeholder for `ghidra.util.map.ValueMap`, needed by
/// [`crate::util::map::LongIteratorImpl`].
///
/// Only the accessors `LongIteratorImpl` needs are declared here; the real port carries
/// the full page-indexed property storage.
pub trait ValueMapLike {
    /// Returns whether there is a property value at `index`.
    fn has_property(&self, index: i64) -> bool;

    /// Get the next index (exclusive of `index`) where a property value exists.
    fn get_next_property_index(&self, index: i64) -> Result<i64, NoSuchIndexException>;

    /// Get the previous index (exclusive of `index`) where a property value exists.
    fn get_previous_property_index(&self, index: i64) -> Result<i64, NoSuchIndexException>;
}

/// Placeholder for `ghidra.util.graph.GraphIterator`, needed by
/// [`crate::util::graph::KeyIndexableSet`].
#[allow(deprecated)]
pub trait GraphIteratorLike<T: KeyedObject> {
    /// Returns true if the iterator has more elements.
    fn has_next(&self) -> bool;

    /// Returns the next element in the iteration.
    fn next(&mut self) -> Option<T>;

    /// Removes the last-returned object from the backing set.
    fn remove(&mut self) -> bool;
}

/// Placeholder for `ghidra.util.graph.attributes.Attribute`, needed by
/// [`crate::util::graph::attributes::AttributeManager`].
///
/// Only the accessor `AttributeManager` needs is declared here; the real port carries the
/// int/long/double/string/object value families and the owning-set bookkeeping.
pub trait AttributeLike<T: KeyedObject> {
    /// Undefine all values set for this attribute.
    fn clear(&mut self);
}

/// Placeholder for `ghidra.util.graph.attributes.IntegerAttribute`, needed by
/// [`crate::util::graph::directed_graph::DirectedGraph`] (`getLevels`/`complexityDepth`).
///
/// Only the int-valued get/set that make the returned attribute usable are declared here; the
/// real port carries the full `Attribute` value-family machinery.
#[allow(deprecated)]
pub trait IntegerAttributeLike<T: KeyedObject>: AttributeLike<T> {
    /// Returns the integer value associated with `obj`, or `NoValueException` if none is set.
    fn get_value(&self, obj: &T) -> Result<i32, NoValueException>;

    /// Sets the integer value associated with `obj`.
    fn set_value(&mut self, obj: &T, value: i32);
}

/// Placeholder for `ghidra.util.graph.VertexSet`, needed by
/// [`crate::util::graph::directed_graph::DirectedGraph`].
///
/// `DirectedGraph`'s defaults recover adjacency (sources/sinks/valence) by scanning `EdgeSet`
/// directly rather than through `VertexSet`'s first/last edge pointers, so the only surface
/// needed beyond the inherited [`KeyIndexableSet`] is `clear`; the real port also threads those
/// edge pointers on behalf of `EdgeSet`.
#[allow(deprecated)]
pub trait VertexSetLike<V: Vertex>: KeyIndexableSet<V> {
    /// Empties the vertex set while leaving capacity unchanged.
    fn clear(&mut self);
}

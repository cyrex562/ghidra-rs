//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use super::datastruct::NoSuchIndexException;
use super::exception::NoValueException;
use super::graph::key_indexable_set::KeyIndexableSet;
use super::graph::keyed_object::KeyedObject;
use super::graph::vertex::Vertex;
use crate::program::model::address::{AddressRange, AddressRangeIterator};

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

/// Placeholder for `ghidra.util.WordLocation`, needed by
/// [`crate::util::string_utilities::StringUtilities`] (`find_word`/`find_word_location`).
///
/// `WordLocation` is a concrete final class in Java, not an interface, but the port only
/// needs to hand callers *something* that carries the located word text without pulling in
/// the real type's full accessor set (`getContext`/`getStart`/`isEmpty`) up front; only
/// `getWord()` is consumed here, so only that accessor is declared.
pub trait WordLocationLike {
    /// Returns the located word text (or the empty string for an empty/`None` location).
    fn word(&self) -> &str;
}

/// Placeholder for `ghidra.util.TwoWayBreakdownAddressRangeIterator.Which`, needed by
/// [`crate::util::address_range_iterators::AddressRangeIteratorFactory`].
///
/// Stands in for the yielded `Map.Entry<AddressRange, Which>` pairs. `Which` in the Java
/// original is a 3-valued enum (`LEFT`, `RIGHT`, `BOTH`) with `inSubtract`/`inXor`/
/// `inIntersect` query methods; those are represented directly as flags here rather than
/// pulling in the real breakdown iterator.
pub struct TwoWayBreakdownEntry {
    pub range: AddressRange,
    /// Only the first (`a`) operand included this range (`Which::LEFT`).
    pub in_a_only: bool,
    /// Only the second (`b`) operand included this range (`Which::RIGHT`).
    pub in_b_only: bool,
    /// Both operands included this range (`Which::BOTH`).
    pub in_both: bool,
}

impl TwoWayBreakdownEntry {
    /// Mirrors `Which.inSubtract`: included in `a - b`.
    pub fn in_subtract(&self) -> bool {
        self.in_a_only
    }

    /// Mirrors `Which.inXor`: included in the symmetric difference `a xor b`.
    pub fn in_xor(&self) -> bool {
        self.in_a_only || self.in_b_only
    }

    /// Mirrors `Which.inIntersect`: included in `a ∩ b`.
    pub fn in_intersect(&self) -> bool {
        self.in_both
    }
}

/// Placeholder for `ghidra.framework.ApplicationProperties`, needed by
/// [`crate::util::application_utilities::ApplicationUtilities`].
///
/// `ApplicationProperties` extends `java.util.Properties` and carries the application's full
/// name/version/release/build-date key set; only the accessor consumed by `ApplicationUtilities`
/// is declared here, the real port carries the rest.
pub trait ApplicationPropertiesLike {
    /// Returns the application's name (empty string if undefined), mirroring
    /// `ApplicationProperties.getApplicationName()`.
    fn application_name(&self) -> String;
}

/// Placeholder for `ghidra.framework.ApplicationIdentifier`, needed by
/// [`crate::util::application_utilities::ApplicationUtilities`].
///
/// The real `ApplicationIdentifier` is constructed *from* an `ApplicationProperties`, and its
/// constructor itself calls `ApplicationUtilities.normalizeApplicationName` -- the other half of
/// the dependency cycle this port breaks. Because a placeholder trait cannot stand in for a
/// constructor, `ApplicationUtilities` methods that need an identifier take an already-built one
/// as a parameter rather than building it internally from `ApplicationPropertiesLike`; only the
/// two accessors consumed there are declared here.
pub trait ApplicationIdentifierLike {
    /// Returns the application name component, mirroring `getApplicationName()`.
    fn application_name(&self) -> String;

    /// Returns the full versioned identifier (`name_version_releaseName`), mirroring
    /// `toString()`.
    fn versioned_name(&self) -> String;
}

/// Placeholder for `ghidra.util.TwoWayBreakdownAddressRangeIterator`, needed by
/// [`crate::util::address_range_iterators::AddressRangeIteratorFactory`].
///
/// Only the construction contract is declared: given two forward- or backward-ordered
/// `AddressRange` iterators, classify every range as belonging to the first iterator only,
/// the second only, or both. The real port carries the lazy merge-scan algorithm that
/// computes this.
pub trait TwoWayBreakdownFactory {
    /// Builds the breakdown of `a` and `b` into per-range membership entries.
    fn build_breakdown(
        &self,
        a: Box<dyn Iterator<Item = AddressRange>>,
        b: Box<dyn Iterator<Item = AddressRange>>,
        forward: bool,
    ) -> Box<dyn Iterator<Item = TwoWayBreakdownEntry>>;
}

/// Placeholder for `ghidra.util.UnionAddressRangeIterator`, needed by
/// [`crate::util::address_range_iterators::AddressRangeIteratorFactory`].
///
/// Only the construction contract is declared: coalesce the ranges from one or more
/// `AddressRange` iterators into their lazily-computed union. The real port carries the
/// merge algorithm; once ported it will itself implement [`AddressRangeIterator`] and can
/// satisfy this trait directly.
pub trait UnionAddressRangeIteratorFactory {
    /// Builds the union of the ranges produced by `iterators`.
    fn build_union(
        &self,
        iterators: Vec<Box<dyn Iterator<Item = AddressRange>>>,
        forward: bool,
    ) -> Box<dyn AddressRangeIterator>;
}

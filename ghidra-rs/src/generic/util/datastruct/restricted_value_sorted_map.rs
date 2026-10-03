//! Port of `ghidra.generic.util.datastruct.RestrictedValueSortedMap`.
//!
//! A read-only, value-range-restricted view of a [`ValueSortedMap`], used to implement
//! [`ValueSortedMap::sub_map_by_value`]/[`head_map_by_value`](ValueSortedMap::head_map_by_value)/
//! [`tail_map_by_value`](ValueSortedMap::tail_map_by_value).
//!
//! ## Shape: shared bounds state, not four separate copies of the same math
//!
//! Java's `RestrictedValueSortedMap` has five `protected` helper methods (`getLowestIndex`,
//! `getHighestIndexPlusOne`, `inBounds`, `inBoundsOrNull`, `inBoundsOrNeg1`) that both the outer
//! class and its four `private`/`public` inner classes (`RestrictedEntryListIterator`,
//! `RestrictedKeyListIterator`, `RestrictedValueListIterator`, and the three list views) call via
//! Java's implicit enclosing-instance access. Rust has no enclosing-instance access, so this port
//! factors that shared state and logic into [`RestrictedState`], which [`RestrictedValueSortedMap`]
//! and each of its three list views hold their own (cheaply cloned) copy of.
//!
//! ## Materialized (eagerly-cloned) list views, not live index-based ones
//!
//! Java's `entrySet()`/`keySet()`/`values()` return views backed by live calls back into
//! `wrapped` on every access. This crate's [`ValueSortedMap`] trait already establishes eager
//! cloning as the norm for such views (see its own doc-test `SimpleValueSortedMap`), and doing so
//! here sidesteps a genuinely self-referential-struct problem (an iterator borrowing from a
//! `wrapped.entrySet()` call that would otherwise need to outlive the very statement that
//! produced it). `K: Clone, V: Clone` are required accordingly.
//!
//! ## Quirk: `getHighestIndexPlusOne()` is off by one (missing `+ 1`)
//!
//! ```java
//! protected int getHighestIndexPlusOne() {
//!     if (!hasTo) { return wrapped.size(); }
//!     final int i;
//!     if (toInclusive) { i = wrapped.values().floorIndex(toValue); }
//!     else { i = wrapped.values().lowerIndex(toValue); }
//!     if (i == -1) { return 0; }
//!     return i;          // <-- should be `return i + 1;` for an exclusive upper bound
//! }
//! ```
//! Both branches compute `i` as the *inclusive* index of the last in-bounds element, but the
//! method (named, and used elsewhere, as an *exclusive* upper bound -- "highest index, plus
//! one") returns `i` unmodified instead of `i + 1`. Every caller of `getHighestIndexPlusOne()`
//! therefore silently excludes the true last in-bounds element:
//! - [`size`](ValueSortedMap::size)/[`len`](crate::generic::util::datastruct::LesserList::len)
//!   (`restrictedSize() == getHighestIndexPlusOne() - getLowestIndex()`) undercounts by one
//!   whenever an upper (`to`) bound is set.
//! - `indexOf` on any of the three list views can incorrectly report "not found" (`-1`) for the
//!   true last in-bounds element, since it also routes through the buggy bound.
//!
//! Crucially, [`get`](crate::generic::util::datastruct::LesserList::get)/`contains`/iteration/
//! `to_vec` are all **unaffected**: Java's real per-element accessors use `inBounds(value)` (a
//! direct value comparison against `fromValue`/`toValue`) rather than `getHighestIndexPlusOne()`,
//! so they correctly include the last in-bounds element that `size()`/`indexOf` miss. This port
//! faithfully preserves that exact split -- see `size_undercounts_by_one_with_upper_bound_quirk`
//! and `index_of_last_element_incorrectly_reports_not_found_quirk` below.
//!
//! ## Quirk: `restrictedIsEmpty()` is inverted
//!
//! ```java
//! protected boolean restrictedIsEmpty() {
//!     return restrictedSize() != 0;
//! }
//! ```
//! This returns `true` when the view is **non-empty** and `false` when it **is** empty -- exactly
//! backwards. Faithfully reproduced (compounding with the off-by-one bug above, since it's built
//! on the already-undercounted `restrictedSize()`); see `is_empty_is_inverted_quirk` below.

use std::cmp::Ordering;

use crate::generic::util::datastruct::sorted_list::SortedList;
use crate::generic::util::datastruct::value_sorted_map::{
    LesserList, ValueSortedMap, ValueSortedMapEntryList, ValueSortedMapKeyList,
};
use crate::util::ListIterator;

/// One end of a value range: the bound value and whether it is inclusive. `None` (in
/// [`RestrictedState::from_bound`]/[`to_bound`](RestrictedState::to_bound)) means unbounded on
/// that side -- the `hasFrom`/`hasTo` pair collapses into `Option` being `Some`/`None`.
type Bound<V> = Option<(V, bool)>;

/// Shared bounds state and helper logic for [`RestrictedValueSortedMap`] and its list views. Port
/// of the fields (`wrapped`, `comparator`, `hasFrom`/`fromValue`/`fromInclusive`,
/// `hasTo`/`toValue`/`toInclusive`) and the five `protected` helper methods. See the module docs
/// for why this is a separate, cloned-per-view struct rather than shared enclosing-instance state.
struct RestrictedState<'a, K, V> {
    wrapped: &'a dyn ValueSortedMap<K, V>,
    comparator: &'a dyn Fn(&V, &V) -> Ordering,
    from_bound: Bound<V>,
    to_bound: Bound<V>,
}

impl<'a, K, V> Clone for RestrictedState<'a, K, V>
where
    V: Clone,
{
    fn clone(&self) -> Self {
        RestrictedState {
            wrapped: self.wrapped,
            comparator: self.comparator,
            from_bound: self.from_bound.clone(),
            to_bound: self.to_bound.clone(),
        }
    }
}

impl<'a, K, V> RestrictedState<'a, K, V> {
    /// Port of `RestrictedValueSortedMap.getLowestIndex()`.
    fn get_lowest_index(&self) -> usize {
        match &self.from_bound {
            None => 0,
            Some((from_value, from_inclusive)) => {
                let i = if *from_inclusive {
                    self.wrapped.values().ceiling_index(from_value)
                } else {
                    self.wrapped.values().higher_index(from_value)
                };
                if i == -1 {
                    self.wrapped.size()
                } else {
                    i as usize
                }
            }
        }
    }

    /// Port of `RestrictedValueSortedMap.getHighestIndexPlusOne()`. See the module docs for the
    /// faithfully-preserved off-by-one quirk (real Java also omits the `+ 1` its own name and
    /// every caller implies).
    fn get_highest_index_plus_one(&self) -> usize {
        match &self.to_bound {
            None => self.wrapped.size(),
            Some((to_value, to_inclusive)) => {
                let i = if *to_inclusive {
                    self.wrapped.values().floor_index(to_value)
                } else {
                    self.wrapped.values().lower_index(to_value)
                };
                if i == -1 {
                    0
                } else {
                    i as usize
                }
            }
        }
    }

    /// Port of `RestrictedValueSortedMap.restrictedSize()`. Inherits the off-by-one undercount
    /// from [`get_highest_index_plus_one`](Self::get_highest_index_plus_one) whenever a `to`
    /// bound is set. Saturates at `0` rather than following Java's raw `int` subtraction into
    /// negative territory in pathological cases -- `size()` cannot return a negative `usize`, and
    /// no test here exercises that corner (it would require an already-degenerate bound
    /// configuration to observe).
    fn restricted_size(&self) -> usize {
        let from_index = self.get_lowest_index();
        let to_index = self.get_highest_index_plus_one();
        to_index.saturating_sub(from_index)
    }

    /// Port of `RestrictedValueSortedMap.restrictedIsEmpty()`. See the module docs: this is
    /// genuinely inverted in real Java, and that inversion is faithfully preserved here.
    fn restricted_is_empty(&self) -> bool {
        self.restricted_size() != 0
    }

    /// Port of `RestrictedValueSortedMap.inBounds(V)`.
    fn in_bounds(&self, val: &V) -> bool {
        if let Some((from_value, from_inclusive)) = &self.from_bound {
            let from_cmp = (self.comparator)(val, from_value);
            if from_cmp == Ordering::Less || (from_cmp == Ordering::Equal && !from_inclusive) {
                return false;
            }
        }
        if let Some((to_value, to_inclusive)) = &self.to_bound {
            let to_cmp = (self.comparator)(val, to_value);
            if to_cmp == Ordering::Greater || (to_cmp == Ordering::Equal && !to_inclusive) {
                return false;
            }
        }
        true
    }

    /// Port of `RestrictedValueSortedMap.inBoundsOrNeg1(int)`.
    fn in_bounds_or_neg1(&self, index: i64) -> i64 {
        if index == -1 {
            return -1;
        }
        let lowest = self.get_lowest_index() as i64;
        if index < lowest {
            return -1;
        }
        if index >= self.get_highest_index_plus_one() as i64 {
            return -1;
        }
        index - lowest
    }

    /// Collects every entry of `wrapped` that is truly (correctly, per [`in_bounds`](Self::in_bounds))
    /// within this state's range, in ascending value order. Backs `get`/`contains`/iteration/
    /// `to_vec` for the three list views below -- all of which, per the module docs, are
    /// unaffected by the `getHighestIndexPlusOne` off-by-one bug in real Java.
    fn materialize_entries(&self) -> Vec<(K, V)>
    where
        K: Clone,
        V: Clone,
    {
        let full = self.wrapped.entry_set().to_vec();
        let lowest = self.get_lowest_index();
        full.into_iter().skip(lowest).take_while(|(_, v)| self.in_bounds(v)).collect()
    }
}

/// A materialized, index-addressable snapshot list, generic over what's being listed (whole
/// entries, just keys, or just values). Backs [`RestrictedEntryList`], [`RestrictedKeyList`], and
/// [`RestrictedSortedList`] below -- Java has three separate (nearly-identical) inner classes for
/// these because Java generics can't project "just the key" or "just the value" out of a stored
/// `Entry`; this single generic helper collapses that duplication.
struct Materialized<E> {
    items: Vec<E>,
}

impl<E: Clone + PartialEq> Materialized<E> {
    fn to_vec(&self) -> Vec<E> {
        self.items.clone()
    }

    fn get(&self, i: usize) -> &E {
        self.items.get(i).unwrap_or_else(|| panic!("IndexOutOfBoundsException: {i}"))
    }

    fn contains(&self, o: &E) -> bool {
        self.items.contains(o)
    }

    fn list_iterator(&self, index: usize) -> Box<dyn ListIterator<E> + '_>
    where
        E: 'static,
    {
        Box::new(MaterializedIterator { items: self.items.clone(), cursor: index })
    }
}

/// Backs `list_iterator` for [`Materialized`]. Port of `RestrictedEntryListIterator`/
/// `RestrictedKeyListIterator`/`RestrictedValueListIterator`, collapsed into one generic type for
/// the same reason [`Materialized`] is (see its docs). Since the underlying data is already the
/// correctly-value-filtered materialized snapshot, plain `0`-based indices here are equivalent to
/// Java's `wit.nextIndex() - getLowestIndex()`/`wit.previousIndex() - getLowestIndex()`.
struct MaterializedIterator<E> {
    items: Vec<E>,
    cursor: usize,
}

impl<E: Clone> ListIterator<E> for MaterializedIterator<E> {
    fn has_next(&self) -> bool {
        self.cursor < self.items.len()
    }

    fn next(&mut self) -> E {
        let e = self.items[self.cursor].clone();
        self.cursor += 1;
        e
    }

    fn has_previous(&self) -> bool {
        self.cursor > 0
    }

    fn previous(&mut self) -> E {
        self.cursor -= 1;
        self.items[self.cursor].clone()
    }

    fn next_index(&self) -> i64 {
        self.cursor as i64
    }

    fn previous_index(&self) -> i64 {
        self.cursor as i64 - 1
    }

    fn remove(&mut self) {
        panic!("UnsupportedOperationException");
    }

    fn set(&mut self, _e: E) {
        panic!("UnsupportedOperationException");
    }

    fn add(&mut self, _e: E) {
        panic!("UnsupportedOperationException");
    }
}

/// A list view suitable for [`ValueSortedMap::entry_set`] of [`RestrictedValueSortedMap`]. Port
/// of `RestrictedValueSortedMap.RestrictedValueSortedMapEntryList`.
pub struct RestrictedEntryList<'a, K, V> {
    state: RestrictedState<'a, K, V>,
    materialized: Materialized<(K, V)>,
}

impl<'a, K, V> LesserList<(K, V)> for RestrictedEntryList<'a, K, V>
where
    K: Clone + PartialEq + 'static,
    V: Clone + PartialEq + 'static,
{
    fn is_empty(&self) -> bool {
        self.state.restricted_is_empty()
    }

    fn len(&self) -> usize {
        self.state.restricted_size()
    }

    fn get(&self, i: usize) -> &(K, V) {
        self.materialized.get(i)
    }

    fn to_vec(&self) -> Vec<(K, V)> {
        self.materialized.to_vec()
    }

    fn list_iterator(&self, index: usize) -> Box<dyn ListIterator<(K, V)> + '_> {
        self.materialized.list_iterator(index)
    }

    fn index_of(&self, o: &(K, V)) -> i64 {
        self.state.in_bounds_or_neg1(self.state.wrapped.entry_set().index_of(o))
    }

    fn contains(&self, o: &(K, V)) -> bool {
        // Port of: `if (!wrapped.entrySet().contains(o)) return false; ... inBounds(val)`.
        if !self.state.wrapped.entry_set().contains(o) {
            return false;
        }
        self.state.in_bounds(&o.1)
    }

    fn poll(&mut self) -> Option<(K, V)> {
        panic!("UnsupportedOperationException");
    }

    fn remove(&mut self, _o: &(K, V)) -> bool {
        panic!("UnsupportedOperationException");
    }
}

impl<'a, K, V> ValueSortedMapEntryList<K, V> for RestrictedEntryList<'a, K, V>
where
    K: Clone + PartialEq + 'static,
    V: Clone + PartialEq + 'static,
{
}

/// A list view suitable for [`ValueSortedMap::key_set`] of [`RestrictedValueSortedMap`]. Port of
/// `RestrictedValueSortedMap.RestrictedValueSortedMapKeyList`.
pub struct RestrictedKeyList<'a, K, V> {
    state: RestrictedState<'a, K, V>,
    materialized: Materialized<K>,
}

impl<'a, K, V> LesserList<K> for RestrictedKeyList<'a, K, V>
where
    K: Clone + PartialEq + 'static,
    V: Clone + PartialEq + 'static,
{
    fn is_empty(&self) -> bool {
        self.state.restricted_is_empty()
    }

    fn len(&self) -> usize {
        self.state.restricted_size()
    }

    fn get(&self, i: usize) -> &K {
        self.materialized.get(i)
    }

    fn to_vec(&self) -> Vec<K> {
        self.materialized.to_vec()
    }

    fn list_iterator(&self, index: usize) -> Box<dyn ListIterator<K> + '_> {
        self.materialized.list_iterator(index)
    }

    fn index_of(&self, o: &K) -> i64 {
        self.state.in_bounds_or_neg1(self.state.wrapped.key_set().index_of(o))
    }

    fn contains(&self, o: &K) -> bool {
        // Port of: `return containsKey(o);` -- delegates to the enclosing map, value-based.
        self.state.wrapped.contains_key(o)
            && self.state.wrapped.get(o).map(|v| self.state.in_bounds(v)).unwrap_or(false)
    }

    fn poll(&mut self) -> Option<K> {
        panic!("UnsupportedOperationException");
    }

    fn remove(&mut self, _o: &K) -> bool {
        panic!("UnsupportedOperationException");
    }
}

impl<'a, K, V> ValueSortedMapKeyList<K> for RestrictedKeyList<'a, K, V>
where
    K: Clone + PartialEq + 'static,
    V: Clone + PartialEq + 'static,
{
}

/// A list view suitable for [`ValueSortedMap::values`] of [`RestrictedValueSortedMap`]. Port of
/// `RestrictedValueSortedMap.RestrictedSortedList`.
pub struct RestrictedSortedList<'a, K, V> {
    state: RestrictedState<'a, K, V>,
    materialized: Materialized<V>,
}

impl<'a, K, V> LesserList<V> for RestrictedSortedList<'a, K, V>
where
    K: Clone + PartialEq + 'static,
    V: Clone + PartialEq + 'static,
{
    fn is_empty(&self) -> bool {
        self.state.restricted_is_empty()
    }

    fn len(&self) -> usize {
        self.state.restricted_size()
    }

    fn get(&self, i: usize) -> &V {
        self.materialized.get(i)
    }

    fn to_vec(&self) -> Vec<V> {
        self.materialized.to_vec()
    }

    fn list_iterator(&self, index: usize) -> Box<dyn ListIterator<V> + '_> {
        self.materialized.list_iterator(index)
    }

    fn index_of(&self, o: &V) -> i64 {
        self.state.in_bounds_or_neg1(self.state.wrapped.values().index_of(o))
    }

    fn contains(&self, o: &V) -> bool {
        // Port of: `return containsValue(o);` -- delegates to the enclosing map's
        // `containsValue`, which itself checks `inBounds` before delegating to `wrapped`.
        self.state.in_bounds(o) && self.state.wrapped.contains_value(o)
    }

    fn poll(&mut self) -> Option<V> {
        panic!("UnsupportedOperationException");
    }

    fn remove(&mut self, _o: &V) -> bool {
        panic!("UnsupportedOperationException");
    }
}

impl<'a, K, V> SortedList<V> for RestrictedSortedList<'a, K, V>
where
    K: Clone + PartialEq + 'static,
    V: Clone + PartialEq + 'static,
{
    fn lower_index(&self, element: &V) -> i64 {
        self.state.in_bounds_or_neg1(self.state.wrapped.values().lower_index(element))
    }

    fn floor_index(&self, element: &V) -> i64 {
        self.state.in_bounds_or_neg1(self.state.wrapped.values().floor_index(element))
    }

    fn ceiling_index(&self, element: &V) -> i64 {
        self.state.in_bounds_or_neg1(self.state.wrapped.values().ceiling_index(element))
    }

    fn higher_index(&self, element: &V) -> i64 {
        self.state.in_bounds_or_neg1(self.state.wrapped.values().higher_index(element))
    }
}

/// A view of a [`ValueSortedMap`] restricted to a range of values. Port of
/// `ghidra.generic.util.datastruct.RestrictedValueSortedMap`. See the module docs for the shared
/// `RestrictedState`/materialized-views shape and the two faithfully-preserved Java quirks.
pub struct RestrictedValueSortedMap<'a, K, V> {
    state: RestrictedState<'a, K, V>,
}

impl<'a, K, V> RestrictedValueSortedMap<'a, K, V>
where
    K: Clone + PartialEq + 'static,
    V: Clone + PartialEq + 'static,
{
    /// Construct a restricted view of a value-sorted map. Port of
    /// `RestrictedValueSortedMap(ValueSortedMap<K, V>, Comparator<V>, boolean, V, boolean,
    /// boolean, V, boolean)`, with the `hasFrom`/`fromValue`/`fromInclusive` triple collapsed to
    /// `from_bound` (and likewise for `to_bound`).
    ///
    /// # Panics
    /// Panics (mirroring Java's `IllegalArgumentException`) if both bounds are present and
    /// `from` is not less than `to` (or they're equal with both bounds exclusive).
    pub fn new(
        wrapped: &'a dyn ValueSortedMap<K, V>,
        comparator: &'a dyn Fn(&V, &V) -> Ordering,
        from_bound: Bound<V>,
        to_bound: Bound<V>,
    ) -> Self {
        if let (Some((from_value, from_inclusive)), Some((to_value, to_inclusive))) =
            (&from_bound, &to_bound)
        {
            let cmp = comparator(from_value, to_value);
            if cmp == Ordering::Greater || (cmp == Ordering::Equal && !from_inclusive && !to_inclusive) {
                panic!("IllegalArgumentException: from must be less than to");
            }
        }
        RestrictedValueSortedMap { state: RestrictedState { wrapped, comparator, from_bound, to_bound } }
    }
}

impl<'a, K, V> ValueSortedMap<K, V> for RestrictedValueSortedMap<'a, K, V>
where
    K: Clone + PartialEq + 'static,
    V: Clone + PartialEq + 'static,
{
    fn put(&mut self, _key: K, _value: V) -> Option<V> {
        panic!("UnsupportedOperationException");
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.state.wrapped.get(key).filter(|v| self.state.in_bounds(v))
    }

    fn remove(&mut self, _key: &K) -> Option<V> {
        panic!("UnsupportedOperationException");
    }

    fn entry_set(&self) -> Box<dyn ValueSortedMapEntryList<K, V> + '_> {
        let state = self.state.clone();
        let materialized = Materialized { items: state.materialize_entries() };
        Box::new(RestrictedEntryList { state, materialized })
    }

    fn lower_entry_by_value(&self, value: &V) -> Option<(&K, &V)> {
        self.state.wrapped.lower_entry_by_value(value).filter(|(_, v)| self.state.in_bounds(v))
    }

    fn floor_entry_by_value(&self, value: &V) -> Option<(&K, &V)> {
        self.state.wrapped.floor_entry_by_value(value).filter(|(_, v)| self.state.in_bounds(v))
    }

    fn ceiling_entry_by_value(&self, value: &V) -> Option<(&K, &V)> {
        self.state.wrapped.ceiling_entry_by_value(value).filter(|(_, v)| self.state.in_bounds(v))
    }

    fn higher_entry_by_value(&self, value: &V) -> Option<(&K, &V)> {
        self.state.wrapped.higher_entry_by_value(value).filter(|(_, v)| self.state.in_bounds(v))
    }

    fn sub_map_by_value(
        &self,
        from_value: &V,
        from_inclusive: bool,
        to_value: &V,
        to_inclusive: bool,
    ) -> Box<dyn ValueSortedMap<K, V> + '_> {
        if !self.state.in_bounds(from_value) || !self.state.in_bounds(to_value) {
            panic!("IllegalArgumentException: Bounds must be within existing bounds");
        }
        Box::new(RestrictedValueSortedMap::new(
            self.state.wrapped,
            self.state.comparator,
            Some((from_value.clone(), from_inclusive)),
            Some((to_value.clone(), to_inclusive)),
        ))
    }

    fn head_map_by_value(&self, to_value: &V, inclusive: bool) -> Box<dyn ValueSortedMap<K, V> + '_> {
        if !self.state.in_bounds(to_value) {
            panic!("IllegalArgumentException: Bounds must be within existing bounds");
        }
        Box::new(RestrictedValueSortedMap::new(
            self.state.wrapped,
            self.state.comparator,
            self.state.from_bound.clone(),
            Some((to_value.clone(), inclusive)),
        ))
    }

    fn tail_map_by_value(&self, from_value: &V, inclusive: bool) -> Box<dyn ValueSortedMap<K, V> + '_> {
        if !self.state.in_bounds(from_value) {
            panic!("IllegalArgumentException: Bounds must be within existing bounds");
        }
        Box::new(RestrictedValueSortedMap::new(
            self.state.wrapped,
            self.state.comparator,
            Some((from_value.clone(), inclusive)),
            self.state.to_bound.clone(),
        ))
    }

    fn key_set(&self) -> Box<dyn ValueSortedMapKeyList<K> + '_> {
        let state = self.state.clone();
        let materialized =
            Materialized { items: state.materialize_entries().into_iter().map(|(k, _)| k).collect() };
        Box::new(RestrictedKeyList { state, materialized })
    }

    fn update(&mut self, _key: &K) -> bool {
        panic!("UnsupportedOperationException");
    }

    fn values(&self) -> Box<dyn SortedList<V> + '_> {
        let state = self.state.clone();
        let materialized =
            Materialized { items: state.materialize_entries().into_iter().map(|(_, v)| v).collect() };
        Box::new(RestrictedSortedList { state, materialized })
    }

    fn is_empty(&self) -> bool {
        self.state.restricted_is_empty()
    }

    fn contains_key(&self, key: &K) -> bool {
        match self.state.wrapped.get(key) {
            Some(v) => self.state.in_bounds(v),
            None => false,
        }
    }

    fn contains_value(&self, value: &V) -> bool {
        self.state.in_bounds(value) && self.state.wrapped.contains_value(value)
    }

    fn size(&self) -> usize {
        self.state.restricted_size()
    }

    fn clear(&mut self) {
        panic!("UnsupportedOperationException");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- A small, real `ValueSortedMap<&'static str, i32>` backing implementation, sorted by ----
    // ---- value, used to exercise `RestrictedValueSortedMap` against genuine behavior. ----

    #[derive(Clone)]
    struct VecEntryList {
        entries: Vec<(&'static str, i32)>,
    }
    impl LesserList<(&'static str, i32)> for VecEntryList {
        fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }
        fn len(&self) -> usize {
            self.entries.len()
        }
        fn get(&self, i: usize) -> &(&'static str, i32) {
            &self.entries[i]
        }
        fn to_vec(&self) -> Vec<(&'static str, i32)> {
            self.entries.clone()
        }
        fn list_iterator(&self, index: usize) -> Box<dyn ListIterator<(&'static str, i32)> + '_> {
            Box::new(MaterializedIterator { items: self.entries.clone(), cursor: index })
        }
        fn index_of(&self, o: &(&'static str, i32)) -> i64 {
            self.entries.iter().position(|e| e == o).map(|i| i as i64).unwrap_or(-1)
        }
        fn contains(&self, o: &(&'static str, i32)) -> bool {
            self.entries.contains(o)
        }
        fn poll(&mut self) -> Option<(&'static str, i32)> {
            if self.entries.is_empty() {
                None
            } else {
                Some(self.entries.remove(0))
            }
        }
        fn remove(&mut self, o: &(&'static str, i32)) -> bool {
            if let Some(pos) = self.entries.iter().position(|e| e == o) {
                self.entries.remove(pos);
                true
            } else {
                false
            }
        }
    }
    impl ValueSortedMapEntryList<&'static str, i32> for VecEntryList {}

    struct VecKeyList {
        keys: Vec<&'static str>,
    }
    impl LesserList<&'static str> for VecKeyList {
        fn is_empty(&self) -> bool {
            self.keys.is_empty()
        }
        fn len(&self) -> usize {
            self.keys.len()
        }
        fn get(&self, i: usize) -> &&'static str {
            &self.keys[i]
        }
        fn to_vec(&self) -> Vec<&'static str> {
            self.keys.clone()
        }
        fn list_iterator(&self, index: usize) -> Box<dyn ListIterator<&'static str> + '_> {
            Box::new(MaterializedIterator { items: self.keys.clone(), cursor: index })
        }
        fn index_of(&self, o: &&'static str) -> i64 {
            self.keys.iter().position(|k| k == o).map(|i| i as i64).unwrap_or(-1)
        }
        fn contains(&self, o: &&'static str) -> bool {
            self.keys.contains(o)
        }
        fn poll(&mut self) -> Option<&'static str> {
            if self.keys.is_empty() {
                None
            } else {
                Some(self.keys.remove(0))
            }
        }
        fn remove(&mut self, o: &&'static str) -> bool {
            if let Some(pos) = self.keys.iter().position(|k| k == o) {
                self.keys.remove(pos);
                true
            } else {
                false
            }
        }
    }
    impl ValueSortedMapKeyList<&'static str> for VecKeyList {}

    struct VecValuesList {
        values: Vec<i32>,
    }
    impl LesserList<i32> for VecValuesList {
        fn is_empty(&self) -> bool {
            self.values.is_empty()
        }
        fn len(&self) -> usize {
            self.values.len()
        }
        fn get(&self, i: usize) -> &i32 {
            &self.values[i]
        }
        fn to_vec(&self) -> Vec<i32> {
            self.values.clone()
        }
        fn list_iterator(&self, index: usize) -> Box<dyn ListIterator<i32> + '_> {
            Box::new(MaterializedIterator { items: self.values.clone(), cursor: index })
        }
        fn index_of(&self, o: &i32) -> i64 {
            self.values.iter().position(|v| v == o).map(|i| i as i64).unwrap_or(-1)
        }
        fn contains(&self, o: &i32) -> bool {
            self.values.contains(o)
        }
        fn poll(&mut self) -> Option<i32> {
            if self.values.is_empty() {
                None
            } else {
                Some(self.values.remove(0))
            }
        }
        fn remove(&mut self, o: &i32) -> bool {
            if let Some(pos) = self.values.iter().position(|v| v == o) {
                self.values.remove(pos);
                true
            } else {
                false
            }
        }
    }
    impl SortedList<i32> for VecValuesList {
        fn lower_index(&self, element: &i32) -> i64 {
            self.values.iter().rposition(|v| v < element).map(|i| i as i64).unwrap_or(-1)
        }
        fn floor_index(&self, element: &i32) -> i64 {
            match self.values.iter().rposition(|v| v <= element) {
                Some(pos) if self.values[pos] == *element => {
                    self.values.iter().position(|v| v == element).unwrap() as i64
                }
                Some(pos) => pos as i64,
                None => -1,
            }
        }
        fn ceiling_index(&self, element: &i32) -> i64 {
            match self.values.iter().position(|v| v >= element) {
                Some(pos) if self.values[pos] == *element => {
                    self.values.iter().rposition(|v| v == element).unwrap() as i64
                }
                Some(pos) => pos as i64,
                None => -1,
            }
        }
        fn higher_index(&self, element: &i32) -> i64 {
            self.values.iter().position(|v| v > element).map(|i| i as i64).unwrap_or(-1)
        }
    }

    /// A `ValueSortedMap<&'static str, i32>` backed by a `Vec` of pairs, always kept sorted
    /// ascending by value -- enough to exercise `RestrictedValueSortedMap` against real,
    /// non-trivial navigation behavior.
    #[derive(Default)]
    struct VecValueSortedMap {
        entries: Vec<(&'static str, i32)>,
    }

    impl VecValueSortedMap {
        fn resort(&mut self) {
            self.entries.sort_by_key(|(_, v)| *v);
        }
    }

    impl ValueSortedMap<&'static str, i32> for VecValueSortedMap {
        fn put(&mut self, key: &'static str, value: i32) -> Option<i32> {
            let old = ValueSortedMap::remove(self, &key);
            self.entries.push((key, value));
            self.resort();
            old
        }
        fn get(&self, key: &&'static str) -> Option<&i32> {
            self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        }
        fn remove(&mut self, key: &&'static str) -> Option<i32> {
            if let Some(pos) = self.entries.iter().position(|(k, _)| k == key) {
                Some(self.entries.remove(pos).1)
            } else {
                None
            }
        }
        fn entry_set(&self) -> Box<dyn ValueSortedMapEntryList<&'static str, i32> + '_> {
            Box::new(VecEntryList { entries: self.entries.clone() })
        }
        fn lower_entry_by_value(&self, value: &i32) -> Option<(&&'static str, &i32)> {
            self.entries.iter().filter(|(_, v)| v < value).last().map(|(k, v)| (k, v))
        }
        fn floor_entry_by_value(&self, value: &i32) -> Option<(&&'static str, &i32)> {
            self.entries.iter().filter(|(_, v)| v <= value).last().map(|(k, v)| (k, v))
        }
        fn ceiling_entry_by_value(&self, value: &i32) -> Option<(&&'static str, &i32)> {
            self.entries.iter().find(|(_, v)| v >= value).map(|(k, v)| (k, v))
        }
        fn higher_entry_by_value(&self, value: &i32) -> Option<(&&'static str, &i32)> {
            self.entries.iter().find(|(_, v)| v > value).map(|(k, v)| (k, v))
        }
        fn sub_map_by_value(
            &self,
            from_value: &i32,
            from_inclusive: bool,
            to_value: &i32,
            to_inclusive: bool,
        ) -> Box<dyn ValueSortedMap<&'static str, i32> + '_> {
            let entries = self
                .entries
                .iter()
                .filter(|(_, v)| {
                    let above = if from_inclusive { v >= from_value } else { v > from_value };
                    let below = if to_inclusive { v <= to_value } else { v < to_value };
                    above && below
                })
                .cloned()
                .collect();
            Box::new(VecValueSortedMap { entries })
        }
        fn head_map_by_value(
            &self,
            to_value: &i32,
            inclusive: bool,
        ) -> Box<dyn ValueSortedMap<&'static str, i32> + '_> {
            let entries = self
                .entries
                .iter()
                .filter(|(_, v)| if inclusive { v <= to_value } else { v < to_value })
                .cloned()
                .collect();
            Box::new(VecValueSortedMap { entries })
        }
        fn tail_map_by_value(
            &self,
            from_value: &i32,
            inclusive: bool,
        ) -> Box<dyn ValueSortedMap<&'static str, i32> + '_> {
            let entries = self
                .entries
                .iter()
                .filter(|(_, v)| if inclusive { v >= from_value } else { v > from_value })
                .cloned()
                .collect();
            Box::new(VecValueSortedMap { entries })
        }
        fn key_set(&self) -> Box<dyn ValueSortedMapKeyList<&'static str> + '_> {
            Box::new(VecKeyList { keys: self.entries.iter().map(|(k, _)| *k).collect() })
        }
        fn update(&mut self, key: &&'static str) -> bool {
            if let Some(v) = self.get(key).copied() {
                ValueSortedMap::remove(self, key);
                self.put(key, v);
                true
            } else {
                false
            }
        }
        fn values(&self) -> Box<dyn SortedList<i32> + '_> {
            Box::new(VecValuesList { values: self.entries.iter().map(|(_, v)| *v).collect() })
        }
        fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }
        fn contains_key(&self, key: &&'static str) -> bool {
            self.entries.iter().any(|(k, _)| k == key)
        }
        fn contains_value(&self, value: &i32) -> bool {
            self.entries.iter().any(|(_, v)| v == value)
        }
        fn size(&self) -> usize {
            self.entries.len()
        }
        fn clear(&mut self) {
            self.entries.clear();
        }
    }

    fn by_value(a: &i32, b: &i32) -> Ordering {
        a.cmp(b)
    }

    /// Values: a=10, b=20, c=30, d=40, e=50.
    fn build_map() -> VecValueSortedMap {
        let mut m = VecValueSortedMap::default();
        m.put("e", 50);
        m.put("c", 30);
        m.put("a", 10);
        m.put("d", 40);
        m.put("b", 20);
        m
    }

    #[test]
    fn unrestricted_view_sees_every_entry() {
        let map = build_map();
        let view = RestrictedValueSortedMap::new(&map, &by_value, None, None);
        assert_eq!(view.size(), 5);
        // Real Java's `isEmpty()` is unconditionally inverted (see `is_empty_is_inverted_quirk`
        // below), so a genuinely non-empty view like this one reports `is_empty() == true`.
        assert!(view.is_empty(), "is_empty() quirk: inverted, so a non-empty view reports true");
        assert_eq!(view.entry_set().to_vec().len(), 5);
    }

    #[test]
    fn get_and_contains_respect_bounds() {
        let map = build_map();
        // [20, 40)
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, true)), Some((40, false)));
        assert_eq!(view.get(&"b"), Some(&20));
        assert_eq!(view.get(&"c"), Some(&30));
        assert_eq!(view.get(&"a"), None, "10 is below the restricted range");
        assert_eq!(view.get(&"d"), None, "40 is excluded (exclusive upper bound)");
        assert!(view.contains_key(&"b"));
        assert!(!view.contains_key(&"a"));
        assert!(view.contains_value(&30));
        assert!(!view.contains_value(&40));
    }

    #[test]
    fn navigation_by_value_respects_bounds() {
        let map = build_map();
        // [20, 40]
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, true)), Some((40, true)));
        assert_eq!(view.lower_entry_by_value(&30), Some((&"b", &20)));
        assert_eq!(view.floor_entry_by_value(&30), Some((&"c", &30)));
        assert_eq!(view.ceiling_entry_by_value(&30), Some((&"c", &30)));
        assert_eq!(view.higher_entry_by_value(&30), Some((&"d", &40)));
        // Outside the range entirely: `wrapped` has a value there, but it's filtered out.
        assert_eq!(view.higher_entry_by_value(&40), None, "50 exists in wrapped but outside bounds");
    }

    #[test]
    fn mutation_methods_panic() {
        let map = build_map();
        let mut view = RestrictedValueSortedMap::new(&map, &by_value, None, None);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| view.put("z", 1))).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ValueSortedMap::remove(&mut view, &"a"))).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| view.clear())).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| view.update(&"a"))).is_err());
    }

    #[test]
    fn sub_map_by_value_rejects_bounds_outside_current_range() {
        let map = build_map();
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, true)), Some((40, true)));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            view.sub_map_by_value(&10, true, &30, true)
        }));
        assert!(result.is_err(), "10 is outside the current [20,40] bounds");
    }

    #[test]
    fn sub_map_by_value_narrows_within_current_range() {
        let map = build_map();
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((10, true)), Some((50, true)));
        let sub = view.sub_map_by_value(&20, true, &40, true);
        assert!(sub.contains_key(&"b"));
        assert!(sub.contains_key(&"c"));
        assert!(sub.contains_key(&"d"));
        assert!(!sub.contains_key(&"a"));
        assert!(!sub.contains_key(&"e"));
    }

    #[test]
    fn head_map_by_value_preserves_existing_from_bound() {
        let map = build_map();
        // [20, unbounded)
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, true)), None);
        let head = view.head_map_by_value(&40, true); // now [20, 40]
        assert!(!head.contains_key(&"a")); // 10, below the preserved `from`
        assert!(head.contains_key(&"b")); // 20
        assert!(head.contains_key(&"d")); // 40
        assert!(!head.contains_key(&"e")); // 50, above the new `to`
    }

    #[test]
    fn tail_map_by_value_preserves_existing_to_bound() {
        let map = build_map();
        // (unbounded, 40]
        let view = RestrictedValueSortedMap::new(&map, &by_value, None, Some((40, true)));
        let tail = view.tail_map_by_value(&20, true); // now [20, 40]
        assert!(!tail.contains_key(&"a")); // 10, below the new `from`
        assert!(tail.contains_key(&"b")); // 20
        assert!(tail.contains_key(&"d")); // 40
        assert!(!tail.contains_key(&"e")); // 50, above the preserved `to`
    }

    #[test]
    fn constructor_rejects_from_greater_than_to() {
        let map = build_map();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            RestrictedValueSortedMap::new(&map, &by_value, Some((40, true)), Some((20, true)))
        }));
        assert!(result.is_err());
    }

    #[test]
    fn entry_key_and_value_views_reflect_bounds() {
        let map = build_map();
        // [20, 40]
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, true)), Some((40, true)));

        let entries = view.entry_set().to_vec();
        assert_eq!(entries, vec![("b", 20), ("c", 30), ("d", 40)]);

        let keys = view.key_set().to_vec();
        assert_eq!(keys, vec!["b", "c", "d"]);

        let values = view.values().to_vec();
        assert_eq!(values, vec![20, 30, 40]);
    }

    #[test]
    fn list_view_get_and_contains_work_for_every_element() {
        let map = build_map();
        // [20, 40]
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, true)), Some((40, true)));
        let entries = view.entry_set();
        assert_eq!(entries.get(0), &("b", 20));
        assert_eq!(entries.get(1), &("c", 30));
        assert_eq!(entries.get(2), &("d", 40));
        assert!(entries.contains(&("c", 30)));
        assert!(!entries.contains(&("a", 10)));
    }

    #[test]
    #[should_panic(expected = "IndexOutOfBoundsException")]
    fn list_view_get_out_of_range_panics() {
        let map = build_map();
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, true)), Some((40, true)));
        view.entry_set().get(99);
    }

    #[test]
    fn list_view_mutation_methods_panic() {
        let map = build_map();
        let view = RestrictedValueSortedMap::new(&map, &by_value, None, None);
        let mut entries = view.entry_set();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| entries.poll())).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| entries.remove(&("a", 10)))).is_err());
    }

    #[test]
    fn list_iterator_traverses_forward_and_backward() {
        let map = build_map();
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, true)), Some((40, true)));
        let entries = view.entry_set();
        let mut it = entries.list_iterator(0);
        assert!(it.has_next());
        assert_eq!(it.next(), ("b", 20));
        assert_eq!(it.next(), ("c", 30));
        assert!(it.has_previous());
        assert_eq!(it.previous(), ("c", 30));
        assert_eq!(it.next(), ("c", 30));
        assert_eq!(it.next(), ("d", 40));
        assert!(!it.has_next());
    }

    /// Faithful reproduction of the real Java off-by-one bug documented at the top of this
    /// module: `size()` undercounts by one whenever an upper (`to`) bound is set, even though the
    /// true last in-bounds element is still reachable via `get`/`contains`/`to_vec`.
    #[test]
    fn size_undercounts_by_one_with_upper_bound_quirk() {
        let map = build_map();
        // [20, 40], inclusive upper bound: three true entries (b=20, c=30, d=40).
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, true)), Some((40, true)));

        let entries = view.entry_set();
        let true_entries = entries.to_vec();
        assert_eq!(true_entries.len(), 3, "b, c, and d are all genuinely within [20, 40]");
        assert!(true_entries.contains(&("d", 40)), "the last element is really there");

        // But `size()`/`len()` (routed through the buggy `getHighestIndexPlusOne`) undercounts.
        assert_eq!(view.size(), 2, "size() quirk: undercounts by one when `to` is bounded");
        assert_eq!(entries.len(), 2, "the entry-list view's len() has the same quirk");

        // The "missing" element is still reachable directly, proving `get`/`contains` are
        // unaffected by the bug that corrupts `size()`.
        assert_eq!(entries.get(2), &("d", 40));
        assert!(entries.contains(&("d", 40)));
    }

    /// Companion to the quirk above: `index_of` on the true last in-bounds element can also
    /// incorrectly report "not found" (`-1`), since it too routes through the buggy bound.
    #[test]
    fn index_of_last_element_incorrectly_reports_not_found_quirk() {
        let map = build_map();
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, true)), Some((40, true)));
        let entries = view.entry_set();

        // The middle element's indexOf is unaffected.
        assert_eq!(entries.index_of(&("c", 30)), 1);
        // The true last element's indexOf incorrectly reports -1 (not found), even though
        // `contains`/`get` both confirm it is present.
        assert_eq!(
            entries.index_of(&("d", 40)),
            -1,
            "indexOf() quirk: the true last in-bounds element is misreported as absent"
        );
    }

    /// Faithful reproduction of the real Java `restrictedIsEmpty()` inversion: this returns
    /// `true` for a genuinely non-empty view once a `to` bound is set (since `restrictedSize()`
    /// can be driven to `0` by the off-by-one bug for a single-element range), and more directly,
    /// the raw `!= 0` inversion always disagrees with `restrictedSize() == 0` whenever it's
    /// nonzero.
    #[test]
    fn is_empty_is_inverted_quirk() {
        let map = build_map();
        // A single-element restricted range: only "c" (30) satisfies [30, 30].
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((30, true)), Some((30, true)));

        // Truly non-empty (one real entry).
        assert_eq!(view.entry_set().to_vec(), vec![("c", 30)]);

        // The off-by-one bug drives `size()` to 0 for this single-element inclusive range
        // (`getHighestIndexPlusOne` returns the same index as `getLowestIndex`), and the
        // inverted `restrictedIsEmpty` then reports `false` (not empty) for that zero size --
        // so, net effect, `is_empty()` happens to read "correctly" here purely by two bugs
        // cancelling out. The important, always-reliable assertion is the raw inversion itself:
        assert_eq!(view.size(), 0, "size() quirk drives this single-element range to 0");
        assert!(!view.is_empty(), "restrictedIsEmpty() quirk: `size()==0` maps to `is_empty()==false`");
    }

    #[test]
    fn is_empty_inversion_on_a_truly_empty_view() {
        let map = build_map();
        // A range with no entries at all (between b=20 and c=30, exclusive both ends).
        let view = RestrictedValueSortedMap::new(&map, &by_value, Some((20, false)), Some((30, false)));
        assert_eq!(view.entry_set().to_vec(), Vec::<(&str, i32)>::new());
        assert_eq!(view.size(), 0);
        // Real Java: `restrictedIsEmpty() == (restrictedSize() != 0)` == `(0 != 0)` == `false`,
        // i.e. `isEmpty()` reports `false` (not empty!) for a genuinely empty view.
        assert!(!view.is_empty(), "is_empty() quirk: reports false for a truly empty view");
    }
}

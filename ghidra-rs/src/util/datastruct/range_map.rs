//! Port of `ghidra.util.datastruct.RangeMap`.

use crate::util::datastruct::index_range_iterator::IndexRangeIterator;
use crate::util::datastruct::property_set_index_range_iterator::PropertySetIndexRangeIterator;
use crate::util::datastruct::value_range::ValueRange;
use crate::util::long_iterator::LongIterator;
use crate::util::map::{IntValueMap, ValueMap, ValueMapIter, ValueStoragePage};

/// Stores ranges of int values throughout "long" space. Every "long" index has an associated
/// int value (initially 0). Users can paint (set) ranges of indexes to a given integer value,
/// overwriting any value that currently exists in that range.
///
/// This class is implemented using an `IntPropertyMap`. The first index (0) will always contain
/// a value. The value at any other given index will either be the value stored at that index, or
/// if no value stored there, then the value stored at the nearest previous index that contains a
/// value.
///
/// Port of `ghidra.util.datastruct.RangeMap`.
///
/// Java's `map` field is a concrete `IntValueMap`. This crate's [`IntValueMap`] is generic over
/// an implementor-supplied page-storage type `P: ValueStoragePage<i32> + Default` (an existing
/// dependency-cycle cut-point -- see that type's own module docs), so `RangeMap` threads the same
/// type parameter through; there is currently no concrete production `ValueStoragePage`
/// implementation in the crate (only test doubles), matching `IntValueMap`'s own current state.
pub struct RangeMap<P: ValueStoragePage<i32> + Default> {
    map: IntValueMap<P>,
    default_value: i32,
}

impl<P: ValueStoragePage<i32> + Default> RangeMap<P> {
    /// Constructor for `RangeMap` with a default value of 0.
    ///
    /// Port of `RangeMap()`.
    pub fn new() -> Self {
        Self::with_default(0)
    }

    /// Creates a new range map with specified default value.
    ///
    /// Port of `RangeMap(int)`.
    pub fn with_default(default_value: i32) -> Self {
        let mut map = IntValueMap::new("RangeMap");
        map.put_int(0, default_value);
        RangeMap { map, default_value }
    }

    /// Get the total number of ranges in map.
    ///
    /// Port of `RangeMap.getNumRanges()`.
    pub fn get_num_ranges(&self) -> i32 {
        self.map.get_size()
    }

    /// Clears all current values from the range map and resets the default value.
    ///
    /// Port of `RangeMap.clear()`.
    pub fn clear(&mut self) {
        self.map.remove_range(0, i64::MAX);
        self.map.put_int(0, self.default_value);
    }

    /// Associates the given value with every index from `start` to `end` (inclusive). Any
    /// previous associates are overwritten.
    ///
    /// Port of `RangeMap.paintRange(long, long, int)`.
    pub fn paint_range(&mut self, start: i64, end: i64, value: i32) {
        // first fix up the end of the range, unless the end goes to the END
        if end != i64::MAX {
            let orig_end_value = self.get_value(end + 1);
            if orig_end_value != value {
                self.map.put_int(end + 1, orig_end_value);
            } else {
                self.map.remove(end + 1);
            }
        }

        // now remove any values stored from start to end (collected up front since the map
        // can't be mutated while a borrowing iterator over it is alive -- see `ValueMap`'s own
        // `move_range` default method for the same pattern).
        let mut points_to_remove = Vec::new();
        {
            let mut it = self.map.get_property_iterator_from(start);
            while it.has_next() {
                let next = it.next();
                if next > end {
                    break;
                }
                points_to_remove.push(next);
            }
        }
        for index in points_to_remove {
            self.map.remove(index);
        }

        if start == 0 {
            self.map.put_int(0, value);
        } else {
            let start_value = self.get_value(start);
            if start_value != value {
                self.map.put_int(start, value);
            }
        }
    }

    /// Returns the int value associated with the given index.
    ///
    /// Port of `RangeMap.getValue(long)`.
    pub fn get_value(&self, index: i64) -> i32 {
        if let Ok(value) = self.map.get_int(index) {
            return value;
        }
        if let Ok(prev_index) = self.map.get_previous_property_index(index) {
            if let Ok(value) = self.map.get_int(prev_index) {
                return value;
            }
        }
        0
    }

    /// Returns the value range containing the given index. The value range indicates the int
    /// value and the start and end index for the range.
    ///
    /// Port of `RangeMap.getValueRange(long)`.
    pub fn get_value_range(&self, index: i64) -> ValueRange {
        if self.map.get_size() == 1 {
            return ValueRange::new(0, i64::MAX, self.default_value);
        }

        let mut start = 0i64;
        if self.map.has_property(index) {
            start = index;
        } else if let Ok(prev) = self.map.get_previous_property_index(index) {
            start = prev;
        }
        // else: use minimum start if index not found: 0.

        let end = match self.map.get_next_property_index(start) {
            Ok(next) => next - 1,
            Err(_) => i64::MAX, // use maximum end.
        };

        let value = self.map.get_int(start).unwrap_or(0); // use minimum value if not found: 0.

        ValueRange::new(start, end, value)
    }

    /// Returns an iterator over all occupied ranges in the map.
    ///
    /// Port of `RangeMap.getIndexRangeIterator(long)`.
    pub fn get_index_range_iterator(
        &self,
        index: i64,
    ) -> PropertySetIndexRangeIterator<'_, i32, IntValueMap<P>> {
        PropertySetIndexRangeIterator::new(&self.map, index)
    }

    /// Returns an iterator over all indexes where the value changes.
    ///
    /// Port of `RangeMap.getChangePointIterator(long, long)`.
    pub fn get_change_point_iterator(&self, start: i64, end: i64) -> ValueMapIter<'_, i32, IntValueMap<P>> {
        self.map.get_property_iterator_range(start, end)
    }
}

impl<P: ValueStoragePage<i32> + Default> Default for RangeMap<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::NoValueException;
    use crate::util::long_iterator::LongIterator;
    use std::collections::BTreeMap;

    /// Minimal in-memory [`ValueStoragePage<i32>`], matching the shape already established by
    /// `IntValueMap`'s own tests.
    #[derive(Default)]
    struct MockPage {
        values: BTreeMap<i16, i32>,
    }

    impl ValueStoragePage<i32> for MockPage {
        fn get_next(&self, offset: i16) -> Option<i16> {
            self.values
                .range((std::ops::Bound::Excluded(offset), std::ops::Bound::Unbounded))
                .next()
                .map(|(&k, _)| k)
        }
        fn get_previous(&self, offset: i16) -> Option<i16> {
            self.values.range(..offset).next_back().map(|(&k, _)| k)
        }
        fn get_first(&self) -> Option<i16> {
            self.values.keys().next().copied()
        }
        fn get_last(&self) -> Option<i16> {
            self.values.keys().next_back().copied()
        }
        fn is_empty(&self) -> bool {
            self.values.is_empty()
        }
        fn has_property(&self, offset: i16) -> bool {
            self.values.contains_key(&offset)
        }
        fn add_key(&mut self, key: i16) {
            self.values.entry(key).or_insert(0);
        }
        fn get_size(&self) -> usize {
            self.values.len()
        }
        fn remove(&mut self, offset: i16) -> bool {
            self.values.remove(&offset).is_some()
        }
        fn get_saveable_object(
            &self,
            _offset: i16,
        ) -> Result<Option<Box<dyn crate::util::saveable::Saveable>>, crate::util::map::TypeMismatchException>
        {
            Err(crate::util::map::TypeMismatchException::new())
        }
        fn add_saveable_object(&mut self, _offset: i16, _value: Box<dyn crate::util::saveable::Saveable>) {}
        fn get_object(&self, _offset: i16) -> Option<i32> {
            None
        }
        fn add_object(&mut self, _offset: i16, _value: i32) {}
        fn get_string(&self, _offset: i16) -> Option<String> {
            None
        }
        fn add_string(&mut self, _offset: i16, _value: String) {}
        fn get_int(&self, offset: i16) -> Result<i32, NoValueException> {
            self.values.get(&offset).copied().ok_or_else(NoValueException::new)
        }
        fn add_int(&mut self, offset: i16, value: i32) {
            self.values.insert(offset, value);
        }
        fn get_long(&self, _offset: i16) -> Result<i64, NoValueException> {
            Err(NoValueException::new())
        }
        fn add_long(&mut self, _offset: i16, _value: i64) {}
        fn get_short(&self, _offset: i16) -> Result<i16, NoValueException> {
            Err(NoValueException::new())
        }
        fn add_short(&mut self, _offset: i16, _value: i16) {}
        fn get_byte(&self, _offset: i16) -> Result<i8, NoValueException> {
            Err(NoValueException::new())
        }
        fn add_byte(&mut self, _offset: i16, _value: i8) {}
    }

    type TestRangeMap = RangeMap<MockPage>;

    #[test]
    fn new_map_has_default_value_everywhere() {
        let map = TestRangeMap::new();
        assert_eq!(map.get_value(0), 0);
        assert_eq!(map.get_value(1000), 0);
        assert_eq!(map.get_value(-1000), 0);
        assert_eq!(map.get_num_ranges(), 1);
    }

    #[test]
    fn with_default_uses_supplied_default_value() {
        let map = TestRangeMap::with_default(7);
        assert_eq!(map.get_value(0), 7);
        assert_eq!(map.get_value(1000), 7);
    }

    #[test]
    fn paint_range_basic() {
        let mut map = TestRangeMap::new();
        map.paint_range(10, 20, 5);

        assert_eq!(map.get_value(0), 0);
        assert_eq!(map.get_value(9), 0);
        assert_eq!(map.get_value(10), 5);
        assert_eq!(map.get_value(20), 5);
        assert_eq!(map.get_value(21), 0);
    }

    #[test]
    fn paint_range_starting_at_zero() {
        let mut map = TestRangeMap::new();
        map.paint_range(0, 20, 5);

        assert_eq!(map.get_value(0), 5);
        assert_eq!(map.get_value(20), 5);
        assert_eq!(map.get_value(21), 0);
    }

    #[test]
    fn paint_range_overwrites_overlapping_range() {
        let mut map = TestRangeMap::new();
        map.paint_range(10, 60, 1);
        map.paint_range(20, 40, 2);

        assert_eq!(map.get_value(9), 0);
        assert_eq!(map.get_value(10), 1);
        assert_eq!(map.get_value(19), 1);
        assert_eq!(map.get_value(20), 2);
        assert_eq!(map.get_value(40), 2);
        assert_eq!(map.get_value(41), 1);
        assert_eq!(map.get_value(60), 1);
        assert_eq!(map.get_value(61), 0);
    }

    #[test]
    fn paint_range_to_max_leaves_no_trailing_boundary() {
        let mut map = TestRangeMap::new();
        map.paint_range(10, i64::MAX, 9);

        assert_eq!(map.get_value(9), 0);
        assert_eq!(map.get_value(10), 9);
        assert_eq!(map.get_value(i64::MAX), 9);
    }

    #[test]
    fn paint_range_same_value_as_following_range_merges_boundary() {
        let mut map = TestRangeMap::new();
        map.paint_range(10, 20, 5);
        // Painting [0, 9] with the same value (5) that already starts at 10 should not leave a
        // stray boundary marker at index 10.
        map.paint_range(0, 9, 5);

        assert_eq!(map.get_value(0), 5);
        assert_eq!(map.get_value(9), 5);
        assert_eq!(map.get_value(10), 5);
        assert_eq!(map.get_value(20), 5);
        assert_eq!(map.get_value(21), 0);
    }

    #[test]
    fn clear_resets_to_default_value() {
        let mut map = TestRangeMap::with_default(3);
        map.paint_range(10, 20, 99);
        map.clear();

        assert_eq!(map.get_value(0), 3);
        assert_eq!(map.get_value(15), 3);
        assert_eq!(map.get_num_ranges(), 1);
    }

    #[test]
    fn get_value_for_negative_index_wraps_to_index_zero_via_unsigned_page_arithmetic() {
        // NOT the hardcoded `return 0;` fallback one might expect from a "negative index, no
        // prior property" reading of `getValue`. Java's `ValueMap.getPageID` computes
        // `index >>> numPageBits` -- an UNSIGNED right shift (verified against ValueMap.java
        // line 364) -- so a negative index's page ID is a huge *positive* number (the top bits
        // of two's-complement -1 survive the unsigned shift), not a small/negative one. Page 0
        // (which always holds a value -- RangeMap's constructor pre-populates index 0 with
        // `defaultValue`, verified against RangeMap.java's constructor) therefore always
        // compares as "previous" to that huge page ID, so `getPreviousPropertyIndex` finds
        // index 0's value instead of exhausting all pages and hitting the `return 0` fallback.
        // That fallback is effectively unreachable through RangeMap's own public API, since the
        // constructor always seeds index 0.
        let map = TestRangeMap::with_default(42);
        assert_eq!(map.get_value(-1), 42);
        assert_eq!(map.get_value(i64::MIN), 42);
    }

    #[test]
    fn get_value_range_single_range_reports_default_value() {
        let map = TestRangeMap::with_default(11);
        let range = map.get_value_range(500);
        assert_eq!(range.start(), 0);
        assert_eq!(range.end(), i64::MAX);
        assert_eq!(range.value(), 11);
    }

    #[test]
    fn get_value_range_within_painted_range() {
        let mut map = TestRangeMap::new();
        map.paint_range(10, 20, 5);

        let range = map.get_value_range(15);
        assert_eq!(range.start(), 10);
        assert_eq!(range.end(), 20);
        assert_eq!(range.value(), 5);
    }

    #[test]
    fn get_value_range_after_painted_range() {
        let mut map = TestRangeMap::new();
        map.paint_range(10, 20, 5);

        let range = map.get_value_range(21);
        assert_eq!(range.start(), 21);
        assert_eq!(range.end(), i64::MAX);
        assert_eq!(range.value(), 0);
    }

    #[test]
    fn get_value_range_exact_start_index() {
        let mut map = TestRangeMap::new();
        map.paint_range(10, 20, 5);

        let range = map.get_value_range(10);
        assert_eq!(range.start(), 10);
        assert_eq!(range.end(), 20);
        assert_eq!(range.value(), 5);
    }

    #[test]
    fn get_index_range_iterator_visits_change_points() {
        let mut map = TestRangeMap::new();
        map.paint_range(10, 20, 5);
        map.paint_range(30, 40, 6);

        let mut it = map.get_index_range_iterator(0);
        let r1 = it.next();
        assert_eq!(r1.start(), 0);
        assert_eq!(r1.end(), 9);

        let r2 = it.next();
        assert_eq!(r2.start(), 10);
        assert_eq!(r2.end(), 20);

        let r3 = it.next();
        assert_eq!(r3.start(), 21);
        assert_eq!(r3.end(), 29);

        let r4 = it.next();
        assert_eq!(r4.start(), 30);
        assert_eq!(r4.end(), 40);

        let r5 = it.next();
        assert_eq!(r5.start(), 41);
        assert_eq!(r5.end(), i64::MAX);

        assert!(!it.has_next());
    }

    #[test]
    fn get_change_point_iterator_walks_only_change_points_in_range() {
        let mut map = TestRangeMap::new();
        map.paint_range(10, 20, 5);
        map.paint_range(30, 40, 6);

        let mut it = map.get_change_point_iterator(0, 100);
        assert_eq!(it.next(), 0);
        assert_eq!(it.next(), 10);
        assert_eq!(it.next(), 21);
        assert_eq!(it.next(), 30);
        assert_eq!(it.next(), 41);
        assert!(!it.has_next());
    }

    #[test]
    fn get_change_point_iterator_respects_bounds() {
        let mut map = TestRangeMap::new();
        map.paint_range(10, 20, 5);
        map.paint_range(30, 40, 6);

        let mut it = map.get_change_point_iterator(15, 35);
        assert_eq!(it.next(), 21);
        assert_eq!(it.next(), 30);
        assert!(!it.has_next());
    }

    #[test]
    fn get_num_ranges_tracks_change_points() {
        let mut map = TestRangeMap::new();
        assert_eq!(map.get_num_ranges(), 1);
        map.paint_range(10, 20, 5);
        // Painting a bounded range creates two change points: one at the start (value) and one
        // just past the end (restoring the previous value).
        assert_eq!(map.get_num_ranges(), 3);
    }

    #[test]
    fn default_trait_impl_matches_new() {
        let map: TestRangeMap = Default::default();
        assert_eq!(map.get_value(0), 0);
    }
}

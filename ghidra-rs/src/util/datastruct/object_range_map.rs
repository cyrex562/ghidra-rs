use super::index_range::IndexRange;
use super::index_range_iterator::IndexRangeIterator;
use super::object_value_range::ObjectValueRange;

fn position_of_range_at_or_before<T>(ranges: &[ObjectValueRange<T>], target: i64) -> i64 {
    match ranges.binary_search_by(|r| r.start().cmp(&target)) {
        Ok(pos) => pos as i64,
        Err(0) => -1,
        Err(insertion) => (insertion - 1) as i64,
    }
}

fn position_of_range_before<T>(ranges: &[ObjectValueRange<T>], target: i64) -> i64 {
    match ranges.binary_search_by(|r| r.start().cmp(&target)) {
        Ok(pos) => pos as i64 - 1,
        Err(0) => -1,
        Err(insertion) => (insertion - 1) as i64,
    }
}

/// Associates objects with `i64` index ranges.
///
/// Port of `ghidra.util.datastruct.ObjectRangeMap`.
#[derive(Debug, Clone)]
pub struct ObjectRangeMap<T: Clone + PartialEq> {
    ranges: Vec<ObjectValueRange<T>>,
    last_range: Option<usize>,
}

impl<T: Clone + PartialEq> ObjectRangeMap<T> {
    /// Constructs a new, empty `ObjectRangeMap`.
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            last_range: None,
        }
    }

    /// Returns an iterator over all ranges that have associated objects.
    pub fn get_index_range_iterator(&self) -> SimpleIndexRangeIterator<'_, T> {
        SimpleIndexRangeIterator {
            ranges: &self.ranges,
            pos: 0,
        }
    }

    /// Returns an iterator over all ranges that have associated objects within the given
    /// range `[start, end]` (inclusive). Ranges that overlap the beginning or end of the
    /// given range are included, but have their start or end index adjusted to be within
    /// the given range.
    pub fn get_index_range_iterator_in_range(
        &self,
        start: i64,
        end: i64,
    ) -> RestrictedIndexRangeIterator<'_, T> {
        RestrictedIndexRangeIterator::new(&self.ranges, start, end)
    }

    /// Associates the given object with all indices in the given range `[start, end]`
    /// (inclusive). The object may be cloned, but an association is still established for
    /// every index in the range. Use [`clear_range`](Self::clear_range) to remove
    /// associations.
    pub fn set_object(&mut self, start: i64, end: i64, object: T) {
        self.last_range = None;
        let mut new_range = ObjectValueRange::new(start, end, object.clone());

        // if ranges list is empty, just add the new entry
        if self.ranges.is_empty() {
            self.ranges.push(new_range);
            return;
        }

        // Look at the stored range before the new range to see if it extends into the new range
        let previous_index = position_of_range_before(&self.ranges, start);
        if previous_index >= 0 {
            new_range = self.adjust_previous_range_for_overlap(
                start,
                end,
                object.clone(),
                new_range,
                previous_index as usize,
            );
        }

        let insertion_index = std::cmp::max(0, previous_index + 1) as usize;
        let new_end = new_range.end();
        self.remove_completely_overlapped_ranges(insertion_index, new_end);

        new_range =
            self.adjust_remaining_range_for_overlap(object, new_range, insertion_index, new_end);

        self.ranges.insert(insertion_index, new_range);
    }

    fn adjust_remaining_range_for_overlap(
        &mut self,
        object: T,
        new_range: ObjectValueRange<T>,
        insertion_index: usize,
        new_end: i64,
    ) -> ObjectValueRange<T> {
        if insertion_index >= self.ranges.len() {
            return new_range; // no record to adjust
        }

        let range = &self.ranges[insertion_index];
        if range.start() > new_end + 1 {
            // no overlap
            return new_range;
        }

        if values_equal(range.value(), &object) {
            // merge records
            let range_end = range.end();
            self.ranges.remove(insertion_index);
            ObjectValueRange::new(new_range.start(), range_end, object)
        } else {
            // overwrite the old record to start past the end of the new range
            let value = range.value().clone();
            let range_end = range.end();
            self.ranges[insertion_index] = ObjectValueRange::new(new_end + 1, range_end, value);
            new_range
        }
    }

    fn remove_completely_overlapped_ranges(&mut self, insertion_index: usize, new_end: i64) {
        let pos = insertion_index;
        while pos < self.ranges.len() {
            if self.ranges[pos].end() > new_end {
                return;
            }
            self.ranges.remove(pos);
        }
    }

    fn adjust_previous_range_for_overlap(
        &mut self,
        start: i64,
        end: i64,
        object: T,
        new_range: ObjectValueRange<T>,
        pos: usize,
    ) -> ObjectValueRange<T> {
        let previous_range = &self.ranges[pos];
        if previous_range.end() < start - 1 {
            return new_range; // no overlap
        }

        let old_start = previous_range.start();
        let old_end = previous_range.end();
        let old_value = previous_range.value().clone();

        if values_equal(previous_range.value(), &object) {
            // same objects, merge
            self.ranges.remove(pos);
            ObjectValueRange::new(old_start, std::cmp::max(old_end, end), object)
        } else {
            // break previous record into sub-ranges that exclude the new range
            self.ranges[pos] = ObjectValueRange::new(old_start, start - 1, old_value.clone());

            // previous range extends past the new range
            if old_end > end {
                self.ranges
                    .insert(pos + 1, ObjectValueRange::new(end + 1, old_end, old_value));
            }
            new_range
        }
    }

    /// Clears any object associations within the given range `[start, end]` (inclusive).
    pub fn clear_range(&mut self, start: i64, end: i64) {
        self.last_range = None;

        // check for range before that extends into cleared area
        let mut pos = position_of_range_before(&self.ranges, start);
        if pos >= 0 {
            let idx = pos as usize;
            let range_start = self.ranges[idx].start();
            let range_end = self.ranges[idx].end();
            if range_end >= start {
                // truncate previous range if needed
                let value = self.ranges[idx].value().clone();
                self.ranges[idx] = ObjectValueRange::new(range_start, start - 1, value);
            }
            if range_end > end {
                // create leftover if previous range extends beyond cleared area.
                let value = self.ranges[idx].value().clone();
                self.ranges
                    .insert(idx + 1, ObjectValueRange::new(end + 1, range_end, value));
            }
        }

        // now clear ranges until we find one past the cleared area
        pos = std::cmp::max(0, pos + 1); // start at 0 or 1 past the previous range
        let idx = pos as usize;
        while idx < self.ranges.len() {
            let range_start = self.ranges[idx].start();
            let range_end = self.ranges[idx].end();
            if range_end <= end {
                // range totally inside cleared area
                self.ranges.remove(idx);
            } else if range_start > end {
                // range totally past clear area - done
                break;
            } else {
                // intersects, fixup start
                let value = self.ranges[idx].value().clone();
                self.ranges[idx] = ObjectValueRange::new(end + 1, range_end, value);
            }
        }
    }

    /// Returns `true` if the given index has an associated object.
    pub fn contains(&mut self, index: i64) -> bool {
        if let Some(pos) = self.last_range {
            if self.ranges[pos].contains(index) {
                return true;
            }
        }

        let pos = position_of_range_at_or_before(&self.ranges, index);
        if pos < 0 {
            return false;
        }
        let idx = pos as usize;
        self.last_range = Some(idx);

        self.ranges[idx].contains(index)
    }

    /// Returns the object associated with the given index, or `None` if no object is
    /// associated with the given index. If [`contains`](Self::contains) returns `true` first,
    /// the result is cached so the next call to `get_object` will be fast.
    pub fn get_object(&mut self, index: i64) -> Option<&T> {
        if let Some(pos) = self.last_range {
            if self.ranges[pos].contains(index) {
                return Some(self.ranges[pos].value());
            }
        }

        let pos = position_of_range_at_or_before(&self.ranges, index);
        if pos < 0 {
            return None;
        }
        let idx = pos as usize;
        self.last_range = Some(idx);
        if self.ranges[idx].contains(index) {
            Some(self.ranges[idx].value())
        } else {
            None
        }
    }
}

impl<T: Clone + PartialEq> Default for ObjectRangeMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

fn values_equal<T: PartialEq>(value: &T, obj: &T) -> bool {
    value == obj
}

/// Iterator over all ranges in an [`ObjectRangeMap`] that have associated objects.
///
/// Port of `ObjectRangeMap.SimpleIndexRangeIterator`.
pub struct SimpleIndexRangeIterator<'a, T> {
    ranges: &'a [ObjectValueRange<T>],
    pos: usize,
}

impl<T> IndexRangeIterator for SimpleIndexRangeIterator<'_, T> {
    fn has_next(&self) -> bool {
        self.pos < self.ranges.len()
    }

    fn next(&mut self) -> IndexRange {
        let range = &self.ranges[self.pos];
        self.pos += 1;
        IndexRange::new(range.start(), range.end())
    }
}

/// Iterator over the ranges in an [`ObjectRangeMap`] that have associated objects within a
/// given index range, clipped to that range.
///
/// Port of `ObjectRangeMap.RestrictedIndexRangeIterator`.
pub struct RestrictedIndexRangeIterator<'a, T> {
    ranges: &'a [ObjectValueRange<T>],
    pos: usize,
    end: i64,
    next_range: Option<IndexRange>,
}

impl<'a, T> RestrictedIndexRangeIterator<'a, T> {
    fn new(ranges: &'a [ObjectValueRange<T>], start: i64, end: i64) -> Self {
        let mut signed_pos = position_of_range_at_or_before(ranges, start);
        let mut next_range = None;
        if signed_pos >= 0 {
            let idx = signed_pos as usize;
            let range = &ranges[idx];
            signed_pos += 1;
            if range.contains(start) {
                next_range = Some(IndexRange::new(start, std::cmp::min(range.end(), end)));
            }
        }

        let mut iter = Self {
            ranges,
            pos: std::cmp::max(0, signed_pos) as usize,
            end,
            next_range,
        };
        if iter.next_range.is_none() {
            iter.advance();
        }
        iter
    }

    fn advance(&mut self) {
        self.next_range = None;
        if self.pos < self.ranges.len() {
            let range = &self.ranges[self.pos];
            self.pos += 1;
            if range.start() <= self.end {
                self.next_range = Some(IndexRange::new(
                    range.start(),
                    std::cmp::min(range.end(), self.end),
                ));
            }
        }
    }
}

impl<T> IndexRangeIterator for RestrictedIndexRangeIterator<'_, T> {
    fn has_next(&self) -> bool {
        self.next_range.is_some()
    }

    fn next(&mut self) -> IndexRange {
        let range = self
            .next_range
            .expect("next() called without checking has_next()");
        self.advance();
        range
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_set_single_range() {
        let mut map = ObjectRangeMap::new();
        map.set_object(10, 20, "obj");
        assert_eq!(map.get_object(0), None);
        assert_eq!(map.get_object(9), None);
        assert_eq!(map.get_object(10), Some(&"obj"));
        assert_eq!(map.get_object(20), Some(&"obj"));
        assert_eq!(map.get_object(21), None);
    }

    #[test]
    fn get_set_overlap_at_start() {
        let mut map = ObjectRangeMap::new();
        map.set_object(10, 60, "obj1");
        map.set_object(5, 15, "obj2");
        assert_eq!(map.get_object(4), None);
        assert_eq!(map.get_object(5), Some(&"obj2"));
        assert_eq!(map.get_object(10), Some(&"obj2"));
        assert_eq!(map.get_object(15), Some(&"obj2"));
        assert_eq!(map.get_object(16), Some(&"obj1"));
        assert_eq!(map.get_object(60), Some(&"obj1"));
        assert_eq!(map.get_object(61), None);
    }

    #[test]
    fn get_set_overlap_at_end() {
        let mut map = ObjectRangeMap::new();
        map.set_object(10, 60, "obj1");
        map.set_object(55, 65, "obj2");
        assert_eq!(map.get_object(9), None);
        assert_eq!(map.get_object(10), Some(&"obj1"));
        assert_eq!(map.get_object(54), Some(&"obj1"));
        assert_eq!(map.get_object(55), Some(&"obj2"));
        assert_eq!(map.get_object(60), Some(&"obj2"));
        assert_eq!(map.get_object(65), Some(&"obj2"));
        assert_eq!(map.get_object(66), None);
    }

    #[test]
    fn get_set_same_start_different_end() {
        let mut map = ObjectRangeMap::new();
        map.set_object(10, 60, "obj1");
        map.set_object(10, 65, "obj2");
        assert_eq!(map.get_object(9), None);
        assert_eq!(map.get_object(10), Some(&"obj2"));
        assert_eq!(map.get_object(65), Some(&"obj2"));
        assert_eq!(map.get_object(66), None);
    }

    #[test]
    fn get_set_new_range_extends_before_old() {
        let mut map = ObjectRangeMap::new();
        map.set_object(10, 60, "obj1");
        map.set_object(5, 60, "obj2");
        assert_eq!(map.get_object(4), None);
        assert_eq!(map.get_object(5), Some(&"obj2"));
        assert_eq!(map.get_object(60), Some(&"obj2"));
        assert_eq!(map.get_object(61), None);
    }

    #[test]
    fn get_set_exact_overwrite() {
        let mut map = ObjectRangeMap::new();
        map.set_object(10, 60, "obj1");
        map.set_object(10, 60, "obj2");
        assert_eq!(map.get_object(9), None);
        assert_eq!(map.get_object(10), Some(&"obj2"));
        assert_eq!(map.get_object(60), Some(&"obj2"));
        assert_eq!(map.get_object(61), None);
    }

    #[test]
    fn get_set_completely_contained() {
        let mut map = ObjectRangeMap::new();
        map.set_object(10, 60, "obj1");
        map.set_object(20, 50, "obj2");
        assert_eq!(map.get_object(9), None);
        assert_eq!(map.get_object(10), Some(&"obj1"));
        assert_eq!(map.get_object(19), Some(&"obj1"));
        assert_eq!(map.get_object(20), Some(&"obj2"));
        assert_eq!(map.get_object(50), Some(&"obj2"));
        assert_eq!(map.get_object(51), Some(&"obj1"));
        assert_eq!(map.get_object(60), Some(&"obj1"));
        assert_eq!(map.get_object(61), None);
    }

    #[test]
    fn get_set_completely_covers_old() {
        let mut map = ObjectRangeMap::new();
        map.set_object(10, 60, "obj1");
        map.set_object(5, 65, "obj2");
        assert_eq!(map.get_object(4), None);
        assert_eq!(map.get_object(5), Some(&"obj2"));
        assert_eq!(map.get_object(9), Some(&"obj2"));
        assert_eq!(map.get_object(10), Some(&"obj2"));
        assert_eq!(map.get_object(60), Some(&"obj2"));
        assert_eq!(map.get_object(61), Some(&"obj2"));
        assert_eq!(map.get_object(65), Some(&"obj2"));
        assert_eq!(map.get_object(66), None);
    }

    #[test]
    fn get_set_covers_multiple_ranges() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");
        map.set_object(25, 85, "obj2");
        assert_eq!(map.get_object(19), None);
        assert_eq!(map.get_object(20), Some(&"obj1"));
        assert_eq!(map.get_object(24), Some(&"obj1"));
        assert_eq!(map.get_object(25), Some(&"obj2"));
        assert_eq!(map.get_object(40), Some(&"obj2"));
        assert_eq!(map.get_object(50), Some(&"obj2"));
        assert_eq!(map.get_object(51), Some(&"obj2"));
        assert_eq!(map.get_object(85), Some(&"obj2"));
        assert_eq!(map.get_object(86), Some(&"obj1"));
        assert_eq!(map.get_object(90), Some(&"obj1"));
        assert_eq!(map.get_object(91), None);
    }

    #[test]
    fn clear_range_truncates_start() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 50, "obj1");
        map.clear_range(10, 29);
        assert_eq!(map.get_object(10), None);
        assert_eq!(map.get_object(29), None);
        assert_eq!(map.get_object(30), Some(&"obj1"));
        assert_eq!(map.get_object(50), Some(&"obj1"));
        assert_eq!(map.get_object(51), None);
    }

    #[test]
    fn clear_range_truncates_end() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 50, "obj1");
        map.clear_range(41, 60);
        assert_eq!(map.get_object(19), None);
        assert_eq!(map.get_object(20), Some(&"obj1"));
        assert_eq!(map.get_object(40), Some(&"obj1"));
        assert_eq!(map.get_object(41), None);
        assert_eq!(map.get_object(50), None);
    }

    #[test]
    fn clear_range_splits_middle() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 50, "obj1");
        map.clear_range(30, 40);
        assert_eq!(map.get_object(19), None);
        assert_eq!(map.get_object(20), Some(&"obj1"));
        assert_eq!(map.get_object(29), Some(&"obj1"));
        assert_eq!(map.get_object(30), None);
        assert_eq!(map.get_object(40), None);
        assert_eq!(map.get_object(41), Some(&"obj1"));
        assert_eq!(map.get_object(50), Some(&"obj1"));
        assert_eq!(map.get_object(51), None);
    }

    #[test]
    fn clear_range_covers_entire_range() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 50, "obj1");
        map.clear_range(10, 60);
        for i in [19, 20, 29, 30, 40, 41, 50, 51] {
            assert_eq!(map.get_object(i), None);
        }
    }

    #[test]
    fn clear_range_before_no_effect() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 50, "obj1");
        map.clear_range(10, 15);
        assert_eq!(map.get_object(19), None);
        assert_eq!(map.get_object(20), Some(&"obj1"));
        assert_eq!(map.get_object(50), Some(&"obj1"));
        assert_eq!(map.get_object(51), None);
    }

    #[test]
    fn clear_range_after_no_effect() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 50, "obj1");
        map.clear_range(70, 80);
        assert_eq!(map.get_object(19), None);
        assert_eq!(map.get_object(20), Some(&"obj1"));
        assert_eq!(map.get_object(50), Some(&"obj1"));
        assert_eq!(map.get_object(51), None);
    }

    #[test]
    fn clear_range_exact_match() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 50, "obj1");
        map.clear_range(20, 50);
        assert_eq!(map.get_object(19), None);
        assert_eq!(map.get_object(20), None);
        assert_eq!(map.get_object(50), None);
        assert_eq!(map.get_object(51), None);
    }

    #[test]
    fn clear_range_spans_multiple_ranges() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");
        map.clear_range(25, 85);
        assert_eq!(map.get_object(19), None);
        assert_eq!(map.get_object(20), Some(&"obj1"));
        assert_eq!(map.get_object(24), Some(&"obj1"));
        assert_eq!(map.get_object(25), None);
        assert_eq!(map.get_object(40), None);
        assert_eq!(map.get_object(50), None);
        assert_eq!(map.get_object(51), None);
        assert_eq!(map.get_object(85), None);
        assert_eq!(map.get_object(86), Some(&"obj1"));
        assert_eq!(map.get_object(90), Some(&"obj1"));
        assert_eq!(map.get_object(91), None);
    }

    #[test]
    fn contains_reflects_ranges() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");
        assert!(!map.contains(10));
        assert!(!map.contains(19));
        assert!(map.contains(20));
        assert!(map.contains(25));
        assert!(map.contains(30));
        assert!(!map.contains(31));
        assert!(!map.contains(39));
        assert!(map.contains(40));
        assert!(!map.contains(79));
        assert!(map.contains(80));
        assert!(map.contains(81));
        assert!(map.contains(89));
        assert!(map.contains(90));
        assert!(!map.contains(91));
        assert!(!map.contains(1000));
    }

    #[test]
    fn iterator_visits_all_ranges() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");

        let mut it = map.get_index_range_iterator();
        let expected = [(20, 30), (40, 50), (60, 70), (80, 90)];
        for (s, e) in expected {
            assert!(it.has_next());
            let range = it.next();
            assert_eq!(range.start(), s);
            assert_eq!(range.end(), e);
        }
        assert!(!it.has_next());
    }

    #[test]
    fn restricted_iterator_clips_boundary_ranges() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");

        let mut it = map.get_index_range_iterator_in_range(25, 85);
        let expected = [(25, 30), (40, 50), (60, 70), (80, 85)];
        for (s, e) in expected {
            assert!(it.has_next());
            let range = it.next();
            assert_eq!(range.start(), s);
            assert_eq!(range.end(), e);
        }
        assert!(!it.has_next());
    }

    #[test]
    fn restricted_iterator_before_all_ranges_is_empty() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");

        let it = map.get_index_range_iterator_in_range(0, 10);
        assert!(!it.has_next());
    }

    #[test]
    fn restricted_iterator_after_all_ranges_is_empty() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");

        let it = map.get_index_range_iterator_in_range(100, 200);
        assert!(!it.has_next());
    }

    #[test]
    fn restricted_iterator_exact_range_match() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");

        let mut it = map.get_index_range_iterator_in_range(40, 50);
        assert!(it.has_next());
        let range = it.next();
        assert_eq!(range.start(), 40);
        assert_eq!(range.end(), 50);
        assert!(!it.has_next());
    }

    #[test]
    fn restricted_iterator_clips_leading_range() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");

        let mut it = map.get_index_range_iterator_in_range(0, 25);
        assert!(it.has_next());
        let range = it.next();
        assert_eq!(range.start(), 20);
        assert_eq!(range.end(), 25);
        assert!(!it.has_next());
    }

    #[test]
    fn restricted_iterator_clips_trailing_range() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");

        let mut it = map.get_index_range_iterator_in_range(65, 100);
        let expected = [(65, 70), (80, 90)];
        for (s, e) in expected {
            assert!(it.has_next());
            let range = it.next();
            assert_eq!(range.start(), s);
            assert_eq!(range.end(), e);
        }
        assert!(!it.has_next());
    }

    #[test]
    fn restricted_iterator_fully_inside_a_single_range() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");

        let mut it = map.get_index_range_iterator_in_range(42, 48);
        assert!(it.has_next());
        let range = it.next();
        assert_eq!(range.start(), 42);
        assert_eq!(range.end(), 48);
        assert!(!it.has_next());
    }

    #[test]
    fn restricted_iterator_spans_a_gap() {
        let mut map = ObjectRangeMap::new();
        map.set_object(20, 30, "obj1");
        map.set_object(40, 50, "obj1");
        map.set_object(60, 70, "obj1");
        map.set_object(80, 90, "obj1");

        let mut it = map.get_index_range_iterator_in_range(35, 55);
        assert!(it.has_next());
        let range = it.next();
        assert_eq!(range.start(), 40);
        assert_eq!(range.end(), 50);
        assert!(!it.has_next());
    }
}

use std::cmp::Ordering;

/// A method outline for setting an entry in a range map where coalescing is desired.
///
/// Implementors supply the primitive map operations; the provided [`set`][RangeMapSetter::set]
/// and [`set_range`][RangeMapSetter::set_range] methods implement the full coalescing algorithm,
/// merging adjacent or overlapping entries that share the same value.
///
/// Mirrors `generic.RangeMapSetter` from Ghidra.
pub trait RangeMapSetter {
    /// The type of a map entry.
    type E;
    /// The type of range bounds. Must be [`Clone`] for internal bookkeeping.
    type D: Clone;
    /// The type of a closed interval. Must be [`Clone`] for internal bookkeeping.
    type R: Clone;
    /// The type of values stored in the map.
    type V: PartialEq + Clone;

    /// Compare two bounds with a total ordering.
    fn compare(&self, d1: &Self::D, d2: &Self::D) -> Ordering;

    /// Return the range covered by `entry`.
    fn get_range(&self, entry: &Self::E) -> Self::R;

    /// Return the value stored in `entry`.
    fn get_value(&self, entry: &Self::E) -> Self::V;

    /// Remove `entry` from the underlying map.
    fn remove_entry(&mut self, entry: &Self::E);

    /// Return the lower (inclusive) bound of `range`.
    fn get_lower(&self, range: &Self::R) -> Self::D;

    /// Return the upper (inclusive) bound of `range`.
    fn get_upper(&self, range: &Self::R) -> Self::D;

    /// Construct a closed range spanning `[lower, upper]`.
    fn to_span(&self, lower: Self::D, upper: Self::D) -> Self::R;

    /// Return the bound immediately preceding `d`, or [`None`] if none exists.
    fn get_previous(&self, d: &Self::D) -> Option<Self::D>;

    /// Return the bound immediately following `d`, or [`None`] if none exists.
    fn get_next(&self, d: &Self::D) -> Option<Self::D>;

    /// Return all entries whose ranges intersect the closed interval `[lower, upper]`.
    ///
    /// Implementations must return owned entries because the map is mutated immediately
    /// after this call returns.
    fn get_intersecting(&self, lower: &Self::D, upper: &Self::D) -> Vec<Self::E>;

    /// Insert a mapping from `range` to `value`, returning the resulting entry.
    fn put(&mut self, range: Self::R, value: Self::V) -> Self::E;

    /// Return whether two values are considered equal. Defaults to [`PartialEq`].
    fn values_equal(&self, v1: &Self::V, v2: &Self::V) -> bool {
        v1 == v2
    }

    /// Return `get_previous(d)` if a predecessor exists, otherwise return `d`.
    fn get_previous_or_same(&self, d: Self::D) -> Self::D {
        self.get_previous(&d).unwrap_or(d)
    }

    /// Return `get_next(d)` if a successor exists, otherwise return `d`.
    fn get_next_or_same(&self, d: Self::D) -> Self::D {
        self.get_next(&d).unwrap_or(d)
    }

    /// Return `true` if the two ranges intersect or their bounds abut.
    fn connects(&self, r1: &Self::R, r2: &Self::R) -> bool {
        let prev_lower1 = self.get_previous_or_same(self.get_lower(r1));
        let upper2 = self.get_upper(r2);
        let prev_lower2 = self.get_previous_or_same(self.get_lower(r2));
        let upper1 = self.get_upper(r1);
        self.compare(&prev_lower1, &upper2) != Ordering::Greater
            || self.compare(&prev_lower2, &upper1) != Ordering::Greater
    }

    /// Set `range` to `value`, coalescing adjacent or overlapping entries that share
    /// the same value. Returns the entry that now covers (at least) `range`.
    fn set_range(&mut self, range: &Self::R, value: Self::V) -> Self::E {
        let lower = self.get_lower(range);
        let upper = self.get_upper(range);
        self.set(lower, upper, value)
    }

    /// Set `[lower, upper]` to `value`, coalescing adjacent or overlapping entries
    /// that share the same value. Returns the entry that now covers (at least)
    /// `[lower, upper]`.
    fn set(&mut self, mut lower: Self::D, mut upper: Self::D, value: Self::V) -> Self::E {
        // Expand one position in each direction to detect abutting entries.
        let prev = self.get_previous_or_same(lower.clone());
        let next = self.get_next_or_same(upper.clone());

        let intersecting = self.get_intersecting(&prev, &next);

        let mut to_remove: Vec<Self::E> = Vec::new();
        let mut to_put: Vec<(Self::R, Self::V)> = Vec::new();

        for entry in intersecting {
            let r = self.get_range(&entry);
            let r_lower = self.get_lower(&r);
            let r_upper = self.get_upper(&r);
            let cmp_min = self.compare(&r_lower, &lower);
            let cmp_max = self.compare(&r_upper, &upper);
            let entry_val = self.get_value(&entry);
            let same_val = self.values_equal(&entry_val, &value);

            if cmp_min != Ordering::Greater && cmp_max != Ordering::Less && same_val {
                return entry;
            }

            to_remove.push(entry);

            if cmp_min == Ordering::Less {
                if same_val {
                    lower = r_lower;
                } else {
                    to_put.push((self.to_span(r_lower, prev.clone()), entry_val.clone()));
                }
            }
            if cmp_max == Ordering::Greater {
                if same_val {
                    upper = r_upper;
                } else {
                    to_put.push((self.to_span(next.clone(), r_upper), entry_val.clone()));
                }
            }
        }

        for entry in &to_remove {
            self.remove_entry(entry);
        }
        let result = self.put(self.to_span(lower, upper), value);
        debug_assert!(to_put.len() <= 2);
        for (range, val) in to_put {
            self.put(range, val);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Concrete test implementation: integer ranges backed by a flat Vec.
    // E = (start, end, value), D = i64, R = (i64, i64), V = i32.
    struct IntRangeMap {
        entries: Vec<(i64, i64, i32)>,
    }

    impl IntRangeMap {
        fn new() -> Self {
            Self { entries: Vec::new() }
        }

        fn sorted(&self) -> Vec<(i64, i64, i32)> {
            let mut v = self.entries.clone();
            v.sort();
            v
        }
    }

    impl RangeMapSetter for IntRangeMap {
        type E = (i64, i64, i32);
        type D = i64;
        type R = (i64, i64);
        type V = i32;

        fn compare(&self, d1: &i64, d2: &i64) -> Ordering {
            d1.cmp(d2)
        }

        fn get_range(&self, entry: &(i64, i64, i32)) -> (i64, i64) {
            (entry.0, entry.1)
        }

        fn get_value(&self, entry: &(i64, i64, i32)) -> i32 {
            entry.2
        }

        fn remove_entry(&mut self, entry: &(i64, i64, i32)) {
            self.entries.retain(|e| e != entry);
        }

        fn get_lower(&self, range: &(i64, i64)) -> i64 {
            range.0
        }

        fn get_upper(&self, range: &(i64, i64)) -> i64 {
            range.1
        }

        fn to_span(&self, lower: i64, upper: i64) -> (i64, i64) {
            (lower, upper)
        }

        fn get_previous(&self, d: &i64) -> Option<i64> {
            d.checked_sub(1)
        }

        fn get_next(&self, d: &i64) -> Option<i64> {
            d.checked_add(1)
        }

        fn get_intersecting(&self, lower: &i64, upper: &i64) -> Vec<(i64, i64, i32)> {
            self.entries
                .iter()
                .filter(|e| e.1 >= *lower && e.0 <= *upper)
                .cloned()
                .collect()
        }

        fn put(&mut self, range: (i64, i64), value: i32) -> (i64, i64, i32) {
            let entry = (range.0, range.1, value);
            self.entries.push(entry);
            entry
        }
    }

    #[test]
    fn test_set_empty_map() {
        let mut m = IntRangeMap::new();
        let result = m.set(1, 5, 42);
        assert_eq!(result, (1, 5, 42));
        assert_eq!(m.sorted(), vec![(1, 5, 42)]);
    }

    #[test]
    fn test_set_no_overlap() {
        let mut m = IntRangeMap::new();
        m.set(1, 3, 10);
        m.set(7, 9, 20);
        assert_eq!(m.sorted(), vec![(1, 3, 10), (7, 9, 20)]);
    }

    #[test]
    fn test_set_same_value_abutting_right_neighbor() {
        // [1,5,v] then set [6,9,v] → coalesce to [1,9,v]
        let mut m = IntRangeMap::new();
        m.set(1, 5, 10);
        m.set(6, 9, 10);
        assert_eq!(m.sorted(), vec![(1, 9, 10)]);
    }

    #[test]
    fn test_set_same_value_abutting_left_neighbor() {
        // [6,9,v] then set [1,5,v] → coalesce to [1,9,v]
        let mut m = IntRangeMap::new();
        m.set(6, 9, 10);
        m.set(1, 5, 10);
        assert_eq!(m.sorted(), vec![(1, 9, 10)]);
    }

    #[test]
    fn test_set_same_value_overlapping_extends_right() {
        // [1,5,v] then set [3,9,v] → coalesce to [1,9,v]
        let mut m = IntRangeMap::new();
        m.set(1, 5, 10);
        m.set(3, 9, 10);
        assert_eq!(m.sorted(), vec![(1, 9, 10)]);
    }

    #[test]
    fn test_set_same_value_overlapping_extends_left() {
        // [5,9,v] then set [1,7,v] → coalesce to [1,9,v]
        let mut m = IntRangeMap::new();
        m.set(5, 9, 10);
        m.set(1, 7, 10);
        assert_eq!(m.sorted(), vec![(1, 9, 10)]);
    }

    #[test]
    fn test_set_same_value_subsumes_both_neighbors() {
        // [1,3,v], [7,9,v] then set [2,8,v] → coalesce to [1,9,v]
        let mut m = IntRangeMap::new();
        m.set(1, 3, 10);
        m.set(7, 9, 10);
        m.set(2, 8, 10);
        assert_eq!(m.sorted(), vec![(1, 9, 10)]);
    }

    #[test]
    fn test_set_already_covered_same_value_returns_existing() {
        // [1,9,v] then set [3,6,v] → no change, returns existing entry
        let mut m = IntRangeMap::new();
        m.set(1, 9, 10);
        let result = m.set(3, 6, 10);
        assert_eq!(result, (1, 9, 10));
        assert_eq!(m.sorted(), vec![(1, 9, 10)]);
    }

    #[test]
    fn test_set_different_value_splits_existing() {
        // [1,9,10] then set [3,6,20] → [1,2,10], [3,6,20], [7,9,10]
        let mut m = IntRangeMap::new();
        m.set(1, 9, 10);
        m.set(3, 6, 20);
        assert_eq!(m.sorted(), vec![(1, 2, 10), (3, 6, 20), (7, 9, 10)]);
    }

    #[test]
    fn test_set_different_value_truncates_left() {
        // [1,5,10] then set [3,9,20] → [1,2,10], [3,9,20]
        let mut m = IntRangeMap::new();
        m.set(1, 5, 10);
        m.set(3, 9, 20);
        assert_eq!(m.sorted(), vec![(1, 2, 10), (3, 9, 20)]);
    }

    #[test]
    fn test_set_different_value_truncates_right() {
        // [5,9,10] then set [1,7,20] → [1,7,20], [8,9,10]
        let mut m = IntRangeMap::new();
        m.set(5, 9, 10);
        m.set(1, 7, 20);
        assert_eq!(m.sorted(), vec![(1, 7, 20), (8, 9, 10)]);
    }

    #[test]
    fn test_set_range_delegates_to_set() {
        let mut m = IntRangeMap::new();
        let result = m.set_range(&(2, 7), 99);
        assert_eq!(result, (2, 7, 99));
        assert_eq!(m.sorted(), vec![(2, 7, 99)]);
    }

    #[test]
    fn test_get_previous_or_same_at_min() {
        let m = IntRangeMap::new();
        assert_eq!(m.get_previous_or_same(i64::MIN), i64::MIN);
    }

    #[test]
    fn test_get_next_or_same_at_max() {
        let m = IntRangeMap::new();
        assert_eq!(m.get_next_or_same(i64::MAX), i64::MAX);
    }

    #[test]
    fn test_connects_overlapping() {
        let m = IntRangeMap::new();
        assert!(m.connects(&(1, 5), &(3, 9)));
    }

    #[test]
    fn test_connects_abutting() {
        // [1,5] and [6,9]: prev(6)=5 <= upper(5) → connected
        let m = IntRangeMap::new();
        assert!(m.connects(&(1, 5), &(6, 9)));
    }

    #[test]
    fn test_values_equal_default() {
        let m = IntRangeMap::new();
        assert!(m.values_equal(&10, &10));
        assert!(!m.values_equal(&10, &20));
    }
}

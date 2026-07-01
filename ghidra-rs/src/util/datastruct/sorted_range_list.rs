use super::Range;
use std::fmt;

/// A list of `i32` ranges maintained in sorted order.
///
/// When a range is added, any ranges that overlap or are adjacent to one another coalesce
/// into a single range.
///
/// Port of `ghidra.util.datastruct.SortedRangeList`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SortedRangeList {
    ranges: Vec<Range>,
}

impl SortedRangeList {
    /// Creates a new empty sorted range list.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Returns the index of the first range whose `min` is `>= min`, i.e. the number of
    /// ranges that sort strictly before it (equivalent to Java's `TreeSet.headSet(key).size()`).
    fn tail_start(&self, min: i32) -> usize {
        self.ranges.partition_point(|r| r.min < min)
    }

    /// Adds the range from `min` to `max` to this sorted range list. If the range is adjacent
    /// to or overlaps any other existing ranges, then those ranges coalesce.
    pub fn add_range(&mut self, min: i32, max: i32) {
        let tail_start = self.tail_start(min);
        if tail_start > 0 {
            let last_idx = tail_start - 1;
            if min <= self.ranges[last_idx].max + 1 {
                self.ranges[last_idx].max = self.ranges[last_idx].max.max(max);
                self.coalesce(last_idx, tail_start);
                return;
            }
        }
        if tail_start == self.ranges.len() {
            self.ranges.push(Range::new(min, max));
            return;
        }
        if max < self.ranges[tail_start].min - 1 {
            self.ranges.insert(tail_start, Range::new(min, max));
            return;
        }
        self.ranges[tail_start].min = self.ranges[tail_start].min.min(min);
        self.ranges[tail_start].max = self.ranges[tail_start].max.max(max);
        self.coalesce(tail_start, tail_start + 1);
    }

    /// Coalesces any ranges starting at `start_idx` that are adjacent to or overlap
    /// `self.ranges[target_idx]`, absorbing them into it and removing them from the list.
    fn coalesce(&mut self, target_idx: usize, start_idx: usize) {
        let mut end = start_idx;
        while end < self.ranges.len() {
            if self.ranges[end].min > self.ranges[target_idx].max + 1 {
                break;
            }
            self.ranges[target_idx].max = self.ranges[target_idx].max.max(self.ranges[end].max);
            end += 1;
        }
        self.ranges.drain(start_idx..end);
    }

    /// Returns an iterator over all the ranges in this list, from minimum to maximum.
    pub fn get_ranges(&self) -> impl Iterator<Item = Range> + '_ {
        self.ranges.iter().copied()
    }

    /// Returns an iterator over all the ranges in this list, ordered as indicated: `true` for
    /// forward iteration from minimum to maximum, `false` for backward iteration from maximum
    /// to minimum.
    pub fn get_ranges_ordered(&self, forward: bool) -> Box<dyn Iterator<Item = Range> + '_> {
        if forward {
            Box::new(self.ranges.iter().copied())
        }
        else {
            Box::new(self.ranges.iter().rev().copied())
        }
    }

    /// Returns the minimum value in this sorted range list, or `None` if the list is empty.
    pub fn get_min(&self) -> Option<i32> {
        self.ranges.first().map(|r| r.min)
    }

    /// Returns the maximum value in this sorted range list, or `None` if the list is empty.
    pub fn get_max(&self) -> Option<i32> {
        self.ranges.last().map(|r| r.max)
    }

    /// Returns the number of ranges in the list.
    pub fn get_num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Removes the indicated range of values from the list. This removes any ranges or
    /// portions of ranges that overlap the indicated range.
    pub fn remove_range(&mut self, min: i32, max: i32) {
        let tail_start = self.tail_start(min);
        if tail_start > 0 {
            let last_idx = tail_start - 1;
            if self.ranges[last_idx].max >= min {
                if max < self.ranges[last_idx].max {
                    let last_max = self.ranges[last_idx].max;
                    self.ranges[last_idx].max = self.ranges[last_idx].max.min(min - 1);
                    self.ranges.insert(tail_start, Range::new(max + 1, last_max));
                    return;
                }
                self.ranges[last_idx].max = self.ranges[last_idx].max.min(min - 1);
            }
        }
        let mut idx = tail_start;
        while idx < self.ranges.len() {
            if self.ranges[idx].min > max {
                break;
            }
            if self.ranges[idx].max > max {
                self.ranges[idx].min = max + 1;
                break;
            }
            idx += 1;
        }
        self.ranges.drain(tail_start..idx);
    }

    /// Returns `true` if the value is contained in any range within this list.
    pub fn contains(&self, value: i32) -> bool {
        let tail_start = self.tail_start(value);
        if tail_start > 0 && self.ranges[tail_start - 1].max >= value {
            return true;
        }
        tail_start < self.ranges.len() && self.ranges[tail_start].min == value
    }

    fn get_range_containing(&self, value: i32) -> Option<Range> {
        let tail_start = self.tail_start(value);
        if tail_start > 0 {
            let last = self.ranges[tail_start - 1];
            if last.max >= value {
                return Some(last);
            }
        }
        if tail_start < self.ranges.len() {
            let range = self.ranges[tail_start];
            if range.min == value {
                return Some(range);
            }
        }
        None
    }

    /// Returns `true` if a single range contains all the values from `min` to `max`.
    pub fn contains_range(&self, min: i32, max: i32) -> bool {
        match self.get_range_containing(min) {
            Some(range) => range.contains(max),
            None => false,
        }
    }

    /// Returns the range index for the range containing the specified value, or a negative
    /// value if the range list doesn't contain the value.
    pub fn get_range_index(&self, value: i32) -> i32 {
        let tail_start = self.tail_start(value);
        let mut index = tail_start as i32 - 1;
        if tail_start > 0 && self.ranges[tail_start - 1].max >= value {
            return index;
        }
        index += 1;
        if tail_start < self.ranges.len() && self.ranges[tail_start].min == value {
            return index;
        }
        -index - 1
    }

    /// Returns the nth range in this list as indicated by `index`, or `None` if there is no
    /// such range in this list.
    pub fn get_range(&self, index: i32) -> Option<Range> {
        if index < 0 {
            return None;
        }
        self.ranges.get(index as usize).copied()
    }

    /// Returns the total number of values covered by the ranges in this list.
    pub fn get_num_values(&self) -> i64 {
        self.ranges.iter().map(|r| r.size()).sum()
    }

    /// Returns `true` if the range from `min` to `max` intersects (overlaps) any ranges in
    /// this sorted range list.
    pub fn intersects(&self, min: i32, max: i32) -> bool {
        let tail_start = self.tail_start(min);
        if tail_start > 0 && self.ranges[tail_start - 1].max >= min {
            return true;
        }
        tail_start < self.ranges.len() && self.ranges[tail_start].min <= max
    }

    /// Returns `true` if the range list is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Removes all the ranges that are in `other` from this list.
    pub fn remove(&mut self, other: &SortedRangeList) {
        for r in other.get_ranges() {
            self.remove_range(r.min, r.max);
        }
    }

    /// Creates a new `SortedRangeList` that is the intersection of this range list and
    /// `other`.
    pub fn intersect(&self, other: &SortedRangeList) -> SortedRangeList {
        let mut srl = self.clone();
        srl.remove(other);
        let mut srl2 = self.clone();
        srl2.remove(&srl);
        srl2
    }

    /// Removes all the ranges from this list.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }
}

impl fmt::Display for SortedRangeList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, r) in self.ranges.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "[{},{}]", r.min, r.max)?;
        }
        Ok(())
    }
}

impl<'a> IntoIterator for &'a SortedRangeList {
    type Item = Range;
    type IntoIter = std::iter::Copied<std::slice::Iter<'a, Range>>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_list_is_empty() {
        let l = SortedRangeList::new();
        assert!(l.is_empty());
        assert_eq!(l.get_num_ranges(), 0);
    }

    #[test]
    fn add_disjoint_ranges_stay_separate() {
        let mut l = SortedRangeList::new();
        l.add_range(10, 20);
        l.add_range(30, 40);
        assert_eq!(l.get_num_ranges(), 2);
        assert_eq!(format!("{l}"), "[10,20] [30,40]");
    }

    #[test]
    fn add_overlapping_ranges_coalesce() {
        let mut l = SortedRangeList::new();
        l.add_range(10, 20);
        l.add_range(15, 25);
        assert_eq!(l.get_num_ranges(), 1);
        assert_eq!(format!("{l}"), "[10,25]");
    }

    #[test]
    fn add_adjacent_ranges_coalesce() {
        let mut l = SortedRangeList::new();
        l.add_range(10, 20);
        l.add_range(21, 30);
        assert_eq!(l.get_num_ranges(), 1);
        assert_eq!(format!("{l}"), "[10,30]");
    }

    #[test]
    fn add_range_bridges_two_existing_ranges() {
        let mut l = SortedRangeList::new();
        l.add_range(0, 5);
        l.add_range(20, 25);
        l.add_range(4, 21);
        assert_eq!(l.get_num_ranges(), 1);
        assert_eq!(format!("{l}"), "[0,25]");
    }

    #[test]
    fn add_range_inserted_before_head() {
        let mut l = SortedRangeList::new();
        l.add_range(50, 60);
        l.add_range(0, 5);
        assert_eq!(format!("{l}"), "[0,5] [50,60]");
    }

    #[test]
    fn copy_constructor_equivalent_clones_ranges() {
        let mut l = SortedRangeList::new();
        l.add_range(1, 5);
        l.add_range(10, 15);
        let copy = l.clone();
        assert_eq!(l, copy);
    }

    #[test]
    fn get_min_and_max() {
        let mut l = SortedRangeList::new();
        assert_eq!(l.get_min(), None);
        assert_eq!(l.get_max(), None);
        l.add_range(10, 20);
        l.add_range(30, 40);
        assert_eq!(l.get_min(), Some(10));
        assert_eq!(l.get_max(), Some(40));
    }

    #[test]
    fn get_ranges_forward_order() {
        let mut l = SortedRangeList::new();
        l.add_range(30, 40);
        l.add_range(10, 20);
        let v: Vec<Range> = l.get_ranges().collect();
        assert_eq!(v, vec![Range::new(10, 20), Range::new(30, 40)]);
    }

    #[test]
    fn get_ranges_ordered_backward() {
        let mut l = SortedRangeList::new();
        l.add_range(30, 40);
        l.add_range(10, 20);
        let v: Vec<Range> = l.get_ranges_ordered(false).collect();
        assert_eq!(v, vec![Range::new(30, 40), Range::new(10, 20)]);
    }

    #[test]
    fn remove_range_splits_a_range() {
        let mut l = SortedRangeList::new();
        l.add_range(0, 20);
        l.remove_range(5, 10);
        assert_eq!(format!("{l}"), "[0,4] [11,20]");
    }

    #[test]
    fn remove_range_truncates_from_start() {
        let mut l = SortedRangeList::new();
        l.add_range(0, 20);
        l.remove_range(0, 5);
        assert_eq!(format!("{l}"), "[6,20]");
    }

    #[test]
    fn remove_range_truncates_from_end() {
        let mut l = SortedRangeList::new();
        l.add_range(0, 20);
        l.remove_range(15, 20);
        assert_eq!(format!("{l}"), "[0,14]");
    }

    #[test]
    fn remove_range_removes_whole_ranges() {
        let mut l = SortedRangeList::new();
        l.add_range(0, 5);
        l.add_range(10, 15);
        l.add_range(20, 25);
        l.remove_range(0, 25);
        assert!(l.is_empty());
    }

    #[test]
    fn remove_range_spans_multiple_ranges() {
        let mut l = SortedRangeList::new();
        l.add_range(0, 5);
        l.add_range(10, 15);
        l.add_range(20, 25);
        l.remove_range(3, 22);
        assert_eq!(format!("{l}"), "[0,2] [23,25]");
    }

    #[test]
    fn contains_value() {
        let mut l = SortedRangeList::new();
        l.add_range(10, 20);
        assert!(l.contains(10));
        assert!(l.contains(15));
        assert!(l.contains(20));
        assert!(!l.contains(9));
        assert!(!l.contains(21));
    }

    #[test]
    fn contains_range() {
        let mut l = SortedRangeList::new();
        l.add_range(10, 20);
        assert!(l.contains_range(12, 18));
        assert!(!l.contains_range(12, 25));
        assert!(!l.contains_range(5, 8));
    }

    #[test]
    fn get_range_index_found_and_not_found() {
        let mut l = SortedRangeList::new();
        l.add_range(10, 20);
        l.add_range(30, 40);
        assert_eq!(l.get_range_index(15), 0);
        assert_eq!(l.get_range_index(35), 1);
        assert!(l.get_range_index(25) < 0);
    }

    #[test]
    fn get_range_by_index() {
        let mut l = SortedRangeList::new();
        l.add_range(10, 20);
        l.add_range(30, 40);
        assert_eq!(l.get_range(0), Some(Range::new(10, 20)));
        assert_eq!(l.get_range(1), Some(Range::new(30, 40)));
        assert_eq!(l.get_range(2), None);
        assert_eq!(l.get_range(-1), None);
    }

    #[test]
    fn get_num_values_sums_range_sizes() {
        let mut l = SortedRangeList::new();
        l.add_range(0, 9);
        l.add_range(20, 24);
        assert_eq!(l.get_num_values(), 15);
    }

    #[test]
    fn intersects_checks_overlap() {
        let mut l = SortedRangeList::new();
        l.add_range(10, 20);
        assert!(l.intersects(15, 25));
        assert!(l.intersects(0, 10));
        assert!(!l.intersects(21, 30));
        assert!(!l.intersects(0, 9));
    }

    #[test]
    fn remove_other_list() {
        let mut a = SortedRangeList::new();
        a.add_range(0, 20);
        let mut b = SortedRangeList::new();
        b.add_range(5, 10);
        a.remove(&b);
        assert_eq!(format!("{a}"), "[0,4] [11,20]");
    }

    #[test]
    fn intersect_two_lists() {
        let mut a = SortedRangeList::new();
        a.add_range(0, 20);
        let mut b = SortedRangeList::new();
        b.add_range(10, 30);
        let result = a.intersect(&b);
        assert_eq!(format!("{result}"), "[10,20]");
    }

    #[test]
    fn clear_empties_list() {
        let mut l = SortedRangeList::new();
        l.add_range(0, 10);
        l.clear();
        assert!(l.is_empty());
        assert_eq!(l.get_num_ranges(), 0);
    }

    #[test]
    fn display_empty_list() {
        let l = SortedRangeList::new();
        assert_eq!(format!("{l}"), "");
    }

    #[test]
    fn into_iter_ref_forward() {
        let mut l = SortedRangeList::new();
        l.add_range(0, 5);
        l.add_range(10, 15);
        let v: Vec<Range> = (&l).into_iter().collect();
        assert_eq!(v, vec![Range::new(0, 5), Range::new(10, 15)]);
    }

    #[test]
    fn equality_and_default() {
        let a = SortedRangeList::default();
        let mut b = SortedRangeList::new();
        assert_eq!(a, b);
        b.add_range(1, 2);
        assert_ne!(a, b);
    }
}

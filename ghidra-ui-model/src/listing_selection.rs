//! Listing selection at whole-row granularity (Java `FieldSelection` as the
//! code browser uses it: whole code units): sorted, merged inclusive index
//! ranges.

/// A set of selected row indices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexSelection {
    ranges: Vec<(u128, u128)>,
}

impl IndexSelection {
    /// Removes everything.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    /// Replaces the selection with rows `a..=b` (either order).
    pub fn set_range(&mut self, a: u128, b: u128) {
        self.ranges = vec![(a.min(b), a.max(b))];
    }

    /// Adds rows `a..=b`, merging with overlapping or adjacent ranges.
    pub fn add_range(&mut self, a: u128, b: u128) {
        let (mut lo, mut hi) = (a.min(b), a.max(b));
        self.ranges.retain(|&(l, h)| {
            let touches = l <= hi.saturating_add(1) && lo <= h.saturating_add(1);
            if touches {
                lo = lo.min(l);
                hi = hi.max(h);
            }
            !touches
        });
        let at = self.ranges.partition_point(|&(l, _)| l < lo);
        self.ranges.insert(at, (lo, hi));
    }

    /// Whether row `i` is selected.
    pub fn contains(&self, i: u128) -> bool {
        self.ranges.iter().any(|&(lo, hi)| lo <= i && i <= hi)
    }

    /// Inclusive ranges in order.
    pub fn ranges(&self) -> &[(u128, u128)] {
        &self.ranges
    }

    /// Whether nothing is selected.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Number of selected rows (saturating).
    pub fn row_count(&self) -> u128 {
        self.ranges.iter().fold(0u128, |n, &(lo, hi)| n.saturating_add((hi - lo).saturating_add(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_ranges_stay_sorted_and_merge_when_touching() {
        let mut s = IndexSelection::default();
        s.add_range(10, 12);
        s.add_range(1, 2);
        s.add_range(4, 3); // adjacent to 1..=2
        assert_eq!(s.ranges(), &[(1, 4), (10, 12)]);
        s.add_range(5, 9); // bridges both
        assert_eq!(s.ranges(), &[(1, 12)]);
    }

    #[test]
    fn ranges_are_order_insensitive_and_inclusive() {
        let mut s = IndexSelection::default();
        s.set_range(7, 4);
        assert_eq!(s.ranges(), &[(4, 7)]);
        assert!(s.contains(4) && s.contains(7) && !s.contains(3) && !s.contains(8));
        assert_eq!(s.row_count(), 4);
    }

    #[test]
    fn a_range_ending_at_u128_max_does_not_overflow() {
        let mut s = IndexSelection::default();
        s.set_range(u128::MAX, u128::MAX - 2);
        assert!(s.contains(u128::MAX));
        assert_eq!(s.row_count(), 3);
        s.set_range(0, u128::MAX);
        assert_eq!(s.row_count(), u128::MAX);
    }

    #[test]
    fn clear_empties() {
        let mut s = IndexSelection::default();
        assert!(s.is_empty());
        s.set_range(1, 1);
        assert!(!s.is_empty());
        s.clear();
        assert!(s.is_empty() && s.ranges().is_empty() && s.row_count() == 0);
    }
}

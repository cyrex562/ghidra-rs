use crate::util::datastruct::IndexRange;

/// Iterator over index ranges.
///
/// Port of `ghidra.util.datastruct.IndexRangeIterator`.
pub trait IndexRangeIterator {
    /// Returns `true` if there are more index ranges.
    fn has_next(&self) -> bool;

    /// Returns the next index range.
    ///
    /// This should only be called when [`has_next`](Self::has_next) returns `true`.
    fn next(&mut self) -> IndexRange;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleIndexRangeIterator {
        ranges: Vec<IndexRange>,
        index: usize,
    }

    impl SimpleIndexRangeIterator {
        fn new(ranges: Vec<IndexRange>) -> Self {
            Self { ranges, index: 0 }
        }
    }

    impl IndexRangeIterator for SimpleIndexRangeIterator {
        fn has_next(&self) -> bool {
            self.index < self.ranges.len()
        }

        fn next(&mut self) -> IndexRange {
            let range = self.ranges[self.index];
            self.index += 1;
            range
        }
    }

    #[test]
    fn empty_iterator_has_no_next() {
        let iter = SimpleIndexRangeIterator::new(vec![]);
        assert!(!iter.has_next());
    }

    #[test]
    fn single_range_iterator() {
        let range = IndexRange::new(10, 20);
        let mut iter = SimpleIndexRangeIterator::new(vec![range]);

        assert!(iter.has_next());
        let next = iter.next();
        assert_eq!(next, range);
        assert!(!iter.has_next());
    }

    #[test]
    fn multiple_ranges_iterator() {
        let ranges = vec![
            IndexRange::new(0, 10),
            IndexRange::new(20, 30),
            IndexRange::new(40, 50),
        ];
        let mut iter = SimpleIndexRangeIterator::new(ranges.clone());

        for expected_range in &ranges {
            assert!(iter.has_next());
            let range = iter.next();
            assert_eq!(range, *expected_range);
        }
        assert!(!iter.has_next());
    }

    #[test]
    fn next_after_exhausted_panics() {
        let range = IndexRange::new(5, 15);
        let mut iter = SimpleIndexRangeIterator::new(vec![range]);

        iter.next();
        assert!(!iter.has_next());
        // Calling next on exhausted iterator will panic on index out of bounds
    }

    #[test]
    fn iterator_with_negative_indices() {
        let ranges = vec![IndexRange::new(-100, -50), IndexRange::new(0, 100)];
        let mut iter = SimpleIndexRangeIterator::new(ranges.clone());

        assert!(iter.has_next());
        assert_eq!(iter.next(), ranges[0]);
        assert!(iter.has_next());
        assert_eq!(iter.next(), ranges[1]);
        assert!(!iter.has_next());
    }

    #[test]
    fn iterator_with_adjacent_ranges() {
        let ranges = vec![
            IndexRange::new(0, 99),
            IndexRange::new(100, 199),
            IndexRange::new(200, 299),
        ];
        let mut iter = SimpleIndexRangeIterator::new(ranges.clone());

        for expected_range in &ranges {
            assert_eq!(iter.next(), *expected_range);
        }
    }
}

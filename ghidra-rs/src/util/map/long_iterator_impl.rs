use std::cell::Cell;

use crate::util::seam_stubs::ValueMapLike;
use crate::util::LongIterator;

/// Iterator over the indexes of a `ValueMap` (property map) that have a value set.
///
/// Port of `ghidra.util.map.LongIteratorImpl`.
///
/// `hasNext`/`hasPrevious` look ahead and cache the found index in Java, mutating the
/// object even though callers treat them as queries; the cached lookahead state
/// (`current`, `does_have_next`, `does_have_previous`) is therefore kept in [`Cell`] so
/// those methods can stay `&self`, matching the [`LongIterator`] trait signature.
pub struct LongIteratorImpl<'a> {
    pm: &'a dyn ValueMapLike,
    start: i64,
    end: i64,
    has_boundaries: bool,
    current: Cell<i64>,
    does_have_next: Cell<bool>,
    does_have_previous: Cell<bool>,
}

impl<'a> LongIteratorImpl<'a> {
    /// Creates a `LongIteratorImpl` that iterates over the entire range of properties.
    pub fn new(pm: &'a dyn ValueMapLike) -> Self {
        Self::with_start_before(pm, 0, true)
    }

    /// Creates a `LongIteratorImpl` that iterates over the entire range of properties,
    /// starting at `start`.
    ///
    /// If `before` is true, `start` will be the first index returned from a call to
    /// [`LongIterator::next`]; if `before` is false, `start` will be the first index
    /// returned from a call to [`LongIterator::previous`].
    pub fn with_start_before(pm: &'a dyn ValueMapLike, start: i64, before: bool) -> Self {
        let start = if before { start } else { start + 1 };
        let iter = Self {
            pm,
            start,
            end: 0,
            has_boundaries: false,
            current: Cell::new(start),
            does_have_next: Cell::new(false),
            does_have_previous: Cell::new(false),
        };
        iter.init(true);
        iter
    }

    /// Creates a `LongIteratorImpl` that iterates over a range of property indexes
    /// (inclusive), starting from `start`.
    pub fn with_range(pm: &'a dyn ValueMapLike, start: i64, end: i64) -> Self {
        Self::with_range_at_start(pm, start, end, true)
    }

    /// Creates a `LongIteratorImpl` that iterates over a range of property indexes
    /// (inclusive). If `at_start` is true, the iterator goes from `start` to `end`;
    /// otherwise, from `end` to `start`.
    pub fn with_range_at_start(pm: &'a dyn ValueMapLike, start: i64, end: i64, at_start: bool) -> Self {
        let current = if at_start { start } else { end };
        let iter = Self {
            pm,
            start,
            end,
            has_boundaries: true,
            current: Cell::new(current),
            does_have_next: Cell::new(false),
            does_have_previous: Cell::new(false),
        };
        iter.init(at_start);
        iter
    }

    /// Determines whether there is a next index; if there is, `current` holds the value.
    fn find_next(&self) {
        if let Ok(next_index) = self.pm.get_next_property_index(self.current.get()) {
            if self.has_boundaries && next_index > self.end {
                self.does_have_next.set(false);
                return;
            }
            self.current.set(next_index);
            self.does_have_next.set(true);
            self.does_have_previous.set(false);
        }
    }

    /// Determines whether there is a previous index; if there is, `current` holds the value.
    fn find_previous(&self) {
        if let Ok(prev_index) = self.pm.get_previous_property_index(self.current.get()) {
            if self.has_boundaries && prev_index < self.start {
                self.does_have_previous.set(false);
                return;
            }
            self.current.set(prev_index);
            self.does_have_previous.set(true);
            self.does_have_next.set(false);
        }
    }

    /// Checks whether the start index has a property, so that the first call to
    /// `next`/`previous` returns it.
    fn init(&self, at_start: bool) {
        if self.pm.has_property(self.current.get()) {
            if at_start {
                self.does_have_next.set(true);
            } else {
                self.does_have_previous.set(true);
            }
        }
    }
}

impl<'a> LongIterator for LongIteratorImpl<'a> {
    fn has_next(&self) -> bool {
        if self.does_have_next.get() {
            return true;
        }
        self.find_next();
        self.does_have_next.get()
    }

    fn next(&mut self) -> i64 {
        if self.has_next() {
            self.does_have_next.set(false);
            self.does_have_previous.set(true);
            return self.current.get();
        }
        panic!("No more indexes.");
    }

    fn has_previous(&self) -> bool {
        if self.does_have_previous.get() {
            return true;
        }
        self.find_previous();
        self.does_have_previous.get()
    }

    fn previous(&mut self) -> i64 {
        if self.has_previous() {
            self.does_have_previous.set(false);
            self.does_have_next.set(true);
            return self.current.get();
        }
        panic!("No more indexes.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::datastruct::NoSuchIndexException;
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    /// A minimal in-memory stand-in for `ValueMap` backed by a sorted set of indexes.
    struct FakeValueMap {
        indexes: RefCell<BTreeSet<i64>>,
    }

    impl FakeValueMap {
        fn new(indexes: &[i64]) -> Self {
            Self { indexes: RefCell::new(indexes.iter().copied().collect()) }
        }
    }

    impl ValueMapLike for FakeValueMap {
        fn has_property(&self, index: i64) -> bool {
            self.indexes.borrow().contains(&index)
        }

        fn get_next_property_index(&self, index: i64) -> Result<i64, NoSuchIndexException> {
            self.indexes
                .borrow()
                .range((index + 1)..)
                .next()
                .copied()
                .ok_or_else(NoSuchIndexException::new)
        }

        fn get_previous_property_index(&self, index: i64) -> Result<i64, NoSuchIndexException> {
            self.indexes
                .borrow()
                .range(..index)
                .next_back()
                .copied()
                .ok_or_else(NoSuchIndexException::new)
        }
    }

    #[test]
    fn iterates_forward_over_all_properties() {
        let map = FakeValueMap::new(&[2, 5, 9]);
        let mut it = LongIteratorImpl::new(&map);
        assert!(it.has_next());
        assert_eq!(it.next(), 2);
        assert_eq!(it.next(), 5);
        assert_eq!(it.next(), 9);
        assert!(!it.has_next());
    }

    #[test]
    fn iterates_backward_over_all_properties() {
        let map = FakeValueMap::new(&[2, 5, 9]);
        let mut it = LongIteratorImpl::with_start_before(&map, i64::MAX, false);
        assert!(it.has_previous());
        assert_eq!(it.previous(), 9);
        assert_eq!(it.previous(), 5);
        assert_eq!(it.previous(), 2);
        assert!(!it.has_previous());
    }

    #[test]
    fn respects_range_boundaries() {
        let map = FakeValueMap::new(&[1, 3, 5, 7, 9]);
        let mut it = LongIteratorImpl::with_range(&map, 3, 7);
        assert_eq!(it.next(), 3);
        assert_eq!(it.next(), 5);
        assert_eq!(it.next(), 7);
        assert!(!it.has_next());
    }

    #[test]
    fn range_at_start_false_iterates_from_end() {
        let map = FakeValueMap::new(&[1, 3, 5, 7, 9]);
        let mut it = LongIteratorImpl::with_range_at_start(&map, 3, 7, false);
        assert_eq!(it.previous(), 7);
        assert_eq!(it.previous(), 5);
        assert_eq!(it.previous(), 3);
        assert!(!it.has_previous());
    }

    #[test]
    fn start_index_with_property_is_returned_first() {
        let map = FakeValueMap::new(&[4, 8]);
        let mut it = LongIteratorImpl::with_start_before(&map, 4, true);
        assert_eq!(it.next(), 4);
        assert_eq!(it.next(), 8);
        assert!(!it.has_next());
    }

    #[test]
    #[should_panic(expected = "No more indexes.")]
    fn next_panics_when_exhausted() {
        let map = FakeValueMap::new(&[]);
        let mut it = LongIteratorImpl::new(&map);
        it.next();
    }

    #[test]
    #[should_panic(expected = "No more indexes.")]
    fn previous_panics_when_exhausted() {
        let map = FakeValueMap::new(&[]);
        let mut it = LongIteratorImpl::with_start_before(&map, 0, false);
        it.previous();
    }

    #[test]
    fn ping_pong_next_then_previous() {
        let map = FakeValueMap::new(&[1, 2, 3]);
        let mut it = LongIteratorImpl::new(&map);
        assert_eq!(it.next(), 1);
        assert_eq!(it.next(), 2);
        assert_eq!(it.previous(), 2);
        assert_eq!(it.next(), 2);
        assert_eq!(it.next(), 3);
        assert!(!it.has_next());
    }
}

use super::ShortKeySet;
use std::collections::BTreeSet;
use std::ops::Bound;

/// The number of bytes in a `RedBlackKeySet` node (informational).
pub const NODESIZE: usize = 15;

/// A [`ShortKeySet`] backed by a balanced binary search tree, storing keys in the
/// range `[0, max_key]`.
///
/// All operations that accept a key require `0 <= key <= max_key`; a key outside that
/// range causes a panic, mirroring the `IndexOutOfBoundsException` thrown by the Java
/// original.
///
/// Port of `ghidra.util.datastruct.RedBlackKeySet`.
pub struct RedBlackKeySet {
    inner: BTreeSet<i16>,
    max_key: i16,
}

impl RedBlackKeySet {
    /// Creates a new empty set that can store keys between 0 and `max_key`.
    pub fn new(max_key: i16) -> Self {
        Self {
            inner: BTreeSet::new(),
            max_key,
        }
    }

    fn check_bounds(&self, key: i16) {
        assert!(
            key >= 0 && key <= self.max_key,
            "key out of bounds: {key}"
        );
    }
}

impl ShortKeySet for RedBlackKeySet {
    fn size(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn contains_key(&self, key: i16) -> bool {
        self.check_bounds(key);
        self.inner.contains(&key)
    }

    fn get_first(&self) -> Option<i16> {
        self.inner.iter().next().copied()
    }

    fn get_last(&self) -> Option<i16> {
        self.inner.iter().next_back().copied()
    }

    fn put(&mut self, key: i16) {
        self.check_bounds(key);
        self.inner.insert(key);
    }

    fn remove(&mut self, key: i16) -> bool {
        self.check_bounds(key);
        self.inner.remove(&key)
    }

    fn remove_all(&mut self) {
        self.inner.clear();
    }

    fn get_next(&self, key: i16) -> Option<i16> {
        self.check_bounds(key);
        self.inner
            .range((Bound::Excluded(&key), Bound::Unbounded))
            .next()
            .copied()
    }

    fn get_previous(&self, key: i16) -> Option<i16> {
        self.check_bounds(key);
        self.inner
            .range((Bound::Unbounded, Bound::Excluded(&key)))
            .next_back()
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_set_is_empty() {
        let s = RedBlackKeySet::new(100);
        assert!(s.is_empty());
        assert_eq!(s.size(), 0);
    }

    #[test]
    fn put_and_contains_key() {
        let mut s = RedBlackKeySet::new(100);
        assert!(!s.contains_key(5));
        s.put(5);
        assert!(s.contains_key(5));
        assert!(!s.contains_key(4));
    }

    #[test]
    fn put_duplicate_does_not_increase_size() {
        let mut s = RedBlackKeySet::new(100);
        s.put(10);
        s.put(10);
        assert_eq!(s.size(), 1);
    }

    #[test]
    fn remove_present_key_returns_true() {
        let mut s = RedBlackKeySet::new(100);
        s.put(7);
        assert!(s.remove(7));
        assert!(!s.contains_key(7));
    }

    #[test]
    fn remove_absent_key_returns_false() {
        let mut s = RedBlackKeySet::new(100);
        assert!(!s.remove(42));
    }

    #[test]
    fn remove_all_clears_set() {
        let mut s = RedBlackKeySet::new(100);
        s.put(1);
        s.put(2);
        s.put(3);
        s.remove_all();
        assert!(s.is_empty());
        assert_eq!(s.size(), 0);
    }

    #[test]
    fn get_first_returns_min_key() {
        let mut s = RedBlackKeySet::new(100);
        assert_eq!(s.get_first(), None);
        s.put(10);
        s.put(3);
        s.put(7);
        assert_eq!(s.get_first(), Some(3));
    }

    #[test]
    fn get_last_returns_max_key() {
        let mut s = RedBlackKeySet::new(100);
        assert_eq!(s.get_last(), None);
        s.put(10);
        s.put(3);
        s.put(7);
        assert_eq!(s.get_last(), Some(10));
    }

    #[test]
    fn get_next_returns_successor() {
        let mut s = RedBlackKeySet::new(100);
        s.put(1);
        s.put(3);
        s.put(5);
        assert_eq!(s.get_next(0), Some(1));
        assert_eq!(s.get_next(1), Some(3));
        assert_eq!(s.get_next(2), Some(3));
        assert_eq!(s.get_next(5), None);
    }

    #[test]
    fn get_previous_returns_predecessor() {
        let mut s = RedBlackKeySet::new(100);
        s.put(1);
        s.put(3);
        s.put(5);
        assert_eq!(s.get_previous(0), None);
        assert_eq!(s.get_previous(1), None);
        assert_eq!(s.get_previous(2), Some(1));
        assert_eq!(s.get_previous(3), Some(1));
        assert_eq!(s.get_previous(6), Some(5));
    }

    #[test]
    fn get_next_on_empty_set_returns_none() {
        let s = RedBlackKeySet::new(100);
        assert_eq!(s.get_next(0), None);
    }

    #[test]
    fn get_previous_on_empty_set_returns_none() {
        let s = RedBlackKeySet::new(100);
        assert_eq!(s.get_previous(0), None);
    }

    #[test]
    fn ascending_iteration_via_get_next() {
        let mut s = RedBlackKeySet::new(100);
        for k in [5i16, 1, 9, 3, 7] {
            s.put(k);
        }
        let mut result = Vec::new();
        let mut cur = s.get_first();
        while let Some(k) = cur {
            result.push(k);
            cur = s.get_next(k);
        }
        assert_eq!(result, vec![1, 3, 5, 7, 9]);
    }

    #[test]
    fn descending_iteration_via_get_previous() {
        let mut s = RedBlackKeySet::new(100);
        for k in [5i16, 1, 9, 3, 7] {
            s.put(k);
        }
        let mut result = Vec::new();
        let mut cur = s.get_last();
        while let Some(k) = cur {
            result.push(k);
            cur = s.get_previous(k);
        }
        assert_eq!(result, vec![9, 7, 5, 3, 1]);
    }

    #[test]
    fn size_tracks_insertions_and_removals() {
        let mut s = RedBlackKeySet::new(100);
        s.put(1);
        s.put(2);
        s.put(3);
        assert_eq!(s.size(), 3);
        s.remove(2);
        assert_eq!(s.size(), 2);
        s.remove(99);
        assert_eq!(s.size(), 2);
    }

    #[test]
    fn zero_key_is_valid() {
        let mut s = RedBlackKeySet::new(100);
        s.put(0);
        assert!(s.contains_key(0));
        assert_eq!(s.get_first(), Some(0));
        assert_eq!(s.get_previous(0), None);
        assert_eq!(s.get_next(0), None);
    }

    #[test]
    #[should_panic]
    fn put_negative_key_panics() {
        let mut s = RedBlackKeySet::new(100);
        s.put(-1);
    }

    #[test]
    #[should_panic]
    fn put_key_above_max_panics() {
        let mut s = RedBlackKeySet::new(10);
        s.put(11);
    }

    #[test]
    #[should_panic]
    fn contains_key_out_of_bounds_panics() {
        let s = RedBlackKeySet::new(10);
        s.contains_key(11);
    }

    #[test]
    #[should_panic]
    fn get_next_out_of_bounds_panics() {
        let s = RedBlackKeySet::new(10);
        s.get_next(-1);
    }

    #[test]
    #[should_panic]
    fn get_previous_out_of_bounds_panics() {
        let s = RedBlackKeySet::new(10);
        s.get_previous(-1);
    }

    #[test]
    fn max_key_is_a_valid_key() {
        let mut s = RedBlackKeySet::new(10);
        s.put(10);
        assert!(s.contains_key(10));
    }
}

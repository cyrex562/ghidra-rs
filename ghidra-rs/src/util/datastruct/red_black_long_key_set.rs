use std::collections::BTreeSet;
use std::ops::Bound;

/// The number of bytes in a `RedBlackLongKeySet` node (informational).
pub const NODESIZE: usize = 15;

/// An ordered set of non-negative `i64` keys backed by a balanced binary search tree.
///
/// All mutating and querying operations that accept a key require `key >= 0`; a negative key
/// causes a panic, mirroring the `IndexOutOfBoundsException` thrown by the Java original.
///
/// Port of `ghidra.util.datastruct.RedBlackLongKeySet`.
pub struct RedBlackLongKeySet {
    inner: BTreeSet<i64>,
}

impl RedBlackLongKeySet {
    /// Creates a new empty set.
    pub fn new() -> Self {
        Self {
            inner: BTreeSet::new(),
        }
    }

    /// Returns the number of keys in this set.
    pub fn size(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the set contains no keys.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns `true` if `key` is present in the set.
    pub fn contains_key(&self, key: i64) -> bool {
        self.inner.contains(&key)
    }

    /// Returns the smallest key in the set, or `None` if the set is empty.
    pub fn get_first(&self) -> Option<i64> {
        self.inner.iter().next().copied()
    }

    /// Returns the largest key in the set, or `None` if the set is empty.
    pub fn get_last(&self) -> Option<i64> {
        self.inner.iter().next_back().copied()
    }

    /// Returns the smallest key strictly greater than `key`, or `None` if no such key exists.
    ///
    /// # Panics
    ///
    /// Panics if `key < 0`.
    pub fn get_next(&self, key: i64) -> Option<i64> {
        assert!(key >= 0, "key out of bounds: {key}");
        self.inner
            .range((Bound::Excluded(&key), Bound::Unbounded))
            .next()
            .copied()
    }

    /// Returns the largest key strictly less than `key`, or `None` if no such key exists.
    ///
    /// # Panics
    ///
    /// Panics if `key < 0`.
    pub fn get_previous(&self, key: i64) -> Option<i64> {
        assert!(key >= 0, "key out of bounds: {key}");
        self.inner
            .range((Bound::Unbounded, Bound::Excluded(&key)))
            .next_back()
            .copied()
    }

    /// Inserts `key` into the set. Does nothing if `key` is already present.
    ///
    /// # Panics
    ///
    /// Panics if `key < 0`.
    pub fn put(&mut self, key: i64) {
        assert!(key >= 0, "key out of bounds: {key}");
        self.inner.insert(key);
    }

    /// Removes `key` from the set. Returns `true` if the key was present.
    ///
    /// # Panics
    ///
    /// Panics if `key < 0`.
    pub fn remove(&mut self, key: i64) -> bool {
        assert!(key >= 0, "key out of bounds: {key}");
        self.inner.remove(&key)
    }

    /// Removes all keys from the set.
    pub fn remove_all(&mut self) {
        self.inner.clear();
    }
}

impl Default for RedBlackLongKeySet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_set_is_empty() {
        let s = RedBlackLongKeySet::new();
        assert!(s.is_empty());
        assert_eq!(s.size(), 0);
    }

    #[test]
    fn default_equals_new() {
        let s: RedBlackLongKeySet = Default::default();
        assert!(s.is_empty());
    }

    #[test]
    fn put_and_contains_key() {
        let mut s = RedBlackLongKeySet::new();
        assert!(!s.contains_key(5));
        s.put(5);
        assert!(s.contains_key(5));
        assert!(!s.contains_key(4));
    }

    #[test]
    fn put_duplicate_does_not_increase_size() {
        let mut s = RedBlackLongKeySet::new();
        s.put(10);
        s.put(10);
        assert_eq!(s.size(), 1);
    }

    #[test]
    fn remove_present_key_returns_true() {
        let mut s = RedBlackLongKeySet::new();
        s.put(7);
        assert!(s.remove(7));
        assert!(!s.contains_key(7));
    }

    #[test]
    fn remove_absent_key_returns_false() {
        let mut s = RedBlackLongKeySet::new();
        assert!(!s.remove(42));
    }

    #[test]
    fn remove_all_clears_set() {
        let mut s = RedBlackLongKeySet::new();
        s.put(1);
        s.put(2);
        s.put(3);
        s.remove_all();
        assert!(s.is_empty());
        assert_eq!(s.size(), 0);
    }

    #[test]
    fn get_first_returns_min_key() {
        let mut s = RedBlackLongKeySet::new();
        assert_eq!(s.get_first(), None);
        s.put(10);
        s.put(3);
        s.put(7);
        assert_eq!(s.get_first(), Some(3));
    }

    #[test]
    fn get_last_returns_max_key() {
        let mut s = RedBlackLongKeySet::new();
        assert_eq!(s.get_last(), None);
        s.put(10);
        s.put(3);
        s.put(7);
        assert_eq!(s.get_last(), Some(10));
    }

    #[test]
    fn get_next_returns_successor() {
        let mut s = RedBlackLongKeySet::new();
        s.put(1);
        s.put(3);
        s.put(5);
        assert_eq!(s.get_next(0), Some(1));
        assert_eq!(s.get_next(1), Some(3));
        assert_eq!(s.get_next(2), Some(3));
        assert_eq!(s.get_next(5), None);
        assert_eq!(s.get_next(100), None);
    }

    #[test]
    fn get_previous_returns_predecessor() {
        let mut s = RedBlackLongKeySet::new();
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
        let s = RedBlackLongKeySet::new();
        assert_eq!(s.get_next(0), None);
    }

    #[test]
    fn get_previous_on_empty_set_returns_none() {
        let s = RedBlackLongKeySet::new();
        assert_eq!(s.get_previous(0), None);
    }

    #[test]
    fn ascending_iteration_via_get_next() {
        let mut s = RedBlackLongKeySet::new();
        for k in [5i64, 1, 9, 3, 7] {
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
        let mut s = RedBlackLongKeySet::new();
        for k in [5i64, 1, 9, 3, 7] {
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
    #[should_panic]
    fn put_negative_key_panics() {
        let mut s = RedBlackLongKeySet::new();
        s.put(-1);
    }

    #[test]
    #[should_panic]
    fn remove_negative_key_panics() {
        let mut s = RedBlackLongKeySet::new();
        s.remove(-1);
    }

    #[test]
    #[should_panic]
    fn get_next_negative_key_panics() {
        let s = RedBlackLongKeySet::new();
        s.get_next(-1);
    }

    #[test]
    #[should_panic]
    fn get_previous_negative_key_panics() {
        let s = RedBlackLongKeySet::new();
        s.get_previous(-1);
    }

    #[test]
    fn size_tracks_insertions_and_removals() {
        let mut s = RedBlackLongKeySet::new();
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
        let mut s = RedBlackLongKeySet::new();
        s.put(0);
        assert!(s.contains_key(0));
        assert_eq!(s.get_first(), Some(0));
        assert_eq!(s.get_previous(0), None);
        assert_eq!(s.get_next(0), None);
    }
}

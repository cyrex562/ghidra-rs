/// An ordered set of short (`i16`) keys in the range [0, N].
///
/// Implementors maintain keys in sorted order and support successor/predecessor
/// queries.
///
/// Port of `ghidra.util.datastruct.ShortKeySet`.
pub trait ShortKeySet {
    /// Returns the number of keys currently in the set.
    fn size(&self) -> usize;

    /// Returns `true` if the set contains no keys.
    fn is_empty(&self) -> bool;

    /// Returns `true` if `key` is present in the set.
    fn contains_key(&self, key: i16) -> bool;

    /// Returns the smallest key in the set, or `None` if the set is empty.
    fn get_first(&self) -> Option<i16>;

    /// Returns the largest key in the set, or `None` if the set is empty.
    fn get_last(&self) -> Option<i16>;

    /// Inserts `key` into the set. Does nothing if `key` is already present.
    fn put(&mut self, key: i16);

    /// Removes `key` from the set. Returns `true` if the key was present.
    fn remove(&mut self, key: i16) -> bool;

    /// Removes all keys from the set.
    fn remove_all(&mut self);

    /// Returns the smallest key strictly greater than `key`, or `None` if none exists.
    fn get_next(&self, key: i16) -> Option<i16>;

    /// Returns the largest key strictly less than `key`, or `None` if none exists.
    fn get_previous(&self, key: i16) -> Option<i16>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::ops::Bound;

    struct SimpleShortKeySet {
        inner: BTreeSet<i16>,
    }

    impl SimpleShortKeySet {
        fn new() -> Self {
            Self {
                inner: BTreeSet::new(),
            }
        }
    }

    impl ShortKeySet for SimpleShortKeySet {
        fn size(&self) -> usize {
            self.inner.len()
        }

        fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        fn contains_key(&self, key: i16) -> bool {
            self.inner.contains(&key)
        }

        fn get_first(&self) -> Option<i16> {
            self.inner.iter().next().copied()
        }

        fn get_last(&self) -> Option<i16> {
            self.inner.iter().next_back().copied()
        }

        fn put(&mut self, key: i16) {
            self.inner.insert(key);
        }

        fn remove(&mut self, key: i16) -> bool {
            self.inner.remove(&key)
        }

        fn remove_all(&mut self) {
            self.inner.clear();
        }

        fn get_next(&self, key: i16) -> Option<i16> {
            self.inner
                .range((Bound::Excluded(&key), Bound::Unbounded))
                .next()
                .copied()
        }

        fn get_previous(&self, key: i16) -> Option<i16> {
            self.inner
                .range((Bound::Unbounded, Bound::Excluded(&key)))
                .next_back()
                .copied()
        }
    }

    #[test]
    fn new_set_is_empty() {
        let s = SimpleShortKeySet::new();
        assert!(s.is_empty());
        assert_eq!(s.size(), 0);
    }

    #[test]
    fn put_and_contains_key() {
        let mut s = SimpleShortKeySet::new();
        assert!(!s.contains_key(5));
        s.put(5);
        assert!(s.contains_key(5));
        assert!(!s.contains_key(4));
    }

    #[test]
    fn put_duplicate_does_not_increase_size() {
        let mut s = SimpleShortKeySet::new();
        s.put(10);
        s.put(10);
        assert_eq!(s.size(), 1);
    }

    #[test]
    fn remove_present_key_returns_true() {
        let mut s = SimpleShortKeySet::new();
        s.put(7);
        assert!(s.remove(7));
        assert!(!s.contains_key(7));
    }

    #[test]
    fn remove_absent_key_returns_false() {
        let mut s = SimpleShortKeySet::new();
        assert!(!s.remove(42));
    }

    #[test]
    fn remove_all_clears_set() {
        let mut s = SimpleShortKeySet::new();
        s.put(1);
        s.put(2);
        s.put(3);
        s.remove_all();
        assert!(s.is_empty());
        assert_eq!(s.size(), 0);
    }

    #[test]
    fn get_first_returns_min_key() {
        let mut s = SimpleShortKeySet::new();
        assert_eq!(s.get_first(), None);
        s.put(10);
        s.put(3);
        s.put(7);
        assert_eq!(s.get_first(), Some(3));
    }

    #[test]
    fn get_last_returns_max_key() {
        let mut s = SimpleShortKeySet::new();
        assert_eq!(s.get_last(), None);
        s.put(10);
        s.put(3);
        s.put(7);
        assert_eq!(s.get_last(), Some(10));
    }

    #[test]
    fn get_next_returns_successor() {
        let mut s = SimpleShortKeySet::new();
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
        let mut s = SimpleShortKeySet::new();
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
        let s = SimpleShortKeySet::new();
        assert_eq!(s.get_next(0), None);
    }

    #[test]
    fn get_previous_on_empty_set_returns_none() {
        let s = SimpleShortKeySet::new();
        assert_eq!(s.get_previous(0), None);
    }

    #[test]
    fn ascending_iteration_via_get_next() {
        let mut s = SimpleShortKeySet::new();
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
        let mut s = SimpleShortKeySet::new();
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
        let mut s = SimpleShortKeySet::new();
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
        let mut s = SimpleShortKeySet::new();
        s.put(0);
        assert!(s.contains_key(0));
        assert_eq!(s.get_first(), Some(0));
        assert_eq!(s.get_previous(0), None);
        assert_eq!(s.get_next(0), None);
    }
}

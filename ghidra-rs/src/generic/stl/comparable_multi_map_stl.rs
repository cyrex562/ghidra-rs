use super::iterator_stl::IteratorStl;

/// An ordered multi-value map keyed by `K`'s natural ordering, mirroring
/// `generic.stl.ComparableMultiMapSTL<K extends Comparable<K>, V>` from Ghidra.
///
/// The Java class adds nothing to `MultiMapSTL<K,V>` beyond a constructor that
/// fixes the comparator to `SelfComparator<K>` (i.e. `K.compareTo`). Since
/// `MultiMapSTL` itself is not yet ported, this trait folds that inherited
/// public API directly into one object-safe trait: the `K: Ord` bound stands
/// in for the constructor-supplied `SelfComparator<K>`, entries are exposed as
/// `(K, V)` pairs in place of the unported `Pair<K,V>`, and traversal uses the
/// already-ported [`IteratorStl`] rather than the unported `MapIteratorSTL`/
/// `ReverseMapIteratorSTL`/`RedBlackTree` machinery. This lets callers depend
/// on `Box<dyn ComparableMultiMapStl<K, V>>` without pulling in a concrete
/// red-black-tree backed map, breaking the cycle this port was selected to cut.
pub trait ComparableMultiMapStl<K: Ord + 'static, V: 'static> {
    /// Inserts `value` under `key`, allowing duplicate keys to coexist.
    ///
    /// Mirrors `add(K, V)`.
    fn add(&mut self, key: K, value: V);

    /// Returns `true` if any entry exists for `key`.
    ///
    /// Mirrors `contains(K)`.
    fn contains(&self, key: &K) -> bool;

    /// Removes and returns the value of one entry matching `key`, if present.
    ///
    /// Mirrors `remove(K)`.
    fn remove(&mut self, key: &K) -> Option<V>;

    /// Removes the entry at the position named by `iter`, advancing `iter`
    /// to the following entry.
    ///
    /// Mirrors `erase(IteratorSTL<Pair<K,V>>)`.
    ///
    /// # Panics
    /// Panics if `iter` is positioned past the last entry.
    fn erase(&mut self, iter: &mut dyn IteratorStl<(K, V)>);

    /// Returns a forward iterator positioned at the first entry, in key order.
    ///
    /// Mirrors `begin()`.
    fn begin(&self) -> Box<dyn IteratorStl<(K, V)>>;

    /// Returns a forward iterator positioned one past the last entry.
    ///
    /// Mirrors `end()`.
    fn end(&self) -> Box<dyn IteratorStl<(K, V)>>;

    /// Returns a reverse iterator positioned at the last entry.
    ///
    /// Mirrors `rBegin()`.
    fn r_begin(&self) -> Box<dyn IteratorStl<(K, V)>>;

    /// Returns a reverse iterator positioned one before the first entry.
    ///
    /// Mirrors `rEnd()`.
    fn r_end(&self) -> Box<dyn IteratorStl<(K, V)>>;

    /// Returns an iterator positioned at the first entry whose key is not
    /// less than `key`.
    ///
    /// Mirrors `lower_bound(K)`.
    fn lower_bound(&self, key: &K) -> Box<dyn IteratorStl<(K, V)>>;

    /// Returns an iterator positioned at the first entry whose key is
    /// greater than `key`.
    ///
    /// Mirrors `upper_bound(K)`.
    fn upper_bound(&self, key: &K) -> Box<dyn IteratorStl<(K, V)>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Vec`-backed mock proving `ComparableMultiMapStl` is object-safe and
    /// exercising real ordered multimap behavior (duplicate keys, ordered
    /// traversal, bound queries, iterator-based erase).
    struct VecMultiMap<K, V> {
        data: Vec<(K, V)>,
    }

    impl<K: Ord, V> VecMultiMap<K, V> {
        fn new() -> Self {
            Self { data: Vec::new() }
        }
    }

    impl<K: Ord + Clone + 'static, V: Clone + PartialEq + 'static> ComparableMultiMapStl<K, V>
        for VecMultiMap<K, V>
    {
        fn add(&mut self, key: K, value: V) {
            let pos = self.data.partition_point(|(k, _)| *k <= key);
            self.data.insert(pos, (key, value));
        }

        fn contains(&self, key: &K) -> bool {
            self.data.iter().any(|(k, _)| k == key)
        }

        fn remove(&mut self, key: &K) -> Option<V> {
            let idx = self.data.iter().position(|(k, _)| k == key)?;
            Some(self.data.remove(idx).1)
        }

        fn erase(&mut self, iter: &mut dyn IteratorStl<(K, V)>) {
            let current = iter.get().clone();
            if let Some(idx) = self.data.iter().position(|entry| *entry == current) {
                self.data.remove(idx);
            }
            iter.increment();
        }

        fn begin(&self) -> Box<dyn IteratorStl<(K, V)>> {
            Box::new(VecMultiMapCursor { data: self.data.clone(), pos: 0, step: 1 })
        }

        fn end(&self) -> Box<dyn IteratorStl<(K, V)>> {
            let len = self.data.len() as isize;
            Box::new(VecMultiMapCursor { data: self.data.clone(), pos: len, step: 1 })
        }

        fn r_begin(&self) -> Box<dyn IteratorStl<(K, V)>> {
            let pos = self.data.len() as isize - 1;
            Box::new(VecMultiMapCursor { data: self.data.clone(), pos, step: -1 })
        }

        fn r_end(&self) -> Box<dyn IteratorStl<(K, V)>> {
            Box::new(VecMultiMapCursor { data: self.data.clone(), pos: -1, step: -1 })
        }

        fn lower_bound(&self, key: &K) -> Box<dyn IteratorStl<(K, V)>> {
            let pos = self.data.partition_point(|(k, _)| k < key) as isize;
            Box::new(VecMultiMapCursor { data: self.data.clone(), pos, step: 1 })
        }

        fn upper_bound(&self, key: &K) -> Box<dyn IteratorStl<(K, V)>> {
            let pos = self.data.partition_point(|(k, _)| k <= key) as isize;
            Box::new(VecMultiMapCursor { data: self.data.clone(), pos, step: 1 })
        }
    }

    /// Forward (`step == 1`) or reverse (`step == -1`) cursor over a snapshot
    /// of a [`VecMultiMap`]'s entries.
    struct VecMultiMapCursor<K, V> {
        data: Vec<(K, V)>,
        pos: isize,
        step: isize,
    }

    impl<K: Clone + 'static, V: Clone + 'static> IteratorStl<(K, V)> for VecMultiMapCursor<K, V> {
        fn get(&self) -> &(K, V) {
            &self.data[self.pos as usize]
        }

        fn set(&mut self, value: (K, V)) {
            self.data[self.pos as usize] = value;
        }

        fn increment(&mut self) {
            assert!(!self.is_end(), "increment past end");
            self.pos += self.step;
        }

        fn increment_by(&mut self, n: usize) {
            for _ in 0..n {
                self.increment();
            }
        }

        fn decrement(&mut self) {
            assert!(!self.is_begin(), "decrement past beginning");
            self.pos -= self.step;
        }

        fn decrement_by(&mut self, n: usize) {
            for _ in 0..n {
                self.decrement();
            }
        }

        fn is_begin(&self) -> bool {
            if self.data.is_empty() {
                return false;
            }
            if self.step > 0 {
                self.pos == 0
            } else {
                self.pos == self.data.len() as isize - 1
            }
        }

        fn is_end(&self) -> bool {
            if self.step > 0 {
                self.pos >= self.data.len() as isize
            } else {
                self.pos < 0
            }
        }

        fn insert(&mut self, value: (K, V)) {
            self.data.insert(self.pos as usize, value);
        }

        fn copy_iter(&self) -> Box<dyn IteratorStl<(K, V)>> {
            Box::new(VecMultiMapCursor { data: self.data.clone(), pos: self.pos, step: self.step })
        }

        fn assign(&mut self, other: &dyn IteratorStl<(K, V)>) {
            if other.is_end() {
                self.pos = if self.step > 0 { self.data.len() as isize } else { -1 };
            } else if other.is_begin() {
                self.pos = if self.step > 0 { 0 } else { self.data.len() as isize - 1 };
            }
        }
    }

    fn sample() -> VecMultiMap<i32, &'static str> {
        let mut map = VecMultiMap::new();
        map.add(7, "dog");
        map.add(3, "blue");
        map.add(20, "gate");
        map.add(20, "hog");
        map.add(1, "apple");
        map
    }

    #[test]
    fn as_trait_object_add_and_contains() {
        let mut map: Box<dyn ComparableMultiMapStl<i32, &'static str>> = Box::new(sample());
        assert!(map.contains(&7));
        assert!(!map.contains(&99));
        map.add(99, "new");
        assert!(map.contains(&99));
    }

    #[test]
    fn begin_end_walks_in_key_order_with_duplicates() {
        let map = sample();
        let mut it = map.begin();
        let mut seen = Vec::new();
        while !it.is_end() {
            seen.push(*it.get());
            it.increment();
        }
        assert_eq!(seen, vec![(1, "apple"), (3, "blue"), (7, "dog"), (20, "gate"), (20, "hog")]);
    }

    #[test]
    fn r_begin_r_end_walks_in_reverse_key_order() {
        let map = sample();
        let mut it = map.r_begin();
        let mut seen = Vec::new();
        while !it.is_end() {
            seen.push(*it.get());
            it.increment();
        }
        assert_eq!(seen, vec![(20, "hog"), (20, "gate"), (7, "dog"), (3, "blue"), (1, "apple")]);
    }

    #[test]
    fn lower_bound_finds_first_of_duplicate_run() {
        let map = sample();
        let it = map.lower_bound(&20);
        assert_eq!(*it.get(), (20, "gate"));
    }

    #[test]
    fn upper_bound_skips_past_duplicate_run() {
        let map = sample();
        let it = map.upper_bound(&20);
        assert!(it.is_end());
    }

    #[test]
    fn remove_drops_one_matching_entry() {
        let mut map = sample();
        assert_eq!(map.remove(&3), Some("blue"));
        assert!(!map.contains(&3));
        assert_eq!(map.remove(&404), None);
    }

    #[test]
    fn erase_removes_current_entry_and_advances() {
        let mut map = sample();
        let mut it = map.begin();
        assert_eq!(*it.get(), (1, "apple"));
        map.erase(&mut *it);
        assert!(!map.contains(&1));
        assert_eq!(*it.get(), (3, "blue"));
    }
}

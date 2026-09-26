use super::iterator_stl::IteratorStl;

/// An ordered multiset keyed by `T`'s natural ordering, mirroring
/// `generic.stl.ComparableMultiSetSTL<T extends Comparable<T>>` from Ghidra.
///
/// The Java class adds nothing to `MultiSetSTL<T>` beyond a constructor that
/// fixes the comparator to `SelfComparator<T>` (i.e. `T.compareTo`). Since
/// `MultiSetSTL` itself is not yet ported, this trait folds that inherited
/// public API directly into one object-safe trait: the `T: Ord` bound stands
/// in for the constructor-supplied `SelfComparator<T>`, and traversal uses
/// the already-ported [`IteratorStl`] rather than the unported
/// `SetIterator`/`ReverseSetIterator`/`RedBlackTree` machinery. This lets
/// callers depend on `Box<dyn ComparableMultiSetStl<T>>` without pulling in
/// a concrete red-black-tree backed set, breaking the cycle this port was
/// selected to cut.
pub trait ComparableMultiSetStl<T: Ord + 'static> {
    /// Inserts `value`, allowing duplicate values to coexist.
    ///
    /// Mirrors `insert(T)`.
    fn insert(&mut self, value: T);

    /// Inserts `value`, using `low` as a positional hint for the search.
    /// Returns an iterator positioned at the newly inserted element.
    ///
    /// Mirrors `insert(IteratorSTL<T> low, T key)`.
    fn insert_with_hint(
        &mut self,
        low: &mut dyn IteratorStl<T>,
        value: T,
    ) -> Box<dyn IteratorStl<T>>;

    /// Returns `true` if any entry equal to `value` exists.
    ///
    /// Mirrors `contains(T)`.
    fn contains(&self, value: &T) -> bool;

    /// Removes one entry equal to `value`, returning `true` if one was found.
    ///
    /// Mirrors `remove(T)`.
    fn remove(&mut self, value: &T) -> bool;

    /// Removes the entry at the position named by `iter`, advancing `iter`
    /// to the following entry.
    ///
    /// Mirrors `erase(IteratorSTL<T>)`.
    ///
    /// # Panics
    /// Panics if `iter` is positioned past the last entry.
    fn erase(&mut self, iter: &mut dyn IteratorStl<T>);

    /// Returns a forward iterator positioned at the first entry, in value order.
    ///
    /// Mirrors `begin()`.
    fn begin(&self) -> Box<dyn IteratorStl<T>>;

    /// Returns a forward iterator positioned one past the last entry.
    ///
    /// Mirrors `end()`.
    fn end(&self) -> Box<dyn IteratorStl<T>>;

    /// Returns a reverse iterator positioned at the last entry.
    ///
    /// Mirrors `rBegin()`.
    fn r_begin(&self) -> Box<dyn IteratorStl<T>>;

    /// Returns a reverse iterator positioned one before the first entry.
    ///
    /// Mirrors `rEnd()`.
    fn r_end(&self) -> Box<dyn IteratorStl<T>>;

    /// Returns an iterator positioned at the first entry not less than `value`.
    ///
    /// Mirrors `lower_bound(T)`.
    fn lower_bound(&self, value: &T) -> Box<dyn IteratorStl<T>>;

    /// Returns an iterator positioned at the first entry greater than `value`.
    ///
    /// Mirrors `upper_bound(T)`.
    fn upper_bound(&self, value: &T) -> Box<dyn IteratorStl<T>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Vec`-backed mock proving `ComparableMultiSetStl` is object-safe and
    /// exercising real ordered multiset behavior (duplicate values, ordered
    /// traversal, bound queries, iterator-based erase).
    struct VecMultiSet<T> {
        data: Vec<T>,
    }

    impl<T: Ord> VecMultiSet<T> {
        fn new() -> Self {
            Self { data: Vec::new() }
        }
    }

    impl<T: Ord + Clone + 'static> ComparableMultiSetStl<T> for VecMultiSet<T> {
        fn insert(&mut self, value: T) {
            let pos = self.data.partition_point(|v| *v <= value);
            self.data.insert(pos, value);
        }

        fn insert_with_hint(
            &mut self,
            _low: &mut dyn IteratorStl<T>,
            value: T,
        ) -> Box<dyn IteratorStl<T>> {
            let pos = self.data.partition_point(|v| *v <= value) as isize;
            self.data.insert(pos as usize, value);
            Box::new(VecMultiSetCursor { data: self.data.clone(), pos, step: 1 })
        }

        fn contains(&self, value: &T) -> bool {
            self.data.iter().any(|v| v == value)
        }

        fn remove(&mut self, value: &T) -> bool {
            match self.data.iter().position(|v| v == value) {
                Some(idx) => {
                    self.data.remove(idx);
                    true
                }
                None => false,
            }
        }

        fn erase(&mut self, iter: &mut dyn IteratorStl<T>) {
            let current = iter.get().clone();
            if let Some(idx) = self.data.iter().position(|v| *v == current) {
                self.data.remove(idx);
            }
            iter.increment();
        }

        fn begin(&self) -> Box<dyn IteratorStl<T>> {
            Box::new(VecMultiSetCursor { data: self.data.clone(), pos: 0, step: 1 })
        }

        fn end(&self) -> Box<dyn IteratorStl<T>> {
            let len = self.data.len() as isize;
            Box::new(VecMultiSetCursor { data: self.data.clone(), pos: len, step: 1 })
        }

        fn r_begin(&self) -> Box<dyn IteratorStl<T>> {
            let pos = self.data.len() as isize - 1;
            Box::new(VecMultiSetCursor { data: self.data.clone(), pos, step: -1 })
        }

        fn r_end(&self) -> Box<dyn IteratorStl<T>> {
            Box::new(VecMultiSetCursor { data: self.data.clone(), pos: -1, step: -1 })
        }

        fn lower_bound(&self, value: &T) -> Box<dyn IteratorStl<T>> {
            let pos = self.data.partition_point(|v| v < value) as isize;
            Box::new(VecMultiSetCursor { data: self.data.clone(), pos, step: 1 })
        }

        fn upper_bound(&self, value: &T) -> Box<dyn IteratorStl<T>> {
            let pos = self.data.partition_point(|v| v <= value) as isize;
            Box::new(VecMultiSetCursor { data: self.data.clone(), pos, step: 1 })
        }
    }

    /// Forward (`step == 1`) or reverse (`step == -1`) cursor over a snapshot
    /// of a [`VecMultiSet`]'s entries.
    struct VecMultiSetCursor<T> {
        data: Vec<T>,
        pos: isize,
        step: isize,
    }

    impl<T: Clone + 'static> IteratorStl<T> for VecMultiSetCursor<T> {
        fn get(&self) -> &T {
            &self.data[self.pos as usize]
        }

        fn set(&mut self, value: T) {
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

        fn insert(&mut self, value: T) {
            self.data.insert(self.pos as usize, value);
        }

        fn copy_iter(&self) -> Box<dyn IteratorStl<T>> {
            Box::new(VecMultiSetCursor { data: self.data.clone(), pos: self.pos, step: self.step })
        }

        fn assign(&mut self, other: &dyn IteratorStl<T>) {
            if other.is_end() {
                self.pos = if self.step > 0 { self.data.len() as isize } else { -1 };
            } else if other.is_begin() {
                self.pos = if self.step > 0 { 0 } else { self.data.len() as isize - 1 };
            }
        }
    }

    fn sample() -> VecMultiSet<i32> {
        let mut set = VecMultiSet::new();
        set.insert(7);
        set.insert(3);
        set.insert(20);
        set.insert(20);
        set.insert(1);
        set
    }

    #[test]
    fn as_trait_object_insert_and_contains() {
        let mut set: Box<dyn ComparableMultiSetStl<i32>> = Box::new(sample());
        assert!(set.contains(&7));
        assert!(!set.contains(&99));
        set.insert(99);
        assert!(set.contains(&99));
    }

    #[test]
    fn begin_end_walks_in_value_order_with_duplicates() {
        let set = sample();
        let mut it = set.begin();
        let mut seen = Vec::new();
        while !it.is_end() {
            seen.push(*it.get());
            it.increment();
        }
        assert_eq!(seen, vec![1, 3, 7, 20, 20]);
    }

    #[test]
    fn r_begin_r_end_walks_in_reverse_value_order() {
        let set = sample();
        let mut it = set.r_begin();
        let mut seen = Vec::new();
        while !it.is_end() {
            seen.push(*it.get());
            it.increment();
        }
        assert_eq!(seen, vec![20, 20, 7, 3, 1]);
    }

    #[test]
    fn lower_bound_finds_first_of_duplicate_run() {
        let set = sample();
        let it = set.lower_bound(&20);
        assert_eq!(*it.get(), 20);
        assert!(!it.is_end());
    }

    #[test]
    fn upper_bound_skips_past_duplicate_run() {
        let set = sample();
        let it = set.upper_bound(&20);
        assert!(it.is_end());
    }

    #[test]
    fn remove_drops_one_matching_entry() {
        let mut set = sample();
        assert!(set.remove(&3));
        assert!(!set.contains(&3));
        assert!(!set.remove(&404));
    }

    #[test]
    fn erase_removes_current_entry_and_advances() {
        let mut set = sample();
        let mut it = set.begin();
        assert_eq!(*it.get(), 1);
        set.erase(&mut *it);
        assert!(!set.contains(&1));
        assert_eq!(*it.get(), 3);
    }

    #[test]
    fn insert_with_hint_places_value_in_order() {
        let mut set = sample();
        let mut hint = set.begin();
        let it = set.insert_with_hint(&mut *hint, 5);
        assert_eq!(*it.get(), 5);
        assert!(set.contains(&5));
        let mut walk = set.begin();
        let mut seen = Vec::new();
        while !walk.is_end() {
            seen.push(*walk.get());
            walk.increment();
        }
        assert_eq!(seen, vec![1, 3, 5, 7, 20, 20]);
    }
}

//! Mirrors `ghidra.util.database.DBCachedObjectStoreKeySet`: the `NavigableSet<Long>`
//! implementation returned by `DBCachedObjectStore.asMap().keySet()`.
//!
//! The Java class holds a `DBCachedObjectStore<?>`, an `ErrorHandler`, a `ReadWriteLock`, and a
//! [`Direction`], and delegates every query/mutation to the store's package-private `keys` field
//! under the appropriate lock. As with
//! [`DBCachedObjectStoreEntrySet`](super::db_cached_object_store_entry_set::DBCachedObjectStoreEntrySet),
//! porting this class faithfully requires `DBCachedObjectStore` to exist first, which does not
//! yet (it is itself a cycle cut-point elsewhere). This is therefore ported as a pure trait,
//! matching the convention used for [`KeySpan`](super::KeySpan)/[`DirectedIterator`](super::DirectedIterator)/
//! `DBCachedObjectStoreEntrySet`: the shape of the Java public API, with no backing
//! implementation here. A concrete implementation belongs alongside the real
//! `DBCachedObjectStore` port.
//!
//! Elements are plain `i64` (`java.util.Map.Entry`'s absence here means there is no analogue of
//! `StoreEntry`; `Long` boxes a primitive key directly), so `contains`/`remove`/etc. take `i64`
//! by value rather than `Object`.
//!
//! Java's overloaded `subSet`/`headSet`/`tailSet` (2-arg vs. 3/4-arg) become distinctly-named
//! methods, since Rust has no overloading; the 2/1-arg forms keep their default-argument
//! semantics as default trait methods that delegate to the fully-specified ones. Likewise, the
//! several methods that unconditionally `throw new UnsupportedOperationException()` (`add`,
//! `addAll`, `pollFirst`, `pollLast`) become default methods that panic, mirroring the Java
//! unchecked exception (there being no `Result` channel on these signatures to report it
//! through), following the convention established by
//! [`UndefinedFunction::undefined_function_get_symbol`](crate::util::undefined_function).

use std::cmp::Ordering;

use crate::util::database::{Direction, RemovableIterator};
use crate::util::seam_stubs::DBCachedObjectStoreKeySubSet;

/// Mirrors `DBCachedObjectStoreKeySet`: a navigable view of a `DBCachedObjectStore`'s keys,
/// ordered forward or backward depending on [`direction`](Self::direction).
pub trait DBCachedObjectStoreKeySet: Send + Sync {
    /// The direction this set is ordered in, mirroring the `direction` field.
    fn direction(&self) -> Direction;

    /// Mirrors `size()`.
    fn size(&self) -> usize;

    /// Mirrors `isEmpty()`.
    fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// Mirrors `contains(Object)`.
    fn contains(&self, key: i64) -> bool;

    /// Mirrors `iterator()`.
    fn iter(&self) -> Box<dyn RemovableIterator<Item = i64> + '_>;

    /// Mirrors `toArray()`/`toArray(T[])`: both Java overloads return every key, so both are
    /// represented by one owned-`Vec` accessor.
    fn to_vec(&self) -> Vec<i64>;

    /// Mirrors `add(Long)`: always unsupported.
    fn add(&mut self, _key: i64) -> bool {
        panic!("UnsupportedOperationException: DBCachedObjectStoreKeySet does not support add")
    }

    /// Mirrors `remove(Object)`.
    fn remove(&mut self, key: i64) -> bool;

    /// Mirrors `containsAll(Collection)`.
    fn contains_all(&self, c: &[i64]) -> bool {
        c.iter().all(|k| self.contains(*k))
    }

    /// Mirrors `addAll(Collection)`: always unsupported.
    fn add_all(&mut self, _c: Vec<i64>) -> bool {
        panic!("UnsupportedOperationException: DBCachedObjectStoreKeySet does not support addAll")
    }

    /// Mirrors `retainAll(Collection)`.
    fn retain_all(&mut self, c: &[i64]) -> bool;

    /// Mirrors `removeAll(Collection)`.
    fn remove_all(&mut self, c: &[i64]) -> bool {
        let mut changed = false;
        for k in c {
            changed |= self.remove(*k);
        }
        changed
    }

    /// Mirrors `clear()`.
    fn clear(&mut self);

    /// Mirrors `comparator()`: orders two keys naturally, reversed when
    /// [`direction`](Self::direction) is [`Direction::Backward`].
    fn compare(&self, a: i64, b: i64) -> Ordering {
        let ord = a.cmp(&b);
        match self.direction() {
            Direction::Forward => ord,
            Direction::Backward => ord.reverse(),
        }
    }

    /// Mirrors `first()`.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if the set is empty.
    fn first(&self) -> i64;

    /// Mirrors `last()`.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if the set is empty.
    fn last(&self) -> i64;

    /// Mirrors `lower(Long)`.
    fn lower(&self, e: i64) -> Option<i64>;

    /// Mirrors `floor(Long)`.
    fn floor(&self, e: i64) -> Option<i64>;

    /// Mirrors `ceiling(Long)`.
    fn ceiling(&self, e: i64) -> Option<i64>;

    /// Mirrors `higher(Long)`.
    fn higher(&self, e: i64) -> Option<i64>;

    /// Mirrors `pollFirst()`: always unsupported.
    fn poll_first(&mut self) -> i64 {
        panic!("UnsupportedOperationException: DBCachedObjectStoreKeySet does not support pollFirst")
    }

    /// Mirrors `pollLast()`: always unsupported.
    fn poll_last(&mut self) -> i64 {
        panic!("UnsupportedOperationException: DBCachedObjectStoreKeySet does not support pollLast")
    }

    /// Mirrors `descendingSet()`.
    fn descending_set(&self) -> Box<dyn DBCachedObjectStoreKeySet>;

    /// Mirrors `descendingIterator()`.
    fn descending_iter(&self) -> Box<dyn RemovableIterator<Item = i64> + '_>;

    /// Mirrors `subSet(Long, boolean, Long, boolean)`.
    fn sub_set(
        &self,
        from_element: i64,
        from_inclusive: bool,
        to_element: i64,
        to_inclusive: bool,
    ) -> Box<dyn DBCachedObjectStoreKeySubSet>;

    /// Mirrors `headSet(Long, boolean)`.
    fn head_set(&self, to_element: i64, inclusive: bool) -> Box<dyn DBCachedObjectStoreKeySubSet>;

    /// Mirrors `tailSet(Long, boolean)`.
    fn tail_set(&self, from_element: i64, inclusive: bool) -> Box<dyn DBCachedObjectStoreKeySubSet>;

    /// Mirrors `subSet(Long, Long)`: `subSet(fromElement, true, toElement, false)`.
    fn sub_set_default(&self, from_element: i64, to_element: i64) -> Box<dyn DBCachedObjectStoreKeySubSet> {
        self.sub_set(from_element, true, to_element, false)
    }

    /// Mirrors `headSet(Long)`: `headSet(toElement, false)`.
    fn head_set_exclusive(&self, to_element: i64) -> Box<dyn DBCachedObjectStoreKeySubSet> {
        self.head_set(to_element, false)
    }

    /// Mirrors `tailSet(Long)`: `tailSet(fromElement, true)`.
    fn tail_set_inclusive(&self, from_element: i64) -> Box<dyn DBCachedObjectStoreKeySubSet> {
        self.tail_set(from_element, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock over a sorted `Vec<i64>`, proving [`DBCachedObjectStoreKeySet`] is object-safe and
    /// that its navigation methods behave like a real `NavigableSet<Long>`.
    struct VecKeySet {
        keys: Vec<i64>,
        direction: Direction,
    }

    struct VecKeyIter {
        items: std::vec::IntoIter<i64>,
    }

    impl Iterator for VecKeyIter {
        type Item = i64;
        fn next(&mut self) -> Option<i64> {
            self.items.next()
        }
    }

    impl RemovableIterator for VecKeyIter {
        fn remove(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl VecKeySet {
        fn ordered(&self) -> Vec<i64> {
            let mut v = self.keys.clone();
            v.sort_by(|a, b| self.compare(*a, *b));
            v
        }

        fn position(&self, key: i64) -> Option<usize> {
            self.ordered().iter().position(|k| *k == key)
        }
    }

    impl DBCachedObjectStoreKeySet for VecKeySet {
        fn direction(&self) -> Direction {
            self.direction
        }

        fn size(&self) -> usize {
            self.keys.len()
        }

        fn contains(&self, key: i64) -> bool {
            self.keys.contains(&key)
        }

        fn iter(&self) -> Box<dyn RemovableIterator<Item = i64> + '_> {
            Box::new(VecKeyIter { items: self.ordered().into_iter() })
        }

        fn to_vec(&self) -> Vec<i64> {
            self.ordered()
        }

        fn remove(&mut self, key: i64) -> bool {
            let before = self.keys.len();
            self.keys.retain(|k| *k != key);
            self.keys.len() != before
        }

        fn retain_all(&mut self, c: &[i64]) -> bool {
            let before = self.keys.len();
            self.keys.retain(|k| c.contains(k));
            self.keys.len() != before
        }

        fn clear(&mut self) {
            self.keys.clear();
        }

        fn first(&self) -> i64 {
            self.ordered().into_iter().next().expect("NoSuchElementException: empty set")
        }

        fn last(&self) -> i64 {
            self.ordered().into_iter().next_back().expect("NoSuchElementException: empty set")
        }

        fn lower(&self, e: i64) -> Option<i64> {
            let ordered = self.ordered();
            let idx = self.position(e)?;
            if idx == 0 {
                None
            } else {
                Some(ordered[idx - 1])
            }
        }

        fn floor(&self, e: i64) -> Option<i64> {
            let ordered = self.ordered();
            ordered.iter().rev().find(|c| self.compare(**c, e) != Ordering::Greater).copied()
        }

        fn ceiling(&self, e: i64) -> Option<i64> {
            let ordered = self.ordered();
            ordered.iter().find(|c| self.compare(**c, e) != Ordering::Less).copied()
        }

        fn higher(&self, e: i64) -> Option<i64> {
            let ordered = self.ordered();
            let idx = self.position(e)?;
            ordered.get(idx + 1).copied()
        }

        fn descending_set(&self) -> Box<dyn DBCachedObjectStoreKeySet> {
            Box::new(VecKeySet { keys: self.keys.clone(), direction: self.direction.reverse() })
        }

        fn descending_iter(&self) -> Box<dyn RemovableIterator<Item = i64> + '_> {
            let mut ordered = self.ordered();
            ordered.reverse();
            Box::new(VecKeyIter { items: ordered.into_iter() })
        }

        fn sub_set(
            &self,
            from_element: i64,
            _from_inclusive: bool,
            to_element: i64,
            _to_inclusive: bool,
        ) -> Box<dyn DBCachedObjectStoreKeySubSet> {
            let _ = (from_element, to_element);
            unimplemented!("not exercised by this smoke test")
        }

        fn head_set(&self, _to_element: i64, _inclusive: bool) -> Box<dyn DBCachedObjectStoreKeySubSet> {
            unimplemented!("not exercised by this smoke test")
        }

        fn tail_set(&self, _from_element: i64, _inclusive: bool) -> Box<dyn DBCachedObjectStoreKeySubSet> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn forward_set() -> VecKeySet {
        VecKeySet { keys: vec![30, 10, 20], direction: Direction::Forward }
    }

    #[test]
    fn object_safe_and_reports_size() {
        let set: Box<dyn DBCachedObjectStoreKeySet> = Box::new(forward_set());
        assert_eq!(set.size(), 3);
        assert!(!set.is_empty());
    }

    #[test]
    fn forward_navigation_orders_by_key() {
        let set = forward_set();
        assert_eq!(set.first(), 10);
        assert_eq!(set.last(), 30);
        assert_eq!(set.lower(20), Some(10));
        assert_eq!(set.floor(20), Some(20));
        assert_eq!(set.ceiling(15), Some(20));
        assert_eq!(set.higher(20), Some(30));
        assert!(set.lower(10).is_none());
        assert!(set.higher(30).is_none());
    }

    #[test]
    fn backward_direction_reverses_navigation() {
        let mut set = forward_set();
        set.direction = Direction::Backward;
        assert_eq!(set.first(), 30);
        assert_eq!(set.last(), 10);
        assert_eq!(set.lower(20), Some(30));
        assert_eq!(set.higher(20), Some(10));
    }

    #[test]
    fn contains_and_remove_mutate_the_backing_set() {
        let mut set = forward_set();
        assert!(set.contains(10));
        assert!(set.remove(10));
        assert!(!set.contains(10));
        assert_eq!(set.size(), 2);
        assert!(!set.remove(10));
    }

    #[test]
    fn contains_all_and_remove_all() {
        let mut set = forward_set();
        assert!(set.contains_all(&[10, 20]));
        assert!(!set.contains_all(&[10, 99]));
        assert!(set.remove_all(&[10, 99]));
        assert_eq!(set.to_vec(), vec![20, 30]);
    }

    #[test]
    fn retain_all_keeps_only_listed_keys() {
        let mut set = forward_set();
        assert!(set.retain_all(&[10, 30]));
        assert_eq!(set.to_vec(), vec![10, 30]);
    }

    #[test]
    fn clear_empties_the_set() {
        let mut set = forward_set();
        set.clear();
        assert!(set.is_empty());
    }

    #[test]
    #[should_panic(expected = "NoSuchElementException")]
    fn first_panics_when_empty() {
        let mut set = forward_set();
        set.clear();
        set.first();
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn add_is_unsupported() {
        let mut set = forward_set();
        set.add(99);
    }

    #[test]
    fn descending_set_reverses_direction_and_iteration_order() {
        let set = forward_set();
        let descending = set.descending_set();
        assert_eq!(descending.first(), 30);
        let keys: Vec<i64> = set.descending_iter().collect();
        assert_eq!(keys, vec![30, 20, 10]);
    }
}

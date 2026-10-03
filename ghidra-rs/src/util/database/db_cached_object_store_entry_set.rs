//! Mirrors `ghidra.util.database.DBCachedObjectStoreEntrySet`: the `NavigableSet<Entry<Long,
//! T>>` implementation returned by `DBCachedObjectStore.asMap().entrySet()`.
//!
//! The Java class holds a `DBCachedObjectStore<T>`, an `ErrorHandler`, a `ReadWriteLock`, and a
//! [`Direction`], and delegates every query/mutation to the store's package-private `entries`
//! field (an anonymous `BoundedStuff<Entry<Long, T>, DBRecord>` inner instance) under the
//! appropriate lock. `BoundedStuff` is not itself a named, independently-portable dependency --
//! it is a private implementation detail of `DBCachedObjectStore` -- so porting this class
//! faithfully requires `DBCachedObjectStore` to exist first, which does not yet (it is itself a
//! cycle cut-point elsewhere). This is therefore ported as a pure trait, matching the convention
//! used for [`KeySpan`](super::KeySpan)/[`DirectedIterator`](super::DirectedIterator): the shape
//! of the Java public API, with no backing implementation here. A concrete implementation
//! belongs alongside the real `DBCachedObjectStore` port.
//!
//! `Entry<Long, T>` (`java.util.Map.Entry`) has no existing port; since `T` is only ever
//! constrained to `DBAnnotatedObject` (never concretely named) in this class, entries are
//! represented as [`StoreEntry`], a `(key, value)` pair over the
//! [`DBAnnotatedObject`](crate::util::database::db_annotated_object::DBAnnotatedObject) trait.
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

use crate::util::database::db_annotated_object::DBAnnotatedObject;
use crate::util::database::{Direction, RemovableIterator};
use crate::util::seam_stubs::DBCachedObjectStoreEntrySubSet;

/// A `(key, value)` pair standing in for `java.util.Map.Entry<Long, T>` as used by this class.
pub type StoreEntry = (i64, std::sync::Arc<dyn DBAnnotatedObject>);

/// Mirrors `DBCachedObjectStoreEntrySet<T>`: a navigable view of a `DBCachedObjectStore`'s
/// key/object pairs, ordered forward or backward depending on [`direction`](Self::direction).
pub trait DBCachedObjectStoreEntrySet: Send + Sync {
    /// The direction this set is ordered in, mirroring the `direction` field.
    fn direction(&self) -> Direction;

    /// Mirrors `size()`.
    fn size(&self) -> usize;

    /// Mirrors `isEmpty()`.
    fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// Mirrors `contains(Object)`.
    fn contains(&self, entry: &StoreEntry) -> bool;

    /// Mirrors `iterator()`.
    fn iter(&self) -> Box<dyn RemovableIterator<Item = StoreEntry> + '_>;

    /// Mirrors `toArray()`/`toArray(U[])`: both Java overloads return every entry, so both are
    /// represented by one owned-`Vec` accessor.
    fn to_vec(&self) -> Vec<StoreEntry>;

    /// Mirrors `add(Entry)`: always unsupported.
    fn add(&mut self, _entry: StoreEntry) -> bool {
        panic!("UnsupportedOperationException: DBCachedObjectStoreEntrySet does not support add")
    }

    /// Mirrors `remove(Object)`.
    fn remove(&mut self, entry: &StoreEntry) -> bool;

    /// Mirrors `containsAll(Collection)`.
    fn contains_all(&self, c: &[StoreEntry]) -> bool {
        c.iter().all(|e| self.contains(e))
    }

    /// Mirrors `addAll(Collection)`: always unsupported.
    fn add_all(&mut self, _c: Vec<StoreEntry>) -> bool {
        panic!("UnsupportedOperationException: DBCachedObjectStoreEntrySet does not support addAll")
    }

    /// Mirrors `retainAll(Collection)`.
    fn retain_all(&mut self, c: &[StoreEntry]) -> bool;

    /// Mirrors `removeAll(Collection)`.
    fn remove_all(&mut self, c: &[StoreEntry]) -> bool {
        let mut changed = false;
        for e in c {
            changed |= self.remove(e);
        }
        changed
    }

    /// Mirrors `clear()`.
    fn clear(&mut self);

    /// Mirrors `comparator()`/the private `reverseComparator`: orders two entries by key,
    /// reversed when [`direction`](Self::direction) is [`Direction::Backward`]. Approximates
    /// `store.keyComparator()` (not exposed to this trait) with natural `i64` order, which is
    /// the comparator `DBCachedObjectStore.keyComparator()` returns by default.
    fn compare(&self, a: &StoreEntry, b: &StoreEntry) -> Ordering {
        let ord = a.0.cmp(&b.0);
        match self.direction() {
            Direction::Forward => ord,
            Direction::Backward => ord.reverse(),
        }
    }

    /// Mirrors `first()`.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if the set is empty.
    fn first(&self) -> StoreEntry;

    /// Mirrors `last()`.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if the set is empty.
    fn last(&self) -> StoreEntry;

    /// Mirrors `lower(Entry)`.
    fn lower(&self, e: &StoreEntry) -> Option<StoreEntry>;

    /// Mirrors `floor(Entry)`.
    fn floor(&self, e: &StoreEntry) -> Option<StoreEntry>;

    /// Mirrors `ceiling(Entry)`.
    fn ceiling(&self, e: &StoreEntry) -> Option<StoreEntry>;

    /// Mirrors `higher(Entry)`.
    fn higher(&self, e: &StoreEntry) -> Option<StoreEntry>;

    /// Mirrors `pollFirst()`: always unsupported.
    fn poll_first(&mut self) -> StoreEntry {
        panic!(
            "UnsupportedOperationException: DBCachedObjectStoreEntrySet does not support pollFirst"
        )
    }

    /// Mirrors `pollLast()`: always unsupported.
    fn poll_last(&mut self) -> StoreEntry {
        panic!(
            "UnsupportedOperationException: DBCachedObjectStoreEntrySet does not support pollLast"
        )
    }

    /// Mirrors `descendingSet()`.
    fn descending_set(&self) -> Box<dyn DBCachedObjectStoreEntrySet>;

    /// Mirrors `descendingIterator()`.
    fn descending_iter(&self) -> Box<dyn RemovableIterator<Item = StoreEntry> + '_>;

    /// Mirrors `subSet(Entry, boolean, Entry, boolean)`.
    fn sub_set(
        &self,
        from_element: &StoreEntry,
        from_inclusive: bool,
        to_element: &StoreEntry,
        to_inclusive: bool,
    ) -> Box<dyn DBCachedObjectStoreEntrySubSet>;

    /// Mirrors `headSet(Entry, boolean)`.
    fn head_set(&self, to_element: &StoreEntry, inclusive: bool) -> Box<dyn DBCachedObjectStoreEntrySubSet>;

    /// Mirrors `tailSet(Entry, boolean)`.
    fn tail_set(&self, from_element: &StoreEntry, inclusive: bool) -> Box<dyn DBCachedObjectStoreEntrySubSet>;

    /// Mirrors `subSet(Entry, Entry)`: `subSet(fromElement, true, toElement, false)`.
    fn sub_set_default(
        &self,
        from_element: &StoreEntry,
        to_element: &StoreEntry,
    ) -> Box<dyn DBCachedObjectStoreEntrySubSet> {
        self.sub_set(from_element, true, to_element, false)
    }

    /// Mirrors `headSet(Entry)`: `headSet(toElement, false)`.
    fn head_set_exclusive(&self, to_element: &StoreEntry) -> Box<dyn DBCachedObjectStoreEntrySubSet> {
        self.head_set(to_element, false)
    }

    /// Mirrors `tailSet(Entry)`: `tailSet(fromElement, true)`.
    fn tail_set_inclusive(&self, from_element: &StoreEntry) -> Box<dyn DBCachedObjectStoreEntrySubSet> {
        self.tail_set(from_element, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockObject(i64);
    impl crate::program::database::db_object::DbObject for MockObject {
        fn state(&self) -> &crate::program::database::db_object::DbObjectState {
            unimplemented!("not exercised by this smoke test")
        }
        fn refresh(&self, _record: Option<&crate::framework::db::record::DBRecord>) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl DBAnnotatedObject for MockObject {
        fn store(&self) -> &dyn crate::util::seam_stubs::DBCachedObjectStoreCore {
            unimplemented!("not exercised by this smoke test")
        }
        fn adapter(&self) -> &dyn crate::util::database::db_cached_domain_object_adapter::DBCachedDomainObjectAdapter {
            unimplemented!("not exercised by this smoke test")
        }
        fn codecs(&self) -> &[Box<dyn crate::util::seam_stubs::DBFieldCodec>] {
            &[]
        }
        fn record(&self) -> crate::framework::db::record::DBRecord {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_record(&self, _record: crate::framework::db::record::DBRecord) {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn entry(key: i64) -> StoreEntry {
        (key, std::sync::Arc::new(MockObject(key)))
    }

    /// A mock over a sorted `Vec<StoreEntry>`, proving [`DBCachedObjectStoreEntrySet`] is
    /// object-safe and that its navigation methods behave like a real `NavigableSet`.
    struct VecEntrySet {
        entries: Vec<StoreEntry>,
        direction: Direction,
    }

    struct VecEntryIter {
        items: std::vec::IntoIter<StoreEntry>,
    }

    impl Iterator for VecEntryIter {
        type Item = StoreEntry;
        fn next(&mut self) -> Option<StoreEntry> {
            self.items.next()
        }
    }

    impl RemovableIterator for VecEntryIter {
        fn remove(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl VecEntrySet {
        fn ordered(&self) -> Vec<StoreEntry> {
            let mut v = self.entries.clone();
            v.sort_by(|a, b| self.compare(a, b));
            v
        }

        fn position(&self, key: i64) -> Option<usize> {
            self.ordered().iter().position(|(k, _)| *k == key)
        }
    }

    impl DBCachedObjectStoreEntrySet for VecEntrySet {
        fn direction(&self) -> Direction {
            self.direction
        }

        fn size(&self) -> usize {
            self.entries.len()
        }

        fn contains(&self, entry: &StoreEntry) -> bool {
            self.entries.iter().any(|(k, _)| *k == entry.0)
        }

        fn iter(&self) -> Box<dyn RemovableIterator<Item = StoreEntry> + '_> {
            Box::new(VecEntryIter { items: self.ordered().into_iter() })
        }

        fn to_vec(&self) -> Vec<StoreEntry> {
            self.ordered()
        }

        fn remove(&mut self, entry: &StoreEntry) -> bool {
            let before = self.entries.len();
            self.entries.retain(|(k, _)| *k != entry.0);
            self.entries.len() != before
        }

        fn retain_all(&mut self, c: &[StoreEntry]) -> bool {
            let before = self.entries.len();
            self.entries.retain(|(k, _)| c.iter().any(|(ck, _)| ck == k));
            self.entries.len() != before
        }

        fn clear(&mut self) {
            self.entries.clear();
        }

        fn first(&self) -> StoreEntry {
            self.ordered().into_iter().next().expect("NoSuchElementException: empty set")
        }

        fn last(&self) -> StoreEntry {
            self.ordered().into_iter().next_back().expect("NoSuchElementException: empty set")
        }

        fn lower(&self, e: &StoreEntry) -> Option<StoreEntry> {
            let ordered = self.ordered();
            let idx = self.position(e.0)?;
            if idx == 0 {
                None
            } else {
                Some(ordered[idx - 1].clone())
            }
        }

        fn floor(&self, e: &StoreEntry) -> Option<StoreEntry> {
            let ordered = self.ordered();
            ordered.iter().rev().find(|c| self.compare(c, e) != Ordering::Greater).cloned()
        }

        fn ceiling(&self, e: &StoreEntry) -> Option<StoreEntry> {
            let ordered = self.ordered();
            ordered.iter().find(|c| self.compare(c, e) != Ordering::Less).cloned()
        }

        fn higher(&self, e: &StoreEntry) -> Option<StoreEntry> {
            let ordered = self.ordered();
            let idx = self.position(e.0)?;
            ordered.get(idx + 1).cloned()
        }

        fn descending_set(&self) -> Box<dyn DBCachedObjectStoreEntrySet> {
            Box::new(VecEntrySet { entries: self.entries.clone(), direction: self.direction.reverse() })
        }

        fn descending_iter(&self) -> Box<dyn RemovableIterator<Item = StoreEntry> + '_> {
            let mut ordered = self.ordered();
            ordered.reverse();
            Box::new(VecEntryIter { items: ordered.into_iter() })
        }

        fn sub_set(
            &self,
            from_element: &StoreEntry,
            _from_inclusive: bool,
            to_element: &StoreEntry,
            _to_inclusive: bool,
        ) -> Box<dyn DBCachedObjectStoreEntrySubSet> {
            let _ = (from_element, to_element);
            unimplemented!("not exercised by this smoke test")
        }

        fn head_set(
            &self,
            _to_element: &StoreEntry,
            _inclusive: bool,
        ) -> Box<dyn DBCachedObjectStoreEntrySubSet> {
            unimplemented!("not exercised by this smoke test")
        }

        fn tail_set(
            &self,
            _from_element: &StoreEntry,
            _inclusive: bool,
        ) -> Box<dyn DBCachedObjectStoreEntrySubSet> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn forward_set() -> VecEntrySet {
        VecEntrySet { entries: vec![entry(30), entry(10), entry(20)], direction: Direction::Forward }
    }

    #[test]
    fn object_safe_and_reports_size() {
        let set: Box<dyn DBCachedObjectStoreEntrySet> = Box::new(forward_set());
        assert_eq!(set.size(), 3);
        assert!(!set.is_empty());
    }

    #[test]
    fn forward_navigation_orders_by_key() {
        let set = forward_set();
        assert_eq!(set.first().0, 10);
        assert_eq!(set.last().0, 30);
        assert_eq!(set.lower(&entry(20)).map(|e| e.0), Some(10));
        assert_eq!(set.floor(&entry(20)).map(|e| e.0), Some(20));
        assert_eq!(set.ceiling(&entry(15)).map(|e| e.0), Some(20));
        assert_eq!(set.higher(&entry(20)).map(|e| e.0), Some(30));
        assert!(set.lower(&entry(10)).is_none());
        assert!(set.higher(&entry(30)).is_none());
    }

    #[test]
    fn backward_direction_reverses_navigation() {
        let mut set = forward_set();
        set.direction = Direction::Backward;
        assert_eq!(set.first().0, 30);
        assert_eq!(set.last().0, 10);
        assert_eq!(set.lower(&entry(20)).map(|e| e.0), Some(30));
        assert_eq!(set.higher(&entry(20)).map(|e| e.0), Some(10));
    }

    #[test]
    fn contains_and_remove_mutate_the_backing_set() {
        let mut set = forward_set();
        assert!(set.contains(&entry(10)));
        assert!(set.remove(&entry(10)));
        assert!(!set.contains(&entry(10)));
        assert_eq!(set.size(), 2);
        assert!(!set.remove(&entry(10)));
    }

    #[test]
    fn contains_all_and_remove_all() {
        let mut set = forward_set();
        assert!(set.contains_all(&[entry(10), entry(20)]));
        assert!(!set.contains_all(&[entry(10), entry(99)]));
        assert!(set.remove_all(&[entry(10), entry(99)]));
        assert_eq!(set.to_vec().iter().map(|e| e.0).collect::<Vec<_>>(), vec![20, 30]);
    }

    #[test]
    fn retain_all_keeps_only_listed_keys() {
        let mut set = forward_set();
        assert!(set.retain_all(&[entry(10), entry(30)]));
        assert_eq!(set.to_vec().iter().map(|e| e.0).collect::<Vec<_>>(), vec![10, 30]);
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
        set.add(entry(99));
    }

    #[test]
    fn descending_set_reverses_direction_and_iteration_order() {
        let set = forward_set();
        let descending = set.descending_set();
        assert_eq!(descending.first().0, 30);
        let keys: Vec<i64> = set.descending_iter().map(|e| e.0).collect();
        assert_eq!(keys, vec![30, 20, 10]);
    }
}

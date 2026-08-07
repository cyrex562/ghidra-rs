//! Mirrors `ghidra.util.database.DBCachedObjectStoreMap`: the `NavigableMap<Long, T>`
//! implementation returned by `DBCachedObjectStore.asMap()`.
//!
//! The Java class holds a `DBCachedObjectStore<T>`, an `ErrorHandler`, a `ReadWriteLock`, and a
//! [`Direction`], and delegates every query/mutation to the store's package-private
//! `keys`/`entries`/`objects` fields (and `asForward*` cached views) under the appropriate lock.
//! As with
//! [`DBCachedObjectStoreEntrySet`](super::db_cached_object_store_entry_set::DBCachedObjectStoreEntrySet)
//! and
//! [`DBCachedObjectStoreKeySet`](super::db_cached_object_store_key_set::DBCachedObjectStoreKeySet),
//! porting this class faithfully requires `DBCachedObjectStore` to exist first, which does not
//! yet (it is itself a cycle cut-point elsewhere). This is therefore ported as a pure trait,
//! matching that same convention: the shape of the Java public API (`NavigableMap<Long, T>`),
//! with no backing implementation here. A concrete implementation belongs alongside the real
//! `DBCachedObjectStore` port.
//!
//! Entries reuse [`StoreEntry`] (already established by `DBCachedObjectStoreEntrySet` for the
//! same `Entry<Long, T>` shape) rather than introducing a second `(key, value)` pair type.
//!
//! Java's overloaded `subMap`/`headMap`/`tailMap` (2-arg vs. 3/4-arg) become distinctly-named
//! methods, since Rust has no overloading; the 2/1-arg forms keep their default-argument
//! semantics as default trait methods that delegate to the fully-specified ones, following the
//! same convention as `DBCachedObjectStoreEntrySet`/`DBCachedObjectStoreKeySet`. Likewise, the
//! methods that unconditionally `throw new UnsupportedOperationException()` (`put`, `putAll`,
//! `pollFirstEntry`, `pollLastEntry`) become default methods that panic, mirroring the Java
//! unchecked exception (there being no `Result` channel on these signatures to report it
//! through).
//!
//! `firstKey()`/`lastKey()` mirror `NavigableMap`'s contract of throwing `NoSuchElementException`
//! when the map is empty (unlike `firstEntry()`/`lastEntry()`, which return `null`/`None`),
//! following the same panic-on-empty convention `DBCachedObjectStoreKeySet::first`/`last` use.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::util::database::{
    db_cached_object_store_entry_set::StoreEntry, DBCachedObjectStoreEntrySet,
    DBCachedObjectStoreKeySet, Direction,
};
use crate::util::seam_stubs::{
    DBAnnotatedObject, DBCachedObjectStoreSubMap, DBCachedObjectStoreValueCollection,
};

/// Mirrors `DBCachedObjectStoreMap<T>`: a navigable map from object key (`long`) to object,
/// ordered forward or backward depending on [`direction`](Self::direction).
pub trait DBCachedObjectStoreMap: Send + Sync {
    /// The direction this map is ordered in, mirroring the `direction` field.
    fn direction(&self) -> Direction;

    /// Mirrors `size()`.
    fn size(&self) -> usize;

    /// Mirrors `isEmpty()`.
    fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// Mirrors `containsKey(Object)`.
    fn contains_key(&self, key: i64) -> bool;

    /// Mirrors `containsValue(Object)`.
    fn contains_value(&self, value: &Arc<dyn DBAnnotatedObject>) -> bool;

    /// Mirrors `get(Object)`.
    fn get(&self, key: i64) -> Option<Arc<dyn DBAnnotatedObject>>;

    /// Mirrors `put(Long, T)`: always unsupported.
    fn put(
        &mut self,
        _key: i64,
        _value: Arc<dyn DBAnnotatedObject>,
    ) -> Option<Arc<dyn DBAnnotatedObject>> {
        panic!("UnsupportedOperationException: DBCachedObjectStoreMap does not support put")
    }

    /// Mirrors `remove(Object)`.
    fn remove(&mut self, key: i64) -> Option<Arc<dyn DBAnnotatedObject>>;

    /// Mirrors `putAll(Map)`: always unsupported.
    fn put_all(&mut self, _m: Vec<(i64, Arc<dyn DBAnnotatedObject>)>) {
        panic!("UnsupportedOperationException: DBCachedObjectStoreMap does not support putAll")
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

    /// Mirrors `firstEntry()`.
    fn first_entry(&self) -> Option<StoreEntry>;

    /// Mirrors `firstKey()`.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if the map is empty.
    fn first_key(&self) -> i64;

    /// Mirrors `lastEntry()`.
    fn last_entry(&self) -> Option<StoreEntry>;

    /// Mirrors `lastKey()`.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if the map is empty.
    fn last_key(&self) -> i64;

    /// Mirrors `lowerEntry(Long)`.
    fn lower_entry(&self, key: i64) -> Option<StoreEntry>;

    /// Mirrors `lowerKey(Long)`.
    fn lower_key(&self, key: i64) -> Option<i64>;

    /// Mirrors `floorEntry(Long)`.
    fn floor_entry(&self, key: i64) -> Option<StoreEntry>;

    /// Mirrors `floorKey(Long)`.
    fn floor_key(&self, key: i64) -> Option<i64>;

    /// Mirrors `ceilingEntry(Long)`.
    fn ceiling_entry(&self, key: i64) -> Option<StoreEntry>;

    /// Mirrors `ceilingKey(Long)`.
    fn ceiling_key(&self, key: i64) -> Option<i64>;

    /// Mirrors `higherEntry(Long)`.
    fn higher_entry(&self, key: i64) -> Option<StoreEntry>;

    /// Mirrors `higherKey(Long)`.
    fn higher_key(&self, key: i64) -> Option<i64>;

    /// Mirrors `pollFirstEntry()`: always unsupported.
    fn poll_first_entry(&mut self) -> StoreEntry {
        panic!(
            "UnsupportedOperationException: DBCachedObjectStoreMap does not support pollFirstEntry"
        )
    }

    /// Mirrors `pollLastEntry()`: always unsupported.
    fn poll_last_entry(&mut self) -> StoreEntry {
        panic!(
            "UnsupportedOperationException: DBCachedObjectStoreMap does not support pollLastEntry"
        )
    }

    /// Mirrors `keySet()`: `navigableKeySet()`.
    fn key_set(&self) -> Box<dyn DBCachedObjectStoreKeySet> {
        self.navigable_key_set()
    }

    /// Mirrors `values()`.
    fn values(&self) -> Box<dyn DBCachedObjectStoreValueCollection>;

    /// Mirrors `entrySet()`.
    fn entry_set(&self) -> Box<dyn DBCachedObjectStoreEntrySet>;

    /// Mirrors `descendingMap()`.
    fn descending_map(&self) -> Box<dyn DBCachedObjectStoreMap>;

    /// Mirrors `navigableKeySet()`.
    fn navigable_key_set(&self) -> Box<dyn DBCachedObjectStoreKeySet>;

    /// Mirrors `descendingKeySet()`.
    fn descending_key_set(&self) -> Box<dyn DBCachedObjectStoreKeySet>;

    /// Mirrors `subMap(Long, boolean, Long, boolean)`.
    fn sub_map(
        &self,
        from_key: i64,
        from_inclusive: bool,
        to_key: i64,
        to_inclusive: bool,
    ) -> Box<dyn DBCachedObjectStoreSubMap>;

    /// Mirrors `headMap(Long, boolean)`.
    fn head_map(&self, to_key: i64, inclusive: bool) -> Box<dyn DBCachedObjectStoreSubMap>;

    /// Mirrors `tailMap(Long, boolean)`.
    fn tail_map(&self, from_key: i64, inclusive: bool) -> Box<dyn DBCachedObjectStoreSubMap>;

    /// Mirrors `subMap(Long, Long)`: `subMap(fromKey, true, toKey, false)`.
    fn sub_map_default(&self, from_key: i64, to_key: i64) -> Box<dyn DBCachedObjectStoreSubMap> {
        self.sub_map(from_key, true, to_key, false)
    }

    /// Mirrors `headMap(Long)`: `headMap(toKey, false)`.
    fn head_map_exclusive(&self, to_key: i64) -> Box<dyn DBCachedObjectStoreSubMap> {
        self.head_map(to_key, false)
    }

    /// Mirrors `tailMap(Long)`: `tailMap(fromKey, true)`.
    fn tail_map_inclusive(&self, from_key: i64) -> Box<dyn DBCachedObjectStoreSubMap> {
        self.tail_map(from_key, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockObject(i64);
    impl DBAnnotatedObject for MockObject {}

    fn entry(key: i64) -> StoreEntry {
        (key, Arc::new(MockObject(key)) as Arc<dyn DBAnnotatedObject>)
    }

    /// A mock over a sorted `Vec<StoreEntry>`, proving [`DBCachedObjectStoreMap`] is object-safe
    /// and that its navigation methods behave like a real `NavigableMap<Long, T>`.
    struct VecMap {
        entries: Vec<StoreEntry>,
        direction: Direction,
    }

    impl VecMap {
        fn ordered(&self) -> Vec<StoreEntry> {
            let mut v = self.entries.clone();
            v.sort_by(|a, b| self.compare(a.0, b.0));
            v
        }

        fn position(&self, key: i64) -> Option<usize> {
            self.ordered().iter().position(|(k, _)| *k == key)
        }
    }

    impl DBCachedObjectStoreMap for VecMap {
        fn direction(&self) -> Direction {
            self.direction
        }

        fn size(&self) -> usize {
            self.entries.len()
        }

        fn contains_key(&self, key: i64) -> bool {
            self.entries.iter().any(|(k, _)| *k == key)
        }

        fn contains_value(&self, value: &Arc<dyn DBAnnotatedObject>) -> bool {
            self.entries.iter().any(|(_, v)| Arc::ptr_eq(v, value))
        }

        fn get(&self, key: i64) -> Option<Arc<dyn DBAnnotatedObject>> {
            self.entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone())
        }

        fn remove(&mut self, key: i64) -> Option<Arc<dyn DBAnnotatedObject>> {
            let idx = self.entries.iter().position(|(k, _)| *k == key)?;
            Some(self.entries.remove(idx).1)
        }

        fn clear(&mut self) {
            self.entries.clear();
        }

        fn first_entry(&self) -> Option<StoreEntry> {
            self.ordered().into_iter().next()
        }

        fn first_key(&self) -> i64 {
            self.first_entry().expect("NoSuchElementException: empty map").0
        }

        fn last_entry(&self) -> Option<StoreEntry> {
            self.ordered().into_iter().next_back()
        }

        fn last_key(&self) -> i64 {
            self.last_entry().expect("NoSuchElementException: empty map").0
        }

        fn lower_entry(&self, key: i64) -> Option<StoreEntry> {
            let ordered = self.ordered();
            let idx = self.position(key)?;
            if idx == 0 {
                None
            } else {
                Some(ordered[idx - 1].clone())
            }
        }

        fn lower_key(&self, key: i64) -> Option<i64> {
            self.lower_entry(key).map(|e| e.0)
        }

        fn floor_entry(&self, key: i64) -> Option<StoreEntry> {
            let ordered = self.ordered();
            ordered.iter().rev().find(|(k, _)| self.compare(*k, key) != Ordering::Greater).cloned()
        }

        fn floor_key(&self, key: i64) -> Option<i64> {
            self.floor_entry(key).map(|e| e.0)
        }

        fn ceiling_entry(&self, key: i64) -> Option<StoreEntry> {
            let ordered = self.ordered();
            ordered.iter().find(|(k, _)| self.compare(*k, key) != Ordering::Less).cloned()
        }

        fn ceiling_key(&self, key: i64) -> Option<i64> {
            self.ceiling_entry(key).map(|e| e.0)
        }

        fn higher_entry(&self, key: i64) -> Option<StoreEntry> {
            let ordered = self.ordered();
            let idx = self.position(key)?;
            ordered.get(idx + 1).cloned()
        }

        fn higher_key(&self, key: i64) -> Option<i64> {
            self.higher_entry(key).map(|e| e.0)
        }

        fn values(&self) -> Box<dyn DBCachedObjectStoreValueCollection> {
            unimplemented!("not exercised by this smoke test")
        }

        fn entry_set(&self) -> Box<dyn DBCachedObjectStoreEntrySet> {
            unimplemented!("not exercised by this smoke test")
        }

        fn descending_map(&self) -> Box<dyn DBCachedObjectStoreMap> {
            Box::new(VecMap { entries: self.entries.clone(), direction: self.direction.reverse() })
        }

        fn navigable_key_set(&self) -> Box<dyn DBCachedObjectStoreKeySet> {
            unimplemented!("not exercised by this smoke test")
        }

        fn descending_key_set(&self) -> Box<dyn DBCachedObjectStoreKeySet> {
            unimplemented!("not exercised by this smoke test")
        }

        fn sub_map(
            &self,
            _from_key: i64,
            _from_inclusive: bool,
            _to_key: i64,
            _to_inclusive: bool,
        ) -> Box<dyn DBCachedObjectStoreSubMap> {
            unimplemented!("not exercised by this smoke test")
        }

        fn head_map(&self, _to_key: i64, _inclusive: bool) -> Box<dyn DBCachedObjectStoreSubMap> {
            unimplemented!("not exercised by this smoke test")
        }

        fn tail_map(&self, _from_key: i64, _inclusive: bool) -> Box<dyn DBCachedObjectStoreSubMap> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn forward_map() -> VecMap {
        VecMap { entries: vec![entry(30), entry(10), entry(20)], direction: Direction::Forward }
    }

    #[test]
    fn object_safe_and_reports_size() {
        let map: Box<dyn DBCachedObjectStoreMap> = Box::new(forward_map());
        assert_eq!(map.size(), 3);
        assert!(!map.is_empty());
    }

    #[test]
    fn forward_navigation_orders_by_key() {
        let map = forward_map();
        assert_eq!(map.first_key(), 10);
        assert_eq!(map.last_key(), 30);
        assert_eq!(map.lower_key(20), Some(10));
        assert_eq!(map.floor_key(20), Some(20));
        assert_eq!(map.ceiling_key(15), Some(20));
        assert_eq!(map.higher_key(20), Some(30));
        assert!(map.lower_key(10).is_none());
        assert!(map.higher_key(30).is_none());
    }

    #[test]
    fn backward_direction_reverses_navigation() {
        let mut map = forward_map();
        map.direction = Direction::Backward;
        assert_eq!(map.first_key(), 30);
        assert_eq!(map.last_key(), 10);
        assert_eq!(map.lower_key(20), Some(30));
        assert_eq!(map.higher_key(20), Some(10));
    }

    #[test]
    fn get_and_remove_mutate_the_backing_map() {
        let mut map = forward_map();
        assert!(map.contains_key(10));
        assert!(map.get(10).is_some());
        assert!(map.remove(10).is_some());
        assert!(!map.contains_key(10));
        assert_eq!(map.size(), 2);
        assert!(map.remove(10).is_none());
    }

    #[test]
    fn clear_empties_the_map() {
        let mut map = forward_map();
        map.clear();
        assert!(map.is_empty());
    }

    #[test]
    #[should_panic(expected = "NoSuchElementException")]
    fn first_key_panics_when_empty() {
        let mut map = forward_map();
        map.clear();
        map.first_key();
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn put_is_unsupported() {
        let mut map = forward_map();
        map.put(99, Arc::new(MockObject(99)));
    }

    #[test]
    fn descending_map_reverses_direction_and_navigation() {
        let map = forward_map();
        let descending = map.descending_map();
        assert_eq!(descending.first_key(), 30);
        assert_eq!(descending.last_key(), 10);
    }
}

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Weak};

/// Operations required from the backing store of an [`AbstractWeakValueMap`].
///
/// Implemented for [`HashMap`]; other map types (e.g. `BTreeMap`) can add
/// implementations when navigable weak-value-map variants are introduced.
pub trait WeakRefStore<K, V> {
    fn store_insert(&mut self, key: K, val: Weak<V>) -> Option<Weak<V>>;
    fn store_get(&self, key: &K) -> Option<&Weak<V>>;
    fn store_remove(&mut self, key: &K) -> Option<Weak<V>>;
    fn store_contains_key(&self, key: &K) -> bool;
    fn store_len(&self) -> usize;
    fn store_is_empty(&self) -> bool;
    fn store_clear(&mut self);
    fn store_retain<F>(&mut self, f: F)
    where
        F: FnMut(&K, &mut Weak<V>) -> bool;
    fn store_for_each<F>(&self, f: F)
    where
        F: FnMut(&K, &Weak<V>);
    fn store_keys_cloned(&self) -> Vec<K>
    where
        K: Clone;
}

impl<K, V> WeakRefStore<K, V> for HashMap<K, Weak<V>>
where
    K: Eq + Hash,
{
    fn store_insert(&mut self, key: K, val: Weak<V>) -> Option<Weak<V>> {
        self.insert(key, val)
    }

    fn store_get(&self, key: &K) -> Option<&Weak<V>> {
        self.get(key)
    }

    fn store_remove(&mut self, key: &K) -> Option<Weak<V>> {
        self.remove(key)
    }

    fn store_contains_key(&self, key: &K) -> bool {
        self.contains_key(key)
    }

    fn store_len(&self) -> usize {
        self.len()
    }

    fn store_is_empty(&self) -> bool {
        self.is_empty()
    }

    fn store_clear(&mut self) {
        self.clear();
    }

    fn store_retain<F>(&mut self, f: F)
    where
        F: FnMut(&K, &mut Weak<V>) -> bool,
    {
        self.retain(f);
    }

    fn store_for_each<F>(&self, mut f: F)
    where
        F: FnMut(&K, &Weak<V>),
    {
        for (k, v) in self.iter() {
            f(k, v);
        }
    }

    fn store_keys_cloned(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.keys().cloned().collect()
    }
}

/// Map with weakly-held values backed by a configurable store.
///
/// Rust equivalent of Java's `AbstractWeakValueMap<K, V>`. Values are stored as
/// [`Weak`] references; entries whose referents have been dropped are purged lazily
/// on each access via [`process_queue`].
///
/// Implementors supply the backing store through [`ref_map`] / [`ref_map_mut`]; all
/// map operations are provided as default methods.
///
/// # Ownership
///
/// Callers must hold an [`Arc<V>`] for any value they want to keep alive. When all
/// external `Arc` handles for a value are dropped, the corresponding map entry is
/// removed on the next access.
pub trait AbstractWeakValueMap<K, V>
where
    K: Eq + Hash + Clone,
{
    /// The concrete backing-store type.
    type Store: WeakRefStore<K, V>;

    /// Returns an immutable reference to the backing store.
    fn ref_map(&self) -> &Self::Store;

    /// Returns a mutable reference to the backing store.
    fn ref_map_mut(&mut self) -> &mut Self::Store;

    /// Removes entries whose values have been dropped.
    ///
    /// Called automatically before each map access.
    fn process_queue(&mut self) {
        self.ref_map_mut().store_retain(|_, w| w.strong_count() > 0);
    }

    /// Inserts `value` under `key`, returning the previous live value if any.
    fn put(&mut self, key: K, value: Arc<V>) -> Option<Arc<V>> {
        self.process_queue();
        let weak = Arc::downgrade(&value);
        self.ref_map_mut()
            .store_insert(key, weak)
            .and_then(|w| w.upgrade())
    }

    /// Returns the live value for `key`, or `None` if absent or dropped.
    fn get(&mut self, key: &K) -> Option<Arc<V>> {
        self.process_queue();
        self.ref_map().store_get(key).and_then(|w| w.upgrade())
    }

    /// Returns the number of entries with live values.
    fn size(&mut self) -> usize {
        self.process_queue();
        self.ref_map().store_len()
    }

    /// Returns `true` if this map contains no live entries.
    fn is_empty(&mut self) -> bool {
        self.process_queue();
        self.ref_map().store_is_empty()
    }

    /// Returns `true` if this map contains a live entry for `key`.
    fn contains_key(&mut self, key: &K) -> bool {
        self.process_queue();
        self.ref_map().store_contains_key(key)
    }

    /// Returns `true` if any currently-live value equals `value`.
    fn contains_value(&mut self, value: &V) -> bool
    where
        V: PartialEq,
    {
        self.process_queue();
        let mut found = false;
        self.ref_map().store_for_each(|_, w| {
            if !found {
                if let Some(v) = w.upgrade() {
                    if *v == *value {
                        found = true;
                    }
                }
            }
        });
        found
    }

    /// Removes the entry for `key`, returning its live value if present.
    ///
    /// Does not call [`process_queue`] first, consistent with the Java original.
    fn remove(&mut self, key: &K) -> Option<Arc<V>> {
        self.ref_map_mut()
            .store_remove(key)
            .and_then(|w| w.upgrade())
    }

    /// Removes all entries.
    fn clear(&mut self) {
        self.ref_map_mut().store_clear();
    }

    /// Returns all currently-live values.
    fn values(&mut self) -> Vec<Arc<V>> {
        self.process_queue();
        let mut result = Vec::new();
        self.ref_map().store_for_each(|_, w| {
            if let Some(v) = w.upgrade() {
                result.push(v);
            }
        });
        result
    }

    /// Returns the keys of all live entries.
    fn key_set(&mut self) -> Vec<K> {
        self.process_queue();
        self.ref_map().store_keys_cloned()
    }

    /// Returns all (key, live-value) pairs.
    fn entry_set(&mut self) -> Vec<(K, Arc<V>)> {
        self.process_queue();
        let mut result = Vec::new();
        self.ref_map().store_for_each(|k, w| {
            if let Some(v) = w.upgrade() {
                result.push((k.clone(), v));
            }
        });
        result
    }

    /// Inserts all (key, value) pairs from `iter`.
    fn put_all<I: IntoIterator<Item = (K, Arc<V>)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.put(k, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMap<K, V> {
        store: HashMap<K, Weak<V>>,
    }

    impl<K: Eq + Hash + Clone, V> TestMap<K, V> {
        fn new() -> Self {
            Self {
                store: HashMap::new(),
            }
        }
    }

    impl<K: Eq + Hash + Clone, V> AbstractWeakValueMap<K, V> for TestMap<K, V> {
        type Store = HashMap<K, Weak<V>>;

        fn ref_map(&self) -> &Self::Store {
            &self.store
        }

        fn ref_map_mut(&mut self) -> &mut Self::Store {
            &mut self.store
        }
    }

    #[test]
    fn put_and_get_returns_value() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let v = Arc::new(42i32);
        map.put("k".into(), v.clone());
        assert_eq!(*map.get(&"k".into()).unwrap(), 42);
    }

    #[test]
    fn get_missing_key_returns_none() {
        let mut map: TestMap<String, i32> = TestMap::new();
        assert!(map.get(&"x".into()).is_none());
    }

    #[test]
    fn put_returns_previous_live_value() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let first = Arc::new(1i32);
        let second = Arc::new(2i32);
        assert!(map.put("k".into(), first.clone()).is_none());
        let old = map.put("k".into(), second.clone()).unwrap();
        assert_eq!(*old, 1);
        drop(first);
        drop(second);
    }

    #[test]
    fn stale_entry_removed_on_get() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let v = Arc::new(99i32);
        map.put("k".into(), v.clone());
        drop(v);
        assert!(map.get(&"k".into()).is_none());
        assert_eq!(map.size(), 0);
    }

    #[test]
    fn size_reflects_live_entries_only() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let a = Arc::new(1i32);
        let b = Arc::new(2i32);
        map.put("a".into(), a.clone());
        map.put("b".into(), b.clone());
        assert_eq!(map.size(), 2);
        drop(a);
        assert_eq!(map.size(), 1);
        drop(b);
        assert_eq!(map.size(), 0);
    }

    #[test]
    fn is_empty_tracks_live_entries() {
        let mut map: TestMap<String, i32> = TestMap::new();
        assert!(map.is_empty());
        let v = Arc::new(0i32);
        map.put("k".into(), v.clone());
        assert!(!map.is_empty());
        drop(v);
        assert!(map.is_empty());
    }

    #[test]
    fn contains_key_false_for_stale_entry() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let v = Arc::new(7i32);
        map.put("k".into(), v.clone());
        assert!(map.contains_key(&"k".into()));
        drop(v);
        assert!(!map.contains_key(&"k".into()));
    }

    #[test]
    fn contains_value_finds_live_value() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let v = Arc::new(5i32);
        map.put("k".into(), v.clone());
        assert!(map.contains_value(&5));
        assert!(!map.contains_value(&9));
        drop(v);
    }

    #[test]
    fn remove_returns_live_value() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let v = Arc::new(3i32);
        map.put("k".into(), v.clone());
        let removed = map.remove(&"k".into()).unwrap();
        assert_eq!(*removed, 3);
        assert!(map.get(&"k".into()).is_none());
        drop(v);
    }

    #[test]
    fn remove_stale_returns_none() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let v = Arc::new(3i32);
        map.put("k".into(), v.clone());
        drop(v);
        assert!(map.remove(&"k".into()).is_none());
    }

    #[test]
    fn clear_empties_map() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let v = Arc::new(1i32);
        map.put("k".into(), v.clone());
        map.clear();
        assert!(map.get(&"k".into()).is_none());
        assert_eq!(map.size(), 0);
        drop(v);
    }

    #[test]
    fn values_returns_live_only() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let a = Arc::new(10i32);
        let b = Arc::new(20i32);
        map.put("a".into(), a.clone());
        map.put("b".into(), b.clone());
        drop(a);
        let vals: Vec<i32> = map.values().iter().map(|v| **v).collect();
        assert_eq!(vals.len(), 1);
        assert!(vals.contains(&20));
        drop(b);
    }

    #[test]
    fn key_set_contains_live_keys_only() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let a = Arc::new(1i32);
        let b = Arc::new(2i32);
        map.put("a".into(), a.clone());
        map.put("b".into(), b.clone());
        drop(b);
        let keys = map.key_set();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&"a".to_string()));
        drop(a);
    }

    #[test]
    fn entry_set_contains_live_pairs() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let v = Arc::new(42i32);
        map.put("k".into(), v.clone());
        let entries = map.entry_set();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "k");
        assert_eq!(*entries[0].1, 42);
        drop(v);
    }

    #[test]
    fn put_all_inserts_all_pairs() {
        let mut map: TestMap<String, i32> = TestMap::new();
        let a = Arc::new(1i32);
        let b = Arc::new(2i32);
        map.put_all([("a".to_string(), a.clone()), ("b".to_string(), b.clone())]);
        assert_eq!(*map.get(&"a".into()).unwrap(), 1);
        assert_eq!(*map.get(&"b".into()).unwrap(), 2);
        drop(a);
        drop(b);
    }
}

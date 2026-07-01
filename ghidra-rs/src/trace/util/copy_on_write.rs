use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Weak};

use crate::util::datastruct::{AbstractWeakValueMap, WeakRefStore};

/// A copy-on-write map backed by a plain `HashMap`.
///
/// Analogous to Java's `ghidra.trace.util.CopyOnWrite.HashCowMap` (via
/// `AbstractCowMap`). Every mutation clones the current backing map, applies
/// the change to the clone, then publishes the clone as the new backing map.
/// Any [`HashCowMap::snapshot`] taken before a mutation is unaffected by it,
/// mirroring the Java class's guarantee that iterators/views obtained before
/// a `put`/`remove` never see later mutations.
pub struct HashCowMap<K, V> {
    map: Arc<HashMap<K, V>>,
}

impl<K, V> HashCowMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    pub fn new() -> Self {
        Self {
            map: Arc::new(HashMap::new()),
        }
    }

    /// Returns a cheaply-cloned handle to the current backing map. The
    /// returned snapshot is unaffected by subsequent mutations of `self`.
    pub fn snapshot(&self) -> Arc<HashMap<K, V>> {
        Arc::clone(&self.map)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    pub fn contains_value(&self, value: &V) -> bool
    where
        V: PartialEq,
    {
        self.map.values().any(|v| v == value)
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        let mut copy = (*self.map).clone();
        let previous = copy.insert(key, value);
        self.map = Arc::new(copy);
        previous
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let mut copy = (*self.map).clone();
        let previous = copy.remove(key);
        self.map = Arc::new(copy);
        previous
    }

    pub fn put_all<I: IntoIterator<Item = (K, V)>>(&mut self, from: I) {
        let mut copy = (*self.map).clone();
        copy.extend(from);
        self.map = Arc::new(copy);
    }

    pub fn clear(&mut self) {
        self.map = Arc::new(HashMap::new());
    }

    pub fn keys(&self) -> Vec<K> {
        self.map.keys().cloned().collect()
    }

    pub fn values(&self) -> Vec<V> {
        self.map.values().cloned().collect()
    }

    pub fn entries(&self) -> Vec<(K, V)> {
        self.map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Returns the existing value for `key`, or computes and inserts one via
    /// `mapping_function` if absent.
    pub fn compute_if_absent<F: FnOnce(&K) -> V>(&mut self, key: K, mapping_function: F) -> V {
        if let Some(existing) = self.map.get(&key) {
            return existing.clone();
        }
        let mut copy = (*self.map).clone();
        let value = mapping_function(&key);
        copy.insert(key, value.clone());
        self.map = Arc::new(copy);
        value
    }
}

impl<K, V> Default for HashCowMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> WeakRefStore<K, V> for HashCowMap<K, Weak<V>>
where
    K: Eq + Hash + Clone,
{
    fn store_insert(&mut self, key: K, val: Weak<V>) -> Option<Weak<V>> {
        self.put(key, val)
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

    fn store_retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut Weak<V>) -> bool,
    {
        let mut copy = (*self.map).clone();
        copy.retain(|k, v| f(k, v));
        self.map = Arc::new(copy);
    }

    fn store_for_each<F>(&self, mut f: F)
    where
        F: FnMut(&K, &Weak<V>),
    {
        for (k, v) in self.map.iter() {
            f(k, v);
        }
    }

    fn store_keys_cloned(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.keys()
    }
}

/// A weak-value map whose backing store is a copy-on-write [`HashCowMap`].
///
/// Analogous to Java's `ghidra.trace.util.CopyOnWrite.WeakValueHashCowMap`
/// (via `WeakValueAbstractCowMap`).
pub struct WeakValueHashCowMap<K, V> {
    store: HashCowMap<K, Weak<V>>,
}

impl<K, V> WeakValueHashCowMap<K, V>
where
    K: Eq + Hash + Clone,
{
    pub fn new() -> Self {
        Self {
            store: HashCowMap::new(),
        }
    }
}

impl<K, V> Default for WeakValueHashCowMap<K, V>
where
    K: Eq + Hash + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> AbstractWeakValueMap<K, V> for WeakValueHashCowMap<K, V>
where
    K: Eq + Hash + Clone,
{
    type Store = HashCowMap<K, Weak<V>>;

    fn ref_map(&self) -> &Self::Store {
        &self.store
    }

    fn ref_map_mut(&mut self) -> &mut Self::Store {
        &mut self.store
    }
}

/// A weak, copy-on-write set that uses `Arc` pointer identity for membership,
/// ignoring `PartialEq`.
///
/// Analogous to Java's `ghidra.trace.util.CopyOnWrite.WeakHashCowSet` (via
/// `WeakAbstractCowSet`), which keys entries by
/// `System.identityHashCode(Object)`. Rust has no equivalent of identity
/// hash codes, so membership is keyed on the element's `Arc` pointer address
/// instead -- preserving the "reference identity, not `equals`" semantics
/// the Java class documents.
pub struct WeakHashCowSet<E> {
    map: WeakValueHashCowMap<usize, E>,
}

impl<E> WeakHashCowSet<E> {
    pub fn new() -> Self {
        Self {
            map: WeakValueHashCowMap::new(),
        }
    }

    fn identity(value: &Arc<E>) -> usize {
        Arc::as_ptr(value) as usize
    }

    pub fn len(&mut self) -> usize {
        self.map.size()
    }

    pub fn is_empty(&mut self) -> bool {
        self.map.is_empty()
    }

    pub fn contains(&mut self, value: &Arc<E>) -> bool {
        match self.map.get(&Self::identity(value)) {
            Some(existing) => Arc::ptr_eq(&existing, value),
            None => false,
        }
    }

    /// Inserts `value`; returns `true` if no entry with the same identity was
    /// already present.
    pub fn insert(&mut self, value: Arc<E>) -> bool {
        let key = Self::identity(&value);
        match self.map.put(key, value.clone()) {
            Some(previous) => !Arc::ptr_eq(&previous, &value),
            None => true,
        }
    }

    /// Removes `value`; returns `true` if an entry with the same identity was
    /// present.
    pub fn remove(&mut self, value: &Arc<E>) -> bool {
        let key = Self::identity(value);
        match self.map.remove(&key) {
            Some(removed) => Arc::ptr_eq(&removed, value),
            None => false,
        }
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    pub fn values(&mut self) -> Vec<Arc<E>> {
        self.map.values()
    }
}

impl<E> Default for WeakHashCowSet<E> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_cow_map_put_and_get() {
        let mut m: HashCowMap<String, i32> = HashCowMap::new();
        assert!(m.put("a".into(), 1).is_none());
        assert_eq!(m.get(&"a".into()), Some(&1));
        assert_eq!(m.len(), 1);
        assert!(!m.is_empty());
    }

    #[test]
    fn hash_cow_map_put_returns_previous() {
        let mut m: HashCowMap<String, i32> = HashCowMap::new();
        m.put("a".into(), 1);
        assert_eq!(m.put("a".into(), 2), Some(1));
        assert_eq!(m.get(&"a".into()), Some(&2));
    }

    #[test]
    fn hash_cow_map_snapshot_unaffected_by_later_mutation() {
        let mut m: HashCowMap<String, i32> = HashCowMap::new();
        m.put("a".into(), 1);
        let snap = m.snapshot();
        m.put("a".into(), 2);
        m.put("b".into(), 3);
        assert_eq!(snap.get("a"), Some(&1));
        assert_eq!(snap.len(), 1);
        assert_eq!(m.get(&"a".into()), Some(&2));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn hash_cow_map_remove() {
        let mut m: HashCowMap<String, i32> = HashCowMap::new();
        m.put("a".into(), 1);
        assert_eq!(m.remove(&"a".into()), Some(1));
        assert!(m.get(&"a".into()).is_none());
        assert!(m.remove(&"a".into()).is_none());
    }

    #[test]
    fn hash_cow_map_put_all_and_clear() {
        let mut m: HashCowMap<String, i32> = HashCowMap::new();
        m.put_all([("a".to_string(), 1), ("b".to_string(), 2)]);
        assert_eq!(m.len(), 2);
        m.clear();
        assert!(m.is_empty());
    }

    #[test]
    fn hash_cow_map_contains_value() {
        let mut m: HashCowMap<String, i32> = HashCowMap::new();
        m.put("a".into(), 42);
        assert!(m.contains_value(&42));
        assert!(!m.contains_value(&7));
    }

    #[test]
    fn hash_cow_map_compute_if_absent_inserts_once() {
        let mut m: HashCowMap<String, i32> = HashCowMap::new();
        let mut calls = 0;
        let v1 = m.compute_if_absent("a".to_string(), |_| {
            calls += 1;
            10
        });
        let v2 = m.compute_if_absent("a".to_string(), |_| {
            calls += 1;
            20
        });
        assert_eq!(v1, 10);
        assert_eq!(v2, 10);
        assert_eq!(calls, 1);
    }

    #[test]
    fn hash_cow_map_keys_values_entries() {
        let mut m: HashCowMap<String, i32> = HashCowMap::new();
        m.put("a".into(), 1);
        m.put("b".into(), 2);
        let mut keys = m.keys();
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
        let mut values = m.values();
        values.sort();
        assert_eq!(values, vec![1, 2]);
        assert_eq!(m.entries().len(), 2);
    }

    #[test]
    fn weak_value_hash_cow_map_drops_stale_entries() {
        let mut m: WeakValueHashCowMap<String, i32> = WeakValueHashCowMap::new();
        let v = Arc::new(1i32);
        m.put("a".to_string(), v.clone());
        assert_eq!(m.size(), 1);
        drop(v);
        assert!(m.get(&"a".to_string()).is_none());
        assert_eq!(m.size(), 0);
    }

    #[test]
    fn weak_hash_cow_set_insert_and_contains() {
        let mut set: WeakHashCowSet<i32> = WeakHashCowSet::new();
        let a = Arc::new(1i32);
        let b = Arc::new(1i32); // equal value, distinct identity
        assert!(set.insert(a.clone()));
        assert!(set.contains(&a));
        // Distinct object, even with an equal value, is a distinct identity.
        assert!(!set.contains(&b));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn weak_hash_cow_set_insert_same_object_twice_returns_false() {
        let mut set: WeakHashCowSet<i32> = WeakHashCowSet::new();
        let a = Arc::new(1i32);
        assert!(set.insert(a.clone()));
        assert!(!set.insert(a.clone()));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn weak_hash_cow_set_remove() {
        let mut set: WeakHashCowSet<i32> = WeakHashCowSet::new();
        let a = Arc::new(1i32);
        set.insert(a.clone());
        assert!(set.remove(&a));
        assert!(!set.contains(&a));
        assert!(!set.remove(&a));
    }

    #[test]
    fn weak_hash_cow_set_drops_stale_entries() {
        let mut set: WeakHashCowSet<i32> = WeakHashCowSet::new();
        let a = Arc::new(1i32);
        set.insert(a.clone());
        drop(a);
        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
    }

    #[test]
    fn weak_hash_cow_set_values_returns_live_elements() {
        let mut set: WeakHashCowSet<i32> = WeakHashCowSet::new();
        let a = Arc::new(1i32);
        let b = Arc::new(2i32);
        set.insert(a.clone());
        set.insert(b.clone());
        let mut values: Vec<i32> = set.values().iter().map(|v| **v).collect();
        values.sort();
        assert_eq!(values, vec![1, 2]);
    }

    #[test]
    fn weak_hash_cow_set_clear() {
        let mut set: WeakHashCowSet<i32> = WeakHashCowSet::new();
        set.insert(Arc::new(1i32));
        set.clear();
        assert!(set.is_empty());
    }
}

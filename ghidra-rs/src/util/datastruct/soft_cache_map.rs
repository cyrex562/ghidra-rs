use std::collections::HashMap;
use std::hash::Hash;

/// A fixed-size, least-recently-used cache map.
///
/// Port of `ghidra.util.datastruct.SoftCacheMap<K, V>`.
///
/// # Java behavioral gap: no GC-pressure eviction
///
/// Java's `SoftCacheMap` wraps a `FixedSizeHashMap` (an access-order
/// `LinkedHashMap` that evicts its least-recently-used entry once `size() >
/// cacheSize`) but additionally stores each value behind a `SoftReference`,
/// so the JVM garbage collector may reclaim (and silently evict) entries
/// *before* the fixed-size limit is ever reached, whenever it decides memory
/// is under pressure -- a nondeterministic, GC-implementation-specific
/// signal.
///
/// Rust has no equivalent to `SoftReference`/GC memory pressure: there is no
/// collector to consult and no way to be notified "memory is getting tight,
/// please drop some caches". This port therefore keeps the *deterministic*
/// half of Java's behavior -- the fixed-size, access-order LRU eviction from
/// `FixedSizeHashMap` (this is an ordinary capacity limit, unrelated to
/// garbage collection) -- but does **not**, and cannot, evict entries early
/// under memory pressure. In other words: this cache holds on to up to
/// `cache_size` entries exactly as long as Java's would *in the best case*
/// (no GC reclaim), and never fewer. Callers relying on `SoftCacheMap` as a
/// last-resort memory-pressure release valve (rather than as a plain
/// bounded LRU cache) will not get that behavior from this port.
#[derive(Debug)]
pub struct SoftCacheMap<K, V> {
    cache_size: usize,
    /// Recency order, oldest (least-recently-used) first.
    order: Vec<K>,
    map: HashMap<K, V>,
}

impl<K: Eq + Hash + Clone, V> SoftCacheMap<K, V> {
    /// Constructs a new `SoftCacheMap` that holds at most `cache_size` entries.
    pub fn new(cache_size: usize) -> Self {
        Self {
            cache_size,
            order: Vec::new(),
            map: HashMap::new(),
        }
    }

    /// Moves `key` to the most-recently-used end of the recency order.
    fn touch(&mut self, key: &K) {
        self.order.retain(|k| k != key);
        self.order.push(key.clone());
    }

    /// Evicts the least-recently-used entry if the map has grown past
    /// `cache_size`.
    fn evict_if_over_capacity(&mut self) {
        if self.map.len() > self.cache_size && !self.order.is_empty() {
            let oldest = self.order.remove(0);
            self.map.remove(&oldest);
        }
    }

    /// Inserts `value` for `key`, returning the previous value if one was
    /// present. Marks `key` as most-recently-used; if the map now holds more
    /// than `cache_size` entries, evicts the least-recently-used one.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        let previous = self.map.insert(key.clone(), value);
        self.touch(&key);
        self.evict_if_over_capacity();
        previous
    }

    /// Returns a reference to the value for `key`, marking it as
    /// most-recently-used, or `None` if absent.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if self.map.contains_key(key) {
            self.touch(key);
        }
        self.map.get(key)
    }

    /// Returns the number of entries currently cached.
    pub fn size(&self) -> usize {
        self.map.len()
    }

    /// Removes every entry.
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    /// Returns `true` if the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns `true` if `key` is present, without affecting recency order.
    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Removes and returns the value for `key`, if present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.order.retain(|k| k != key);
        self.map.remove(key)
    }

    /// Returns all keys currently cached, in unspecified order.
    pub fn key_set(&self) -> Vec<K> {
        self.map.keys().cloned().collect()
    }

    /// Returns references to all `(key, value)` pairs currently cached, in
    /// unspecified order.
    pub fn entry_set(&self) -> Vec<(&K, &V)> {
        self.map.iter().collect()
    }

    /// Inserts every `(key, value)` pair from `pairs`.
    pub fn put_all(&mut self, pairs: Vec<(K, V)>) {
        for (key, value) in pairs {
            self.put(key, value);
        }
    }
}

impl<K: Eq + Hash + Clone, V: PartialEq> SoftCacheMap<K, V> {
    /// Returns `true` if any cached value equals `value`.
    pub fn contains_value(&self, value: &V) -> bool {
        self.map.values().any(|v| v == value)
    }
}

impl<K: Eq + Hash + Clone, V: Clone> SoftCacheMap<K, V> {
    /// Returns a `Vec` of all cached values, in unspecified order.
    pub fn values(&self) -> Vec<V> {
        self.map.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let map: SoftCacheMap<String, i32> = SoftCacheMap::new(3);
        assert!(map.is_empty());
        assert_eq!(map.size(), 0);
    }

    #[test]
    fn put_and_get() {
        let mut map = SoftCacheMap::new(3);
        map.put("a".to_string(), 1);
        assert_eq!(map.get(&"a".to_string()), Some(&1));
    }

    #[test]
    fn put_returns_previous_value() {
        let mut map = SoftCacheMap::new(3);
        assert_eq!(map.put("a".to_string(), 1), None);
        assert_eq!(map.put("a".to_string(), 2), Some(1));
        assert_eq!(map.get(&"a".to_string()), Some(&2));
    }

    #[test]
    fn get_missing_returns_none() {
        let mut map: SoftCacheMap<String, i32> = SoftCacheMap::new(3);
        assert_eq!(map.get(&"missing".to_string()), None);
    }

    #[test]
    fn size_tracks_entries() {
        let mut map = SoftCacheMap::new(5);
        map.put("a".to_string(), 1);
        map.put("b".to_string(), 2);
        assert_eq!(map.size(), 2);
    }

    #[test]
    fn contains_key_and_value() {
        let mut map = SoftCacheMap::new(3);
        map.put("a".to_string(), 1);
        assert!(map.contains_key(&"a".to_string()));
        assert!(!map.contains_key(&"z".to_string()));
        assert!(map.contains_value(&1));
        assert!(!map.contains_value(&99));
    }

    #[test]
    fn remove_entry() {
        let mut map = SoftCacheMap::new(3);
        map.put("a".to_string(), 1);
        assert_eq!(map.remove(&"a".to_string()), Some(1));
        assert_eq!(map.get(&"a".to_string()), None);
        assert_eq!(map.size(), 0);
    }

    #[test]
    fn remove_missing_returns_none() {
        let mut map: SoftCacheMap<String, i32> = SoftCacheMap::new(3);
        assert_eq!(map.remove(&"missing".to_string()), None);
    }

    #[test]
    fn clear_empties_map() {
        let mut map = SoftCacheMap::new(3);
        map.put("a".to_string(), 1);
        map.put("b".to_string(), 2);
        map.clear();
        assert!(map.is_empty());
        assert_eq!(map.size(), 0);
    }

    #[test]
    fn values_and_key_set() {
        let mut map = SoftCacheMap::new(3);
        map.put("a".to_string(), 1);
        map.put("b".to_string(), 2);

        let mut values = map.values();
        values.sort();
        assert_eq!(values, vec![1, 2]);

        let mut keys = map.key_set();
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn entry_set_contains_all_pairs() {
        let mut map = SoftCacheMap::new(3);
        map.put("a".to_string(), 1);
        map.put("b".to_string(), 2);
        let mut entries: Vec<(String, i32)> =
            map.entry_set().into_iter().map(|(k, v)| (k.clone(), *v)).collect();
        entries.sort();
        assert_eq!(
            entries,
            vec![("a".to_string(), 1), ("b".to_string(), 2)]
        );
    }

    #[test]
    fn put_all_inserts_every_pair() {
        let mut map = SoftCacheMap::new(5);
        map.put_all(vec![("a".to_string(), 1), ("b".to_string(), 2)]);
        assert_eq!(map.get(&"a".to_string()), Some(&1));
        assert_eq!(map.get(&"b".to_string()), Some(&2));
    }

    /// Core `FixedSizeHashMap`-derived behavior: once the cache holds more than
    /// `cache_size` entries, the least-recently-used one is evicted.
    #[test]
    fn fixed_size_eviction_removes_least_recently_used() {
        let mut map = SoftCacheMap::new(2);
        map.put("a".to_string(), 1);
        map.put("b".to_string(), 2);
        map.put("c".to_string(), 3); // "a" is LRU, gets evicted.

        assert_eq!(map.size(), 2);
        assert_eq!(map.get(&"a".to_string()), None);
        assert_eq!(map.get(&"b".to_string()), Some(&2));
        assert_eq!(map.get(&"c".to_string()), Some(&3));
    }

    /// `get` (like Java's access-order `LinkedHashMap`) promotes an entry to
    /// most-recently-used, protecting it from the next eviction.
    #[test]
    fn get_promotes_entry_to_most_recently_used() {
        let mut map = SoftCacheMap::new(2);
        map.put("a".to_string(), 1);
        map.put("b".to_string(), 2);

        // Touch "a" so "b" becomes the least-recently-used entry.
        assert_eq!(map.get(&"a".to_string()), Some(&1));
        map.put("c".to_string(), 3); // "b" is now LRU, gets evicted.

        assert_eq!(map.get(&"a".to_string()), Some(&1));
        assert_eq!(map.get(&"b".to_string()), None);
        assert_eq!(map.get(&"c".to_string()), Some(&3));
    }

    /// Re-`put`ting an existing key updates its value and promotes it to
    /// most-recently-used without growing the map's size (matching Java's
    /// access-order `LinkedHashMap.put` on an existing key).
    #[test]
    fn put_existing_key_promotes_without_growing_size() {
        let mut map = SoftCacheMap::new(2);
        map.put("a".to_string(), 1);
        map.put("b".to_string(), 2);
        map.put("a".to_string(), 100); // "a" refreshed to MRU; "b" is now LRU.
        assert_eq!(map.size(), 2);

        map.put("c".to_string(), 3); // "b" evicted.
        assert_eq!(map.get(&"a".to_string()), Some(&100));
        assert_eq!(map.get(&"b".to_string()), None);
        assert_eq!(map.get(&"c".to_string()), Some(&3));
    }

    #[test]
    fn zero_cache_size_never_retains_entries() {
        let mut map = SoftCacheMap::new(0);
        map.put("a".to_string(), 1);
        assert_eq!(map.size(), 0);
        assert_eq!(map.get(&"a".to_string()), None);
    }
}

use lru::LruCache;
use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, Weak};

/// Cache that removes items when they are no longer externally referenced.
///
/// Values are stored as weak references; a bounded hard cache keeps recent
/// entries alive so they are not immediately eligible for collection.
/// All public methods are thread-safe.
pub struct WeakReferenceCache<K, V> {
    inner: Mutex<CacheInner<K, V>>,
}

struct CacheInner<K, V> {
    refs: HashMap<K, Weak<V>>,
    hard_cache: LruCache<K, Arc<V>>,
}

impl<K, V> CacheInner<K, V>
where
    K: Clone + Eq + Hash,
{
    /// Purges entries whose referents have been dropped, mirroring Java's `processQueue`.
    fn process_stale(&mut self) {
        self.refs.retain(|_, w| w.strong_count() > 0);
    }
}

impl<K, V> WeakReferenceCache<K, V>
where
    K: Clone + Eq + Hash,
{
    /// Creates a cache whose hard cache holds at most `hard_cache_size` strong references.
    pub fn new(hard_cache_size: usize) -> Self {
        let cap = NonZeroUsize::new(hard_cache_size).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            inner: Mutex::new(CacheInner {
                refs: HashMap::new(),
                hard_cache: LruCache::new(cap),
            }),
        }
    }

    /// Returns the cached value for `key`, or `None` if absent or collected.
    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        let mut inner = self.inner.lock().unwrap();
        match inner.refs.get(key).and_then(|w| w.upgrade()) {
            Some(v) => {
                inner.hard_cache.put(key.clone(), v.clone());
                Some(v)
            }
            None => {
                inner.refs.remove(key);
                None
            }
        }
    }

    /// Returns the number of entries tracked, including potentially stale ones.
    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().refs.len()
    }

    /// Replaces the hard cache with an empty one of `size` capacity.
    pub fn set_hard_cache_size(&self, size: usize) {
        let cap = NonZeroUsize::new(size).unwrap_or(NonZeroUsize::new(1).unwrap());
        let mut inner = self.inner.lock().unwrap();
        inner.hard_cache = LruCache::new(cap);
    }

    /// Inserts `value` under `key` and returns an `Arc` to it.
    pub fn add(&self, key: K, value: V) -> Arc<V> {
        let mut inner = self.inner.lock().unwrap();
        inner.process_stale();
        let arc_v = Arc::new(value);
        inner.hard_cache.put(key.clone(), arc_v.clone());
        inner.refs.insert(key, Arc::downgrade(&arc_v));
        arc_v
    }

    /// Returns all currently live cached values.
    pub fn get_cached_objects(&self) -> Vec<Arc<V>> {
        let mut inner = self.inner.lock().unwrap();
        inner.process_stale();
        inner.refs.values().filter_map(|w| w.upgrade()).collect()
    }

    /// Calls `f` with a reference to each live cached value.
    pub fn apply<F: FnMut(&V)>(&self, mut f: F) {
        let mut inner = self.inner.lock().unwrap();
        inner.process_stale();
        for weak in inner.refs.values() {
            if let Some(v) = weak.upgrade() {
                f(&v);
            }
        }
    }

    /// Removes the entry for `key` and returns the value if it is still live.
    pub fn delete(&self, key: &K) -> Option<Arc<V>> {
        let mut inner = self.inner.lock().unwrap();
        inner.process_stale();
        inner.hard_cache.pop(key);
        inner.refs.remove(key).and_then(|w| w.upgrade())
    }

    /// Removes all entries whose live values satisfy `predicate`, and all stale entries.
    pub fn delete_if<F: Fn(&V) -> bool>(&self, predicate: F) {
        let mut inner = self.inner.lock().unwrap();
        inner.refs.retain(|_, w| match w.upgrade() {
            None => false,
            Some(v) => !predicate(&v),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_get_returns_value() {
        let cache = WeakReferenceCache::new(4);
        let arc = cache.add(1u32, "hello".to_string());
        assert_eq!(*arc, "hello");
        assert_eq!(*cache.get(&1).unwrap(), "hello");
    }

    #[test]
    fn get_missing_key_returns_none() {
        let cache: WeakReferenceCache<u32, String> = WeakReferenceCache::new(4);
        assert!(cache.get(&99).is_none());
    }

    #[test]
    fn size_reflects_entry_count() {
        let cache = WeakReferenceCache::new(4);
        assert_eq!(cache.size(), 0);
        let _a = cache.add(1u32, "a".to_string());
        let _b = cache.add(2u32, "b".to_string());
        assert_eq!(cache.size(), 2);
    }

    #[test]
    fn delete_removes_entry_and_returns_value() {
        let cache = WeakReferenceCache::new(4);
        cache.add(1u32, "one".to_string());
        let removed = cache.delete(&1).unwrap();
        assert_eq!(*removed, "one");
        assert!(cache.get(&1).is_none());
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn delete_missing_key_returns_none() {
        let cache: WeakReferenceCache<u32, String> = WeakReferenceCache::new(4);
        assert!(cache.delete(&42).is_none());
    }

    #[test]
    fn get_cached_objects_returns_live_values() {
        let cache = WeakReferenceCache::new(4);
        let _a = cache.add(1u32, 10i32);
        let _b = cache.add(2u32, 20i32);
        let mut objects: Vec<i32> = cache.get_cached_objects().iter().map(|a| **a).collect();
        objects.sort();
        assert_eq!(objects, vec![10, 20]);
    }

    #[test]
    fn apply_visits_all_live_values() {
        let cache = WeakReferenceCache::new(4);
        let _a = cache.add(1u32, 1i32);
        let _b = cache.add(2u32, 2i32);
        let _c = cache.add(3u32, 3i32);
        let mut sum = 0i32;
        cache.apply(|v| sum += v);
        assert_eq!(sum, 6);
    }

    #[test]
    fn delete_if_removes_matching_entries() {
        let cache = WeakReferenceCache::new(4);
        let _a = cache.add(1u32, 1i32);
        let _b = cache.add(2u32, 2i32);
        let _c = cache.add(3u32, 3i32);
        cache.delete_if(|v| *v % 2 == 0);
        // key 2 should be gone; 1 and 3 remain
        assert!(cache.get(&2).is_none());
        assert!(cache.get(&1).is_some());
        assert!(cache.get(&3).is_some());
    }

    #[test]
    fn set_hard_cache_size_clears_old_hard_cache() {
        // Hard cache of size 2 holds arcs for keys 1 and 2
        let cache = WeakReferenceCache::new(2);
        let _a = cache.add(1u32, "a".to_string());
        let _b = cache.add(2u32, "b".to_string());
        // Resize — old hard cache entries are dropped
        cache.set_hard_cache_size(1);
        // Refs still exist as long as our _a and _b arcs are alive
        assert!(cache.get(&1).is_some());
        assert!(cache.get(&2).is_some());
    }

    #[test]
    fn weak_ref_evicted_from_hard_cache_becomes_none() {
        // Hard cache size 1: adding a second entry evicts the first.
        // If the caller also drops the Arc for the first entry, get should return None.
        let cache = WeakReferenceCache::new(1);
        // Add key 1 but immediately drop the returned Arc so we hold no strong ref.
        drop(cache.add(1u32, "one".to_string()));
        // Adding key 2 evicts key 1 from the hard cache; no other strong ref exists.
        let _b = cache.add(2u32, "two".to_string());
        assert!(cache.get(&1).is_none());
        assert_eq!(*cache.get(&2).unwrap(), "two");
    }

    #[test]
    fn add_same_key_replaces_entry() {
        let cache = WeakReferenceCache::new(4);
        let _a = cache.add(1u32, "first".to_string());
        let _b = cache.add(1u32, "second".to_string());
        assert_eq!(*cache.get(&1).unwrap(), "second");
        assert_eq!(cache.size(), 1);
    }

    #[test]
    fn stale_entries_cleaned_on_add() {
        // Start with hard cache of size 1
        let cache = WeakReferenceCache::new(1);
        // Add and immediately drop so the hard cache is the only holder
        drop(cache.add(1u32, "a".to_string()));
        drop(cache.add(2u32, "b".to_string())); // evicts key 1 from hard cache
        // size() can still report stale count, but add() calls process_stale
        drop(cache.add(3u32, "c".to_string())); // process_stale purges 1 and 2
        // After process_stale inside add(3), only key 3 with live hard-cache Arc remains
        assert_eq!(cache.size(), 1);
    }
}

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;

use crate::util::Lock;

/// A map interface backed by a cached, lazily (re)loaded set of key/value pairs.
///
/// Implementors must be able to regenerate the map from scratch at any time via
/// [`load_map`][Self::load_map]; adding/removing items is just a mirror of changes made
/// elsewhere. The map is lazy in that it won't load the data until first needed.
///
/// Implementors provide storage for the cached map (via
/// [`cached_map`][Self::cached_map]) and the lock used to coordinate loading (via
/// [`database_lock`][Self::database_lock]). The Java original caches the loaded map
/// behind a `SoftReference` so the GC may evict it under memory pressure; Rust has no
/// equivalent mechanism, so the cached map is held strongly and only dropped by an
/// explicit [`clear`][Self::clear].
///
/// Port of `ghidra.program.database.data.LazyLoadingCachingMap`.
pub trait LazyLoadingCachingMap<K, V>: Send + Sync
where
    K: Eq + Hash,
{
    /// Reloads the map data from scratch. Implementors may assume the database lock
    /// has been acquired.
    fn load_map(&self) -> HashMap<K, V>;

    /// Returns the lock used to coordinate loading the underlying map data.
    fn database_lock(&self) -> &Lock<()>;

    /// Returns the storage slot holding the cached map, or `None` if not currently
    /// loaded.
    fn cached_map(&self) -> &Mutex<Option<HashMap<K, V>>>;

    /// Adds the key/value pair to the map. If the map is not currently loaded, this
    /// does nothing.
    fn put(&self, key: K, value: V) {
        let mut guard = self.cached_map().lock().unwrap();
        if let Some(map) = guard.as_mut() {
            map.insert(key, value);
        }
    }

    /// Removes the key/value pair from the map as specified by `key`. If the map is
    /// not currently loaded, this does nothing.
    fn remove(&self, key: &K) {
        let mut guard = self.cached_map().lock().unwrap();
        if let Some(map) = guard.as_mut() {
            map.remove(key);
        }
    }

    /// Removes any cached map of values, restoring the map to its initial state.
    fn clear(&self) {
        *self.cached_map().lock().unwrap() = None;
    }

    /// Retrieves the value for `key`, loading the map first if not already loaded.
    fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        self.with_loaded_map(|map| map.get(key).cloned())
    }

    /// Returns a snapshot of the values in this map, loading it first if not already
    /// loaded.
    fn values(&self) -> Vec<V>
    where
        V: Clone,
    {
        self.with_loaded_map(|map| map.values().cloned().collect())
    }

    /// Runs `f` against the loaded map, loading it first if necessary.
    fn with_loaded_map<R>(&self, f: impl FnOnce(&HashMap<K, V>) -> R) -> R {
        {
            let guard = self.cached_map().lock().unwrap();
            if let Some(map) = guard.as_ref() {
                return f(map);
            }
        }

        // The database lock must be held while loading, but not while holding the
        // cache mutex, since loading may take a while and other methods only need the
        // cache mutex.
        let _read_guard = self.database_lock().read();
        let mut guard = self.cached_map().lock().unwrap();
        if guard.is_none() {
            *guard = Some(self.load_map());
        }
        f(guard.as_ref().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingMap {
        lock: Lock<()>,
        cached: Mutex<Option<HashMap<i32, &'static str>>>,
        load_count: Arc<AtomicUsize>,
    }

    impl CountingMap {
        fn new(load_count: Arc<AtomicUsize>) -> Self {
            Self {
                lock: Lock::new_unit("test_lock"),
                cached: Mutex::new(None),
                load_count,
            }
        }
    }

    impl LazyLoadingCachingMap<i32, &'static str> for CountingMap {
        fn load_map(&self) -> HashMap<i32, &'static str> {
            self.load_count.fetch_add(1, Ordering::SeqCst);
            let mut map = HashMap::new();
            map.insert(1, "one");
            map.insert(2, "two");
            map
        }

        fn database_lock(&self) -> &Lock<()> {
            &self.lock
        }

        fn cached_map(&self) -> &Mutex<Option<HashMap<i32, &'static str>>> {
            &self.cached
        }
    }

    #[test]
    fn get_loads_map_on_first_access() {
        let count = Arc::new(AtomicUsize::new(0));
        let map = CountingMap::new(Arc::clone(&count));
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(map.get(&1), Some("one"));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn get_does_not_reload_once_cached() {
        let count = Arc::new(AtomicUsize::new(0));
        let map = CountingMap::new(Arc::clone(&count));
        assert_eq!(map.get(&1), Some("one"));
        assert_eq!(map.get(&2), Some("two"));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn get_missing_key_returns_none() {
        let map = CountingMap::new(Arc::new(AtomicUsize::new(0)));
        assert_eq!(map.get(&99), None);
    }

    #[test]
    fn values_loads_map_and_returns_all_values() {
        let map = CountingMap::new(Arc::new(AtomicUsize::new(0)));
        let mut values = map.values();
        values.sort_unstable();
        assert_eq!(values, vec!["one", "two"]);
    }

    #[test]
    fn put_before_load_is_noop() {
        let count = Arc::new(AtomicUsize::new(0));
        let map = CountingMap::new(Arc::clone(&count));
        map.put(3, "three");
        assert_eq!(count.load(Ordering::SeqCst), 0);
        // A subsequent load regenerates from scratch, losing the pre-load put.
        assert_eq!(map.get(&3), None);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn put_after_load_is_visible() {
        let map = CountingMap::new(Arc::new(AtomicUsize::new(0)));
        map.get(&1); // force load
        map.put(3, "three");
        assert_eq!(map.get(&3), Some("three"));
    }

    #[test]
    fn remove_after_load_deletes_entry() {
        let map = CountingMap::new(Arc::new(AtomicUsize::new(0)));
        map.get(&1); // force load
        map.remove(&1);
        assert_eq!(map.get(&1), None);
    }

    #[test]
    fn remove_before_load_is_noop() {
        let map = CountingMap::new(Arc::new(AtomicUsize::new(0)));
        map.remove(&1);
        // Removing before load must not force a load nor error.
        assert_eq!(map.get(&1), Some("one"));
    }

    #[test]
    fn clear_forces_reload_on_next_access() {
        let count = Arc::new(AtomicUsize::new(0));
        let map = CountingMap::new(Arc::clone(&count));
        map.get(&1);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        map.clear();
        map.get(&1);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn clear_discards_uncached_puts() {
        let map = CountingMap::new(Arc::new(AtomicUsize::new(0)));
        map.get(&1); // force load
        map.put(3, "three");
        map.clear();
        assert_eq!(map.get(&3), None);
    }
}

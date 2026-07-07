use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Weak};

/// Fixed-size `i64`-keyed object cache combining a hard (strong-reference) tier
/// and a weak-reference tier.
///
/// The weak cache maps keys to [`Weak`] pointers; the hard cache retains up to
/// `hard_cache_size` [`Arc`] references for recently-accessed objects, keeping
/// their weak entries live. When an object is evicted from the hard cache and
/// the caller drops its last [`Arc`], the corresponding weak entry is cleaned up
/// lazily on the next mutating access.
///
/// This structure ensures that at most one live instance per key is visible.
///
/// Port of `ghidra.util.datastruct.ObjectCache`.
pub struct ObjectCache<T> {
    hash_table: HashMap<i64, Weak<T>>,
    hard_cache: VecDeque<Arc<T>>,
    hard_cache_size: usize,
}

impl<T> ObjectCache<T> {
    /// Creates a cache with a hard-cache capacity of `hard_cache_size`.
    pub fn new(hard_cache_size: usize) -> Self {
        Self {
            hash_table: HashMap::new(),
            hard_cache: VecDeque::new(),
            hard_cache_size,
        }
    }

    /// Returns `true` if a live object is cached for `key`.
    pub fn contains(&mut self, key: i64) -> bool {
        self.process_queue();
        self.hash_table.contains_key(&key)
    }

    /// Returns the cached object for `key`, or `None` if absent or expired.
    ///
    /// Promotes the returned object into the hard cache.
    pub fn get(&mut self, key: i64) -> Option<Arc<T>> {
        let upgraded = self.hash_table.get(&key).and_then(Weak::upgrade);
        match upgraded {
            Some(obj) => {
                self.add_to_hard_cache(obj.clone());
                Some(obj)
            }
            None => {
                self.hash_table.remove(&key);
                None
            }
        }
    }

    /// Returns the cached object for `key` when present; otherwise calls `f(key)`,
    /// inserts the result if `Some`, and returns it.
    ///
    /// If `f` returns `None`, nothing is inserted and `None` is returned.
    pub fn compute_if_absent<F>(&mut self, key: i64, f: F) -> Option<Arc<T>>
    where
        F: FnOnce(i64) -> Option<Arc<T>>,
    {
        if let Some(existing) = self.get(key) {
            return Some(existing);
        }
        let new_value = f(key)?;
        self.put(key, new_value.clone());
        Some(new_value)
    }

    /// Returns the configured hard-cache capacity.
    pub fn size(&self) -> usize {
        self.hard_cache_size
    }

    /// Sets a new hard-cache capacity, evicting the most-recently-added entries
    /// if the current hard cache exceeds the new limit.
    pub fn set_hard_cache_size(&mut self, size: usize) {
        while self.hard_cache.len() > size {
            self.hard_cache.pop_back();
        }
        self.hard_cache_size = size;
    }

    /// Inserts `obj` under `key`, replacing any previous entry.
    pub fn put(&mut self, key: i64, obj: Arc<T>) {
        self.process_queue();
        let weak = Arc::downgrade(&obj);
        self.hash_table.insert(key, weak);
        self.add_to_hard_cache(obj);
    }

    /// Removes the hash-table entry for `key`.
    ///
    /// The object may remain alive until it is evicted from the hard cache and all
    /// external [`Arc`] handles are dropped.
    pub fn remove(&mut self, key: i64) {
        self.process_queue();
        self.hash_table.remove(&key);
    }

    fn add_to_hard_cache(&mut self, obj: Arc<T>) {
        self.hard_cache.push_back(obj);
        if self.hard_cache.len() > self.hard_cache_size {
            self.hard_cache.pop_front();
        }
    }

    fn process_queue(&mut self) {
        self.hash_table.retain(|_, w| w.strong_count() > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_none_for_missing_key() {
        let mut cache: ObjectCache<i32> = ObjectCache::new(4);
        assert!(cache.get(1).is_none());
    }

    #[test]
    fn put_and_get_round_trip() {
        let mut cache = ObjectCache::new(4);
        let val = Arc::new(42i32);
        cache.put(1, val.clone());
        assert_eq!(*cache.get(1).unwrap(), 42);
    }

    #[test]
    fn contains_reflects_live_entries() {
        let mut cache = ObjectCache::new(4);
        let val = Arc::new(1i32);
        cache.put(10, val.clone());
        assert!(cache.contains(10));
        assert!(!cache.contains(99));
    }

    #[test]
    fn hard_cache_keeps_weak_ref_alive_after_caller_drops_arc() {
        let mut cache = ObjectCache::new(4);
        let val = Arc::new(7i32);
        cache.put(1, val.clone());
        drop(val);
        assert!(cache.get(1).is_some());
    }

    #[test]
    fn evicted_entry_becomes_dead_when_all_arcs_dropped() {
        let mut cache = ObjectCache::new(1);
        let a = Arc::new(1i32);
        let b = Arc::new(2i32);
        cache.put(1, a.clone());
        cache.put(2, b.clone()); // evicts a from hard cache (size == 1)
        drop(a); // no remaining strong refs to a
        assert!(cache.get(1).is_none());
        assert!(cache.get(2).is_some());
    }

    #[test]
    fn remove_invalidates_hash_table_entry() {
        let mut cache = ObjectCache::new(4);
        let val = Arc::new(5i32);
        cache.put(1, val.clone());
        cache.remove(1);
        assert!(cache.get(1).is_none());
        assert!(!cache.contains(1));
    }

    #[test]
    fn remove_nonexistent_key_is_no_op() {
        let mut cache: ObjectCache<i32> = ObjectCache::new(4);
        cache.remove(99); // must not panic
    }

    #[test]
    fn size_returns_configured_capacity() {
        let cache: ObjectCache<i32> = ObjectCache::new(8);
        assert_eq!(cache.size(), 8);
    }

    #[test]
    fn set_hard_cache_size_updates_capacity() {
        let mut cache: ObjectCache<i32> = ObjectCache::new(4);
        cache.set_hard_cache_size(2);
        assert_eq!(cache.size(), 2);
    }

    #[test]
    fn set_hard_cache_size_evicts_newest_entries() {
        let mut cache = ObjectCache::new(3);
        let a = Arc::new(1i32);
        let b = Arc::new(2i32);
        let c = Arc::new(3i32);
        cache.put(1, a.clone());
        cache.put(2, b.clone());
        cache.put(3, c.clone());
        // hard_cache = [a, b, c] (front=oldest)
        cache.set_hard_cache_size(1);
        // pop_back twice → removes c then b → hard_cache = [a]
        drop(b);
        drop(c);
        // a is still held by hard cache
        assert!(cache.get(1).is_some());
    }

    #[test]
    fn compute_if_absent_returns_existing_without_calling_function() {
        let mut cache = ObjectCache::new(4);
        let val = Arc::new(10i32);
        cache.put(1, val.clone());
        let mut called = false;
        let result = cache.compute_if_absent(1, |_| {
            called = true;
            None
        });
        assert_eq!(*result.unwrap(), 10);
        assert!(!called);
    }

    #[test]
    fn compute_if_absent_inserts_and_returns_new_value() {
        let mut cache: ObjectCache<i32> = ObjectCache::new(4);
        let result = cache.compute_if_absent(5, |_| Some(Arc::new(99i32)));
        assert_eq!(*result.unwrap(), 99);
        assert_eq!(*cache.get(5).unwrap(), 99);
    }

    #[test]
    fn compute_if_absent_returns_none_when_function_returns_none() {
        let mut cache: ObjectCache<i32> = ObjectCache::new(4);
        let result = cache.compute_if_absent(5, |_| None);
        assert!(result.is_none());
        assert!(cache.get(5).is_none());
    }

    #[test]
    fn process_queue_removes_dead_entries_on_contains() {
        let mut cache = ObjectCache::new(1);
        let a = Arc::new(100i32);
        let b = Arc::new(200i32);
        cache.put(1, a.clone());
        cache.put(2, b.clone()); // evicts a from hard cache
        drop(a);
        // contains triggers process_queue, which removes the dead entry for key 1
        assert!(!cache.contains(1));
        assert!(cache.contains(2));
    }

    #[test]
    fn zero_hard_cache_size_still_allows_weak_lookup_while_arc_held() {
        let mut cache = ObjectCache::new(0);
        let val = Arc::new(55i32);
        cache.put(1, val.clone());
        // hard cache is empty (evicted immediately), but caller still holds val
        assert!(cache.get(1).is_some());
        drop(val);
        // now dead
        assert!(cache.get(1).is_none());
    }
}

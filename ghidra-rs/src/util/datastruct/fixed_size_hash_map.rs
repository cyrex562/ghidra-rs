/// An LRU map that discards the least-recently-used entry once its size exceeds a fixed
/// maximum.
///
/// Port of `ghidra.util.datastruct.FixedSizeHashMap`, cut to a trait to break a dependency
/// cycle at this node in the port graph. The original class extends Java's `LinkedHashMap` in
/// access-order mode and overrides `removeEldestEntry` to evict once `size() > maxSize`; that
/// eviction bookkeeping (and how recency order is tracked) is therefore an implementation
/// detail behind this trait rather than something the trait itself prescribes.
///
/// If you would like an LRU map based on access-order without automatic eviction, see `LRUMap`
/// (not yet ported).
pub trait FixedSizeHashMap<K, V> {
    /// Returns the maximum number of entries this map retains before evicting the
    /// least-recently-used entry.
    fn max_size(&self) -> usize;

    /// Returns the number of entries currently stored.
    fn len(&self) -> usize;

    /// Returns `true` if this map holds no entries.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a reference to the value for `key`, marking it as most-recently-used, or
    /// `None` if absent.
    fn get(&mut self, key: &K) -> Option<&V>;

    /// Returns `true` if `key` is present, without affecting recency order.
    fn contains_key(&self, key: &K) -> bool;

    /// Inserts `value` for `key`, returning the previous value if one was present. If the
    /// map exceeds `max_size` as a result, the least-recently-used entry is evicted.
    fn put(&mut self, key: K, value: V) -> Option<V>;

    /// Removes and returns the value for `key`, if present.
    fn remove(&mut self, key: &K) -> Option<V>;

    /// Removes every entry.
    fn clear(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Trivial mock proving `FixedSizeHashMap` is object-safe and usable behind
    /// `Box<dyn FixedSizeHashMap<K, V>>`.
    struct MockFixedSizeHashMap {
        max_size: usize,
        order: Vec<i32>,
        store: HashMap<i32, String>,
    }

    impl MockFixedSizeHashMap {
        fn new(max_size: usize) -> Self {
            Self {
                max_size,
                order: Vec::new(),
                store: HashMap::new(),
            }
        }

        fn touch(&mut self, key: &i32) {
            self.order.retain(|k| k != key);
            self.order.push(*key);
        }
    }

    impl FixedSizeHashMap<i32, String> for MockFixedSizeHashMap {
        fn max_size(&self) -> usize {
            self.max_size
        }

        fn len(&self) -> usize {
            self.store.len()
        }

        fn get(&mut self, key: &i32) -> Option<&String> {
            if self.store.contains_key(key) {
                self.touch(key);
            }
            self.store.get(key)
        }

        fn contains_key(&self, key: &i32) -> bool {
            self.store.contains_key(key)
        }

        fn put(&mut self, key: i32, value: String) -> Option<String> {
            let previous = self.store.insert(key, value);
            self.touch(&key);
            if self.store.len() > self.max_size {
                let oldest = self.order.remove(0);
                self.store.remove(&oldest);
            }
            previous
        }

        fn remove(&mut self, key: &i32) -> Option<String> {
            self.order.retain(|k| k != key);
            self.store.remove(key)
        }

        fn clear(&mut self) {
            self.order.clear();
            self.store.clear();
        }
    }

    #[test]
    fn put_get_evict_behind_trait_object() {
        let mut map: Box<dyn FixedSizeHashMap<i32, String>> =
            Box::new(MockFixedSizeHashMap::new(2));

        assert!(map.is_empty());
        assert_eq!(map.max_size(), 2);

        assert_eq!(map.put(1, "one".to_string()), None);
        assert_eq!(map.put(2, "two".to_string()), None);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&1));

        // Touch 1 so it becomes most-recently-used, then insert a third entry: 2 (now
        // least-recently-used) should be evicted.
        assert_eq!(map.get(&1), Some(&"one".to_string()));
        assert_eq!(map.put(3, "three".to_string()), None);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&1));
        assert!(!map.contains_key(&2));
        assert!(map.contains_key(&3));

        assert_eq!(map.remove(&1), Some("one".to_string()));
        assert_eq!(map.len(), 1);

        map.clear();
        assert!(map.is_empty());
    }
}

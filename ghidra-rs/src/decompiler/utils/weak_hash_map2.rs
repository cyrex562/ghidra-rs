use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::rc::{Rc, Weak};

/// [`Weak<V>`] wrapper that compares and hashes by pointer identity.
///
/// Mirrors the private `WeakValue` inner class from the Java source: two
/// instances are equal iff they point to the same [`Rc`] allocation, even
/// after the strong count drops to zero.
struct WeakByPtr<V>(Weak<V>);

impl<V> Hash for WeakByPtr<V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.0.as_ptr() as usize).hash(state);
    }
}

impl<V> PartialEq for WeakByPtr<V> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}

impl<V> Eq for WeakByPtr<V> {}

/// A hashtable-based map with weak values and bidirectional key↔value lookup.
///
/// Stores [`Weak`] references to values; on each mutation dead entries (whose
/// owning [`Rc`] has been dropped) are pruned from both the forward and
/// reverse maps.  [`reverse_get`](WeakHashMap2::reverse_get) provides `O(1)`
/// lookup of the key associated with a given value.
///
/// Models `ghidra.pcodeCPort.utils.WeakHashMap2`.
pub struct WeakHashMap2<K, V> {
    hash: HashMap<K, Weak<V>>,
    reverse_hash: HashMap<WeakByPtr<V>, K>,
}

impl<K: Hash + Eq + Clone, V> WeakHashMap2<K, V> {
    /// Creates an empty map.
    pub fn new() -> Self {
        WeakHashMap2 {
            hash: HashMap::new(),
            reverse_hash: HashMap::new(),
        }
    }

    /// Creates an empty map pre-allocated for `capacity` entries.
    pub fn with_capacity(capacity: usize) -> Self {
        WeakHashMap2 {
            hash: HashMap::with_capacity(capacity),
            reverse_hash: HashMap::with_capacity(capacity),
        }
    }

    /// Removes all entries whose values have been dropped.
    fn process_queue(&mut self) {
        self.reverse_hash.retain(|weak, _| weak.0.upgrade().is_some());
        self.hash.retain(|_, w| w.upgrade().is_some());
    }

    /// Returns `true` if a mapping for `key` is present (value may be dropped).
    pub fn contains_key(&self, key: &K) -> bool {
        self.hash.contains_key(key)
    }

    /// Returns the value for `key`, or `None` if absent or already dropped.
    pub fn get(&self, key: &K) -> Option<Rc<V>> {
        self.hash.get(key).and_then(|w| w.upgrade())
    }

    /// Inserts `key → value`; returns the previous value if one existed and
    /// was still live.
    pub fn put(&mut self, key: K, value: Rc<V>) -> Option<Rc<V>> {
        self.process_queue();
        let old_rc = if let Some(old_weak) = self.hash.get(&key) {
            let ptr = WeakByPtr(old_weak.clone());
            let old_rc = old_weak.upgrade();
            self.reverse_hash.remove(&ptr);
            old_rc
        } else {
            None
        };
        let new_weak = Rc::downgrade(&value);
        self.reverse_hash
            .insert(WeakByPtr(new_weak.clone()), key.clone());
        self.hash.insert(key, new_weak);
        old_rc
    }

    /// Returns the key whose value is the same [`Rc`] allocation as `value`.
    pub fn reverse_get(&self, value: &Rc<V>) -> Option<&K> {
        self.reverse_hash
            .get(&WeakByPtr(Rc::downgrade(value)))
    }

    /// Removes the entry for `key`; returns the old value if it was still live.
    pub fn remove(&mut self, key: &K) -> Option<Rc<V>> {
        self.process_queue();
        if let Some(weak) = self.hash.remove(key) {
            let old_rc = weak.upgrade();
            self.reverse_hash.remove(&WeakByPtr(weak));
            old_rc
        } else {
            None
        }
    }

    /// Removes all entries.
    pub fn clear(&mut self) {
        self.process_queue();
        self.hash.clear();
        self.reverse_hash.clear();
    }

    /// Returns the count of entries whose values are still live.
    pub fn len(&self) -> usize {
        self.hash.values().filter(|w| w.upgrade().is_some()).count()
    }

    /// Returns `true` when there are no live entries.
    pub fn is_empty(&self) -> bool {
        !self.hash.values().any(|w| w.upgrade().is_some())
    }

    /// Iterates over `(key, Rc<value>)` pairs for all live entries.
    pub fn iter(&self) -> impl Iterator<Item = (&K, Rc<V>)> {
        self.hash
            .iter()
            .filter_map(|(k, w)| w.upgrade().map(|v| (k, v)))
    }
}

impl<K: Hash + Eq + Clone, V> Default for WeakHashMap2<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let m: WeakHashMap2<String, i32> = WeakHashMap2::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn default_is_empty() {
        let m: WeakHashMap2<String, i32> = WeakHashMap2::default();
        assert!(m.is_empty());
    }

    #[test]
    fn put_and_get() {
        let mut m = WeakHashMap2::new();
        let v = Rc::new(42i32);
        m.put("key".to_string(), Rc::clone(&v));
        assert_eq!(*m.get(&"key".to_string()).unwrap(), 42);
    }

    #[test]
    fn get_missing_key_returns_none() {
        let m: WeakHashMap2<String, i32> = WeakHashMap2::new();
        assert!(m.get(&"missing".to_string()).is_none());
    }

    #[test]
    fn put_returns_old_value() {
        let mut m = WeakHashMap2::new();
        let v1 = Rc::new(1i32);
        let v2 = Rc::new(2i32);
        m.put("key".to_string(), Rc::clone(&v1));
        let old = m.put("key".to_string(), Rc::clone(&v2));
        assert_eq!(*old.unwrap(), 1);
        assert_eq!(*m.get(&"key".to_string()).unwrap(), 2);
    }

    #[test]
    fn get_after_value_dropped_returns_none() {
        let mut m = WeakHashMap2::new();
        {
            let v = Rc::new(99i32);
            m.put("key".to_string(), Rc::clone(&v));
            assert!(m.get(&"key".to_string()).is_some());
        }
        assert!(m.get(&"key".to_string()).is_none());
    }

    #[test]
    fn contains_key() {
        let mut m = WeakHashMap2::new();
        let v = Rc::new(7i32);
        m.put("x".to_string(), Rc::clone(&v));
        assert!(m.contains_key(&"x".to_string()));
        assert!(!m.contains_key(&"y".to_string()));
    }

    #[test]
    fn reverse_get_finds_key_by_value() {
        let mut m = WeakHashMap2::new();
        let v = Rc::new(100i32);
        m.put("mykey".to_string(), Rc::clone(&v));
        assert_eq!(m.reverse_get(&v).unwrap(), "mykey");
    }

    #[test]
    fn reverse_get_unknown_value_returns_none() {
        let m: WeakHashMap2<String, i32> = WeakHashMap2::new();
        let v = Rc::new(1i32);
        assert!(m.reverse_get(&v).is_none());
    }

    #[test]
    fn remove_returns_old_value() {
        let mut m = WeakHashMap2::new();
        let v = Rc::new(5i32);
        m.put("k".to_string(), Rc::clone(&v));
        let removed = m.remove(&"k".to_string());
        assert_eq!(*removed.unwrap(), 5);
        assert!(m.get(&"k".to_string()).is_none());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn remove_missing_key_returns_none() {
        let mut m: WeakHashMap2<String, i32> = WeakHashMap2::new();
        assert!(m.remove(&"missing".to_string()).is_none());
    }

    #[test]
    fn clear_empties_the_map() {
        let mut m = WeakHashMap2::new();
        let v1 = Rc::new(1i32);
        let v2 = Rc::new(2i32);
        m.put("a".to_string(), Rc::clone(&v1));
        m.put("b".to_string(), Rc::clone(&v2));
        m.clear();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn len_counts_live_entries_only() {
        let mut m = WeakHashMap2::new();
        let v1 = Rc::new(1i32);
        {
            let v2 = Rc::new(2i32);
            m.put("a".to_string(), Rc::clone(&v1));
            m.put("b".to_string(), Rc::clone(&v2));
            assert_eq!(m.len(), 2);
        }
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn process_queue_prunes_dead_entries_on_put() {
        let mut m = WeakHashMap2::new();
        {
            let v = Rc::new(1i32);
            m.put("dead".to_string(), Rc::clone(&v));
        }
        let v2 = Rc::new(2i32);
        m.put("live".to_string(), Rc::clone(&v2));
        assert!(!m.contains_key(&"dead".to_string()));
        assert!(m.contains_key(&"live".to_string()));
    }

    #[test]
    fn iter_yields_only_live_entries() {
        let mut m = WeakHashMap2::new();
        let v1 = Rc::new(10i32);
        {
            let v2 = Rc::new(20i32);
            m.put("a".to_string(), Rc::clone(&v1));
            m.put("b".to_string(), Rc::clone(&v2));
        }
        let entries: Vec<_> = m.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(*entries[0].1, 10);
    }

    #[test]
    fn with_capacity_works() {
        let mut m: WeakHashMap2<u32, u32> = WeakHashMap2::with_capacity(16);
        let v = Rc::new(1u32);
        m.put(1u32, Rc::clone(&v));
        assert_eq!(*m.get(&1u32).unwrap(), 1);
    }

    #[test]
    fn put_updates_reverse_map_on_overwrite() {
        let mut m = WeakHashMap2::new();
        let v1 = Rc::new(1i32);
        let v2 = Rc::new(2i32);
        m.put("key".to_string(), Rc::clone(&v1));
        m.put("key".to_string(), Rc::clone(&v2));
        assert!(m.reverse_get(&v1).is_none());
        assert_eq!(m.reverse_get(&v2).unwrap(), "key");
    }
}

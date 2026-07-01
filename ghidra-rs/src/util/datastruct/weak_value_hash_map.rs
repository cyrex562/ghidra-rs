use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Weak;

use super::abstract_weak_value_map::AbstractWeakValueMap;

/// Hash map with weakly-held values.
///
/// Rust equivalent of Java's `WeakValueHashMap<K, V>`. Values are stored
/// as [`Weak`] references and cleaned up lazily when accessed.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// # use ghidra_rs::util::WeakValueHashMap;
/// let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
/// let value = Arc::new(42);
/// map.put("key".to_string(), value.clone());
/// assert_eq!(*map.get(&"key".to_string()).unwrap(), 42);
/// ```
pub struct WeakValueHashMap<K, V> {
    ref_map: HashMap<K, Weak<V>>,
}

impl<K, V> WeakValueHashMap<K, V>
where
    K: Eq + Hash + Clone,
{
    /// Creates an empty weak-value hash map.
    pub fn new() -> Self {
        Self {
            ref_map: HashMap::new(),
        }
    }

    /// Creates an empty weak-value hash map with the specified initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ref_map: HashMap::with_capacity(capacity),
        }
    }
}

impl<K, V> Default for WeakValueHashMap<K, V>
where
    K: Eq + Hash + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> AbstractWeakValueMap<K, V> for WeakValueHashMap<K, V>
where
    K: Eq + Hash + Clone,
{
    type Store = HashMap<K, Weak<V>>;

    fn ref_map(&self) -> &Self::Store {
        &self.ref_map
    }

    fn ref_map_mut(&mut self) -> &mut Self::Store {
        &mut self.ref_map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn new_is_empty() {
        let map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        assert_eq!(map.ref_map.len(), 0);
    }

    #[test]
    fn with_capacity_reserves_space() {
        let map: WeakValueHashMap<String, i32> = WeakValueHashMap::with_capacity(10);
        assert!(map.ref_map.capacity() >= 10);
    }

    #[test]
    fn put_and_get() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let value = Arc::new(42);
        map.put("key".to_string(), value.clone());
        let retrieved = map.get(&"key".to_string()).unwrap();
        assert_eq!(*retrieved, 42);
    }

    #[test]
    fn put_returns_previous_value() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let first = Arc::new(10);
        let second = Arc::new(20);
        assert!(map.put("k".to_string(), first.clone()).is_none());
        let old = map.put("k".to_string(), second.clone()).unwrap();
        assert_eq!(*old, 10);
    }

    #[test]
    fn get_missing_returns_none() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        assert!(map.get(&"missing".to_string()).is_none());
    }

    #[test]
    fn get_dropped_value_returns_none() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let value = Arc::new(99);
        map.put("k".to_string(), value.clone());
        drop(value);
        assert!(map.get(&"k".to_string()).is_none());
    }

    #[test]
    fn size_reflects_live_entries() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        assert_eq!(map.size(), 0);
        let v1 = Arc::new(1);
        let v2 = Arc::new(2);
        map.put("a".to_string(), v1.clone());
        assert_eq!(map.size(), 1);
        map.put("b".to_string(), v2.clone());
        assert_eq!(map.size(), 2);
        drop(v1);
        assert_eq!(map.size(), 1);
        drop(v2);
        assert_eq!(map.size(), 0);
    }

    #[test]
    fn is_empty() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        assert!(map.is_empty());
        let v = Arc::new(0);
        map.put("k".to_string(), v.clone());
        assert!(!map.is_empty());
        drop(v);
        assert!(map.is_empty());
    }

    #[test]
    fn contains_key() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let v = Arc::new(7);
        map.put("k".to_string(), v.clone());
        assert!(map.contains_key(&"k".to_string()));
        drop(v);
        assert!(!map.contains_key(&"k".to_string()));
    }

    #[test]
    fn contains_value() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let v = Arc::new(5);
        map.put("k".to_string(), v.clone());
        assert!(map.contains_value(&5));
        assert!(!map.contains_value(&9));
        drop(v);
    }

    #[test]
    fn remove() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let v = Arc::new(3);
        map.put("k".to_string(), v.clone());
        let removed = map.remove(&"k".to_string()).unwrap();
        assert_eq!(*removed, 3);
        assert!(map.get(&"k".to_string()).is_none());
    }

    #[test]
    fn remove_missing_returns_none() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        assert!(map.remove(&"missing".to_string()).is_none());
    }

    #[test]
    fn clear() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let v = Arc::new(1);
        map.put("k".to_string(), v.clone());
        map.clear();
        assert!(map.get(&"k".to_string()).is_none());
        assert_eq!(map.size(), 0);
    }

    #[test]
    fn values() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let a = Arc::new(10);
        let b = Arc::new(20);
        map.put("a".to_string(), a.clone());
        map.put("b".to_string(), b.clone());
        drop(a);
        let vals = map.values();
        assert_eq!(vals.len(), 1);
        assert_eq!(*vals[0], 20);
    }

    #[test]
    fn key_set() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let a = Arc::new(1);
        let b = Arc::new(2);
        map.put("a".to_string(), a.clone());
        map.put("b".to_string(), b.clone());
        drop(b);
        let keys = map.key_set();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&"a".to_string()));
    }

    #[test]
    fn entry_set() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let v = Arc::new(42);
        map.put("k".to_string(), v.clone());
        let entries = map.entry_set();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "k");
        assert_eq!(*entries[0].1, 42);
    }

    #[test]
    fn put_all() {
        let mut map: WeakValueHashMap<String, i32> = WeakValueHashMap::new();
        let a = Arc::new(1);
        let b = Arc::new(2);
        let pairs = vec![("a".to_string(), a.clone()), ("b".to_string(), b.clone())];
        map.put_all(pairs);
        assert_eq!(*map.get(&"a".to_string()).unwrap(), 1);
        assert_eq!(*map.get(&"b".to_string()).unwrap(), 2);
    }

    #[test]
    fn default() {
        let map: WeakValueHashMap<String, i32> = WeakValueHashMap::default();
        assert_eq!(map.ref_map.len(), 0);
    }
}

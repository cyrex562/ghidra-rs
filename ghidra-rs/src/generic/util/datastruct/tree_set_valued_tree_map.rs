use std::collections::{BTreeMap, BTreeSet};

/// A multi-valued map backed by a `BTreeMap` of `BTreeSet`s.
///
/// Each key maps to a sorted, deduplicated set of values. Mirrors
/// `ghidra.generic.util.datastruct.TreeSetValuedTreeMap`, which extends Apache
/// Commons `AbstractSetValuedMap` using a `TreeMap` as the outer container and
/// `TreeSet` as each inner collection.
///
/// Iteration order over keys and over values within a key is ascending sort order.
pub struct TreeSetValuedTreeMap<K: Ord, V: Ord> {
    map: BTreeMap<K, BTreeSet<V>>,
}

impl<K: Ord, V: Ord> TreeSetValuedTreeMap<K, V> {
    /// Creates a new, empty `TreeSetValuedTreeMap`.
    pub fn new() -> Self {
        Self { map: BTreeMap::new() }
    }

    /// Inserts `value` into the set of values associated with `key`.
    ///
    /// Returns `true` if the value was not already present for that key.
    pub fn put(&mut self, key: K, value: V) -> bool {
        self.map.entry(key).or_default().insert(value)
    }

    /// Returns a reference to the set of values for `key`, or `None` if the key
    /// has no associated values.
    pub fn get(&self, key: &K) -> Option<&BTreeSet<V>> {
        self.map.get(key).filter(|s| !s.is_empty())
    }

    /// Removes all values associated with `key` and returns them.
    ///
    /// Returns `None` if the key was not present.
    pub fn remove_key(&mut self, key: &K) -> Option<BTreeSet<V>> {
        self.map.remove(key)
    }

    /// Removes a single `value` from the set associated with `key`.
    ///
    /// Drops the key entirely if its set becomes empty. Returns `true` if the
    /// value was present and was removed.
    pub fn remove_value(&mut self, key: &K, value: &V) -> bool {
        let removed = if let Some(set) = self.map.get_mut(key) {
            set.remove(value)
        } else {
            return false;
        };
        if removed {
            if self.map.get(key).map_or(false, |s| s.is_empty()) {
                self.map.remove(key);
            }
        }
        removed
    }

    /// Returns `true` if the map contains at least one value for `key`.
    pub fn contains_key(&self, key: &K) -> bool {
        self.map.get(key).map_or(false, |s| !s.is_empty())
    }

    /// Returns `true` if the map contains the specific `(key, value)` pair.
    pub fn contains_mapping(&self, key: &K, value: &V) -> bool {
        self.map.get(key).map_or(false, |s| s.contains(value))
    }

    /// Returns the total number of key-value pairs across all sets.
    pub fn size(&self) -> usize {
        self.map.values().map(|s| s.len()).sum()
    }

    /// Returns `true` if the map contains no key-value pairs.
    pub fn is_empty(&self) -> bool {
        self.map.values().all(|s| s.is_empty())
    }

    /// Returns an iterator over the keys in ascending order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    /// Returns a flat iterator over all values across all keys in key-then-value
    /// ascending order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.map.values().flat_map(|s| s.iter())
    }

    /// Returns an iterator over all `(key, value)` pairs in ascending key, then
    /// ascending value order.
    pub fn entries(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter().flat_map(|(k, vs)| vs.iter().map(move |v| (k, v)))
    }
}

impl<K: Ord, V: Ord> Default for TreeSetValuedTreeMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get() {
        let mut m: TreeSetValuedTreeMap<i32, &str> = TreeSetValuedTreeMap::new();
        assert!(m.put(1, "a"));
        assert!(m.put(1, "b"));
        let set = m.get(&1).unwrap();
        assert!(set.contains("a"));
        assert!(set.contains("b"));
    }

    #[test]
    fn put_duplicate_returns_false() {
        let mut m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::new();
        assert!(m.put(1, 10));
        assert!(!m.put(1, 10));
    }

    #[test]
    fn get_missing_key_returns_none() {
        let m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::new();
        assert!(m.get(&99).is_none());
    }

    #[test]
    fn contains_key() {
        let mut m: TreeSetValuedTreeMap<&str, i32> = TreeSetValuedTreeMap::new();
        m.put("x", 1);
        assert!(m.contains_key(&"x"));
        assert!(!m.contains_key(&"y"));
    }

    #[test]
    fn contains_mapping() {
        let mut m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::new();
        m.put(1, 10);
        assert!(m.contains_mapping(&1, &10));
        assert!(!m.contains_mapping(&1, &99));
        assert!(!m.contains_mapping(&2, &10));
    }

    #[test]
    fn remove_value_cleans_up_empty_key() {
        let mut m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::new();
        m.put(1, 10);
        assert!(m.remove_value(&1, &10));
        assert!(!m.contains_key(&1));
        assert!(m.get(&1).is_none());
    }

    #[test]
    fn remove_value_absent_returns_false() {
        let mut m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::new();
        assert!(!m.remove_value(&1, &10));
        m.put(1, 10);
        assert!(!m.remove_value(&1, &99));
    }

    #[test]
    fn remove_key() {
        let mut m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::new();
        m.put(1, 10);
        m.put(1, 20);
        let removed = m.remove_key(&1).unwrap();
        assert!(removed.contains(&10));
        assert!(removed.contains(&20));
        assert!(!m.contains_key(&1));
    }

    #[test]
    fn size_counts_all_pairs() {
        let mut m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::new();
        assert_eq!(m.size(), 0);
        m.put(1, 10);
        m.put(1, 20);
        m.put(2, 30);
        assert_eq!(m.size(), 3);
        m.put(1, 10); // duplicate
        assert_eq!(m.size(), 3);
    }

    #[test]
    fn is_empty() {
        let mut m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::new();
        assert!(m.is_empty());
        m.put(1, 1);
        assert!(!m.is_empty());
    }

    #[test]
    fn keys_in_ascending_order() {
        let mut m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::new();
        m.put(3, 0);
        m.put(1, 0);
        m.put(2, 0);
        let keys: Vec<&i32> = m.keys().collect();
        assert_eq!(keys, vec![&1, &2, &3]);
    }

    #[test]
    fn values_in_key_then_value_order() {
        let mut m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::new();
        m.put(2, 30);
        m.put(1, 20);
        m.put(1, 10);
        let vals: Vec<&i32> = m.values().collect();
        assert_eq!(vals, vec![&10, &20, &30]);
    }

    #[test]
    fn entries_in_order() {
        let mut m: TreeSetValuedTreeMap<i32, &str> = TreeSetValuedTreeMap::new();
        m.put(1, "b");
        m.put(1, "a");
        m.put(2, "c");
        let entries: Vec<(&i32, &&str)> = m.entries().collect();
        assert_eq!(entries, vec![(&1, &"a"), (&1, &"b"), (&2, &"c")]);
    }

    #[test]
    fn default_is_empty() {
        let m: TreeSetValuedTreeMap<i32, i32> = TreeSetValuedTreeMap::default();
        assert!(m.is_empty());
    }
}

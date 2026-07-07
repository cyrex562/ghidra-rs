use std::collections::BTreeMap;
use std::hash::Hash;
use std::sync::Weak;

use super::abstract_weak_value_map::AbstractWeakValueMap;
use super::abstract_weak_value_navigable_map::AbstractWeakValueNavigableMap;

/// Ordered map with weakly-held values backed by a `BTreeMap`.
///
/// Rust equivalent of Java's `WeakValueTreeMap<K, V>`. Values are stored
/// as [`Weak`] references and cleaned up lazily when accessed. Entries are
/// kept in key order as defined by [`Ord`].
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// # use ghidra_rs::util::WeakValueTreeMap;
/// let mut map: WeakValueTreeMap<i32, String> = WeakValueTreeMap::new();
/// let value = Arc::new("hello".to_string());
/// map.put(1, value.clone());
/// assert_eq!(*map.get(&1).unwrap(), "hello");
/// ```
pub struct WeakValueTreeMap<K, V> {
    ref_map: BTreeMap<K, Weak<V>>,
}

impl<K, V> WeakValueTreeMap<K, V>
where
    K: Ord + Clone,
{
    /// Creates an empty weak-value tree map.
    pub fn new() -> Self {
        Self {
            ref_map: BTreeMap::new(),
        }
    }
}

impl<K, V> Default for WeakValueTreeMap<K, V>
where
    K: Ord + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> AbstractWeakValueMap<K, V> for WeakValueTreeMap<K, V>
where
    K: Ord + Eq + Hash + Clone,
{
    type Store = BTreeMap<K, Weak<V>>;

    fn ref_map(&self) -> &Self::Store {
        &self.ref_map
    }

    fn ref_map_mut(&mut self) -> &mut Self::Store {
        &mut self.ref_map
    }
}

impl<K, V> AbstractWeakValueNavigableMap<K, V> for WeakValueTreeMap<K, V>
where
    K: Ord + Eq + Hash + Clone,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn new_is_empty() {
        let mut map: WeakValueTreeMap<i32, String> = WeakValueTreeMap::new();
        assert!(map.is_empty());
        assert_eq!(map.size(), 0);
    }

    #[test]
    fn put_and_get() {
        let mut map: WeakValueTreeMap<i32, String> = WeakValueTreeMap::new();
        let value = Arc::new("test".to_string());
        map.put(1, value.clone());
        let retrieved = map.get(&1).unwrap();
        assert_eq!(*retrieved, "test");
    }

    #[test]
    fn entries_ordered_by_key() {
        let mut map: WeakValueTreeMap<i32, i32> = WeakValueTreeMap::new();
        let vals: Vec<Arc<i32>> = (0..5).map(Arc::new).collect();
        for i in [3, 1, 4, 2, 0] {
            map.put(i as i32, vals[i].clone());
        }
        let keys = map.navigable_key_set();
        assert_eq!(keys, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn first_and_last_key() {
        let mut map: WeakValueTreeMap<i32, i32> = WeakValueTreeMap::new();
        let a = Arc::new(10);
        let b = Arc::new(20);
        let c = Arc::new(30);
        map.put(2, a.clone());
        map.put(1, b.clone());
        map.put(3, c.clone());
        assert_eq!(map.first_key(), Some(1));
        assert_eq!(map.last_key(), Some(3));
    }

    #[test]
    fn ceiling_and_floor() {
        let mut map: WeakValueTreeMap<i32, i32> = WeakValueTreeMap::new();
        let a = Arc::new(100);
        let b = Arc::new(200);
        map.put(10, a.clone());
        map.put(20, b.clone());
        assert_eq!(map.ceiling_key(&15), Some(20));
        assert_eq!(map.floor_key(&15), Some(10));
    }

    #[test]
    fn sub_map() {
        let mut map: WeakValueTreeMap<i32, i32> = WeakValueTreeMap::new();
        let vals: Vec<Arc<i32>> = (0..5).map(Arc::new).collect();
        for (i, v) in vals.iter().enumerate() {
            map.put(i as i32, v.clone());
        }
        let sub = map.sorted_sub_map(&1, &3);
        let keys: Vec<i32> = sub.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec![1, 2]);
    }

    #[test]
    fn remove_from_ordered_map() {
        let mut map: WeakValueTreeMap<i32, i32> = WeakValueTreeMap::new();
        let a = Arc::new(1);
        let b = Arc::new(2);
        let c = Arc::new(3);
        map.put(1, a.clone());
        map.put(2, b.clone());
        map.put(3, c.clone());
        assert_eq!(*map.remove(&2).unwrap(), 2);
        assert_eq!(map.navigable_key_set(), vec![1, 3]);
    }

    #[test]
    fn weak_reference_cleanup() {
        let mut map: WeakValueTreeMap<i32, i32> = WeakValueTreeMap::new();
        let a = Arc::new(42);
        map.put(1, a.clone());
        assert_eq!(map.size(), 1);
        drop(a);
        assert_eq!(map.size(), 0);
        assert!(map.get(&1).is_none());
    }

    #[test]
    fn descending_order() {
        let mut map: WeakValueTreeMap<i32, i32> = WeakValueTreeMap::new();
        let vals: Vec<Arc<i32>> = (1..=3).map(Arc::new).collect();
        for (i, v) in vals.iter().enumerate() {
            map.put((i + 1) as i32, v.clone());
        }
        let desc = map.descending_key_set();
        assert_eq!(desc, vec![3, 2, 1]);
    }

    #[test]
    fn poll_first_and_last() {
        let mut map: WeakValueTreeMap<i32, i32> = WeakValueTreeMap::new();
        let a = Arc::new(10);
        let b = Arc::new(20);
        map.put(1, a.clone());
        map.put(2, b.clone());

        let first = map.poll_first_entry().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(*first.1, 10);

        let last = map.poll_last_entry().unwrap();
        assert_eq!(last.0, 2);
        assert_eq!(*last.1, 20);

        assert!(map.is_empty());
    }
}

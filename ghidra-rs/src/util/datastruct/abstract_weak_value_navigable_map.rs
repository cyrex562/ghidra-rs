use std::collections::BTreeMap;
use std::hash::Hash;
use std::ops::Bound;
use std::sync::{Arc, Weak};

use super::abstract_weak_value_map::{AbstractWeakValueMap, WeakRefStore};

/// Ordered operations required from the backing store of an
/// [`AbstractWeakValueNavigableMap`].
///
/// Implemented for [`BTreeMap`]; other ordered map types can add implementations
/// as needed.
pub trait NavigableWeakRefStore<K, V>: WeakRefStore<K, V>
where
    K: Ord,
{
    fn store_first_key_value(&self) -> Option<(&K, &Weak<V>)>;
    fn store_last_key_value(&self) -> Option<(&K, &Weak<V>)>;
    fn store_lower_key_value(&self, key: &K) -> Option<(&K, &Weak<V>)>;
    fn store_floor_key_value(&self, key: &K) -> Option<(&K, &Weak<V>)>;
    fn store_ceiling_key_value(&self, key: &K) -> Option<(&K, &Weak<V>)>;
    fn store_higher_key_value(&self, key: &K) -> Option<(&K, &Weak<V>)>;
    fn store_pop_first(&mut self) -> Option<(K, Weak<V>)>;
    fn store_pop_last(&mut self) -> Option<(K, Weak<V>)>;
    fn store_range_cloned(&self, lower: Bound<&K>, upper: Bound<&K>) -> Vec<(K, Weak<V>)>
    where
        K: Clone;
}

impl<K, V> WeakRefStore<K, V> for BTreeMap<K, Weak<V>>
where
    K: Ord,
{
    fn store_insert(&mut self, key: K, val: Weak<V>) -> Option<Weak<V>> {
        self.insert(key, val)
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

    fn store_retain<F>(&mut self, f: F)
    where
        F: FnMut(&K, &mut Weak<V>) -> bool,
    {
        self.retain(f);
    }

    fn store_for_each<F>(&self, mut f: F)
    where
        F: FnMut(&K, &Weak<V>),
    {
        for (k, v) in self.iter() {
            f(k, v);
        }
    }

    fn store_keys_cloned(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.keys().cloned().collect()
    }
}

impl<K, V> NavigableWeakRefStore<K, V> for BTreeMap<K, Weak<V>>
where
    K: Ord + Clone,
{
    fn store_first_key_value(&self) -> Option<(&K, &Weak<V>)> {
        self.iter().next()
    }

    fn store_last_key_value(&self) -> Option<(&K, &Weak<V>)> {
        self.iter().next_back()
    }

    fn store_lower_key_value(&self, key: &K) -> Option<(&K, &Weak<V>)> {
        self.range((Bound::Unbounded, Bound::Excluded(key)))
            .next_back()
    }

    fn store_floor_key_value(&self, key: &K) -> Option<(&K, &Weak<V>)> {
        self.range((Bound::Unbounded, Bound::Included(key)))
            .next_back()
    }

    fn store_ceiling_key_value(&self, key: &K) -> Option<(&K, &Weak<V>)> {
        self.range((Bound::Included(key), Bound::Unbounded)).next()
    }

    fn store_higher_key_value(&self, key: &K) -> Option<(&K, &Weak<V>)> {
        self.range((Bound::Excluded(key), Bound::Unbounded)).next()
    }

    fn store_pop_first(&mut self) -> Option<(K, Weak<V>)> {
        self.pop_first()
    }

    fn store_pop_last(&mut self) -> Option<(K, Weak<V>)> {
        self.pop_last()
    }

    fn store_range_cloned(&self, lower: Bound<&K>, upper: Bound<&K>) -> Vec<(K, Weak<V>)>
    where
        K: Clone,
    {
        self.range((lower, upper))
            .map(|(k, w)| (k.clone(), w.clone()))
            .collect()
    }
}

fn generate_entry<K: Clone, V>(entry: Option<(&K, &Weak<V>)>) -> Option<(K, Arc<V>)> {
    let (key, weak) = entry?;
    let value = weak.upgrade()?;
    Some((key.clone(), value))
}

/// Rust equivalent of Java's `AbstractWeakValueNavigableMap<K, V>`.
///
/// Extends [`AbstractWeakValueMap`] with ordered (navigable) operations over a store
/// keyed by [`Ord`], such as a [`BTreeMap`]. As with the base trait, entries whose
/// values have been dropped are purged lazily via [`process_queue`][AbstractWeakValueMap::process_queue].
///
/// # Deviations from Java
///
/// - `comparator()` is omitted: Rust's ordered maps are ordered by [`Ord`] at compile
///   time, so there is no runtime `Comparator` object to expose.
/// - The Java original's `subMap`/`headMap`/`tailMap`/`descendingMap`/`navigableKeySet`/
///   `descendingKeySet` return live views backed by the same underlying map. As with
///   [`AbstractWeakValueMap::key_set`] and [`AbstractWeakValueMap::values`], Rust's
///   ownership model makes such views impractical here, so these instead return owned
///   snapshots of the live entries at call time.
/// - Java's overloaded `subMap`/`headMap`/`tailMap` (inherited from `SortedMap`) become
///   distinctly named methods: [`sorted_sub_map`][Self::sorted_sub_map],
///   [`sorted_head_map`][Self::sorted_head_map], and [`sorted_tail_map`][Self::sorted_tail_map].
pub trait AbstractWeakValueNavigableMap<K, V>: AbstractWeakValueMap<K, V>
where
    K: Ord + Eq + Hash + Clone,
    Self::Store: NavigableWeakRefStore<K, V>,
{
    /// Returns the smallest key currently in the map.
    fn first_key(&mut self) -> Option<K> {
        self.process_queue();
        self.ref_map().store_first_key_value().map(|(k, _)| k.clone())
    }

    /// Returns the largest key currently in the map.
    fn last_key(&mut self) -> Option<K> {
        self.process_queue();
        self.ref_map().store_last_key_value().map(|(k, _)| k.clone())
    }

    /// Returns the entry for the greatest key strictly less than `key`, if any live entry exists.
    fn lower_entry(&mut self, key: &K) -> Option<(K, Arc<V>)> {
        self.process_queue();
        generate_entry(self.ref_map().store_lower_key_value(key))
    }

    /// Returns the greatest key strictly less than `key`.
    fn lower_key(&mut self, key: &K) -> Option<K> {
        self.process_queue();
        self.ref_map()
            .store_lower_key_value(key)
            .map(|(k, _)| k.clone())
    }

    /// Returns the entry for the greatest key less than or equal to `key`, if any live entry exists.
    fn floor_entry(&mut self, key: &K) -> Option<(K, Arc<V>)> {
        self.process_queue();
        generate_entry(self.ref_map().store_floor_key_value(key))
    }

    /// Returns the greatest key less than or equal to `key`.
    fn floor_key(&mut self, key: &K) -> Option<K> {
        self.process_queue();
        self.ref_map()
            .store_floor_key_value(key)
            .map(|(k, _)| k.clone())
    }

    /// Returns the entry for the smallest key greater than or equal to `key`, if any live entry exists.
    fn ceiling_entry(&mut self, key: &K) -> Option<(K, Arc<V>)> {
        self.process_queue();
        generate_entry(self.ref_map().store_ceiling_key_value(key))
    }

    /// Returns the smallest key greater than or equal to `key`.
    fn ceiling_key(&mut self, key: &K) -> Option<K> {
        self.process_queue();
        self.ref_map()
            .store_ceiling_key_value(key)
            .map(|(k, _)| k.clone())
    }

    /// Returns the entry for the smallest key strictly greater than `key`, if any live entry exists.
    fn higher_entry(&mut self, key: &K) -> Option<(K, Arc<V>)> {
        self.process_queue();
        generate_entry(self.ref_map().store_higher_key_value(key))
    }

    /// Returns the smallest key strictly greater than `key`.
    fn higher_key(&mut self, key: &K) -> Option<K> {
        self.process_queue();
        self.ref_map()
            .store_higher_key_value(key)
            .map(|(k, _)| k.clone())
    }

    /// Returns the entry for the smallest key, if any live entry exists.
    fn first_entry(&mut self) -> Option<(K, Arc<V>)> {
        self.process_queue();
        generate_entry(self.ref_map().store_first_key_value())
    }

    /// Returns the entry for the largest key, if any live entry exists.
    fn last_entry(&mut self) -> Option<(K, Arc<V>)> {
        self.process_queue();
        generate_entry(self.ref_map().store_last_key_value())
    }

    /// Removes and returns the entry for the smallest key, if any live entry exists.
    fn poll_first_entry(&mut self) -> Option<(K, Arc<V>)> {
        self.process_queue();
        let (key, weak) = self.ref_map_mut().store_pop_first()?;
        let value = weak.upgrade()?;
        Some((key, value))
    }

    /// Removes and returns the entry for the largest key, if any live entry exists.
    fn poll_last_entry(&mut self) -> Option<(K, Arc<V>)> {
        self.process_queue();
        let (key, weak) = self.ref_map_mut().store_pop_last()?;
        let value = weak.upgrade()?;
        Some((key, value))
    }

    /// Returns a snapshot of all live entries in descending key order.
    fn descending_map(&mut self) -> Vec<(K, Arc<V>)> {
        self.process_queue();
        let mut entries: Vec<(K, Arc<V>)> = self
            .ref_map()
            .store_range_cloned(Bound::Unbounded, Bound::Unbounded)
            .into_iter()
            .filter_map(|(k, w)| w.upgrade().map(|v| (k, v)))
            .collect();
        entries.reverse();
        entries
    }

    /// Returns a snapshot of all keys in ascending order.
    fn navigable_key_set(&self) -> Vec<K> {
        self.ref_map().store_keys_cloned()
    }

    /// Returns a snapshot of all keys in descending order.
    fn descending_key_set(&self) -> Vec<K> {
        let mut keys = self.ref_map().store_keys_cloned();
        keys.reverse();
        keys
    }

    /// Returns a snapshot of the live entries with keys in `[fromKey, toKey]` (bounds
    /// inclusive per `from_inclusive`/`to_inclusive`), in ascending order.
    fn sub_map(
        &mut self,
        from_key: &K,
        from_inclusive: bool,
        to_key: &K,
        to_inclusive: bool,
    ) -> Vec<(K, Arc<V>)> {
        self.process_queue();
        let lower = if from_inclusive {
            Bound::Included(from_key)
        } else {
            Bound::Excluded(from_key)
        };
        let upper = if to_inclusive {
            Bound::Included(to_key)
        } else {
            Bound::Excluded(to_key)
        };
        self.ref_map()
            .store_range_cloned(lower, upper)
            .into_iter()
            .filter_map(|(k, w)| w.upgrade().map(|v| (k, v)))
            .collect()
    }

    /// Equivalent of Java's `SortedMap.subMap(fromKey, toKey)`: `[fromKey, toKey)`.
    fn sorted_sub_map(&mut self, from_key: &K, to_key: &K) -> Vec<(K, Arc<V>)> {
        self.sub_map(from_key, true, to_key, false)
    }

    /// Returns a snapshot of the live entries with keys less than (or equal to, if
    /// `inclusive`) `to_key`, in ascending order.
    fn head_map(&mut self, to_key: &K, inclusive: bool) -> Vec<(K, Arc<V>)> {
        self.process_queue();
        let upper = if inclusive {
            Bound::Included(to_key)
        } else {
            Bound::Excluded(to_key)
        };
        self.ref_map()
            .store_range_cloned(Bound::Unbounded, upper)
            .into_iter()
            .filter_map(|(k, w)| w.upgrade().map(|v| (k, v)))
            .collect()
    }

    /// Equivalent of Java's `SortedMap.headMap(toKey)`: keys strictly less than `to_key`.
    fn sorted_head_map(&mut self, to_key: &K) -> Vec<(K, Arc<V>)> {
        self.head_map(to_key, false)
    }

    /// Returns a snapshot of the live entries with keys greater than (or equal to, if
    /// `inclusive`) `from_key`, in ascending order.
    fn tail_map(&mut self, from_key: &K, inclusive: bool) -> Vec<(K, Arc<V>)> {
        self.process_queue();
        let lower = if inclusive {
            Bound::Included(from_key)
        } else {
            Bound::Excluded(from_key)
        };
        self.ref_map()
            .store_range_cloned(lower, Bound::Unbounded)
            .into_iter()
            .filter_map(|(k, w)| w.upgrade().map(|v| (k, v)))
            .collect()
    }

    /// Equivalent of Java's `SortedMap.tailMap(fromKey)`: keys greater than or equal to `from_key`.
    fn sorted_tail_map(&mut self, from_key: &K) -> Vec<(K, Arc<V>)> {
        self.tail_map(from_key, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMap<K, V> {
        store: BTreeMap<K, Weak<V>>,
    }

    impl<K: Ord + Clone, V> TestMap<K, V> {
        fn new() -> Self {
            Self {
                store: BTreeMap::new(),
            }
        }
    }

    impl<K: Ord + Eq + Hash + Clone, V> AbstractWeakValueMap<K, V> for TestMap<K, V> {
        type Store = BTreeMap<K, Weak<V>>;

        fn ref_map(&self) -> &Self::Store {
            &self.store
        }

        fn ref_map_mut(&mut self) -> &mut Self::Store {
            &mut self.store
        }
    }

    impl<K: Ord + Eq + Hash + Clone, V> AbstractWeakValueNavigableMap<K, V> for TestMap<K, V> {}

    #[test]
    fn first_and_last_key() {
        let mut map: TestMap<i32, &str> = TestMap::new();
        let a = Arc::new("a");
        let b = Arc::new("b");
        let c = Arc::new("c");
        map.put(1, a.clone());
        map.put(2, b.clone());
        map.put(3, c.clone());
        assert_eq!(map.first_key(), Some(1));
        assert_eq!(map.last_key(), Some(3));
    }

    #[test]
    fn first_key_none_when_empty() {
        let mut map: TestMap<i32, &str> = TestMap::new();
        assert_eq!(map.first_key(), None);
        assert_eq!(map.last_key(), None);
    }

    #[test]
    fn lower_floor_ceiling_higher_entry() {
        let mut map: TestMap<i32, &str> = TestMap::new();
        let ten = Arc::new("ten");
        let twenty = Arc::new("twenty");
        map.put(10, ten.clone());
        map.put(20, twenty.clone());

        assert_eq!(map.lower_key(&20), Some(10));
        assert_eq!(map.lower_key(&10), None);

        assert_eq!(map.floor_key(&15), Some(10));
        assert_eq!(map.floor_key(&10), Some(10));

        assert_eq!(map.ceiling_key(&15), Some(20));
        assert_eq!(map.ceiling_key(&20), Some(20));

        assert_eq!(map.higher_key(&10), Some(20));
        assert_eq!(map.higher_key(&20), None);

        let entry = map.floor_entry(&15).unwrap();
        assert_eq!(entry.0, 10);
        assert_eq!(*entry.1, "ten");
    }

    #[test]
    fn first_and_last_entry() {
        let mut map: TestMap<i32, i32> = TestMap::new();
        let a = Arc::new(1);
        let b = Arc::new(2);
        map.put(1, a.clone());
        map.put(2, b.clone());
        assert_eq!(map.first_entry(), Some((1, a.clone())));
        assert_eq!(map.last_entry(), Some((2, b.clone())));
    }

    #[test]
    fn poll_first_and_last_entry_removes() {
        let mut map: TestMap<i32, i32> = TestMap::new();
        let a = Arc::new(1);
        let b = Arc::new(2);
        map.put(1, a.clone());
        map.put(2, b.clone());

        let first = map.poll_first_entry().unwrap();
        assert_eq!(first, (1, a));
        assert_eq!(map.size(), 1);

        let last = map.poll_last_entry().unwrap();
        assert_eq!(last, (2, b));
        assert_eq!(map.size(), 0);
        assert_eq!(map.poll_first_entry(), None);
    }

    #[test]
    fn stale_entry_skipped_by_navigable_lookups() {
        let mut map: TestMap<i32, i32> = TestMap::new();
        let a = Arc::new(1);
        map.put(1, a.clone());
        drop(a);
        assert_eq!(map.first_entry(), None);
        assert_eq!(map.floor_entry(&1), None);
        assert_eq!(map.size(), 0);
    }

    #[test]
    fn descending_map_reverses_order() {
        let mut map: TestMap<i32, i32> = TestMap::new();
        let a = Arc::new(1);
        let b = Arc::new(2);
        let c = Arc::new(3);
        map.put(1, a.clone());
        map.put(2, b.clone());
        map.put(3, c.clone());
        let desc = map.descending_map();
        assert_eq!(desc, vec![(3, c), (2, b), (1, a)]);
    }

    #[test]
    fn navigable_and_descending_key_set() {
        let mut map: TestMap<i32, i32> = TestMap::new();
        let a = Arc::new(1);
        let b = Arc::new(2);
        map.put(2, b.clone());
        map.put(1, a.clone());
        assert_eq!(map.navigable_key_set(), vec![1, 2]);
        assert_eq!(map.descending_key_set(), vec![2, 1]);
    }

    #[test]
    fn sub_map_respects_inclusivity() {
        let mut map: TestMap<i32, i32> = TestMap::new();
        let vals: Vec<Arc<i32>> = (0..5).map(Arc::new).collect();
        for (i, v) in vals.iter().enumerate() {
            map.put(i as i32, v.clone());
        }
        let inclusive = map.sub_map(&1, true, &3, true);
        assert_eq!(
            inclusive.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let exclusive = map.sub_map(&1, false, &3, false);
        assert_eq!(
            exclusive.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![2]
        );
        let sorted = map.sorted_sub_map(&1, &3);
        assert_eq!(
            sorted.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn head_and_tail_map() {
        let mut map: TestMap<i32, i32> = TestMap::new();
        let vals: Vec<Arc<i32>> = (0..5).map(Arc::new).collect();
        for (i, v) in vals.iter().enumerate() {
            map.put(i as i32, v.clone());
        }
        let head = map.head_map(&2, true);
        assert_eq!(
            head.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        let head_sorted = map.sorted_head_map(&2);
        assert_eq!(
            head_sorted.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![0, 1]
        );
        let tail = map.tail_map(&2, false);
        assert_eq!(
            tail.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![3, 4]
        );
        let tail_sorted = map.sorted_tail_map(&2);
        assert_eq!(
            tail_sorted.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }
}

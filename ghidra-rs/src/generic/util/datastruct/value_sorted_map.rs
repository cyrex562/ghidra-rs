use crate::generic::util::datastruct::sorted_list::SortedList;
use crate::util::ListIterator;

/// A minimal analogue of `java.util.List`, restricted to the subset of methods that
/// [`ValueSortedMap`]'s associated collection views need.
///
/// Mirrors the nested interface `ValueSortedMap.LesserList`. Hoisted to a top-level trait
/// since Rust traits cannot be nested inside other traits. Ghidra's own doc comment explains
/// the motivation: implementing this instead of `java.util.List` means newer JDKs cannot
/// impose new requirements on implementations; the Rust port keeps the same narrow surface.
pub trait LesserList<E> {
    fn is_empty(&self) -> bool;

    fn len(&self) -> usize;

    /// Returns the element at the given index.
    ///
    /// # Panics
    /// Panics if `i` is out of bounds, mirroring Java's `IndexOutOfBoundsException`.
    fn get(&self, i: usize) -> &E;

    /// Copies this list's elements into a new `Vec`.
    fn to_vec(&self) -> Vec<E>
    where
        E: Clone;

    fn list_iterator(&self, index: usize) -> Box<dyn ListIterator<E> + '_>
    where
        E: Clone;

    /// Returns the index of `o`, or `-1` if not found.
    fn index_of(&self, o: &E) -> i64
    where
        E: PartialEq;

    fn contains(&self, o: &E) -> bool
    where
        E: PartialEq;

    /// Gets and removes the first element, or `None` if empty.
    fn poll(&mut self) -> Option<E>;

    fn remove(&mut self, o: &E) -> bool
    where
        E: PartialEq;

    fn remove_all(&mut self, col: &[E]) -> bool
    where
        E: PartialEq,
    {
        let mut result = false;
        for e in col {
            result |= self.remove(e);
        }
        result
    }
}

/// Mirrors the nested interface `ValueSortedMap.ValueSortedMapEntryList`.
pub trait ValueSortedMapEntryList<K, V>: LesserList<(K, V)> {}

/// Mirrors the nested interface `ValueSortedMap.ValueSortedMapKeyList`.
pub trait ValueSortedMapKeyList<K>: LesserList<K> {}

/// A map that is sorted by value.
///
/// This is an extension of `Map` where entries are sorted by value, rather than by key. Such a
/// map may be useful as a priority queue where the cost of an entry may change over time. As
/// such, the collections returned by [`entry_set`](ValueSortedMap::entry_set),
/// [`key_set`](ValueSortedMap::key_set), and [`values`](ValueSortedMap::values) are all views
/// that stay live for as long as the borrow of the map that produced them. The order of the
/// entries is updated on any call to [`put`](ValueSortedMap::put). Additionally, if the values
/// are mutable objects whose order may change, there is an [`update`](ValueSortedMap::update)
/// method, which notifies the map that the given key may need to be repositioned.
pub trait ValueSortedMap<K, V> {
    /// Associates `value` with `key`, returning the previous value, if any.
    fn put(&mut self, key: K, value: V) -> Option<V>;

    fn get(&self, key: &K) -> Option<&V>;

    fn remove(&mut self, key: &K) -> Option<V>;

    fn entry_set(&self) -> Box<dyn ValueSortedMapEntryList<K, V> + '_>;

    /// Returns a key-value mapping associated with the greatest value strictly less than the
    /// given value, or `None` if there is no such value.
    fn lower_entry_by_value(&self, value: &V) -> Option<(&K, &V)>;

    /// Returns a key-value mapping associated with the greatest value less than or equal to the
    /// given value, or `None` if there is no such value.
    fn floor_entry_by_value(&self, value: &V) -> Option<(&K, &V)>;

    /// Returns a key-value mapping associated with the least value greater than or equal to the
    /// given value, or `None` if there is no such value.
    fn ceiling_entry_by_value(&self, value: &V) -> Option<(&K, &V)>;

    /// Returns a key-value mapping associated with the least value strictly greater than the
    /// given value, or `None` if there is no such value.
    fn higher_entry_by_value(&self, value: &V) -> Option<(&K, &V)>;

    /// Returns a view of the portion of this map whose values range from `from_value` to
    /// `to_value`. The returned map is an unmodifiable view.
    fn sub_map_by_value(
        &self,
        from_value: &V,
        from_inclusive: bool,
        to_value: &V,
        to_inclusive: bool,
    ) -> Box<dyn ValueSortedMap<K, V> + '_>;

    /// Returns a view of the portion of this map whose values are less than (or equal to, if
    /// `inclusive` is true) `to_value`. The returned map is an unmodifiable view.
    fn head_map_by_value(&self, to_value: &V, inclusive: bool) -> Box<dyn ValueSortedMap<K, V> + '_>;

    /// Returns a view of the portion of this map whose values are greater than (or equal to, if
    /// `inclusive` is true) `from_value`. The returned map is an unmodifiable view.
    fn tail_map_by_value(&self, from_value: &V, inclusive: bool) -> Box<dyn ValueSortedMap<K, V> + '_>;

    fn key_set(&self) -> Box<dyn ValueSortedMapKeyList<K> + '_>;

    /// Notifies the map of an external change to the cost of a key's associated value.
    ///
    /// This is meant to update the entry's position after a change in cost. The position may not
    /// necessarily change, however, if the cost did not change significantly.
    ///
    /// Returns `true` if the entry's position changed.
    fn update(&mut self, key: &K) -> bool;

    fn values(&self) -> Box<dyn SortedList<V> + '_>;

    fn is_empty(&self) -> bool;

    fn contains_key(&self, key: &K) -> bool;

    fn contains_value(&self, value: &V) -> bool;

    fn size(&self) -> usize;

    fn clear(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny `LesserList<i32>` backed by a `Vec`, just enough to prove `LesserList` is
    /// object-safe and its default method behaves correctly.
    struct VecLesserList {
        data: Vec<i32>,
    }

    impl LesserList<i32> for VecLesserList {
        fn is_empty(&self) -> bool {
            self.data.is_empty()
        }

        fn len(&self) -> usize {
            self.data.len()
        }

        fn get(&self, i: usize) -> &i32 {
            &self.data[i]
        }

        fn to_vec(&self) -> Vec<i32> {
            self.data.clone()
        }

        fn list_iterator(&self, index: usize) -> Box<dyn ListIterator<i32> + '_> {
            struct Iter<'a> {
                data: &'a [i32],
                cursor: usize,
            }
            impl<'a> ListIterator<i32> for Iter<'a> {
                fn has_next(&self) -> bool {
                    self.cursor < self.data.len()
                }
                fn next(&mut self) -> i32 {
                    let v = self.data[self.cursor];
                    self.cursor += 1;
                    v
                }
                fn has_previous(&self) -> bool {
                    self.cursor > 0
                }
                fn previous(&mut self) -> i32 {
                    self.cursor -= 1;
                    self.data[self.cursor]
                }
                fn next_index(&self) -> i64 {
                    self.cursor as i64
                }
                fn previous_index(&self) -> i64 {
                    self.cursor as i64 - 1
                }
                fn remove(&mut self) {}
                fn set(&mut self, _e: i32) {}
                fn add(&mut self, _e: i32) {}
            }
            Box::new(Iter { data: &self.data, cursor: index })
        }

        fn index_of(&self, o: &i32) -> i64 {
            self.data.iter().position(|x| x == o).map(|i| i as i64).unwrap_or(-1)
        }

        fn contains(&self, o: &i32) -> bool {
            self.data.contains(o)
        }

        fn poll(&mut self) -> Option<i32> {
            if self.data.is_empty() {
                None
            } else {
                Some(self.data.remove(0))
            }
        }

        fn remove(&mut self, o: &i32) -> bool {
            if let Some(pos) = self.data.iter().position(|x| x == o) {
                self.data.remove(pos);
                true
            } else {
                false
            }
        }
    }

    /// A simple `ValueSortedMap<&'static str, i32>` backed by a `Vec` of pairs, kept sorted by
    /// value on every `put`. Proves `ValueSortedMap` is object-safe and exercises real
    /// navigation/view behavior, not just trivial getters.
    #[derive(Default)]
    struct SimpleValueSortedMap {
        entries: Vec<(&'static str, i32)>,
    }

    impl SimpleValueSortedMap {
        fn resort(&mut self) {
            self.entries.sort_by_key(|(_, v)| *v);
        }
    }

    struct EntryList {
        entries: Vec<(&'static str, i32)>,
    }
    impl LesserList<(&'static str, i32)> for EntryList {
        fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }
        fn len(&self) -> usize {
            self.entries.len()
        }
        fn get(&self, i: usize) -> &(&'static str, i32) {
            &self.entries[i]
        }
        fn to_vec(&self) -> Vec<(&'static str, i32)> {
            self.entries.clone()
        }
        fn list_iterator(&self, _index: usize) -> Box<dyn ListIterator<(&'static str, i32)> + '_> {
            unimplemented!("not exercised by the smoke test")
        }
        fn index_of(&self, o: &(&'static str, i32)) -> i64 {
            self.entries.iter().position(|e| e == o).map(|i| i as i64).unwrap_or(-1)
        }
        fn contains(&self, o: &(&'static str, i32)) -> bool {
            self.entries.contains(o)
        }
        fn poll(&mut self) -> Option<(&'static str, i32)> {
            if self.entries.is_empty() {
                None
            } else {
                Some(self.entries.remove(0))
            }
        }
        fn remove(&mut self, o: &(&'static str, i32)) -> bool {
            if let Some(pos) = self.entries.iter().position(|e| e == o) {
                self.entries.remove(pos);
                true
            } else {
                false
            }
        }
    }
    impl ValueSortedMapEntryList<&'static str, i32> for EntryList {}

    struct KeyList {
        keys: Vec<&'static str>,
    }
    impl LesserList<&'static str> for KeyList {
        fn is_empty(&self) -> bool {
            self.keys.is_empty()
        }
        fn len(&self) -> usize {
            self.keys.len()
        }
        fn get(&self, i: usize) -> &&'static str {
            &self.keys[i]
        }
        fn to_vec(&self) -> Vec<&'static str> {
            self.keys.clone()
        }
        fn list_iterator(&self, _index: usize) -> Box<dyn ListIterator<&'static str> + '_> {
            unimplemented!("not exercised by the smoke test")
        }
        fn index_of(&self, o: &&'static str) -> i64 {
            self.keys.iter().position(|k| k == o).map(|i| i as i64).unwrap_or(-1)
        }
        fn contains(&self, o: &&'static str) -> bool {
            self.keys.contains(o)
        }
        fn poll(&mut self) -> Option<&'static str> {
            if self.keys.is_empty() {
                None
            } else {
                Some(self.keys.remove(0))
            }
        }
        fn remove(&mut self, o: &&'static str) -> bool {
            if let Some(pos) = self.keys.iter().position(|k| k == o) {
                self.keys.remove(pos);
                true
            } else {
                false
            }
        }
    }
    impl ValueSortedMapKeyList<&'static str> for KeyList {}

    struct ValuesList {
        values: Vec<i32>,
    }
    impl LesserList<i32> for ValuesList {
        fn is_empty(&self) -> bool {
            self.values.is_empty()
        }
        fn len(&self) -> usize {
            self.values.len()
        }
        fn get(&self, i: usize) -> &i32 {
            &self.values[i]
        }
        fn to_vec(&self) -> Vec<i32> {
            self.values.clone()
        }
        fn list_iterator(&self, _index: usize) -> Box<dyn ListIterator<i32> + '_> {
            unimplemented!("not exercised by the smoke test")
        }
        fn index_of(&self, o: &i32) -> i64 {
            self.values.iter().position(|v| v == o).map(|i| i as i64).unwrap_or(-1)
        }
        fn contains(&self, o: &i32) -> bool {
            self.values.contains(o)
        }
        fn poll(&mut self) -> Option<i32> {
            if self.values.is_empty() {
                None
            } else {
                Some(self.values.remove(0))
            }
        }
        fn remove(&mut self, o: &i32) -> bool {
            if let Some(pos) = self.values.iter().position(|v| v == o) {
                self.values.remove(pos);
                true
            } else {
                false
            }
        }
    }
    impl SortedList<i32> for ValuesList {
        fn lower_index(&self, element: &i32) -> i64 {
            self.values.iter().rposition(|v| v < element).map(|i| i as i64).unwrap_or(-1)
        }

        fn floor_index(&self, element: &i32) -> i64 {
            self.values.iter().rposition(|v| v <= element).map(|i| i as i64).unwrap_or(-1)
        }

        fn ceiling_index(&self, element: &i32) -> i64 {
            self.values.iter().position(|v| v >= element).map(|i| i as i64).unwrap_or(-1)
        }

        fn higher_index(&self, element: &i32) -> i64 {
            self.values.iter().position(|v| v > element).map(|i| i as i64).unwrap_or(-1)
        }
    }

    impl ValueSortedMap<&'static str, i32> for SimpleValueSortedMap {
        fn put(&mut self, key: &'static str, value: i32) -> Option<i32> {
            let old = self.remove(&key);
            self.entries.push((key, value));
            self.resort();
            old
        }

        fn get(&self, key: &&'static str) -> Option<&i32> {
            self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        }

        fn remove(&mut self, key: &&'static str) -> Option<i32> {
            if let Some(pos) = self.entries.iter().position(|(k, _)| k == key) {
                Some(self.entries.remove(pos).1)
            } else {
                None
            }
        }

        fn entry_set(&self) -> Box<dyn ValueSortedMapEntryList<&'static str, i32> + '_> {
            Box::new(EntryList { entries: self.entries.clone() })
        }

        fn lower_entry_by_value(&self, value: &i32) -> Option<(&&'static str, &i32)> {
            self.entries.iter().filter(|(_, v)| v < value).last().map(|(k, v)| (k, v))
        }

        fn floor_entry_by_value(&self, value: &i32) -> Option<(&&'static str, &i32)> {
            self.entries.iter().filter(|(_, v)| v <= value).last().map(|(k, v)| (k, v))
        }

        fn ceiling_entry_by_value(&self, value: &i32) -> Option<(&&'static str, &i32)> {
            self.entries.iter().find(|(_, v)| v >= value).map(|(k, v)| (k, v))
        }

        fn higher_entry_by_value(&self, value: &i32) -> Option<(&&'static str, &i32)> {
            self.entries.iter().find(|(_, v)| v > value).map(|(k, v)| (k, v))
        }

        fn sub_map_by_value(
            &self,
            from_value: &i32,
            from_inclusive: bool,
            to_value: &i32,
            to_inclusive: bool,
        ) -> Box<dyn ValueSortedMap<&'static str, i32> + '_> {
            let entries = self
                .entries
                .iter()
                .filter(|(_, v)| {
                    let above = if from_inclusive { v >= from_value } else { v > from_value };
                    let below = if to_inclusive { v <= to_value } else { v < to_value };
                    above && below
                })
                .cloned()
                .collect();
            Box::new(SimpleValueSortedMap { entries })
        }

        fn head_map_by_value(
            &self,
            to_value: &i32,
            inclusive: bool,
        ) -> Box<dyn ValueSortedMap<&'static str, i32> + '_> {
            let entries = self
                .entries
                .iter()
                .filter(|(_, v)| if inclusive { v <= to_value } else { v < to_value })
                .cloned()
                .collect();
            Box::new(SimpleValueSortedMap { entries })
        }

        fn tail_map_by_value(
            &self,
            from_value: &i32,
            inclusive: bool,
        ) -> Box<dyn ValueSortedMap<&'static str, i32> + '_> {
            let entries = self
                .entries
                .iter()
                .filter(|(_, v)| if inclusive { v >= from_value } else { v > from_value })
                .cloned()
                .collect();
            Box::new(SimpleValueSortedMap { entries })
        }

        fn key_set(&self) -> Box<dyn ValueSortedMapKeyList<&'static str> + '_> {
            Box::new(KeyList { keys: self.entries.iter().map(|(k, _)| *k).collect() })
        }

        fn update(&mut self, key: &&'static str) -> bool {
            if let Some(v) = self.get(key).copied() {
                self.remove(key);
                self.put(key, v);
                true
            } else {
                false
            }
        }

        fn values(&self) -> Box<dyn SortedList<i32> + '_> {
            Box::new(ValuesList { values: self.entries.iter().map(|(_, v)| *v).collect() })
        }

        fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }

        fn contains_key(&self, key: &&'static str) -> bool {
            self.entries.iter().any(|(k, _)| k == key)
        }

        fn contains_value(&self, value: &i32) -> bool {
            self.entries.iter().any(|(_, v)| v == value)
        }

        fn size(&self) -> usize {
            self.entries.len()
        }

        fn clear(&mut self) {
            self.entries.clear();
        }
    }

    fn build_map() -> SimpleValueSortedMap {
        let mut m = SimpleValueSortedMap::default();
        m.put("c", 30);
        m.put("a", 10);
        m.put("b", 20);
        m
    }

    #[test]
    fn put_keeps_entries_sorted_by_value() {
        let m = build_map();
        let keys: Vec<&str> = m.entries.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn get_and_remove() {
        let mut m = build_map();
        assert_eq!(m.get(&"b"), Some(&20));
        assert_eq!(m.remove(&"b"), Some(20));
        assert_eq!(m.get(&"b"), None);
        assert_eq!(m.size(), 2);
    }

    #[test]
    fn navigation_by_value() {
        let m = build_map();
        assert_eq!(m.lower_entry_by_value(&20), Some((&"a", &10)));
        assert_eq!(m.floor_entry_by_value(&20), Some((&"b", &20)));
        assert_eq!(m.ceiling_entry_by_value(&20), Some((&"b", &20)));
        assert_eq!(m.higher_entry_by_value(&20), Some((&"c", &30)));
        assert_eq!(m.higher_entry_by_value(&30), None);
    }

    #[test]
    fn sub_map_by_value_view() {
        let m = build_map();
        let sub = m.sub_map_by_value(&10, false, &30, true);
        assert_eq!(sub.size(), 2);
        assert!(sub.contains_key(&"b"));
        assert!(sub.contains_key(&"c"));
        assert!(!sub.contains_key(&"a"));
    }

    #[test]
    fn head_and_tail_map_by_value() {
        let m = build_map();
        let head = m.head_map_by_value(&20, true);
        assert_eq!(head.size(), 2);
        let tail = m.tail_map_by_value(&20, false);
        assert_eq!(tail.size(), 1);
        assert!(tail.contains_key(&"c"));
    }

    #[test]
    fn update_repositions_after_mutation() {
        let mut m = build_map();
        // Bump "a"'s value above everything else, then notify the map.
        m.remove(&"a");
        m.entries.push(("a", 99));
        assert!(m.update(&"a"));
        let keys: Vec<&str> = m.entries.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec!["b", "c", "a"]);
    }

    #[test]
    fn entry_set_key_set_and_values_views() {
        let m = build_map();
        let entries = m.entry_set();
        assert_eq!(entries.len(), 3);
        assert!(entries.contains(&("a", 10)));

        let keys = m.key_set();
        assert_eq!(keys.to_vec(), vec!["a", "b", "c"]);

        let values = m.values();
        assert_eq!(values.to_vec(), vec![10, 20, 30]);
    }

    #[test]
    fn clear_empties_the_map() {
        let mut m = build_map();
        m.clear();
        assert!(m.is_empty());
        assert_eq!(m.size(), 0);
    }

    #[test]
    fn lesser_list_object_safety_and_remove_all_default() {
        let mut list: Box<dyn LesserList<i32>> = Box::new(VecLesserList { data: vec![1, 2, 3, 4] });
        assert_eq!(list.len(), 4);
        assert_eq!(list.index_of(&3), 2);
        assert_eq!(list.index_of(&99), -1);
        assert!(list.remove_all(&[2, 4]));
        assert_eq!(list.to_vec(), vec![1, 3]);
        assert_eq!(list.poll(), Some(1));
        assert_eq!(list.to_vec(), vec![3]);
    }
}

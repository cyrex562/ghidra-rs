//! Port of `ghidra.program.database.data.SettingsCache`.
//!
//! The Java type is a thin wrapper around a synchronized, access-order
//! `FixedSizeHashMap` keyed by an `(id, name)` pair. [`FixedSizeHashMap`](
//! crate::util::datastruct::fixed_size_hash_map::FixedSizeHashMap) was itself ported as an
//! object-safe trait with no concrete implementation (a dependency-cycle cut-point), so this
//! port implements the same fixed-size LRU eviction behavior directly rather than depending on
//! that trait.

use std::collections::HashMap;
use std::hash::Hash;

use crate::program::database::data::setting_db::SettingDB;

/// Key combining an association ID (e.g. an address or datatype ID) with a setting name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IdNamePair<K> {
    id: K,
    name: String,
}

/// Fixed-size, least-recently-used cache of [`SettingDB`] entries keyed by `(id, name)`.
///
/// Port of `ghidra.program.database.data.SettingsCache`.
pub struct SettingsCache<K: Eq + Hash + Clone> {
    max_size: usize,
    /// Recency order, oldest first; the trailing entry is the most-recently-used.
    order: Vec<IdNamePair<K>>,
    map: HashMap<IdNamePair<K>, SettingDB>,
}

impl<K: Eq + Hash + Clone> SettingsCache<K> {
    /// Construct a settings cache of the specified size (maximum number of entries held).
    pub fn new(size: usize) -> Self {
        SettingsCache {
            max_size: size,
            order: Vec::new(),
            map: HashMap::new(),
        }
    }

    fn touch(&mut self, key: &IdNamePair<K>) {
        self.order.retain(|k| k != key);
        self.order.push(key.clone());
    }

    /// Remove a specific setting record from the cache.
    ///
    /// `id` is the association ID object (e.g. an address or datatype ID); `name` is the setting
    /// name.
    pub fn remove(&mut self, id: K, name: &str) {
        let key = IdNamePair {
            id,
            name: name.to_string(),
        };
        self.order.retain(|k| k != &key);
        self.map.remove(&key);
    }

    /// Clear all cached entries.
    pub fn clear(&mut self) {
        self.order.clear();
        self.map.clear();
    }

    /// Get a cached setting record, or `None` if not found.
    ///
    /// `id` is the association ID object (e.g. an address or datatype ID); `name` is the setting
    /// name. A successful lookup marks the entry as most-recently-used.
    pub fn get(&mut self, id: K, name: &str) -> Option<&SettingDB> {
        let key = IdNamePair {
            id,
            name: name.to_string(),
        };
        if self.map.contains_key(&key) {
            self.touch(&key);
        }
        self.map.get(&key)
    }

    /// Add a setting record to the cache.
    ///
    /// `id` is the association ID object (e.g. an address or datatype ID); `name` is the setting
    /// name; `setting` is the setting object to cache. If the cache exceeds its maximum size as a
    /// result, the least-recently-used entry is evicted.
    pub fn put(&mut self, id: K, name: &str, setting: SettingDB) {
        let key = IdNamePair {
            id,
            name: name.to_string(),
        };
        self.map.insert(key.clone(), setting);
        self.touch(&key);
        if self.map.len() > self.max_size {
            if let Some(oldest) = (!self.order.is_empty()).then(|| self.order.remove(0)) {
                self.map.remove(&oldest);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBRecord, Field, FieldType, Schema};
    use std::sync::Arc;

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Settings ID".to_string(),
            vec![FieldType::Long, FieldType::String],
            vec!["Long Value".to_string(), "String Value".to_string()],
            vec![],
        ))
    }

    fn make_setting(key: i64) -> SettingDB {
        let record = DBRecord::new(schema(), Field::Long(Some(key)));
        SettingDB::new(record, "format".to_string())
    }

    #[test]
    fn put_and_get_round_trip() {
        let mut cache: SettingsCache<i64> = SettingsCache::new(2);
        assert!(cache.get(1, "format").is_none());

        cache.put(1, "format", make_setting(100));
        let fetched = cache.get(1, "format").expect("entry should be cached");
        assert_eq!(fetched.get_key(), 100);
    }

    #[test]
    fn remove_evicts_specific_entry() {
        let mut cache: SettingsCache<i64> = SettingsCache::new(4);
        cache.put(1, "format", make_setting(100));
        cache.put(1, "color", make_setting(101));

        cache.remove(1, "format");
        assert!(cache.get(1, "format").is_none());
        assert!(cache.get(1, "color").is_some());
    }

    #[test]
    fn clear_removes_all_entries() {
        let mut cache: SettingsCache<i64> = SettingsCache::new(4);
        cache.put(1, "format", make_setting(100));
        cache.put(2, "format", make_setting(101));

        cache.clear();
        assert!(cache.get(1, "format").is_none());
        assert!(cache.get(2, "format").is_none());
    }

    #[test]
    fn exceeding_max_size_evicts_least_recently_used() {
        let mut cache: SettingsCache<i64> = SettingsCache::new(2);
        cache.put(1, "format", make_setting(100));
        cache.put(2, "format", make_setting(101));

        // Touch id 1 so it becomes most-recently-used; inserting a third entry should evict
        // id 2 (now least-recently-used), not id 1.
        assert!(cache.get(1, "format").is_some());
        cache.put(3, "format", make_setting(102));

        assert!(cache.get(1, "format").is_some());
        assert!(cache.get(2, "format").is_none());
        assert!(cache.get(3, "format").is_some());
    }

    #[test]
    fn distinct_names_for_same_id_are_independent_entries() {
        let mut cache: SettingsCache<i64> = SettingsCache::new(4);
        cache.put(1, "format", make_setting(100));
        cache.put(1, "color", make_setting(101));

        assert_eq!(cache.get(1, "format").unwrap().get_key(), 100);
        assert_eq!(cache.get(1, "color").unwrap().get_key(), 101);
    }
}

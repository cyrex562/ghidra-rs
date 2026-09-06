//! Port of `ghidra.program.database.data.SettingsDBAdapterV1`.
//!
//! Version 1 (current) implementation for accessing the data type settings database table. This
//! version stores each setting's name as a `Short` index into a second, append-only "Names"
//! table (`<table name> Names`) rather than repeating the name string in every settings record;
//! [`SettingsDBAdapterV0`](super::settings_db_adapter_v0::SettingsDBAdapterV0) is the prior,
//! read-only version that stored the name string directly.
//!
//! The name-index maps (`name_index_map`/`name_string_map`) are lazily populated from the names
//! table on first use (mirroring Java's `initNameMaps`) and cached behind a `RefCell` since most
//! trait methods take `&self`; [`invalidate_name_cache`](SettingsDBAdapter::invalidate_name_cache)
//! clears them so the next access re-reads the names table.
//!
//! `assign_name_index_value` reserves the next names-table key via
//! [`Table::get_next_key`]/[`Table::ensure_next_key_at_least`], clamped to a minimum of
//! [`MIN_NAME_INDEX`] (`1`) so index `0` is never assigned -- matching Java's
//! `Math.max(MIN_NAME_INDEX, settingsNameTable.getKey())`.
//!
//! This crate's `Table` has no secondary-index support, so the association-ID range/lookup
//! methods that Java implements via `Table.findRecords`/`indexIterator` (both index-column
//! lookups) are implemented here as a linear scan instead, same observable result, just O(n)
//! rather than indexed -- matching the established convention elsewhere in this adapter family
//! (see e.g. `PointerDBAdapterV2::get_record_ids_in_category`).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::data::settings_db_adapter::{
    self, SettingsDBAdapter, SettingsDeleteError, SETTINGS_ASSOCIATION_ID_COL,
    SETTINGS_LONG_VALUE_COL, SETTINGS_NAME_INDEX_COL, SETTINGS_STRING_VALUE_COL,
};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// First assigned settings-name index value; `0` is never handed out.
const MIN_NAME_INDEX: i16 = 1;

/// Schema version implemented by the settings-name lookup table.
const NAMES_SCHEMA_VERSION: i32 = 1;

/// Column index of the setting name string within the names table.
pub const V1_NAME_COL: usize = 0;

/// Column index of the setting's association ID, as defined by `SettingsDBAdapterV1`.
pub const V1_SETTINGS_ASSOCIATION_ID_COL: usize = SETTINGS_ASSOCIATION_ID_COL;

/// Column index of the setting's normalized name index, as defined by `SettingsDBAdapterV1`.
pub const V1_SETTINGS_NAME_INDEX_COL: usize = SETTINGS_NAME_INDEX_COL;

/// Column index of the setting's long value, as defined by `SettingsDBAdapterV1`.
pub const V1_SETTINGS_LONG_VALUE_COL: usize = SETTINGS_LONG_VALUE_COL;

/// Column index of the setting's string value, as defined by `SettingsDBAdapterV1`.
pub const V1_SETTINGS_STRING_VALUE_COL: usize = SETTINGS_STRING_VALUE_COL;

/// Build the names-lookup table schema, as defined by `SettingsDBAdapterV1.V1_NAME_TABLE_SCHEMA`.
fn names_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        NAMES_SCHEMA_VERSION,
        FieldType::Long,
        "NameIndex".to_string(),
        vec![FieldType::String],
        vec!["Settings Name".to_string()],
        vec![],
    ))
}

fn names_table_name(table_name: &str) -> String {
    format!("{table_name} Names")
}

/// Returns `true` if `s` is `None` or contains only whitespace, matching
/// `org.apache.commons.lang3.StringUtils.isBlank`.
fn is_blank(s: Option<&str>) -> bool {
    s.map(|s| s.trim().is_empty()).unwrap_or(true)
}

/// A `RecordIterator` over an eagerly-collected set of records.
struct VecRecordIterator {
    records: std::vec::IntoIter<DBRecord>,
}

impl RecordIterator for VecRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.records.next())
    }

    fn has_next(&self) -> bool {
        self.records.len() > 0
    }
}

/// Version 1 (current) implementation for accessing the data type settings database table.
///
/// Port of `ghidra.program.database.data.SettingsDBAdapterV1`.
pub struct SettingsDBAdapterV1 {
    table_name: String,
    settings_table: Arc<RwLock<Table>>,
    names_table: Arc<RwLock<Table>>,
    name_index_map: RefCell<Option<HashMap<i16, String>>>,
    name_string_map: RefCell<Option<HashMap<String, i16>>>,
}

impl SettingsDBAdapterV1 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = settings_db_adapter::CURRENT_VERSION;

    /// Gets a version 1 adapter for the accessing the data type settings database table.
    ///
    /// If `create` is `true`, both the settings table and its companion names table are created;
    /// otherwise both must already exist with matching schema versions.
    pub fn new(
        table_name: &str,
        handle: &mut DBHandle,
        create: bool,
    ) -> Result<Self, VersionException> {
        let names_name = names_table_name(table_name);
        let (settings_table, names_table) = if create {
            let settings_table = handle
                .create_table(table_name.to_string(), settings_db_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?;
            let names_table = handle
                .create_table(names_name.clone(), names_schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?;
            (settings_table, names_table)
        } else {
            let settings_table = handle.get_table(table_name).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {table_name}"))
            })?;
            {
                let version = settings_table.read().unwrap().get_schema().get_version();
                if version != Self::VERSION {
                    return Err(VersionException::with_upgradeable(version < Self::VERSION));
                }
            }
            let names_table = handle.get_table(&names_name).ok_or_else(|| {
                VersionException::with_message(format!("Missing expected table: {names_name}"))
            })?;
            {
                let version = names_table.read().unwrap().get_schema().get_version();
                if version != NAMES_SCHEMA_VERSION {
                    return Err(VersionException::with_message(format!(
                        "Missing expected table: {names_name}"
                    )));
                }
            }
            (settings_table, names_table)
        };
        Ok(SettingsDBAdapterV1 {
            table_name: table_name.to_string(),
            settings_table,
            names_table,
            name_index_map: RefCell::new(None),
            name_string_map: RefCell::new(None),
        })
    }

    fn init_name_maps(&self) -> io::Result<()> {
        if self.name_index_map.borrow().is_some() {
            return Ok(());
        }
        let mut index_map = HashMap::new();
        let mut string_map = HashMap::new();
        let table = self.names_table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            let idx = rec.get_key().get_long_value() as i16;
            let name = match rec.get_field(V1_NAME_COL) {
                Field::String(Some(s)) => s.clone(),
                _ => String::new(),
            };
            index_map.insert(idx, name.clone());
            string_map.insert(name, idx);
        }
        *self.name_index_map.borrow_mut() = Some(index_map);
        *self.name_string_map.borrow_mut() = Some(string_map);
        Ok(())
    }

    /// Get the previously assigned name index, or a value less than [`MIN_NAME_INDEX`] if `name`
    /// has never been assigned an index.
    fn get_name_index(&self, name: &str) -> io::Result<i16> {
        self.init_name_maps()?;
        let map = self.name_string_map.borrow();
        Ok(*map.as_ref().unwrap().get(name).unwrap_or(&-1))
    }

    /// Look up the name for an already-assigned index, or `None` if `name_index` is unassigned.
    fn lookup_setting_name(&self, name_index: i16) -> io::Result<Option<String>> {
        self.init_name_maps()?;
        Ok(self
            .name_index_map
            .borrow()
            .as_ref()
            .unwrap()
            .get(&name_index)
            .cloned())
    }

    fn assign_name_index_value(&self, name: &str) -> io::Result<i16> {
        self.init_name_maps()?;
        if let Some(&idx) = self.name_string_map.borrow().as_ref().unwrap().get(name) {
            return Ok(idx);
        }

        // 1 is the first assigned name key value which allows for short cast.
        let mut names_table = self.names_table.write().unwrap();
        let raw_next = names_table.get_next_key();
        let key = std::cmp::max(MIN_NAME_INDEX as i64, raw_next);
        if key != raw_next {
            names_table.ensure_next_key_at_least(key);
        }
        if key == i16::MAX as i64 {
            // 32766 should be way more than enough unique setting names.
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Too many settings names defined",
            ));
        }

        let name_index = key as i16;
        let mut name_rec = DBRecord::new(names_schema(), Field::Long(Some(key)));
        name_rec.set_field(V1_NAME_COL, Field::String(Some(name.to_string())));
        names_table.put_record(name_rec)?;
        drop(names_table);

        self.name_index_map
            .borrow_mut()
            .as_mut()
            .unwrap()
            .insert(name_index, name.to_string());
        self.name_string_map
            .borrow_mut()
            .as_mut()
            .unwrap()
            .insert(name.to_string(), name_index);

        Ok(name_index)
    }

    fn matching_keys(&self, association_id: i64) -> io::Result<Vec<Field>> {
        let table = self.settings_table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(V1_SETTINGS_ASSOCIATION_ID_COL), Field::Long(Some(v)) if *v == association_id)
            {
                keys.push(rec.get_key().clone());
            }
        }
        Ok(keys)
    }
}

impl SettingsDBAdapter for SettingsDBAdapterV1 {
    fn get_table_name(&self) -> &str {
        &self.table_name
    }

    fn get_record_count(&self) -> i32 {
        self.settings_table.read().unwrap().get_record_count() as i32
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.settings_table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_records_in_range(
        &self,
        min_association_id: i64,
        max_association_id: i64,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.settings_table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(v)) = rec.get_field(V1_SETTINGS_ASSOCIATION_ID_COL) {
                if *v >= min_association_id && *v <= max_association_id {
                    records.push(rec);
                }
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn delete(
        &mut self,
        min_association_id: i64,
        max_association_id: i64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), SettingsDeleteError> {
        let keys: Vec<Field> = {
            let table = self.settings_table.read().unwrap();
            let mut iter = table.get_record_iterator()?;
            let mut keys = Vec::new();
            while let Some(rec) = iter.next()? {
                if let Field::Long(Some(v)) = rec.get_field(V1_SETTINGS_ASSOCIATION_ID_COL) {
                    if *v >= min_association_id && *v <= max_association_id {
                        keys.push(rec.get_key().clone());
                    }
                }
            }
            keys
        };
        let mut table = self.settings_table.write().unwrap();
        for key in keys {
            monitor.check_cancelled()?;
            table.delete_record(&key)?;
        }
        Ok(())
    }

    fn create_settings_record(
        &mut self,
        association_id: i64,
        name: &str,
        str_value: Option<&str>,
        long_value: i64,
    ) -> io::Result<DBRecord> {
        let name_index = self.assign_name_index_value(name)?;
        let mut table = self.settings_table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(settings_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(
            V1_SETTINGS_ASSOCIATION_ID_COL,
            Field::Long(Some(association_id)),
        );
        record.set_field(
            V1_SETTINGS_NAME_INDEX_COL,
            Field::Short(Some(name_index)),
        );
        record.set_field(
            V1_SETTINGS_STRING_VALUE_COL,
            Field::String(str_value.map(|s| s.to_string())),
        );
        record.set_field(V1_SETTINGS_LONG_VALUE_COL, Field::Long(Some(long_value)));
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_settings_keys(&self, association_id: i64) -> io::Result<Vec<Field>> {
        self.matching_keys(association_id)
    }

    fn remove_all_settings_records(&mut self, association_id: i64) -> io::Result<()> {
        for key in self.matching_keys(association_id)? {
            self.remove_settings_record(key.get_long_value())?;
        }
        Ok(())
    }

    fn remove_settings_record(&mut self, settings_id: i64) -> io::Result<bool> {
        self.settings_table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(settings_id)))
    }

    fn remove_settings_record_by_name(
        &mut self,
        association_id: i64,
        name: &str,
    ) -> io::Result<bool> {
        let name_index = self.get_name_index(name)?;
        if name_index < MIN_NAME_INDEX {
            return Ok(false); // no such name defined
        }
        for key in self.matching_keys(association_id)? {
            let rec = self
                .settings_table
                .read()
                .unwrap()
                .get_record(&key)?
                .expect("key came from a live scan of this table");
            if matches!(rec.get_field(V1_SETTINGS_NAME_INDEX_COL), Field::Short(Some(v)) if *v == name_index)
            {
                self.settings_table.write().unwrap().delete_record(&key)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn get_settings_record(&self, settings_id: i64) -> io::Result<Option<DBRecord>> {
        self.settings_table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(settings_id)))
    }

    fn get_settings_record_by_name(
        &self,
        association_id: i64,
        name: &str,
    ) -> io::Result<Option<DBRecord>> {
        let name_index = self.get_name_index(name)?;
        if name_index < MIN_NAME_INDEX {
            return Ok(None); // not found - name not defined
        }
        for key in self.matching_keys(association_id)? {
            let rec = self
                .settings_table
                .read()
                .unwrap()
                .get_record(&key)?
                .expect("key came from a live scan of this table");
            if matches!(rec.get_field(V1_SETTINGS_NAME_INDEX_COL), Field::Short(Some(v)) if *v == name_index)
            {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }

    fn update_settings_record(&mut self, record: &DBRecord) -> io::Result<()> {
        let name_index = match record.get_field(V1_SETTINGS_NAME_INDEX_COL) {
            Field::Short(Some(v)) => *v,
            _ => -1,
        };
        if self.lookup_setting_name(name_index)?.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Record refers to invalid setting name index value",
            ));
        }
        self.settings_table.write().unwrap().put_record(record.clone())
    }

    fn update_settings_record_by_name(
        &mut self,
        association_id: i64,
        name: &str,
        str_value: Option<&str>,
        long_value: i64,
    ) -> io::Result<Option<DBRecord>> {
        let str_value = if is_blank(str_value) {
            None
        } else {
            Some(str_value.unwrap().trim().to_string())
        };

        let existing = self.get_settings_record_by_name(association_id, name)?;
        let Some(mut record) = existing else {
            return Ok(Some(self.create_settings_record(
                association_id,
                name,
                str_value.as_deref(),
                long_value,
            )?));
        };

        let rec_str_value = match record.get_field(V1_SETTINGS_STRING_VALUE_COL) {
            Field::String(v) => v.clone(),
            _ => None,
        };
        let rec_long_value = record.get_field(V1_SETTINGS_LONG_VALUE_COL).get_long_value();

        if rec_long_value != long_value || rec_str_value != str_value {
            record.set_field(
                V1_SETTINGS_STRING_VALUE_COL,
                Field::String(str_value.clone()),
            );
            record.set_field(V1_SETTINGS_LONG_VALUE_COL, Field::Long(Some(long_value)));
            self.settings_table
                .write()
                .unwrap()
                .put_record(record.clone())?;
            return Ok(Some(record));
        }
        Ok(None)
    }

    fn get_settings_names(&self, association_id: i64) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for key in self.matching_keys(association_id)? {
            let rec = self
                .settings_table
                .read()
                .unwrap()
                .get_record(&key)?
                .expect("key came from a live scan of this table");
            names.push(self.get_setting_name(&rec)?);
        }
        Ok(names)
    }

    fn add_all_values(&self, name: &str, set: &mut HashSet<String>) -> io::Result<()> {
        let name_index = self.get_name_index(name)?;
        if name_index < MIN_NAME_INDEX {
            return Ok(()); // no such name defined
        }
        let table = self.settings_table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(V1_SETTINGS_NAME_INDEX_COL), Field::Short(Some(v)) if *v == name_index)
            {
                if let Field::String(Some(s)) = rec.get_field(V1_SETTINGS_STRING_VALUE_COL) {
                    if !s.trim().is_empty() {
                        set.insert(s.clone());
                    }
                }
            }
        }
        Ok(())
    }

    fn get_setting_name(&self, record: &DBRecord) -> io::Result<String> {
        let name_index = match record.get_field(V1_SETTINGS_NAME_INDEX_COL) {
            Field::Short(Some(v)) => *v,
            _ => -1,
        };
        Ok(self.lookup_setting_name(name_index)?.unwrap_or_default())
    }

    fn invalidate_name_cache(&mut self) {
        *self.name_index_map.borrow_mut() = None;
        *self.name_string_map.borrow_mut() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_handle() -> DBHandle {
        DBHandle::new().unwrap()
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let mut handle = new_handle();
        assert!(SettingsDBAdapterV1::new("Settings", &mut handle, false).is_err());
    }

    #[test]
    fn create_settings_record_assigns_and_reuses_name_index() {
        let mut handle = new_handle();
        let mut adapter = SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap();

        let rec1 = adapter
            .create_settings_record(100, "format", Some("hex"), -1)
            .unwrap();
        let rec2 = adapter
            .create_settings_record(200, "format", Some("dec"), -1)
            .unwrap();

        // Same setting name -> same name index, distinct records.
        assert_eq!(
            rec1.get_field(V1_SETTINGS_NAME_INDEX_COL),
            rec2.get_field(V1_SETTINGS_NAME_INDEX_COL)
        );
        assert_ne!(rec1.get_key(), rec2.get_key());
        assert_eq!(adapter.get_record_count(), 2);
    }

    #[test]
    fn get_settings_record_by_name_round_trips() {
        let mut handle = new_handle();
        let mut adapter = SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap();
        adapter
            .create_settings_record(100, "format", Some("hex"), -1)
            .unwrap();

        let found = adapter
            .get_settings_record_by_name(100, "format")
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            adapter.get_setting_name(&found).unwrap(),
            "format".to_string()
        );

        assert!(adapter
            .get_settings_record_by_name(100, "nonexistent")
            .unwrap()
            .is_none());
        assert!(adapter
            .get_settings_record_by_name(999, "format")
            .unwrap()
            .is_none());
    }

    #[test]
    fn update_settings_record_by_name_creates_updates_and_no_ops() {
        let mut handle = new_handle();
        let mut adapter = SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap();

        // First call creates.
        let created = adapter
            .update_settings_record_by_name(1, "align", Some("left"), -1)
            .unwrap()
            .expect("should create a record");

        // Same values -> no-op (None).
        let noop = adapter
            .update_settings_record_by_name(1, "align", Some("left"), -1)
            .unwrap();
        assert!(noop.is_none());

        // Different value -> updates and returns Some.
        let updated = adapter
            .update_settings_record_by_name(1, "align", Some("right"), -1)
            .unwrap()
            .expect("should update");
        assert_eq!(updated.get_key(), created.get_key());
        assert_eq!(
            updated.get_field(V1_SETTINGS_STRING_VALUE_COL),
            &Field::String(Some("right".to_string()))
        );
    }

    #[test]
    fn remove_settings_record_and_remove_all() {
        let mut handle = new_handle();
        let mut adapter = SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap();
        adapter
            .create_settings_record(1, "a", Some("x"), -1)
            .unwrap();
        adapter
            .create_settings_record(1, "b", Some("y"), -1)
            .unwrap();
        adapter
            .create_settings_record(2, "a", Some("z"), -1)
            .unwrap();

        assert!(adapter
            .remove_settings_record_by_name(1, "a")
            .unwrap());
        assert!(!adapter.remove_settings_record_by_name(1, "a").unwrap());
        assert_eq!(adapter.get_record_count(), 2);

        adapter.remove_all_settings_records(2).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn add_all_values_and_get_settings_names() {
        let mut handle = new_handle();
        let mut adapter = SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap();
        adapter
            .create_settings_record(1, "format", Some("hex"), -1)
            .unwrap();
        adapter
            .create_settings_record(2, "format", Some("dec"), -1)
            .unwrap();
        adapter
            .create_settings_record(1, "align", Some(""), -1)
            .unwrap();

        let mut set = HashSet::new();
        adapter.add_all_values("format", &mut set).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains("hex"));
        assert!(set.contains("dec"));

        let mut blank_set = HashSet::new();
        adapter.add_all_values("align", &mut blank_set).unwrap();
        assert!(blank_set.is_empty());

        let names = adapter.get_settings_names(1).unwrap();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"format".to_string()));
        assert!(names.contains(&"align".to_string()));
    }

    #[test]
    fn invalidate_name_cache_forces_reread() {
        let mut handle = new_handle();
        let mut adapter = SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap();
        adapter
            .create_settings_record(1, "format", Some("hex"), -1)
            .unwrap();
        assert!(adapter.name_index_map.borrow().is_some());
        adapter.invalidate_name_cache();
        assert!(adapter.name_index_map.borrow().is_none());
        // Still resolvable after cache invalidation (re-reads from names table).
        assert_eq!(adapter.get_settings_names(1).unwrap(), vec!["format"]);
    }

    #[test]
    fn get_records_in_range_filters_by_association_id() {
        let mut handle = new_handle();
        let mut adapter = SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap();
        adapter
            .create_settings_record(10, "a", Some("x"), -1)
            .unwrap();
        adapter
            .create_settings_record(20, "a", Some("y"), -1)
            .unwrap();
        adapter
            .create_settings_record(30, "a", Some("z"), -1)
            .unwrap();

        let mut iter = adapter.get_records_in_range(10, 20).unwrap();
        let mut count = 0;
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn reopening_existing_tables_preserves_records_and_names() {
        let mut handle = new_handle();
        {
            let mut adapter = SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap();
            adapter
                .create_settings_record(1, "format", Some("hex"), -1)
                .unwrap();
        }
        let adapter = SettingsDBAdapterV1::new("Settings", &mut handle, false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
        assert_eq!(adapter.get_settings_names(1).unwrap(), vec!["format"]);
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = new_handle();
        let adapter: Box<dyn SettingsDBAdapter> =
            Box::new(SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
        assert_eq!(adapter.get_table_name(), "Settings");
    }
}

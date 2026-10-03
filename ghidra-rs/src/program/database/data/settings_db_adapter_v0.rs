//! Port of `ghidra.program.database.data.SettingsDBAdapterV0`.
//!
//! Version 0 (read-only) implementation for accessing the data type settings database table.
//! This version stores each setting's name as a plain string directly within each record, rather
//! than as an index into a separate names table (see
//! [`SettingsDBAdapterV1`](super::settings_db_adapter_v1::SettingsDBAdapterV1), the current,
//! writable version). Every mutating method matches Java's behavior of unconditionally throwing
//! `ReadOnlyException`, surfaced here as an [`io::Error`] with kind
//! [`Unsupported`](io::ErrorKind::Unsupported) since the [`SettingsDBAdapter`] trait's methods
//! return plain `io::Result`.
//!
//! [`translate_v0_record`](SettingsDBAdapterV0::translate_v0_record) normalizes each V0 record
//! into the current (V1) schema by assigning each distinct name string a fresh, session-local
//! `Short` index (via `assign_name_index_value`) the first time it is seen; unlike V1's
//! `invalidate_name_cache`, V0's is a no-op, matching Java's comment that "name map values can be
//! retained" since V0 has no on-disk names table to re-read from.
//!
//! This crate's `Table` has no secondary-index support, so the association-ID lookup methods
//! that Java implements via `Table.findRecords` are implemented here as a linear scan instead --
//! same observable result, just O(n) rather than indexed, matching the established convention
//! elsewhere in this adapter family (see e.g. `PointerDBAdapterV2::get_record_ids_in_category`).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::data::settings_db_adapter::{
    self, SettingsDBAdapter, SettingsDeleteError, SETTINGS_ASSOCIATION_ID_COL,
    SETTINGS_LONG_VALUE_COL, SETTINGS_NAME_INDEX_COL, SETTINGS_STRING_VALUE_COL,
};
use crate::util::exception::VersionException;
use crate::util::read_only_exception::ReadOnlyException;
use crate::util::task::TaskMonitor;

const VERSION: i32 = 0;

/// Column index of the setting's association ID, as defined by `SettingsDBAdapterV0`.
pub const V0_SETTINGS_ASSOCIATION_ID_COL: usize = 0;

/// Column index of the setting's name string, as defined by `SettingsDBAdapterV0`.
pub const V0_SETTINGS_NAME_COL: usize = 1;

/// Column index of the setting's long value, as defined by `SettingsDBAdapterV0`.
pub const V0_SETTINGS_LONG_VALUE_COL: usize = 2;

/// Column index of the setting's string value, as defined by `SettingsDBAdapterV0`.
pub const V0_SETTINGS_STRING_VALUE_COL: usize = 3;

/// Build the `io::Error` corresponding to Java's `throw new ReadOnlyException()`.
fn read_only_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        ReadOnlyException::default().to_string(),
    )
}

/// A `RecordIterator` over an eagerly-collected, already-translated set of records.
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

/// Version 0 (read-only) implementation for accessing the data type settings database table.
///
/// Port of `ghidra.program.database.data.SettingsDBAdapterV0`.
pub struct SettingsDBAdapterV0 {
    table_name: String,
    table: Arc<RwLock<Table>>,
    name_index_map: RefCell<HashMap<i16, String>>,
    name_string_map: RefCell<HashMap<String, i16>>,
}

impl SettingsDBAdapterV0 {
    /// Gets a version 0 adapter for the data type settings database table.
    pub fn new(table_name: &str, handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(table_name).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {table_name}"))
        })?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version != VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
        }
        let name = table.read().unwrap().get_name().to_string();
        Ok(SettingsDBAdapterV0 {
            table_name: name,
            table,
            name_index_map: RefCell::new(HashMap::new()),
            name_string_map: RefCell::new(HashMap::new()),
        })
    }

    fn assign_name_index_value(&self, name: &str) -> i16 {
        if let Some(&idx) = self.name_string_map.borrow().get(name) {
            return idx;
        }
        let idx = self.name_string_map.borrow().len() as i16;
        self.name_string_map
            .borrow_mut()
            .insert(name.to_string(), idx);
        self.name_index_map
            .borrow_mut()
            .insert(idx, name.to_string());
        idx
    }

    fn translate_v0_record(&self, rec: DBRecord) -> DBRecord {
        let mut normalized = DBRecord::new(settings_db_adapter::schema(), rec.get_key().clone());
        normalized.set_field(
            SETTINGS_ASSOCIATION_ID_COL,
            rec.get_field(V0_SETTINGS_ASSOCIATION_ID_COL).clone(),
        );
        let name = match rec.get_field(V0_SETTINGS_NAME_COL) {
            Field::String(Some(s)) => s.clone(),
            _ => String::new(),
        };
        let name_index = self.assign_name_index_value(&name);
        normalized.set_field(SETTINGS_NAME_INDEX_COL, Field::Short(Some(name_index)));
        normalized.set_field(
            SETTINGS_LONG_VALUE_COL,
            rec.get_field(V0_SETTINGS_LONG_VALUE_COL).clone(),
        );
        normalized.set_field(
            SETTINGS_STRING_VALUE_COL,
            rec.get_field(V0_SETTINGS_STRING_VALUE_COL).clone(),
        );
        normalized
    }
}

impl SettingsDBAdapter for SettingsDBAdapterV0 {
    fn get_table_name(&self) -> &str {
        &self.table_name
    }

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut translated = Vec::new();
        while let Some(rec) = iter.next()? {
            translated.push(self.translate_v0_record(rec));
        }
        Ok(Box::new(VecRecordIterator {
            records: translated.into_iter(),
        }))
    }

    fn get_records_in_range(
        &self,
        min_association_id: i64,
        max_association_id: i64,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut translated = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(v)) = rec.get_field(V0_SETTINGS_ASSOCIATION_ID_COL) {
                if *v >= min_association_id && *v <= max_association_id {
                    translated.push(self.translate_v0_record(rec));
                }
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: translated.into_iter(),
        }))
    }

    fn delete(
        &mut self,
        _min_association_id: i64,
        _max_association_id: i64,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), SettingsDeleteError> {
        Err(SettingsDeleteError::Io(read_only_error()))
    }

    fn create_settings_record(
        &mut self,
        _association_id: i64,
        _name: &str,
        _str_value: Option<&str>,
        _long_value: i64,
    ) -> io::Result<DBRecord> {
        Err(read_only_error())
    }

    fn get_settings_keys(&self, association_id: i64) -> io::Result<Vec<Field>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(V0_SETTINGS_ASSOCIATION_ID_COL), Field::Long(Some(v)) if *v == association_id)
            {
                keys.push(rec.get_key().clone());
            }
        }
        Ok(keys)
    }

    fn remove_all_settings_records(&mut self, association_id: i64) -> io::Result<()> {
        for key in self.get_settings_keys(association_id)? {
            self.remove_settings_record(key.get_long_value())?;
        }
        Ok(())
    }

    fn remove_settings_record(&mut self, _settings_id: i64) -> io::Result<bool> {
        Err(read_only_error())
    }

    fn remove_settings_record_by_name(
        &mut self,
        _association_id: i64,
        _name: &str,
    ) -> io::Result<bool> {
        Err(read_only_error())
    }

    fn get_settings_record(&self, settings_id: i64) -> io::Result<Option<DBRecord>> {
        let raw = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(settings_id)))?;
        Ok(raw.map(|rec| self.translate_v0_record(rec)))
    }

    fn get_settings_record_by_name(
        &self,
        association_id: i64,
        name: &str,
    ) -> io::Result<Option<DBRecord>> {
        for key in self.get_settings_keys(association_id)? {
            let rec = self
                .table
                .read()
                .unwrap()
                .get_record(&key)?
                .expect("key came from a live scan of this table");
            if matches!(rec.get_field(V0_SETTINGS_NAME_COL), Field::String(Some(s)) if s == name)
            {
                return Ok(Some(self.translate_v0_record(rec)));
            }
        }
        Ok(None)
    }

    fn update_settings_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(read_only_error())
    }

    fn update_settings_record_by_name(
        &mut self,
        _association_id: i64,
        _name: &str,
        _str_value: Option<&str>,
        _long_value: i64,
    ) -> io::Result<Option<DBRecord>> {
        Err(read_only_error())
    }

    fn get_settings_names(&self, association_id: i64) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for key in self.get_settings_keys(association_id)? {
            let rec = self
                .table
                .read()
                .unwrap()
                .get_record(&key)?
                .expect("key came from a live scan of this table");
            let name = match rec.get_field(V0_SETTINGS_NAME_COL) {
                Field::String(Some(s)) => s.clone(),
                _ => String::new(),
            };
            names.push(name);
        }
        Ok(names)
    }

    fn add_all_values(&self, name: &str, set: &mut HashSet<String>) -> io::Result<()> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(V0_SETTINGS_NAME_COL), Field::String(Some(s)) if s == name)
            {
                if let Field::String(Some(s)) = rec.get_field(V0_SETTINGS_STRING_VALUE_COL) {
                    if !s.trim().is_empty() {
                        set.insert(s.clone());
                    }
                }
            }
        }
        Ok(())
    }

    fn get_setting_name(&self, record: &DBRecord) -> io::Result<String> {
        let name_index = match record.get_field(SETTINGS_NAME_INDEX_COL) {
            Field::Short(Some(v)) => *v,
            _ => -1,
        };
        Ok(self
            .name_index_map
            .borrow()
            .get(&name_index)
            .cloned()
            .unwrap_or_default())
    }

    fn invalidate_name_cache(&mut self) {
        // Ignore -- name map values can be retained (V0 has no on-disk names table to re-read).
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};

    fn v0_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            VERSION,
            FieldType::Long,
            "SettingsID".to_string(),
            vec![
                FieldType::Long,
                FieldType::String,
                FieldType::Long,
                FieldType::String,
            ],
            vec![
                "AssociationID".to_string(),
                "Settings Name".to_string(),
                "Long Value".to_string(),
                "String Value".to_string(),
            ],
            vec![],
        ))
    }

    fn make_handle_with_v0_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table("Settings".to_string(), v0_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        for (assoc, name, str_val) in
            [(100i64, "format", "hex"), (100, "align", "left"), (200, "format", "dec")]
        {
            let key = t.get_next_key();
            let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(key)));
            rec.set_field(V0_SETTINGS_ASSOCIATION_ID_COL, Field::Long(Some(assoc)));
            rec.set_field(
                V0_SETTINGS_NAME_COL,
                Field::String(Some(name.to_string())),
            );
            rec.set_field(V0_SETTINGS_LONG_VALUE_COL, Field::Long(Some(-1)));
            rec.set_field(
                V0_SETTINGS_STRING_VALUE_COL,
                Field::String(Some(str_val.to_string())),
            );
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(SettingsDBAdapterV0::new("Settings", &handle).is_err());
    }

    #[test]
    fn get_record_translates_name_to_index() {
        let handle = make_handle_with_v0_table();
        let adapter = SettingsDBAdapterV0::new("Settings", &handle).unwrap();

        let rec = adapter.get_settings_record(0).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(SETTINGS_ASSOCIATION_ID_COL),
            &Field::Long(Some(100))
        );
        assert_eq!(adapter.get_setting_name(&rec).unwrap(), "format");
        assert_eq!(adapter.get_record_count(), 3);
    }

    #[test]
    fn same_name_reuses_index_across_records() {
        let handle = make_handle_with_v0_table();
        let adapter = SettingsDBAdapterV0::new("Settings", &handle).unwrap();

        let rec0 = adapter.get_settings_record(0).unwrap().unwrap(); // assoc 100, "format"
        let rec2 = adapter.get_settings_record(2).unwrap().unwrap(); // assoc 200, "format"
        assert_eq!(
            rec0.get_field(SETTINGS_NAME_INDEX_COL),
            rec2.get_field(SETTINGS_NAME_INDEX_COL)
        );
    }

    #[test]
    fn get_settings_record_by_name_and_names() {
        let handle = make_handle_with_v0_table();
        let adapter = SettingsDBAdapterV0::new("Settings", &handle).unwrap();

        let found = adapter
            .get_settings_record_by_name(100, "align")
            .unwrap()
            .expect("record should exist");
        assert_eq!(adapter.get_setting_name(&found).unwrap(), "align");

        assert!(adapter
            .get_settings_record_by_name(100, "nonexistent")
            .unwrap()
            .is_none());

        let mut names = adapter.get_settings_names(100).unwrap();
        names.sort();
        assert_eq!(names, vec!["align".to_string(), "format".to_string()]);
    }

    #[test]
    fn add_all_values_collects_matching_string_values() {
        let handle = make_handle_with_v0_table();
        let adapter = SettingsDBAdapterV0::new("Settings", &handle).unwrap();

        let mut set = HashSet::new();
        adapter.add_all_values("format", &mut set).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains("hex"));
        assert!(set.contains("dec"));
    }

    #[test]
    fn get_settings_keys_filters_by_association_id() {
        let handle = make_handle_with_v0_table();
        let adapter = SettingsDBAdapterV0::new("Settings", &handle).unwrap();
        assert_eq!(adapter.get_settings_keys(100).unwrap().len(), 2);
        assert_eq!(adapter.get_settings_keys(200).unwrap().len(), 1);
        assert!(adapter.get_settings_keys(999).unwrap().is_empty());
    }

    #[test]
    fn get_records_in_range_filters_and_translates() {
        let handle = make_handle_with_v0_table();
        let adapter = SettingsDBAdapterV0::new("Settings", &handle).unwrap();
        let mut iter = adapter.get_records_in_range(100, 100).unwrap();
        let mut count = 0;
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let handle = make_handle_with_v0_table();
        let mut adapter = SettingsDBAdapterV0::new("Settings", &handle).unwrap();

        assert_eq!(
            adapter
                .create_settings_record(1, "x", None, -1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_settings_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter
                .remove_settings_record_by_name(100, "format")
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter
                .update_settings_record_by_name(100, "format", Some("oct"), -1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let monitor = crate::util::task::DummyMonitor;
        assert!(adapter.delete(0, 1000, &monitor).is_err());
    }

    #[test]
    fn remove_all_settings_records_is_a_noop_when_nothing_matches() {
        let handle = make_handle_with_v0_table();
        let mut adapter = SettingsDBAdapterV0::new("Settings", &handle).unwrap();
        // No records for association 999, so the loop body (which would error) never runs.
        assert!(adapter.remove_all_settings_records(999).is_ok());
        // But a matching association triggers the read-only error, matching the real Java quirk.
        assert!(adapter.remove_all_settings_records(100).is_err());
    }

    #[test]
    fn invalidate_name_cache_is_a_noop() {
        let handle = make_handle_with_v0_table();
        let adapter = SettingsDBAdapterV0::new("Settings", &handle).unwrap();
        let rec = adapter.get_settings_record(0).unwrap().unwrap();
        assert_eq!(adapter.get_setting_name(&rec).unwrap(), "format");
        let mut adapter = adapter;
        adapter.invalidate_name_cache();
        // Cache retained -- name is still resolvable without re-reading anything.
        assert_eq!(adapter.get_setting_name(&rec).unwrap(), "format");
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_v0_table();
        let adapter: Box<dyn SettingsDBAdapter> =
            Box::new(SettingsDBAdapterV0::new("Settings", &handle).unwrap());
        assert_eq!(adapter.get_record_count(), 3);
        assert_eq!(adapter.get_table_name(), "Settings");
    }
}

//! Port of `ghidra.program.database.data.SettingsDBAdapter`.
//!
//! The Java type is an abstract class whose static factory methods (`getAdapter`,
//! `findReadOnlyAdapter`, `upgrade`) select and migrate between concrete version-specific
//! implementations (`SettingsDBAdapterV0`/`SettingsDBAdapterV1`). Those concrete adapters have
//! not been ported yet, so this port only models the abstract instance API each version
//! implements, as an object-safe trait; the version-selection/upgrade logic belongs with
//! whichever type ends up owning the concrete adapters. This trait was itself selected as a
//! dependency-cycle cut-point.

use std::collections::HashSet;
use std::io;

use crate::framework::db::{DBRecord, Field, RecordIterator};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Error returned by [`SettingsDBAdapter::delete`], mirroring the Java method's
/// `throws CancelledException, IOException`.
#[derive(Debug, thiserror::Error)]
pub enum SettingsDeleteError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Adapter to access settings database tables.
///
/// Port of `ghidra.program.database.data.SettingsDBAdapter`.
pub trait SettingsDBAdapter {
    /// Get DB table name.
    fn get_table_name(&self) -> &str;

    /// Returns number of settings records.
    fn get_record_count(&self) -> i32;

    /// Get iterator over all settings records.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get an iterator over those records that fall in the given range for the association ID
    /// column in the table.
    fn get_records_in_range(
        &self,
        min_association_id: i64,
        max_association_id: i64,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Delete all settings records over the specified range of association IDs.
    fn delete(
        &mut self,
        min_association_id: i64,
        max_association_id: i64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), SettingsDeleteError>;

    /// Create a settings record.
    ///
    /// `str_value` is `None` if the setting is not a `String`; `long_value` is `-1` if the
    /// setting is not a `long`.
    fn create_settings_record(
        &mut self,
        association_id: i64,
        name: &str,
        str_value: Option<&str>,
        long_value: i64,
    ) -> io::Result<DBRecord>;

    /// Get settings record keys for all settings corresponding to the specified associationId.
    fn get_settings_keys(&self, association_id: i64) -> io::Result<Vec<Field>>;

    /// Remove all settings records for specified associationId.
    fn remove_all_settings_records(&mut self, association_id: i64) -> io::Result<()>;

    /// Remove the specified settings record. Returns `true` if the record was deleted.
    fn remove_settings_record(&mut self, settings_id: i64) -> io::Result<bool>;

    /// Remove the specified settings record if found. Returns `true` if the record was found and
    /// removed.
    fn remove_settings_record_by_name(
        &mut self,
        association_id: i64,
        name: &str,
    ) -> io::Result<bool>;

    /// Get the specified settings record, or `None` if not found.
    fn get_settings_record(&self, settings_id: i64) -> io::Result<Option<DBRecord>>;

    /// Get the settings record which corresponds to a specific associatedId and setting name, or
    /// `None` if not found.
    fn get_settings_record_by_name(
        &self,
        association_id: i64,
        name: &str,
    ) -> io::Result<Option<DBRecord>>;

    /// Update the settings record in the table.
    ///
    /// IMPORTANT: This method must not be used during upgrades since it bypasses allocation of
    /// settings name index values.
    fn update_settings_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Update the setting record corresponding to the specified setting data. Search for an
    /// existing record will be performed. Returns the updated record if the setting was updated,
    /// else `None`.
    fn update_settings_record_by_name(
        &mut self,
        association_id: i64,
        name: &str,
        str_value: Option<&str>,
        long_value: i64,
    ) -> io::Result<Option<DBRecord>>;

    /// Get an array of names for settings records which correspond to the specified
    /// associationId.
    fn get_settings_names(&self, association_id: i64) -> io::Result<Vec<String>>;

    /// Add all values stored for the specified setting name to the specified set.
    fn add_all_values(&self, name: &str, set: &mut HashSet<String>) -> io::Result<()>;

    /// Get the setting name which corresponds to the specified record (whose name column is a
    /// normalized integer index value).
    fn get_setting_name(&self, record: &DBRecord) -> io::Result<String>;

    /// Invalidate name cache.
    fn invalidate_name_cache(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBRecord, Field, FieldType, Schema};
    use std::cell::RefCell;
    use std::sync::Arc;

    struct MockRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.len() > 0
        }
    }

    struct MockSettingsDBAdapter {
        table_name: String,
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        invalidated: RefCell<bool>,
        next_key: RefCell<i64>,
    }

    impl MockSettingsDBAdapter {
        fn new(table_name: &str) -> Self {
            let schema = Arc::new(Schema::new(
                1,
                FieldType::Long,
                "Settings ID".to_string(),
                vec![FieldType::Long, FieldType::Int, FieldType::Long, FieldType::String],
                vec![
                    "Association ID".to_string(),
                    "Name Index".to_string(),
                    "Long Value".to_string(),
                    "String Value".to_string(),
                ],
                vec![],
            ));
            MockSettingsDBAdapter {
                table_name: table_name.to_string(),
                schema,
                records: RefCell::new(Vec::new()),
                invalidated: RefCell::new(false),
                next_key: RefCell::new(0),
            }
        }
    }

    impl SettingsDBAdapter for MockSettingsDBAdapter {
        fn get_table_name(&self) -> &str {
            &self.table_name
        }

        fn get_record_count(&self) -> i32 {
            self.records.borrow().len() as i32
        }

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn get_records_in_range(
            &self,
            min_association_id: i64,
            max_association_id: i64,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let filtered: Vec<DBRecord> = self
                .records
                .borrow()
                .iter()
                .filter(|r| match r.get_field(0) {
                    Field::Long(Some(v)) => *v >= min_association_id && *v <= max_association_id,
                    _ => false,
                })
                .cloned()
                .collect();
            Ok(Box::new(MockRecordIterator {
                records: filtered.into_iter(),
            }))
        }

        fn delete(
            &mut self,
            min_association_id: i64,
            max_association_id: i64,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), SettingsDeleteError> {
            self.records.borrow_mut().retain(|r| match r.get_field(0) {
                Field::Long(Some(v)) => !(*v >= min_association_id && *v <= max_association_id),
                _ => true,
            });
            Ok(())
        }

        fn create_settings_record(
            &mut self,
            association_id: i64,
            _name: &str,
            str_value: Option<&str>,
            long_value: i64,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(0, Field::Long(Some(association_id)));
            rec.set_field(2, Field::Long(Some(long_value)));
            rec.set_field(3, Field::String(str_value.map(|s| s.to_string())));
            self.records.borrow_mut().push(rec.clone());
            Ok(rec)
        }

        fn get_settings_keys(&self, association_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| matches!(r.get_field(0), Field::Long(Some(v)) if *v == association_id))
                .map(|r| r.get_key().clone())
                .collect())
        }

        fn remove_all_settings_records(&mut self, association_id: i64) -> io::Result<()> {
            self.records
                .borrow_mut()
                .retain(|r| !matches!(r.get_field(0), Field::Long(Some(v)) if *v == association_id));
            Ok(())
        }

        fn remove_settings_record(&mut self, settings_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(settings_id)));
            Ok(records.len() != len_before)
        }

        fn remove_settings_record_by_name(
            &mut self,
            association_id: i64,
            _name: &str,
        ) -> io::Result<bool> {
            self.remove_all_settings_records(association_id)?;
            Ok(true)
        }

        fn get_settings_record(&self, settings_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(settings_id)))
                .cloned())
        }

        fn get_settings_record_by_name(
            &self,
            association_id: i64,
            _name: &str,
        ) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| matches!(r.get_field(0), Field::Long(Some(v)) if *v == association_id))
                .cloned())
        }

        fn update_settings_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                *existing = record.clone();
            }
            Ok(())
        }

        fn update_settings_record_by_name(
            &mut self,
            association_id: i64,
            name: &str,
            str_value: Option<&str>,
            long_value: i64,
        ) -> io::Result<Option<DBRecord>> {
            self.remove_all_settings_records(association_id)?;
            Ok(Some(self.create_settings_record(
                association_id,
                name,
                str_value,
                long_value,
            )?))
        }

        fn get_settings_names(&self, association_id: i64) -> io::Result<Vec<String>> {
            let _ = association_id;
            Ok(Vec::new())
        }

        fn add_all_values(&self, _name: &str, set: &mut HashSet<String>) -> io::Result<()> {
            for rec in self.records.borrow().iter() {
                if let Field::String(Some(v)) = rec.get_field(3) {
                    set.insert(v.clone());
                }
            }
            Ok(())
        }

        fn get_setting_name(&self, _record: &DBRecord) -> io::Result<String> {
            Ok("mock-setting".to_string())
        }

        fn invalidate_name_cache(&mut self) {
            *self.invalidated.borrow_mut() = true;
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let mut adapter: Box<dyn SettingsDBAdapter> =
            Box::new(MockSettingsDBAdapter::new("Settings"));

        assert_eq!(adapter.get_table_name(), "Settings");
        assert_eq!(adapter.get_record_count(), 0);

        let rec = adapter
            .create_settings_record(100, "format", Some("hex"), -1)
            .unwrap();
        assert_eq!(adapter.get_record_count(), 1);

        let fetched = adapter
            .get_settings_record_by_name(100, "format")
            .unwrap()
            .expect("record should exist");
        assert_eq!(fetched.get_key(), rec.get_key());

        let mut set = HashSet::new();
        adapter.add_all_values("format", &mut set).unwrap();
        assert!(set.contains("hex"));

        let keys = adapter.get_settings_keys(100).unwrap();
        assert_eq!(keys.len(), 1);

        let removed = adapter.remove_settings_record(0).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 0);

        adapter.invalidate_name_cache();
    }
}

//! Port of `ghidra.feature.vt.api.db.VTMatchTagDBAdapter`.
//!
//! Abstract adapter for the database table that holds tags for version tracking matches. The
//! Java class carries only class-level (static) state -- the table name and schema -- plus a
//! pair of static factory methods; per-instance state (the backing [`Table`]) belongs to the
//! concrete subclass. That split is mirrored here: [`VTMatchTagDBAdapterBase`] is a namespace for
//! the shared table name/schema and the factory methods, while [`VTMatchTagDBAdapter`] declares
//! the abstract per-instance operations that a concrete adapter (currently only
//! `VTMatchTagDBAdapterV0`) must implement.

use std::io;
use std::sync::Arc;

use crate::feature::seam_stubs::VTMatchTagDBAdapterV0;
use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, FieldType, RecordIterator, Schema};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Name of the database table backing this adapter.
pub const TABLE_NAME: &str = "MatchTagTable";

/// Columns of the `MatchTagTable`.
///
/// Corresponds to the Java nested enum `VTMatchTagDBAdapter.ColumnDescription`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnDescription {
    TagNameCol,
}

impl ColumnDescription {
    const VARIANTS: [ColumnDescription; 1] = [ColumnDescription::TagNameCol];

    /// The Java enum constant name, e.g. `"TAG_NAME_COL"`.
    fn name(&self) -> &'static str {
        match self {
            ColumnDescription::TagNameCol => "TAG_NAME_COL",
        }
    }

    /// The field type backing this column (Java: `getColumnField()`).
    pub fn column_field(&self) -> FieldType {
        match self {
            ColumnDescription::TagNameCol => FieldType::String,
        }
    }

    /// The column index (Java: `column()`, i.e. the enum ordinal).
    pub fn column(&self) -> usize {
        match self {
            ColumnDescription::TagNameCol => 0,
        }
    }

    fn column_names() -> Vec<String> {
        Self::VARIANTS.iter().map(|c| c.name().to_string()).collect()
    }

    fn column_fields() -> Vec<FieldType> {
        Self::VARIANTS.iter().map(|c| c.column_field()).collect()
    }
}

/// Abstract per-instance operations a concrete match-tag table adapter must implement.
///
/// Corresponds to the abstract instance methods of the Java `VTMatchTagDBAdapter` class.
pub trait VTMatchTagDBAdapter {
    fn insert_record(&self, tag_name: &str) -> io::Result<DBRecord>;
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator>>;
    fn get_record(&self, tag_record_key: i64) -> io::Result<Option<DBRecord>>;
    fn get_record_count(&self) -> usize;
    fn update_record(&self, record: &DBRecord) -> io::Result<()>;
    fn delete_record(&self, tag_record_key: i64) -> io::Result<bool>;
}

/// Shared (class-level) state and factory methods for match-tag table adapters.
///
/// Corresponds to the static members of the Java `VTMatchTagDBAdapter` class.
pub struct VTMatchTagDBAdapterBase;

impl VTMatchTagDBAdapterBase {
    /// Builds the schema for the `MatchTagTable` (Java: static field `TABLE_SCHEMA`).
    pub fn table_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            ColumnDescription::column_fields(),
            ColumnDescription::column_names(),
            vec![],
        ))
    }

    /// Creates a new match-tag table adapter, creating the backing table.
    ///
    /// Corresponds to the Java static method `createAdapter(DBHandle)`.
    pub fn create_adapter(db_handle: &mut DBHandle) -> io::Result<Box<dyn VTMatchTagDBAdapter>> {
        let adapter = VTMatchTagDBAdapterV0::create(db_handle, TABLE_NAME, Self::table_schema())?;
        Ok(Box::new(adapter))
    }

    /// Opens an existing match-tag table adapter.
    ///
    /// Corresponds to the Java static method `getAdapter(DBHandle, OpenMode, TaskMonitor)`.
    pub fn get_adapter(
        db_handle: &DBHandle,
        _open_mode: OpenMode,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn VTMatchTagDBAdapter>, VersionException> {
        let adapter = VTMatchTagDBAdapterV0::open(db_handle, TABLE_NAME)?;
        Ok(Box::new(adapter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_description_matches_java_shape() {
        assert_eq!(ColumnDescription::TagNameCol.column(), 0);
        assert_eq!(ColumnDescription::TagNameCol.column_field(), FieldType::String);
        assert_eq!(ColumnDescription::column_names(), vec!["TAG_NAME_COL".to_string()]);
    }

    #[test]
    fn table_schema_has_one_string_column_and_long_key() {
        let schema = VTMatchTagDBAdapterBase::table_schema();
        assert_eq!(schema.get_version(), 0);
        assert_eq!(schema.get_key_type(), FieldType::Long);
        assert_eq!(schema.get_key_name(), "Key");
        assert_eq!(schema.get_field_count(), 1);
        assert_eq!(schema.get_field_type(0), FieldType::String);
        assert_eq!(schema.get_field_name(0), "TAG_NAME_COL");
    }

    #[test]
    fn create_adapter_then_insert_and_read_back_tag() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchTagDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        let record = adapter.insert_record("MY_TAG").unwrap();
        assert_eq!(record.get_string(ColumnDescription::TagNameCol.column()), Some("MY_TAG"));
        assert_eq!(adapter.get_record_count(), 1);

        let fetched = adapter.get_record(record.get_key().get_long_value()).unwrap().unwrap();
        assert_eq!(fetched.get_string(0), Some("MY_TAG"));
    }

    #[test]
    fn insert_record_rejects_blank_tag_name() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchTagDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        assert!(adapter.insert_record("   ").is_err());
    }

    #[test]
    fn delete_record_removes_it() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchTagDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        let record = adapter.insert_record("DOOMED").unwrap();
        let key = record.get_key().get_long_value();
        assert!(adapter.delete_record(key).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
        // A second delete of the same (now-removed) key reports no record was removed.
        assert!(!adapter.delete_record(key).unwrap());
    }

    struct NoOpMonitor;
    impl TaskMonitor for NoOpMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn get_adapter_on_missing_table_returns_version_exception() {
        let db_handle = DBHandle::new().unwrap();
        let monitor = NoOpMonitor;
        let result = VTMatchTagDBAdapterBase::get_adapter(&db_handle, OpenMode::Update, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn get_adapter_reopens_created_table() {
        let mut db_handle = DBHandle::new().unwrap();
        VTMatchTagDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        let monitor = NoOpMonitor;
        let adapter =
            VTMatchTagDBAdapterBase::get_adapter(&db_handle, OpenMode::Update, &monitor).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_records_iterates_all_inserted() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchTagDBAdapterBase::create_adapter(&mut db_handle).unwrap();
        adapter.insert_record("A").unwrap();
        adapter.insert_record("B").unwrap();

        let mut iter = adapter.get_records().unwrap();
        let mut names = Vec::new();
        while let Some(record) = iter.next().unwrap() {
            names.push(record.get_string(0).unwrap().to_string());
        }
        names.sort();
        assert_eq!(names, vec!["A".to_string(), "B".to_string()]);
    }
}

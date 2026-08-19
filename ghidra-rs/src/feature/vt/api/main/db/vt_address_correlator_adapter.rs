//! Port of `ghidra.feature.vt.api.db.VTAddressCorrelatorAdapter`.
//!
//! The Java class is an abstract adapter for the database table that records
//! source-entry/source-address/destination-address correlation triples. Unlike its siblings in
//! this module (e.g. [`super::vt_match_table_db_adapter`]), it carries genuine per-instance state
//! -- the `dbHandle` field -- alongside concrete (non-abstract) instance methods (`close`, `save`,
//! `saveAs`) that use it. That split is mirrored here: [`VTAddressCorrelatorAdapterBase`] owns the
//! `db_handle` field, the schema, the factory methods, and the concrete lifecycle methods, while
//! [`VTAddressCorrelatorAdapter`] declares the abstract per-instance operations that a concrete
//! adapter (currently only `VTAddressCorrelationAdapterV0`) must implement, plus a `base()`
//! accessor back to the shared state.

use std::io;
use std::path::Path;
use std::sync::{Arc, RwLock};

use thiserror::Error;

use crate::feature::seam_stubs::VTAddressCorrelationAdapterV0;
use crate::framework::db::{DBHandle, DBRecord, FieldType, Schema};
use crate::util::exception::{CancelledException, VersionException};
use crate::util::task::TaskMonitor;

/// Name of the database table backing this adapter (Java: `TABLE_NAME`).
pub const TABLE_NAME: &str = "AddressCorrelationTable";

/// Columns of the `AddressCorrelationTable`.
///
/// Corresponds to the Java nested class `VTAddressCorrelatorAdapter.AddressCorrelationTableDescriptor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnDescription {
    SourceEntryCol,
    SourceAddressCol,
    DestinationAddressCol,
}

impl ColumnDescription {
    const VARIANTS: [ColumnDescription; 3] = [
        ColumnDescription::SourceEntryCol,
        ColumnDescription::SourceAddressCol,
        ColumnDescription::DestinationAddressCol,
    ];

    /// The Java field name, e.g. `"SOURCE_ENTRY_COL"`.
    fn name(&self) -> &'static str {
        match self {
            ColumnDescription::SourceEntryCol => "SOURCE_ENTRY_COL",
            ColumnDescription::SourceAddressCol => "SOURCE_ADDRESS_COL",
            ColumnDescription::DestinationAddressCol => "DESTINATION_ADDRESS_COL",
        }
    }

    /// The field type backing this column (Java: `getColumnField()`). All three columns are
    /// `LongField.INSTANCE` in the Java source.
    pub fn column_field(&self) -> FieldType {
        FieldType::Long
    }

    /// The column index (Java: `TableColumn.column()`, assigned in declaration order).
    pub fn column(&self) -> usize {
        match self {
            ColumnDescription::SourceEntryCol => 0,
            ColumnDescription::SourceAddressCol => 1,
            ColumnDescription::DestinationAddressCol => 2,
        }
    }

    /// Whether this column is indexed (Java: `TableColumn.isIndexed()`). Only `SOURCE_ENTRY_COL`
    /// is constructed with `isIndexed = true`.
    pub fn is_indexed(&self) -> bool {
        matches!(self, ColumnDescription::SourceEntryCol)
    }

    fn column_names() -> Vec<String> {
        Self::VARIANTS.iter().map(|c| c.name().to_string()).collect()
    }

    fn column_fields() -> Vec<FieldType> {
        Self::VARIANTS.iter().map(|c| c.column_field()).collect()
    }

    /// Java: `TableDescriptor.getIndexedColumns()`.
    pub fn indexed_columns() -> Vec<usize> {
        Self::VARIANTS.iter().filter(|c| c.is_indexed()).map(|c| c.column()).collect()
    }
}

/// Combines the checked exceptions declared on `VTAddressCorrelatorAdapter.save`/`saveAs`.
#[derive(Error, Debug)]
pub enum SaveError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Abstract per-instance operations a concrete address-correlator adapter must implement.
///
/// Corresponds to the abstract instance methods of the Java `VTAddressCorrelatorAdapter` class.
pub trait VTAddressCorrelatorAdapter {
    /// Access the shared adapter state (the `dbHandle` field and its concrete operations).
    fn base(&self) -> &VTAddressCorrelatorAdapterBase;

    /// Java: `createAddressRecord(long sourceEntryLong, long sourceLong, long destinationLong)`.
    ///
    /// Note: faithfully mirrors the Java source, which stores `source_long` (not
    /// `source_entry_long`) into `SOURCE_ENTRY_COL` -- `source_entry_long` is otherwise unused by
    /// this method and only consumed by [`Self::get_address_records`].
    fn create_address_record(
        &self,
        source_entry_long: i64,
        source_long: i64,
        destination_long: i64,
    ) -> io::Result<()>;

    /// Java: `getAddressRecords(long sourceEntryLong)`.
    fn get_address_records(&self, source_entry_long: i64) -> io::Result<Vec<DBRecord>>;
}

/// Shared (per-instance) state and concrete operations for address-correlator adapters.
///
/// Corresponds to the `dbHandle` field and the concrete (non-abstract) methods of the Java
/// `VTAddressCorrelatorAdapter` class.
pub struct VTAddressCorrelatorAdapterBase {
    db_handle: Arc<RwLock<DBHandle>>,
}

impl VTAddressCorrelatorAdapterBase {
    pub fn new(db_handle: Arc<RwLock<DBHandle>>) -> Self {
        Self { db_handle }
    }

    pub fn db_handle(&self) -> &Arc<RwLock<DBHandle>> {
        &self.db_handle
    }

    /// Builds the schema for the `AddressCorrelationTable` (Java: static field `TABLE_SCHEMA`).
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

    /// Java: static method `createAdapter(DBHandle)`.
    pub fn create_adapter(
        db_handle: Arc<RwLock<DBHandle>>,
    ) -> io::Result<Box<dyn VTAddressCorrelatorAdapter>> {
        let adapter =
            VTAddressCorrelationAdapterV0::create(db_handle, TABLE_NAME, Self::table_schema())?;
        Ok(Box::new(adapter))
    }

    /// Java: static method `getAdapter(DBHandle, TaskMonitor)`.
    pub fn get_adapter(
        db_handle: Arc<RwLock<DBHandle>>,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn VTAddressCorrelatorAdapter>, VersionException> {
        let adapter = VTAddressCorrelationAdapterV0::open(db_handle, TABLE_NAME)?;
        Ok(Box::new(adapter))
    }

    /// Java: `close()`. The ported [`DBHandle`] does not yet expose a close/dispose lifecycle, so
    /// this is currently a no-op.
    pub fn close(&self) {}

    /// Java: `save(TaskMonitor)`. The ported [`DBHandle`] does not yet expose a save-to-disk
    /// lifecycle, so this only honors cancellation.
    pub fn save(&self, monitor: &dyn TaskMonitor) -> Result<(), SaveError> {
        monitor.check_cancelled()?;
        Ok(())
    }

    /// Java: `saveAs(File, TaskMonitor)`. See [`Self::save`].
    pub fn save_as(&self, _file: &Path, monitor: &dyn TaskMonitor) -> Result<(), SaveError> {
        monitor.check_cancelled()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::CancelledException;

    struct NeverCancelledMonitor;
    impl TaskMonitor for NeverCancelledMonitor {
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
        fn check_cancelled(&self) -> Result<(), CancelledException> {
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
            false
        }
        fn clear_cancelled(&self) {}
    }

    struct AlwaysCancelledMonitor;
    impl TaskMonitor for AlwaysCancelledMonitor {
        fn is_cancelled(&self) -> bool {
            true
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
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Err(CancelledException::default())
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
            false
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn column_description_matches_java_shape() {
        assert_eq!(ColumnDescription::SourceEntryCol.column(), 0);
        assert_eq!(ColumnDescription::SourceAddressCol.column(), 1);
        assert_eq!(ColumnDescription::DestinationAddressCol.column(), 2);

        assert!(ColumnDescription::SourceEntryCol.is_indexed());
        assert!(!ColumnDescription::SourceAddressCol.is_indexed());
        assert!(!ColumnDescription::DestinationAddressCol.is_indexed());

        assert_eq!(ColumnDescription::indexed_columns(), vec![0]);
        assert_eq!(
            ColumnDescription::column_names(),
            vec!["SOURCE_ENTRY_COL", "SOURCE_ADDRESS_COL", "DESTINATION_ADDRESS_COL"]
        );
    }

    #[test]
    fn table_schema_has_three_long_columns_and_long_key() {
        let schema = VTAddressCorrelatorAdapterBase::table_schema();
        assert_eq!(schema.get_version(), 0);
        assert_eq!(schema.get_key_type(), FieldType::Long);
        assert_eq!(schema.get_key_name(), "Key");
        assert_eq!(schema.get_field_count(), 3);
        assert_eq!(schema.get_field_type(0), FieldType::Long);
        assert_eq!(schema.get_field_name(2), "DESTINATION_ADDRESS_COL");
    }

    #[test]
    fn create_adapter_then_create_and_read_back_address_record() {
        let db_handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = VTAddressCorrelatorAdapterBase::create_adapter(db_handle).unwrap();

        adapter.create_address_record(100, 200, 300).unwrap();

        // Faithful port of the Java bug: SOURCE_ENTRY_COL is populated with `source_long`
        // (200), not `source_entry_long` (100), so looking up by 100 finds nothing...
        assert!(adapter.get_address_records(100).unwrap().is_empty());
        // ...while looking up by 200 (the actual stored value) finds the record.
        let records = adapter.get_address_records(200).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].get_long(ColumnDescription::SourceAddressCol.column()),
            Some(200)
        );
        assert_eq!(
            records[0].get_long(ColumnDescription::DestinationAddressCol.column()),
            Some(300)
        );
    }

    #[test]
    fn get_address_records_for_missing_entry_returns_empty() {
        let db_handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = VTAddressCorrelatorAdapterBase::create_adapter(db_handle).unwrap();

        assert!(adapter.get_address_records(42).unwrap().is_empty());
    }

    #[test]
    fn save_and_save_as_honor_cancellation() {
        let db_handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let base = VTAddressCorrelatorAdapterBase::new(db_handle);

        assert!(base.save(&NeverCancelledMonitor).is_ok());
        assert!(base.save(&AlwaysCancelledMonitor).is_err());
        assert!(base.save_as(Path::new("/tmp/x.vtdb"), &NeverCancelledMonitor).is_ok());
        assert!(base.save_as(Path::new("/tmp/x.vtdb"), &AlwaysCancelledMonitor).is_err());
    }
}

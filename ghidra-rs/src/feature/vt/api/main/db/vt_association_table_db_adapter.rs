//! Port of `ghidra.feature.vt.api.db.VTAssociationTableDBAdapter`.
//!
//! Abstract adapter for the database table that holds version-tracking associations. As with
//! [`super::vt_match_set_table_db_adapter`] and [`super::vt_match_table_db_adapter`], the Java
//! class carries only class-level (static) state -- the table name and schema -- plus a pair of
//! static factory methods; per-instance state (the backing [`Table`]) belongs to the concrete
//! subclass. That split is mirrored here: [`VTAssociationTableDBAdapterBase`] is a namespace for
//! the shared schema and the factory methods, while [`VTAssociationTableDBAdapter`] declares the
//! abstract per-instance operations that a concrete adapter (currently only
//! `VTAssociationTableDBAdapterV0`) must implement.

use std::io;
use std::sync::Arc;

use crate::feature::seam_stubs::VTAssociationTableDBAdapterV0;
use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, FieldType, RecordIterator, Schema};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Name of the database table backing this adapter (Java: `TABLE_NAME`).
pub const TABLE_NAME: &str = "AssociationTable";

/// Columns of the `AssociationTable`.
///
/// Corresponds to the Java nested class `VTAssociationTableDBAdapter.AssociationTableDescriptor`
/// (a `TableDescriptor` populated with `TableColumn` fields, discovered by field-declaration order
/// via reflection -- mirrored here as a plain enum in that same declaration order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnDescription {
    SourceAddressCol,
    DestinationAddressCol,
    TypeCol,
    StatusCol,
    AppliedStatusCol,
    VoteCountCol,
}

impl ColumnDescription {
    const VARIANTS: [ColumnDescription; 6] = [
        ColumnDescription::SourceAddressCol,
        ColumnDescription::DestinationAddressCol,
        ColumnDescription::TypeCol,
        ColumnDescription::StatusCol,
        ColumnDescription::AppliedStatusCol,
        ColumnDescription::VoteCountCol,
    ];

    /// The Java field name, e.g. `"SOURCE_ADDRESS_COL"`.
    fn name(&self) -> &'static str {
        match self {
            ColumnDescription::SourceAddressCol => "SOURCE_ADDRESS_COL",
            ColumnDescription::DestinationAddressCol => "DESTINATION_ADDRESS_COL",
            ColumnDescription::TypeCol => "TYPE_COL",
            ColumnDescription::StatusCol => "STATUS_COL",
            ColumnDescription::AppliedStatusCol => "APPLIED_STATUS_COL",
            ColumnDescription::VoteCountCol => "VOTE_COUNT_COL",
        }
    }

    /// The field type backing this column (Java: `TableColumn.getColumnField()`).
    pub fn column_field(&self) -> FieldType {
        match self {
            ColumnDescription::SourceAddressCol => FieldType::Long,
            ColumnDescription::DestinationAddressCol => FieldType::Long,
            ColumnDescription::TypeCol => FieldType::Byte,
            ColumnDescription::StatusCol => FieldType::Byte,
            ColumnDescription::AppliedStatusCol => FieldType::Byte,
            ColumnDescription::VoteCountCol => FieldType::Int,
        }
    }

    /// The column index (Java: `TableColumn.column()`, assigned in declaration order).
    pub fn column(&self) -> usize {
        match self {
            ColumnDescription::SourceAddressCol => 0,
            ColumnDescription::DestinationAddressCol => 1,
            ColumnDescription::TypeCol => 2,
            ColumnDescription::StatusCol => 3,
            ColumnDescription::AppliedStatusCol => 4,
            ColumnDescription::VoteCountCol => 5,
        }
    }

    /// Whether this column is indexed (Java: `TableColumn.isIndexed()`). Only the two address
    /// columns are constructed with `isIndexed = true`.
    pub fn is_indexed(&self) -> bool {
        matches!(
            self,
            ColumnDescription::SourceAddressCol | ColumnDescription::DestinationAddressCol
        )
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

/// Abstract per-instance operations a concrete association-table adapter must implement.
///
/// Corresponds to the abstract instance methods of the Java `VTAssociationTableDBAdapter` class.
pub trait VTAssociationTableDBAdapter {
    /// Java: `insertRecord(long, long, VTAssociationType, VTAssociationStatus, int)`.
    fn insert_record(
        &self,
        source_address_id: i64,
        destination_address_id: i64,
        association_type: VtAssociationType,
        status: VtAssociationStatus,
        vote_count: i32,
    ) -> io::Result<DBRecord>;

    /// Java: `deleteRecord(long sourceAddressID)`. Despite the parameter name, the only concrete
    /// implementation (`VTAssociationTableDBAdapterV0`) treats the argument as the record's
    /// primary key, not a source address.
    fn delete_record(&self, key: i64) -> io::Result<()>;

    fn get_records_for_source_address(&self, address_id: i64) -> io::Result<Box<dyn RecordIterator>>;

    fn get_records_for_destination_address(
        &self,
        address_id: i64,
    ) -> io::Result<Box<dyn RecordIterator>>;

    fn get_record_count(&self) -> usize;

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator>>;

    fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>>;

    fn get_related_association_records_by_source_and_destination_address(
        &self,
        source_address_id: i64,
        destination_address_id: i64,
    ) -> io::Result<Vec<DBRecord>>;

    fn get_related_association_records_by_source_address(
        &self,
        source_address_id: i64,
    ) -> io::Result<Vec<DBRecord>>;

    fn get_related_association_records_by_destination_address(
        &self,
        destination_address_id: i64,
    ) -> io::Result<Vec<DBRecord>>;

    fn update_record(&self, record: &DBRecord) -> io::Result<()>;

    /// Java: `removeAssociaiton(long id)` (sic -- misspelled in the Java source).
    fn remove_association(&self, id: i64) -> io::Result<()>;
}

/// Shared (class-level) state and factory methods for association-table adapters.
///
/// Corresponds to the static members of the Java `VTAssociationTableDBAdapter` class.
pub struct VTAssociationTableDBAdapterBase;

impl VTAssociationTableDBAdapterBase {
    /// Builds the schema for the `AssociationTable` (Java: static field `TABLE_SCHEMA`).
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

    /// Creates a new association-table adapter, creating the backing table.
    ///
    /// Corresponds to the Java static method `createAdapter(DBHandle)`.
    pub fn create_adapter(
        db_handle: &mut DBHandle,
    ) -> io::Result<Box<dyn VTAssociationTableDBAdapter + Send + Sync>> {
        let adapter =
            VTAssociationTableDBAdapterV0::create(db_handle, TABLE_NAME, Self::table_schema())?;
        Ok(Box::new(adapter))
    }

    /// Opens an existing association-table adapter.
    ///
    /// Corresponds to the Java static method `getAdapter(DBHandle, OpenMode, TaskMonitor)`.
    pub fn get_adapter(
        db_handle: &DBHandle,
        _open_mode: OpenMode,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn VTAssociationTableDBAdapter + Send + Sync>, VersionException> {
        let adapter = VTAssociationTableDBAdapterV0::open(db_handle, TABLE_NAME)?;
        Ok(Box::new(adapter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_description_matches_java_shape() {
        assert_eq!(ColumnDescription::SourceAddressCol.column(), 0);
        assert_eq!(ColumnDescription::DestinationAddressCol.column(), 1);
        assert_eq!(ColumnDescription::TypeCol.column(), 2);
        assert_eq!(ColumnDescription::StatusCol.column(), 3);
        assert_eq!(ColumnDescription::AppliedStatusCol.column(), 4);
        assert_eq!(ColumnDescription::VoteCountCol.column(), 5);

        assert!(ColumnDescription::SourceAddressCol.is_indexed());
        assert!(ColumnDescription::DestinationAddressCol.is_indexed());
        assert!(!ColumnDescription::TypeCol.is_indexed());
        assert!(!ColumnDescription::StatusCol.is_indexed());
        assert!(!ColumnDescription::AppliedStatusCol.is_indexed());
        assert!(!ColumnDescription::VoteCountCol.is_indexed());

        assert_eq!(ColumnDescription::indexed_columns(), vec![0, 1]);
        assert_eq!(
            ColumnDescription::column_names(),
            vec![
                "SOURCE_ADDRESS_COL",
                "DESTINATION_ADDRESS_COL",
                "TYPE_COL",
                "STATUS_COL",
                "APPLIED_STATUS_COL",
                "VOTE_COUNT_COL",
            ]
        );
    }

    #[test]
    fn table_schema_has_six_columns_and_long_key() {
        let schema = VTAssociationTableDBAdapterBase::table_schema();
        assert_eq!(schema.get_version(), 0);
        assert_eq!(schema.get_key_type(), FieldType::Long);
        assert_eq!(schema.get_key_name(), "Key");
        assert_eq!(schema.get_field_count(), 6);
        assert_eq!(schema.get_field_type(0), FieldType::Long);
        assert_eq!(schema.get_field_type(2), FieldType::Byte);
        assert_eq!(schema.get_field_type(5), FieldType::Int);
        assert_eq!(schema.get_field_name(5), "VOTE_COUNT_COL");
    }

    #[test]
    fn create_adapter_then_insert_and_read_back_association() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTAssociationTableDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        let record = adapter
            .insert_record(100, 200, VtAssociationType::Function, VtAssociationStatus::Accepted, 3)
            .unwrap();

        assert_eq!(
            record.get_long(ColumnDescription::SourceAddressCol.column()),
            Some(100)
        );
        assert_eq!(
            record.get_long(ColumnDescription::DestinationAddressCol.column()),
            Some(200)
        );
        // VtAssociationType::Function is ordinal 0 in the Java enum; VtAssociationStatus::Accepted
        // is ordinal 1.
        assert_eq!(record.get_byte(ColumnDescription::TypeCol.column()), Some(0));
        assert_eq!(record.get_byte(ColumnDescription::StatusCol.column()), Some(1));
        assert_eq!(record.get_int(ColumnDescription::VoteCountCol.column()), Some(3));

        assert_eq!(adapter.get_record_count(), 1);
        let key = record.get_key().get_long_value();
        let fetched = adapter.get_record(key).unwrap().unwrap();
        assert_eq!(
            fetched.get_long(ColumnDescription::DestinationAddressCol.column()),
            Some(200)
        );
    }

    #[test]
    fn delete_record_removes_it() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTAssociationTableDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        let record = adapter
            .insert_record(1, 2, VtAssociationType::Data, VtAssociationStatus::Available, 0)
            .unwrap();
        let key = record.get_key().get_long_value();

        adapter.delete_record(key).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_records_for_source_and_destination_address_filter_correctly() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTAssociationTableDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        adapter
            .insert_record(10, 20, VtAssociationType::Function, VtAssociationStatus::Available, 0)
            .unwrap();
        adapter
            .insert_record(10, 30, VtAssociationType::Function, VtAssociationStatus::Available, 0)
            .unwrap();
        adapter
            .insert_record(40, 20, VtAssociationType::Function, VtAssociationStatus::Available, 0)
            .unwrap();

        let mut src_iter = adapter.get_records_for_source_address(10).unwrap();
        let mut count = 0;
        while src_iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);

        let mut dst_iter = adapter.get_records_for_destination_address(20).unwrap();
        let mut count = 0;
        while dst_iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn related_association_records_merge_and_dedupe_by_source_and_destination() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTAssociationTableDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        // Matches by source address only.
        adapter
            .insert_record(10, 999, VtAssociationType::Function, VtAssociationStatus::Available, 0)
            .unwrap();
        // Matches by destination address only.
        adapter
            .insert_record(999, 20, VtAssociationType::Function, VtAssociationStatus::Available, 0)
            .unwrap();
        // Matches neither.
        adapter
            .insert_record(1, 2, VtAssociationType::Function, VtAssociationStatus::Available, 0)
            .unwrap();

        let related = adapter
            .get_related_association_records_by_source_and_destination_address(10, 20)
            .unwrap();
        assert_eq!(related.len(), 2);

        let by_source = adapter
            .get_related_association_records_by_source_address(10)
            .unwrap();
        assert_eq!(by_source.len(), 1);

        let by_destination = adapter
            .get_related_association_records_by_destination_address(20)
            .unwrap();
        assert_eq!(by_destination.len(), 1);
    }

    #[test]
    fn update_record_persists_changes() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTAssociationTableDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        let mut record = adapter
            .insert_record(1, 2, VtAssociationType::Function, VtAssociationStatus::Available, 0)
            .unwrap();
        record.set_int(ColumnDescription::VoteCountCol.column(), 42);
        adapter.update_record(&record).unwrap();

        let key = record.get_key().get_long_value();
        let fetched = adapter.get_record(key).unwrap().unwrap();
        assert_eq!(fetched.get_int(ColumnDescription::VoteCountCol.column()), Some(42));
    }

    #[test]
    fn remove_association_deletes_the_record() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTAssociationTableDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        let record = adapter
            .insert_record(1, 2, VtAssociationType::Function, VtAssociationStatus::Available, 0)
            .unwrap();
        let key = record.get_key().get_long_value();

        adapter.remove_association(key).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_adapter_on_missing_table_returns_version_exception() {
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
            fn add_cancelled_listener(
                &self,
                _listener: Box<dyn crate::util::task::CancelledListener>,
            ) {
            }
            fn remove_cancelled_listener(
                &self,
                _listener: &dyn crate::util::task::CancelledListener,
            ) {
            }
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        let db_handle = DBHandle::new().unwrap();
        let monitor = NoOpMonitor;
        let result =
            VTAssociationTableDBAdapterBase::get_adapter(&db_handle, OpenMode::Update, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn get_adapter_reopens_created_table() {
        let mut db_handle = DBHandle::new().unwrap();
        VTAssociationTableDBAdapterBase::create_adapter(&mut db_handle).unwrap();

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
            fn add_cancelled_listener(
                &self,
                _listener: Box<dyn crate::util::task::CancelledListener>,
            ) {
            }
            fn remove_cancelled_listener(
                &self,
                _listener: &dyn crate::util::task::CancelledListener,
            ) {
            }
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        let monitor = NoOpMonitor;
        let adapter =
            VTAssociationTableDBAdapterBase::get_adapter(&db_handle, OpenMode::Update, &monitor)
                .unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }
}

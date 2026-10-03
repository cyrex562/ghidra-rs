//! Port of `ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter`.
//!
//! Abstract adapter for the database table that holds markup items belonging to
//! version-tracking matches. The Java class carries a handful of abstract instance methods plus
//! two static factory methods (`createAdapter`, `getAdapter`) and class-level state (`TABLE_NAME`,
//! `TABLE_SCHEMA`, the nested `MarkupTableDescriptor`). That class-level state was already folded
//! into the sole concrete subclass,
//! [`VTMatchMarkupItemTableDBAdapterV0`](super::vt_match_markup_item_table_db_adapter_v0), when it
//! was ported ahead of this abstract class (see that module's docs). This port therefore only adds
//! the abstract instance-method trait and the two static factory methods, mirroring the split
//! already used by [`super::vt_association_table_db_adapter`].

use std::io;

use crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage;
use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, RecordIterator};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

use super::vt_match_markup_item_table_db_adapter_v0::VTMatchMarkupItemTableDBAdapterV0;

/// Abstract per-instance operations a concrete markup-item-table adapter must implement.
///
/// Corresponds to the abstract instance methods of the Java `VTMatchMarkupItemTableDBAdapter`
/// class.
pub trait VTMatchMarkupItemTableDBAdapter {
    /// Java: `getRecords()`.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator>>;

    /// Java: `removeMarkupItemRecord(long)`.
    fn remove_markup_item_record(&self, key: i64) -> io::Result<()>;

    /// Java: `getRecord(long)`.
    fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>>;

    /// Java: `getRecords(long associationKey)`.
    fn get_records_for_association(&self, association_key: i64)
        -> io::Result<Box<dyn RecordIterator>>;

    /// Java: `updateRecord(DBRecord)` (package-private in the Java source).
    fn update_record(&self, record: &DBRecord) -> io::Result<()>;

    /// Java: `getRecordCount()`.
    fn get_record_count(&self) -> usize;

    /// Java: `createMarkupItemRecord(MarkupItemStorage)`.
    fn create_markup_item_record(
        &self,
        markup_item: &dyn MarkupItemStorage,
    ) -> io::Result<DBRecord>;
}

// Rust's inherent-method-priority rule means `self.<name>(..)` below resolves to
// `VTMatchMarkupItemTableDBAdapterV0`'s own inherent methods (of the same name), not back into
// this trait impl.
impl VTMatchMarkupItemTableDBAdapter for VTMatchMarkupItemTableDBAdapterV0 {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator>> {
        self.get_records()
    }

    fn remove_markup_item_record(&self, key: i64) -> io::Result<()> {
        self.remove_markup_item_record(key)
    }

    fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.get_record(key)
    }

    fn get_records_for_association(
        &self,
        association_key: i64,
    ) -> io::Result<Box<dyn RecordIterator>> {
        self.get_records_for_association(association_key)
    }

    fn update_record(&self, record: &DBRecord) -> io::Result<()> {
        self.update_record(record)
    }

    fn get_record_count(&self) -> usize {
        self.get_record_count()
    }

    fn create_markup_item_record(
        &self,
        markup_item: &dyn MarkupItemStorage,
    ) -> io::Result<DBRecord> {
        self.create_markup_item_record(markup_item)
    }
}

/// Static factory methods for markup-item-table adapters.
///
/// Corresponds to the static factory methods of the Java `VTMatchMarkupItemTableDBAdapter` class.
pub struct VTMatchMarkupItemTableDBAdapterBase;

impl VTMatchMarkupItemTableDBAdapterBase {
    /// Java: `createAdapter(DBHandle)`.
    pub fn create_adapter(
        db_handle: &mut DBHandle,
    ) -> io::Result<Box<dyn VTMatchMarkupItemTableDBAdapter + Send + Sync>> {
        Ok(Box::new(VTMatchMarkupItemTableDBAdapterV0::create(db_handle)?))
    }

    /// Java: `getAdapter(DBHandle, OpenMode, TaskMonitor)`.
    pub fn get_adapter(
        db_handle: &DBHandle,
        open_mode: OpenMode,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn VTMatchMarkupItemTableDBAdapter + Send + Sync>, VersionException> {
        Ok(Box::new(VTMatchMarkupItemTableDBAdapterV0::open(db_handle, open_mode, monitor)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::vt::api::main::db::vt_match_markup_item_table_db_adapter_v0::ColumnDescription;
    use crate::framework::db::Field;

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

    /// Exercises the trait through a `Box<dyn VTMatchMarkupItemTableDBAdapter>` obtained from
    /// `createAdapter`, seeding rows via `updateRecord` (the same `Table::put_record` path Java's
    /// `createMarkupItemRecord` ultimately uses) to avoid re-building the full
    /// `MarkupItemStorage`/`VTAssociation`/`VTSession` mock chain already exercised by
    /// `VTMatchMarkupItemTableDBAdapterV0`'s own tests.
    #[test]
    fn trait_object_matches_java_record_and_association_lookup_behavior() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchMarkupItemTableDBAdapterBase::create_adapter(&mut db_handle).unwrap();
        assert_eq!(adapter.get_record_count(), 0);

        let schema = VTMatchMarkupItemTableDBAdapterV0::table_schema();
        let mut record = DBRecord::new(schema.clone(), Field::Long(Some(1)));
        record.set_long(ColumnDescription::AssociationKeyCol.column(), 42);
        record.set_string(ColumnDescription::SourceValueCol.column(), Some("hello".to_string()));
        adapter.update_record(&record).unwrap();

        let mut other = DBRecord::new(schema, Field::Long(Some(2)));
        other.set_long(ColumnDescription::AssociationKeyCol.column(), 99);
        adapter.update_record(&other).unwrap();

        assert_eq!(adapter.get_record_count(), 2);

        let fetched = adapter.get_record(1).unwrap().unwrap();
        assert_eq!(fetched.get_long(ColumnDescription::AssociationKeyCol.column()), Some(42));
        assert_eq!(
            fetched.get_string(ColumnDescription::SourceValueCol.column()),
            Some("hello")
        );

        let mut for_association = adapter.get_records_for_association(42).unwrap();
        let mut count = 0;
        while for_association.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 1);

        let mut all = adapter.get_records().unwrap();
        let mut all_count = 0;
        while all.next().unwrap().is_some() {
            all_count += 1;
        }
        assert_eq!(all_count, 2);

        adapter.remove_markup_item_record(1).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn get_adapter_on_missing_table_returns_version_exception() {
        let db_handle = DBHandle::new().unwrap();
        let monitor = NoOpMonitor;
        let result =
            VTMatchMarkupItemTableDBAdapterBase::get_adapter(&db_handle, OpenMode::Update, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn get_adapter_reopens_created_table() {
        let mut db_handle = DBHandle::new().unwrap();
        VTMatchMarkupItemTableDBAdapterBase::create_adapter(&mut db_handle).unwrap();

        let monitor = NoOpMonitor;
        let adapter =
            VTMatchMarkupItemTableDBAdapterBase::get_adapter(&db_handle, OpenMode::Update, &monitor)
                .unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }
}

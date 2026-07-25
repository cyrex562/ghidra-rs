//! Port of `ghidra.program.database.data.TypedefDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects and migrates between concrete
//! version-specific implementations (`TypedefDBAdapterV0`/`V1`/`V2`). Those concrete adapters
//! have not been ported yet, so this port only models the abstract instance API each version
//! implements, as an object-safe trait; the version-selection/upgrade logic belongs with
//! whichever type ends up owning the concrete adapters. This trait was itself selected as a
//! dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field};
use crate::program::util::DBRecordAdapter;
use crate::util::UniversalID;

/// Name of the database table used to store typedef data types.
pub const TYPEDEF_TABLE_NAME: &str = "Typedefs";

/// Column index of the typedef's referenced data type ID, as defined by `TypedefDBAdapterV2`.
pub const TYPEDEF_DT_ID_COL: usize = 0;

/// Column index of the typedef flags, as defined by `TypedefDBAdapterV2`.
pub const TYPEDEF_FLAGS_COL: usize = 1;

/// Column index of the typedef's name, as defined by `TypedefDBAdapterV2`.
pub const TYPEDEF_NAME_COL: usize = 2;

/// Column index of the typedef's category ID, as defined by `TypedefDBAdapterV2`.
pub const TYPEDEF_CAT_COL: usize = 3;

/// Column index of the typedef's source archive ID, as defined by `TypedefDBAdapterV2`.
pub const TYPEDEF_SOURCE_ARCHIVE_ID_COL: usize = 4;

/// Column index of the typedef's universal data type ID, as defined by `TypedefDBAdapterV2`.
pub const TYPEDEF_UNIVERSAL_DT_ID_COL: usize = 5;

/// Column index of the typedef's source sync time, as defined by `TypedefDBAdapterV2`.
pub const TYPEDEF_SOURCE_SYNC_TIME_COL: usize = 6;

/// Column index of the typedef's last change time, as defined by `TypedefDBAdapterV2`.
pub const TYPEDEF_LAST_CHANGE_TIME_COL: usize = 7;

/// Typedef flag bit indicating the typedef's name was auto-generated.
pub const TYPEDEF_FLAG_AUTONAME: i16 = 0x1;

/// Adapter to access the database table for typedef data types.
///
/// Port of `ghidra.program.database.data.TypedefDBAdapter`.
pub trait TypedefDBAdapter: DBRecordAdapter {
    /// Creates a database record for a type definition data type.
    ///
    /// `data_type_id` is the ID of the data type that is referred to by this type definition,
    /// `name` is the unique name for this data type, `flags` are the typedef flags (e.g. the
    /// auto-name flag bit), `category_id` is the ID for the category that contains this data
    /// type, `source_archive_id` is the ID for the source archive where this data type
    /// originated, `source_data_type_id` is the ID of the associated data type in the source
    /// archive, and `last_change_time` is the time this data type was last changed.
    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        data_type_id: i64,
        name: &str,
        flags: i16,
        category_id: i64,
        source_archive_id: i64,
        source_data_type_id: i64,
        last_change_time: i64,
    ) -> io::Result<DBRecord>;

    /// Gets a type definition data type record from the database based on its ID, or `None` if
    /// not found.
    fn get_record(&self, typedef_id: i64) -> io::Result<Option<DBRecord>>;

    /// Removes the type definition data type record with the specified ID. Returns `true` if
    /// the record was removed.
    fn remove_record(&mut self, data_id: i64) -> io::Result<bool>;

    /// Updates the type definition data type table with the provided record.
    ///
    /// `set_last_change_time` means change the last change time in the record to the current
    /// time before putting the record in the database.
    fn update_record(&mut self, record: &DBRecord, set_last_change_time: bool) -> io::Result<()>;

    /// Deletes the type definition data type table from the database with the given handle.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Gets all the type definition data types that are contained in the category with the
    /// indicated ID, as `Field::Long` IDs.
    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>>;

    /// Gets an array with the IDs of all data types in the type definition table that were
    /// derived from the source data type archive indicated by the source archive ID.
    fn get_record_ids_for_source_archive(&self, archive_id: i64) -> io::Result<Vec<Field>>;

    /// Gets the typedef record whose source and datatype IDs match the specified universal IDs,
    /// or `None` if not found.
    fn get_record_with_ids(
        &self,
        source_id: UniversalID,
        datatype_id: UniversalID,
    ) -> io::Result<Option<DBRecord>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, RecordIterator, Schema};
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

    struct MockTypedefRecord {
        source_archive_id: i64,
        universal_dt_id: i64,
    }

    struct MockTypedefDBAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        meta: RefCell<Vec<MockTypedefRecord>>,
        next_key: RefCell<i64>,
        deleted: RefCell<bool>,
    }

    impl MockTypedefDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                8,
                FieldType::Long,
                "Typedef ID".to_string(),
                vec![
                    FieldType::Long,
                    FieldType::Byte,
                    FieldType::String,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Long,
                ],
                vec![
                    "Data Type ID".to_string(),
                    "Flags".to_string(),
                    "Name".to_string(),
                    "Category ID".to_string(),
                    "Source Archive ID".to_string(),
                    "Source Data Type ID".to_string(),
                    "Source Sync Time".to_string(),
                    "Last Change Time".to_string(),
                ],
                vec![],
            ));
            MockTypedefDBAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                meta: RefCell::new(Vec::new()),
                next_key: RefCell::new(0),
                deleted: RefCell::new(false),
            }
        }
    }

    impl DBRecordAdapter for MockTypedefDBAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn get_record_count(&self) -> usize {
            self.records.borrow().len()
        }
    }

    impl TypedefDBAdapter for MockTypedefDBAdapter {
        fn create_record(
            &mut self,
            data_type_id: i64,
            name: &str,
            flags: i16,
            category_id: i64,
            source_archive_id: i64,
            source_data_type_id: i64,
            last_change_time: i64,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(TYPEDEF_DT_ID_COL, Field::Long(Some(data_type_id)));
            rec.set_field(TYPEDEF_FLAGS_COL, Field::Byte(Some(flags as i8)));
            rec.set_field(TYPEDEF_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(TYPEDEF_CAT_COL, Field::Long(Some(category_id)));
            rec.set_field(
                TYPEDEF_SOURCE_ARCHIVE_ID_COL,
                Field::Long(Some(source_archive_id)),
            );
            rec.set_field(
                TYPEDEF_UNIVERSAL_DT_ID_COL,
                Field::Long(Some(source_data_type_id)),
            );
            rec.set_field(TYPEDEF_SOURCE_SYNC_TIME_COL, Field::Long(Some(0)));
            rec.set_field(
                TYPEDEF_LAST_CHANGE_TIME_COL,
                Field::Long(Some(last_change_time)),
            );
            self.records.borrow_mut().push(rec.clone());
            self.meta.borrow_mut().push(MockTypedefRecord {
                source_archive_id,
                universal_dt_id: source_data_type_id,
            });
            Ok(rec)
        }

        fn get_record(&self, typedef_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(typedef_id)))
                .cloned())
        }

        fn remove_record(&mut self, data_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(data_id)));
            Ok(records.len() != len_before)
        }

        fn update_record(
            &mut self,
            record: &DBRecord,
            set_last_change_time: bool,
        ) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                let mut updated = record.clone();
                if set_last_change_time {
                    updated.set_field(TYPEDEF_LAST_CHANGE_TIME_COL, Field::Long(Some(999)));
                }
                *existing = updated;
            }
            Ok(())
        }

        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            *self.deleted.borrow_mut() = true;
            self.records.borrow_mut().clear();
            self.meta.borrow_mut().clear();
            Ok(())
        }

        fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(TYPEDEF_CAT_COL), Field::Long(Some(v)) if *v == category_id)
                })
                .map(|r| r.get_key().clone())
                .collect())
        }

        fn get_record_ids_for_source_archive(&self, archive_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .zip(self.meta.borrow().iter())
                .filter(|(_, m)| m.source_archive_id == archive_id)
                .map(|(r, _)| r.get_key().clone())
                .collect())
        }

        fn get_record_with_ids(
            &self,
            source_id: UniversalID,
            datatype_id: UniversalID,
        ) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .zip(self.meta.borrow().iter())
                .find(|(_, m)| {
                    m.source_archive_id == source_id.value()
                        && m.universal_dt_id == datatype_id.value()
                })
                .map(|(r, _)| r.clone()))
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_typedefs() {
        let mut adapter: Box<dyn TypedefDBAdapter> = Box::new(MockTypedefDBAdapter::new());

        assert_eq!(adapter.get_record_count(), 0);

        let created = adapter
            .create_record(10, "MyTypedef", TYPEDEF_FLAG_AUTONAME, 5, 100, 200, 1000)
            .unwrap();
        assert_eq!(created.get_key(), &Field::Long(Some(0)));
        adapter
            .create_record(11, "OtherTypedef", 0, 5, 101, 201, 1001)
            .unwrap();
        adapter
            .create_record(12, "ThirdTypedef", 0, 6, 100, 202, 1002)
            .unwrap();

        assert_eq!(adapter.get_record_count(), 3);

        let fetched = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            fetched.get_field(TYPEDEF_NAME_COL),
            &Field::String(Some("MyTypedef".to_string()))
        );
        assert_eq!(
            fetched.get_field(TYPEDEF_DT_ID_COL),
            &Field::Long(Some(10))
        );

        let ids_in_category = adapter.get_record_ids_in_category(5).unwrap();
        assert_eq!(ids_in_category.len(), 2);
        assert_eq!(adapter.get_record_ids_in_category(6).unwrap().len(), 1);

        let ids_for_archive = adapter.get_record_ids_for_source_archive(100).unwrap();
        assert_eq!(ids_for_archive.len(), 2);

        let by_ids = adapter
            .get_record_with_ids(UniversalID::new(101), UniversalID::new(201))
            .unwrap()
            .expect("record should exist");
        assert_eq!(by_ids.get_key(), &Field::Long(Some(1)));
        assert!(adapter
            .get_record_with_ids(UniversalID::new(999), UniversalID::new(999))
            .unwrap()
            .is_none());

        let mut updated = fetched.clone();
        updated.set_field(
            TYPEDEF_NAME_COL,
            Field::String(Some("RenamedTypedef".to_string())),
        );
        adapter.update_record(&updated, true).unwrap();
        let refetched = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(TYPEDEF_NAME_COL),
            &Field::String(Some("RenamedTypedef".to_string()))
        );
        assert_eq!(
            refetched.get_field(TYPEDEF_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(999))
        );

        let removed = adapter.remove_record(0).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 2);
        assert!(adapter.get_record(0).unwrap().is_none());

        {
            let mut iter = adapter.get_records().unwrap();
            assert!(iter.has_next());
            let first = iter.next().unwrap().expect("record present");
            assert_eq!(
                first.get_field(TYPEDEF_NAME_COL),
                &Field::String(Some("OtherTypedef".to_string()))
            );
        }

        let mut handle = DBHandle::new().unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }
}

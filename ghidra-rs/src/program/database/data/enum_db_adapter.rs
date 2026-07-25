//! Port of `ghidra.program.database.data.EnumDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects and migrates between concrete
//! version-specific implementations (`EnumDBAdapterV0`/`V1`/`NoTable`). Those concrete adapters
//! have not been ported yet, so this port only models the abstract instance API each version
//! implements, as an object-safe trait; the version-selection/upgrade logic belongs with
//! whichever type ends up owning the concrete adapters. This trait was itself selected as a
//! dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field};
use crate::program::util::DBRecordAdapter;
use crate::util::UniversalID;

/// Name of the database table used to store enumeration data types.
pub const ENUM_TABLE_NAME: &str = "Enumeration Data Types";

/// Column index of the enum's name, as defined by `EnumDBAdapterV1`.
pub const ENUM_NAME_COL: usize = 0;

/// Column index of the enum's comment, as defined by `EnumDBAdapterV1`.
pub const ENUM_COMMENT_COL: usize = 1;

/// Column index of the enum's category ID, as defined by `EnumDBAdapterV1`.
pub const ENUM_CAT_COL: usize = 2;

/// Column index of the enum's total length, as defined by `EnumDBAdapterV1`.
pub const ENUM_SIZE_COL: usize = 3;

/// Column index of the enum's source archive ID, as defined by `EnumDBAdapterV1`.
pub const ENUM_SOURCE_ARCHIVE_ID_COL: usize = 4;

/// Column index of the enum's universal data type ID, as defined by `EnumDBAdapterV1`.
pub const ENUM_UNIVERSAL_DT_ID_COL: usize = 5;

/// Column index of the enum's source sync time, as defined by `EnumDBAdapterV1`.
pub const ENUM_SOURCE_SYNC_TIME_COL: usize = 6;

/// Column index of the enum's last change time, as defined by `EnumDBAdapterV1`.
pub const ENUM_LAST_CHANGE_TIME_COL: usize = 7;

/// Adapter to access the Enumeration data types table.
///
/// Port of `ghidra.program.database.data.EnumDBAdapter`.
pub trait EnumDBAdapter: DBRecordAdapter {
    /// Creates a database record for an enumeration data type.
    ///
    /// `name` is the unique name for this data type, `comments` are comments about this data
    /// type, `category_id` is the ID for the category that contains this data type, `size` is
    /// the total length or size of this data type, `source_archive_id` is the ID for the source
    /// archive where this data type originated, `source_data_type_id` is the ID of the
    /// associated data type in the source archive, and `last_change_time` is the time this data
    /// type was last changed.
    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        name: &str,
        comments: Option<&str>,
        category_id: i64,
        size: i8,
        source_archive_id: i64,
        source_data_type_id: i64,
        last_change_time: i64,
    ) -> io::Result<DBRecord>;

    /// Gets an enumeration data type record from the database based on its ID, or `None` if not
    /// found.
    fn get_record(&self, enum_id: i64) -> io::Result<Option<DBRecord>>;

    /// Updates the enumeration data type table with the provided record.
    ///
    /// `set_last_change_time` indicates whether the last change time in the record should be
    /// updated to the current time before the record is put into the database.
    fn update_record(&mut self, record: &DBRecord, set_last_change_time: bool) -> io::Result<()>;

    /// Remove the record for the given enumeration ID, and remove all of its associated value
    /// records. Returns `true` if successful.
    fn remove_record(&mut self, enum_id: i64) -> io::Result<bool>;

    /// Deletes the enumeration data type table from the database with the specified database
    /// handle.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Gets the IDs (as `Field::Long` values) of all enumeration data types contained in the
    /// category with the given ID.
    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>>;

    /// Gets the IDs (as `Field::Long` values) of all enumeration data types derived from the
    /// source data type archive with the given ID.
    fn get_record_ids_for_source_archive(&self, archive_id: i64) -> io::Result<Vec<Field>>;

    /// Get the enum record whose source archive ID and data type ID match the specified
    /// universal IDs, or `None` if not found.
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

    struct MockEnumDBAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
        deleted: RefCell<bool>,
    }

    impl MockEnumDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                1,
                FieldType::Long,
                "Enum ID".to_string(),
                vec![
                    FieldType::String,
                    FieldType::String,
                    FieldType::Long,
                    FieldType::Byte,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Long,
                ],
                vec![
                    "Name".to_string(),
                    "Comment".to_string(),
                    "Category ID".to_string(),
                    "Size".to_string(),
                    "Source Archive ID".to_string(),
                    "Source Data Type ID".to_string(),
                    "Source Sync Time".to_string(),
                    "Last Change Time".to_string(),
                ],
                vec![],
            ));
            MockEnumDBAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(0),
                deleted: RefCell::new(false),
            }
        }
    }

    impl DBRecordAdapter for MockEnumDBAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn get_record_count(&self) -> usize {
            self.records.borrow().len()
        }
    }

    impl EnumDBAdapter for MockEnumDBAdapter {
        fn create_record(
            &mut self,
            name: &str,
            comments: Option<&str>,
            category_id: i64,
            size: i8,
            source_archive_id: i64,
            source_data_type_id: i64,
            last_change_time: i64,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(ENUM_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(
                ENUM_COMMENT_COL,
                Field::String(comments.map(str::to_string)),
            );
            rec.set_field(ENUM_CAT_COL, Field::Long(Some(category_id)));
            rec.set_field(ENUM_SIZE_COL, Field::Byte(Some(size)));
            rec.set_field(
                ENUM_SOURCE_ARCHIVE_ID_COL,
                Field::Long(Some(source_archive_id)),
            );
            rec.set_field(
                ENUM_UNIVERSAL_DT_ID_COL,
                Field::Long(Some(source_data_type_id)),
            );
            rec.set_field(ENUM_SOURCE_SYNC_TIME_COL, Field::Long(Some(0)));
            rec.set_field(
                ENUM_LAST_CHANGE_TIME_COL,
                Field::Long(Some(last_change_time)),
            );
            self.records.borrow_mut().push(rec.clone());
            Ok(rec)
        }

        fn get_record(&self, enum_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(enum_id)))
                .cloned())
        }

        fn update_record(
            &mut self,
            record: &DBRecord,
            set_last_change_time: bool,
        ) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                *existing = record.clone();
                if set_last_change_time {
                    existing.set_field(ENUM_LAST_CHANGE_TIME_COL, Field::Long(Some(999)));
                }
            }
            Ok(())
        }

        fn remove_record(&mut self, enum_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(enum_id)));
            Ok(records.len() != len_before)
        }

        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            *self.deleted.borrow_mut() = true;
            self.records.borrow_mut().clear();
            Ok(())
        }

        fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(ENUM_CAT_COL), Field::Long(Some(v)) if *v == category_id)
                })
                .map(|r| r.get_key().clone())
                .collect())
        }

        fn get_record_ids_for_source_archive(&self, archive_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(ENUM_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == archive_id)
                })
                .map(|r| r.get_key().clone())
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
                .find(|r| {
                    matches!(r.get_field(ENUM_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == source_id.value())
                        && matches!(r.get_field(ENUM_UNIVERSAL_DT_ID_COL), Field::Long(Some(v)) if *v == datatype_id.value())
                })
                .cloned())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_enums() {
        let mut adapter: Box<dyn EnumDBAdapter> = Box::new(MockEnumDBAdapter::new());

        assert_eq!(adapter.get_record_count(), 0);

        let created = adapter
            .create_record("Colors", Some("an enum"), 5, 4, 10, 20, 100)
            .unwrap();
        assert_eq!(created.get_key(), &Field::Long(Some(0)));
        adapter
            .create_record("Flags", None, 5, 1, 10, 21, 100)
            .unwrap();

        assert_eq!(adapter.get_record_count(), 2);

        let fetched = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            fetched.get_field(ENUM_NAME_COL),
            &Field::String(Some("Colors".to_string()))
        );
        assert_eq!(fetched.get_field(ENUM_SIZE_COL), &Field::Byte(Some(4)));

        let ids_in_category = adapter.get_record_ids_in_category(5).unwrap();
        assert_eq!(ids_in_category.len(), 2);

        let ids_for_archive = adapter.get_record_ids_for_source_archive(10).unwrap();
        assert_eq!(ids_for_archive.len(), 2);

        let by_ids = adapter
            .get_record_with_ids(UniversalID::new(10), UniversalID::new(21))
            .unwrap()
            .expect("record should exist");
        assert_eq!(by_ids.get_key(), &Field::Long(Some(1)));

        let mut updated = fetched.clone();
        updated.set_field(ENUM_NAME_COL, Field::String(Some("Renamed".to_string())));
        adapter.update_record(&updated, true).unwrap();
        let refetched = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(ENUM_NAME_COL),
            &Field::String(Some("Renamed".to_string()))
        );
        assert_eq!(
            refetched.get_field(ENUM_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(999))
        );

        let removed = adapter.remove_record(0).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 1);
        assert!(adapter.get_record(0).unwrap().is_none());

        {
            let mut iter = adapter.get_records().unwrap();
            assert!(iter.has_next());
            let first = iter.next().unwrap().expect("record present");
            assert_eq!(first.get_key(), &Field::Long(Some(1)));
        }

        let mut handle = DBHandle::new().unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }
}

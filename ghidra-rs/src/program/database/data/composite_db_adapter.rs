//! Port of `ghidra.program.database.data.CompositeDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects and migrates between concrete
//! version-specific implementations (`CompositeDBAdapterV0`/`V1`/`V2V4`/`V5V6`). Those concrete
//! adapters have not been ported yet, so this port only models the abstract instance API each
//! version implements, as an object-safe trait; the version-selection/upgrade logic (and the
//! `isFlexArrayMigrationRequired` flag it sets) belongs with whichever type ends up owning the
//! concrete adapters. This trait was itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field};
use crate::program::util::DBRecordAdapter;
use crate::util::UniversalID;

/// Name of the database table used to store structures and unions.
pub const COMPOSITE_TABLE_NAME: &str = "Composite Data Types";

/// Schema version at/after which Structure flex-array components were eliminated, as defined by
/// `CompositeDBAdapter`.
pub const FLEX_ARRAY_ELIMINATION_SCHEMA_VERSION: i32 = 6;

/// Column index of the composite's name, as defined by `CompositeDBAdapterV5V6`.
pub const COMPOSITE_NAME_COL: usize = 0;

/// Column index of the composite's comment, as defined by `CompositeDBAdapterV5V6`.
pub const COMPOSITE_COMMENT_COL: usize = 1;

/// Column index of the flag indicating whether the composite is a union, as defined by
/// `CompositeDBAdapterV5V6`.
pub const COMPOSITE_IS_UNION_COL: usize = 2;

/// Column index of the composite's category ID, as defined by `CompositeDBAdapterV5V6`.
pub const COMPOSITE_CAT_COL: usize = 3;

/// Column index of the composite's total length, as defined by `CompositeDBAdapterV5V6`.
pub const COMPOSITE_LENGTH_COL: usize = 4;

/// Column index of the composite's computed alignment, as defined by `CompositeDBAdapterV5V6`.
pub const COMPOSITE_ALIGNMENT_COL: usize = 5;

/// Column index of the composite's component count, as defined by `CompositeDBAdapterV5V6`.
pub const COMPOSITE_NUM_COMPONENTS_COL: usize = 6;

/// Column index of the composite's source archive ID, as defined by `CompositeDBAdapterV5V6`.
pub const COMPOSITE_SOURCE_ARCHIVE_ID_COL: usize = 7;

/// Column index of the composite's universal data type ID, as defined by
/// `CompositeDBAdapterV5V6`.
pub const COMPOSITE_UNIVERSAL_DT_ID_COL: usize = 8;

/// Column index of the composite's source sync time, as defined by `CompositeDBAdapterV5V6`.
pub const COMPOSITE_SOURCE_SYNC_TIME_COL: usize = 9;

/// Column index of the composite's last change time, as defined by `CompositeDBAdapterV5V6`.
pub const COMPOSITE_LAST_CHANGE_TIME_COL: usize = 10;

/// Column index of the composite's pack value, as defined by `CompositeDBAdapterV5V6`.
pub const COMPOSITE_PACKING_COL: usize = 11;

/// Column index of the composite's minimum alignment value, as defined by
/// `CompositeDBAdapterV5V6`.
pub const COMPOSITE_MIN_ALIGN_COL: usize = 12;

/// Adapter to access the Composite database table.
///
/// The composite table is used to store structures and unions.
///
/// Port of `ghidra.program.database.data.CompositeDBAdapter`.
pub trait CompositeDBAdapter: DBRecordAdapter {
    /// Get the adapter schema version.
    fn version(&self) -> i32;

    /// Creates a database record for a composite data type (structure or union).
    ///
    /// `name` is the unique name for this data type, `comments` are comments about this data
    /// type, `is_union` indicates whether this data type is a union (all component offsets are
    /// at zero), `category_id` is the ID of the category that contains this composite,
    /// `length` is the total length or size of this data type, `computed_alignment` is the
    /// computed alignment for the composite or `-1` if not yet computed, `source_archive_id` is
    /// the ID of the source archive where this data type originated, `source_data_type_id` is
    /// the ID of the associated data type in the source archive, `last_change_time` is the time
    /// this data type was last changed, `pack_value` is the explicit pack value (or a sentinel
    /// for no/default packing) currently in use by this data type, and `min_alignment` is the
    /// minimum alignment value (or a sentinel for default/machine alignment) currently in use by
    /// this data type.
    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        name: &str,
        comments: Option<&str>,
        is_union: bool,
        category_id: i64,
        length: i32,
        computed_alignment: i32,
        source_archive_id: i64,
        source_data_type_id: i64,
        last_change_time: i64,
        pack_value: i32,
        min_alignment: i32,
    ) -> io::Result<DBRecord>;

    /// Gets a composite data type record from the database based on its ID, or `None` if not
    /// found.
    fn get_record(&self, data_type_id: i64) -> io::Result<Option<DBRecord>>;

    /// Updates the composite data type table with the provided record.
    ///
    /// `set_last_change_time` indicates whether the last change time in the record should be
    /// updated to the current time before the record is put into the database.
    fn update_record(&mut self, record: &DBRecord, set_last_change_time: bool) -> io::Result<()>;

    /// Removes the composite data type record with the specified ID. Returns `true` if the
    /// record was removed.
    fn remove_record(&mut self, data_id: i64) -> io::Result<bool>;

    /// Deletes the composite data type table from the database with the specified database
    /// handle.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Gets the IDs (as `Field::Long` values) of all composite data types contained in the
    /// category with the given ID.
    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>>;

    /// Gets the IDs (as `Field::Long` values) of all composite data types derived from the
    /// source data type archive with the given ID.
    fn get_record_ids_for_source_archive(&self, archive_id: i64) -> io::Result<Vec<Field>>;

    /// Get the composite record whose source archive ID and data type ID match the specified
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

    struct MockCompositeDBAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
        deleted: RefCell<bool>,
    }

    impl MockCompositeDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                FLEX_ARRAY_ELIMINATION_SCHEMA_VERSION,
                FieldType::Long,
                "Data Type ID".to_string(),
                vec![
                    FieldType::String,
                    FieldType::String,
                    FieldType::Boolean,
                    FieldType::Long,
                    FieldType::Int,
                    FieldType::Int,
                    FieldType::Int,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Int,
                    FieldType::Int,
                ],
                vec![
                    "Name".to_string(),
                    "Comment".to_string(),
                    "Is Union".to_string(),
                    "Category ID".to_string(),
                    "Length".to_string(),
                    "Alignment".to_string(),
                    "Number Of Components".to_string(),
                    "Source Archive ID".to_string(),
                    "Source Data Type ID".to_string(),
                    "Source Sync Time".to_string(),
                    "Last Change Time".to_string(),
                    "Pack".to_string(),
                    "MinAlign".to_string(),
                ],
                vec![],
            ));
            MockCompositeDBAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(0),
                deleted: RefCell::new(false),
            }
        }
    }

    impl DBRecordAdapter for MockCompositeDBAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn get_record_count(&self) -> usize {
            self.records.borrow().len()
        }
    }

    impl CompositeDBAdapter for MockCompositeDBAdapter {
        fn version(&self) -> i32 {
            FLEX_ARRAY_ELIMINATION_SCHEMA_VERSION
        }

        fn create_record(
            &mut self,
            name: &str,
            comments: Option<&str>,
            is_union: bool,
            category_id: i64,
            length: i32,
            computed_alignment: i32,
            source_archive_id: i64,
            source_data_type_id: i64,
            last_change_time: i64,
            pack_value: i32,
            min_alignment: i32,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(COMPOSITE_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(
                COMPOSITE_COMMENT_COL,
                Field::String(comments.map(str::to_string)),
            );
            rec.set_field(COMPOSITE_IS_UNION_COL, Field::Boolean(Some(is_union)));
            rec.set_field(COMPOSITE_CAT_COL, Field::Long(Some(category_id)));
            rec.set_field(COMPOSITE_LENGTH_COL, Field::Int(Some(length)));
            rec.set_field(
                COMPOSITE_ALIGNMENT_COL,
                Field::Int(Some(computed_alignment)),
            );
            rec.set_field(COMPOSITE_NUM_COMPONENTS_COL, Field::Int(Some(0)));
            rec.set_field(
                COMPOSITE_SOURCE_ARCHIVE_ID_COL,
                Field::Long(Some(source_archive_id)),
            );
            rec.set_field(
                COMPOSITE_UNIVERSAL_DT_ID_COL,
                Field::Long(Some(source_data_type_id)),
            );
            rec.set_field(COMPOSITE_SOURCE_SYNC_TIME_COL, Field::Long(Some(0)));
            rec.set_field(
                COMPOSITE_LAST_CHANGE_TIME_COL,
                Field::Long(Some(last_change_time)),
            );
            rec.set_field(COMPOSITE_PACKING_COL, Field::Int(Some(pack_value)));
            rec.set_field(COMPOSITE_MIN_ALIGN_COL, Field::Int(Some(min_alignment)));
            self.records.borrow_mut().push(rec.clone());
            Ok(rec)
        }

        fn get_record(&self, data_type_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(data_type_id)))
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
                    existing.set_field(COMPOSITE_LAST_CHANGE_TIME_COL, Field::Long(Some(999)));
                }
            }
            Ok(())
        }

        fn remove_record(&mut self, data_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(data_id)));
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
                    matches!(r.get_field(COMPOSITE_CAT_COL), Field::Long(Some(v)) if *v == category_id)
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
                    matches!(r.get_field(COMPOSITE_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == archive_id)
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
                    matches!(r.get_field(COMPOSITE_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == source_id.value())
                        && matches!(r.get_field(COMPOSITE_UNIVERSAL_DT_ID_COL), Field::Long(Some(v)) if *v == datatype_id.value())
                })
                .cloned())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_composites() {
        let mut adapter: Box<dyn CompositeDBAdapter> = Box::new(MockCompositeDBAdapter::new());

        assert_eq!(adapter.get_record_count(), 0);
        assert_eq!(adapter.version(), FLEX_ARRAY_ELIMINATION_SCHEMA_VERSION);

        let created = adapter
            .create_record("Foo", Some("a struct"), false, 5, 8, -1, 10, 20, 100, -1, -1)
            .unwrap();
        assert_eq!(created.get_key(), &Field::Long(Some(0)));
        adapter
            .create_record("Bar", None, true, 5, 4, -1, 10, 21, 100, -1, -1)
            .unwrap();

        assert_eq!(adapter.get_record_count(), 2);

        let fetched = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            fetched.get_field(COMPOSITE_NAME_COL),
            &Field::String(Some("Foo".to_string()))
        );
        assert_eq!(
            fetched.get_field(COMPOSITE_IS_UNION_COL),
            &Field::Boolean(Some(false))
        );

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
        updated.set_field(COMPOSITE_NAME_COL, Field::String(Some("Renamed".to_string())));
        adapter.update_record(&updated, true).unwrap();
        let refetched = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(COMPOSITE_NAME_COL),
            &Field::String(Some("Renamed".to_string()))
        );
        assert_eq!(
            refetched.get_field(COMPOSITE_LAST_CHANGE_TIME_COL),
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

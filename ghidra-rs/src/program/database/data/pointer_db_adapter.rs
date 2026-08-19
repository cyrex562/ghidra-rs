//! Port of `ghidra.program.database.data.PointerDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects and migrates between concrete
//! version-specific implementations (`PointerDBAdapterV0`/`V1`/`V2`). Those concrete adapters
//! have not been ported yet, so this port only models the abstract instance API each version
//! implements, as an object-safe trait; the version-selection/upgrade logic belongs with
//! whichever type ends up owning the concrete adapters. This trait was itself selected as a
//! dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field, RecordTranslator};
use crate::program::util::DBRecordAdapter;

/// Name of the database table used to store pointer data types.
pub const POINTER_TABLE_NAME: &str = "Pointers";

/// Column index of the pointer's referenced data type ID, as defined by `PointerDBAdapterV2`.
pub const PTR_DT_ID_COL: usize = 0;

/// Column index of the pointer's category ID, as defined by `PointerDBAdapterV2`.
pub const PTR_CATEGORY_COL: usize = 1;

/// Column index of the pointer's length in bytes, as defined by `PointerDBAdapterV2`.
pub const PTR_LENGTH_COL: usize = 2;

/// Adapter to access the Pointer database table for Pointer data types.
///
/// Port of `ghidra.program.database.data.PointerDBAdapter`.
pub trait PointerDBAdapter: DBRecordAdapter + RecordTranslator {
    /// Deletes the pointer table; used when upgrading.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Create a pointer record.
    ///
    /// `data_type_id` is the data type ID of the data type being pointed to, `category_id` is
    /// the category ID of the datatype, and `length` is the pointer size in bytes.
    fn create_record(
        &mut self,
        data_type_id: i64,
        category_id: i64,
        length: i32,
    ) -> io::Result<DBRecord>;

    /// Get the record with the given pointer ID, or `None` if not found.
    fn get_record(&self, pointer_id: i64) -> io::Result<Option<DBRecord>>;

    /// Delete the record with the given pointer ID. Returns `true` if the record was deleted.
    fn remove_record(&mut self, pointer_id: i64) -> io::Result<bool>;

    /// Update the record in the table.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Gets the IDs (as `Field::Long` values) of all pointer data types contained in the
    /// category with the given ID.
    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>>;
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

    struct MockPointerDBAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
        deleted: RefCell<bool>,
    }

    impl MockPointerDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                1,
                FieldType::Long,
                "Pointer ID".to_string(),
                vec![FieldType::Long, FieldType::Long, FieldType::Byte],
                vec![
                    "Data Type ID".to_string(),
                    "Category ID".to_string(),
                    "Length".to_string(),
                ],
                vec![],
            ));
            MockPointerDBAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(0),
                deleted: RefCell::new(false),
            }
        }
    }

    impl DBRecordAdapter for MockPointerDBAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn get_record_count(&self) -> usize {
            self.records.borrow().len()
        }
    }

    impl RecordTranslator for MockPointerDBAdapter {
        fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
            Ok(old_record)
        }
    }

    impl PointerDBAdapter for MockPointerDBAdapter {
        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            *self.deleted.borrow_mut() = true;
            self.records.borrow_mut().clear();
            Ok(())
        }

        fn create_record(
            &mut self,
            data_type_id: i64,
            category_id: i64,
            length: i32,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(PTR_DT_ID_COL, Field::Long(Some(data_type_id)));
            rec.set_field(PTR_CATEGORY_COL, Field::Long(Some(category_id)));
            rec.set_field(PTR_LENGTH_COL, Field::Byte(Some(length as i8)));
            self.records.borrow_mut().push(rec.clone());
            Ok(rec)
        }

        fn get_record(&self, pointer_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(pointer_id)))
                .cloned())
        }

        fn remove_record(&mut self, pointer_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(pointer_id)));
            Ok(records.len() != len_before)
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                *existing = record.clone();
            }
            Ok(())
        }

        fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(PTR_CATEGORY_COL), Field::Long(Some(v)) if *v == category_id)
                })
                .map(|r| r.get_key().clone())
                .collect())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_pointers() {
        let mut adapter: Box<dyn PointerDBAdapter> = Box::new(MockPointerDBAdapter::new());

        assert_eq!(adapter.get_record_count(), 0);

        let created = adapter.create_record(10, 5, 8).unwrap();
        assert_eq!(created.get_key(), &Field::Long(Some(0)));
        adapter.create_record(11, 5, 4).unwrap();
        adapter.create_record(12, 6, 8).unwrap();

        assert_eq!(adapter.get_record_count(), 3);

        let fetched = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(fetched.get_field(PTR_DT_ID_COL), &Field::Long(Some(10)));
        assert_eq!(fetched.get_field(PTR_LENGTH_COL), &Field::Byte(Some(8)));

        let ids_in_category = adapter.get_record_ids_in_category(5).unwrap();
        assert_eq!(ids_in_category.len(), 2);
        assert_eq!(adapter.get_record_ids_in_category(6).unwrap().len(), 1);

        let mut updated = fetched.clone();
        updated.set_field(PTR_LENGTH_COL, Field::Byte(Some(2)));
        adapter.update_record(&updated).unwrap();
        let refetched = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(refetched.get_field(PTR_LENGTH_COL), &Field::Byte(Some(2)));

        let translated = adapter.translate_record(refetched.clone()).unwrap();
        assert_eq!(translated.get_key(), refetched.get_key());

        let removed = adapter.remove_record(0).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 2);
        assert!(adapter.get_record(0).unwrap().is_none());

        {
            let mut iter = adapter.get_records().unwrap();
            assert!(iter.has_next());
            let first = iter.next().unwrap().expect("record present");
            assert_eq!(first.get_field(PTR_DT_ID_COL), &Field::Long(Some(11)));
        }

        let mut handle = DBHandle::new().unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }
}

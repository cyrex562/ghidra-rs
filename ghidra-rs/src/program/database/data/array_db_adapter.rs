//! Port of `ghidra.program.database.data.ArrayDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects and migrates between concrete
//! version-specific implementations (`ArrayDBAdapterV0`/`ArrayDBAdapterV1`). Those concrete
//! adapters have not been ported yet, so this port only models the abstract instance API each
//! version implements, as an object-safe trait; the version-selection/upgrade logic belongs with
//! whichever type ends up owning the concrete adapters. This trait was itself selected as a
//! dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator};

/// Adapter to access the Array database table for array data types.
///
/// Port of `ghidra.program.database.data.ArrayDBAdapter`.
pub trait ArrayDBAdapter {
    /// Create a new array data type record.
    fn create_record(
        &mut self,
        data_type_id: i64,
        number_of_elements: i32,
        length: i32,
        cat_id: i64,
    ) -> io::Result<DBRecord>;

    /// Get the record for the given array data type ID, or `None` if not found.
    fn get_record(&self, array_id: i64) -> io::Result<Option<DBRecord>>;

    /// Get an iterator over all array data type records.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Remove the record for the given array data type ID. Returns `true` if a record was
    /// removed.
    fn remove_record(&mut self, data_id: i64) -> io::Result<bool>;

    /// Update the array data type record in the table.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Delete the underlying database table.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Get the array data type record IDs contained within the specified category.
    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>>;

    /// Get the number of array datatype records.
    fn get_record_count(&self) -> i32;
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

    struct MockArrayDBAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
        deleted: RefCell<bool>,
    }

    impl MockArrayDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                1,
                FieldType::Long,
                "Array ID".to_string(),
                vec![FieldType::Long, FieldType::Int, FieldType::Int, FieldType::Long],
                vec![
                    "Data Type ID".to_string(),
                    "Number Of Elements".to_string(),
                    "Element Length".to_string(),
                    "Category ID".to_string(),
                ],
                vec![],
            ));
            MockArrayDBAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(0),
                deleted: RefCell::new(false),
            }
        }
    }

    impl ArrayDBAdapter for MockArrayDBAdapter {
        fn create_record(
            &mut self,
            data_type_id: i64,
            number_of_elements: i32,
            length: i32,
            cat_id: i64,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(0, Field::Long(Some(data_type_id)));
            rec.set_field(1, Field::Int(Some(number_of_elements)));
            rec.set_field(2, Field::Int(Some(length)));
            rec.set_field(3, Field::Long(Some(cat_id)));
            self.records.borrow_mut().push(rec.clone());
            Ok(rec)
        }

        fn get_record(&self, array_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(array_id)))
                .cloned())
        }

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn remove_record(&mut self, data_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(data_id)));
            Ok(records.len() != len_before)
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                *existing = record.clone();
            }
            Ok(())
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
                .filter(|r| matches!(r.get_field(3), Field::Long(Some(v)) if *v == category_id))
                .map(|r| r.get_key().clone())
                .collect())
        }

        fn get_record_count(&self) -> i32 {
            self.records.borrow().len() as i32
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let mut adapter: Box<dyn ArrayDBAdapter> = Box::new(MockArrayDBAdapter::new());

        assert_eq!(adapter.get_record_count(), 0);

        let rec = adapter.create_record(100, 4, 8, 55).unwrap();
        assert_eq!(adapter.get_record_count(), 1);

        let fetched = adapter
            .get_record(0)
            .unwrap()
            .expect("record should exist");
        assert_eq!(fetched.get_key(), rec.get_key());

        let ids = adapter.get_record_ids_in_category(55).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], Field::Long(Some(0)));

        {
            let mut iter = adapter.get_records().unwrap();
            assert!(iter.has_next());
            let first = iter.next().unwrap().expect("record present");
            assert_eq!(first.get_key(), rec.get_key());
        }

        let removed = adapter.remove_record(0).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 0);
        assert!(adapter.get_record(0).unwrap().is_none());
    }
}

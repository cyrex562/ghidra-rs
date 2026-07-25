//! Port of `ghidra.program.database.data.BuiltinDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`) selects the
//! concrete version-specific implementation (`BuiltinDBAdapterV0`). That concrete adapter has not
//! been ported yet, so this port only models the abstract instance API it implements, as an
//! object-safe trait; the version-selection logic belongs with whichever type ends up owning the
//! concrete adapter. This trait was itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, Field, RecordIterator};

/// Database adapter for managing built-in data types.
///
/// Port of `ghidra.program.database.data.BuiltinDBAdapter`.
pub trait BuiltinDBAdapter {
    /// Create a new built in types record.
    fn create_record(
        &mut self,
        name: &str,
        class_name: &str,
        category_id: i64,
    ) -> io::Result<DBRecord>;

    /// Gets the Built-in data type record with the indicated ID, or `None` if not found.
    fn get_record(&self, data_type_id: i64) -> io::Result<Option<DBRecord>>;

    /// Returns an array containing the data type IDs for the given category ID; empty if no
    /// built-in data types are found.
    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>>;

    /// Update the built-ins table with the given record.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Remove the record with the given dataID. Returns `true` if the record was deleted
    /// successfully.
    fn remove_record(&mut self, data_id: i64) -> io::Result<bool>;

    /// Returns an iterator over all records for built-in data types.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get the number of built-in datatype records.
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

    struct MockBuiltinDBAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
    }

    impl MockBuiltinDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                0,
                FieldType::Long,
                "Data Type ID".to_string(),
                vec![FieldType::String, FieldType::String, FieldType::Long],
                vec![
                    "Name".to_string(),
                    "Class Name".to_string(),
                    "Category ID".to_string(),
                ],
                vec![],
            ));
            MockBuiltinDBAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(100),
            }
        }
    }

    impl BuiltinDBAdapter for MockBuiltinDBAdapter {
        fn create_record(
            &mut self,
            name: &str,
            class_name: &str,
            category_id: i64,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(0, Field::String(Some(name.to_string())));
            rec.set_field(1, Field::String(Some(class_name.to_string())));
            rec.set_field(2, Field::Long(Some(category_id)));
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

        fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| matches!(r.get_field(2), Field::Long(Some(v)) if *v == category_id))
                .map(|r| r.get_key().clone())
                .collect())
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                *existing = record.clone();
            }
            Ok(())
        }

        fn remove_record(&mut self, data_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(data_id)));
            Ok(records.len() != len_before)
        }

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn get_record_count(&self) -> i32 {
            self.records.borrow().len() as i32
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let mut adapter: Box<dyn BuiltinDBAdapter> = Box::new(MockBuiltinDBAdapter::new());

        assert_eq!(adapter.get_record_count(), 0);

        let rec = adapter.create_record("undefined1", "ghidra.Undefined1", 42).unwrap();
        assert_eq!(adapter.get_record_count(), 1);

        let fetched = adapter
            .get_record(100)
            .unwrap()
            .expect("record should exist");
        assert_eq!(fetched.get_key(), rec.get_key());

        let ids = adapter.get_record_ids_in_category(42).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], Field::Long(Some(100)));

        {
            let mut iter = adapter.get_records().unwrap();
            assert!(iter.has_next());
            let first = iter.next().unwrap().expect("record present");
            assert_eq!(first.get_key(), rec.get_key());
        }

        let removed = adapter.remove_record(100).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 0);
        assert!(adapter.get_record(100).unwrap().is_none());
    }
}

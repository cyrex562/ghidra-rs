//! Reference record adapter.
//!
//! Port of `ghidra.program.database.references.RecordAdapter`.

use std::io;

use crate::framework::db::DBRecord;

/// Adapter interface for storing and retrieving reference records.
pub trait RecordAdapter {
    /// Create a new record with the given key and reference data.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_record(
        &mut self,
        key: i64,
        num_refs: i32,
        ref_level: u8,
        ref_data: &[u8],
    ) -> io::Result<DBRecord>;

    /// Get the record for the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_record(&self, key: i64) -> io::Result<DBRecord>;

    /// Store the given record.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn put_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Remove the record for the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_record(&mut self, key: i64) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Int],
            vec!["NumRefs".to_string()],
            vec![],
        ))
    }

    struct MockRecordAdapter {
        schema: Arc<Schema>,
        records: HashMap<i64, DBRecord>,
    }

    impl MockRecordAdapter {
        fn new() -> Self {
            Self {
                schema: test_schema(),
                records: HashMap::new(),
            }
        }
    }

    impl RecordAdapter for MockRecordAdapter {
        fn create_record(
            &mut self,
            key: i64,
            num_refs: i32,
            _ref_level: u8,
            _ref_data: &[u8],
        ) -> io::Result<DBRecord> {
            let mut record = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            record.set_int(0, num_refs);
            self.records.insert(key, record.clone());
            Ok(record)
        }

        fn get_record(&self, key: i64) -> io::Result<DBRecord> {
            self.records
                .get(&key)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "record not found"))
        }

        fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = record.get_key().get_long_value();
            self.records.insert(key, record.clone());
            Ok(())
        }

        fn remove_record(&mut self, key: i64) -> io::Result<()> {
            self.records.remove(&key);
            Ok(())
        }
    }

    #[test]
    fn create_get_put_remove_round_trip() {
        let mut adapter = MockRecordAdapter::new();

        let record = adapter.create_record(1, 3, 0, &[]).unwrap();
        assert_eq!(record.get_int(0).unwrap(), 3);

        let fetched = adapter.get_record(1).unwrap();
        assert_eq!(fetched.get_int(0).unwrap(), 3);

        let mut updated = fetched;
        updated.set_int(0, 7);
        adapter.put_record(&updated).unwrap();
        assert_eq!(adapter.get_record(1).unwrap().get_int(0).unwrap(), 7);

        adapter.remove_record(1).unwrap();
        assert!(adapter.get_record(1).is_err());
    }

    #[test]
    fn object_safety_via_trait_object() {
        let adapter: Box<dyn RecordAdapter> = Box::new(MockRecordAdapter::new());
        let mut adapter = adapter;
        adapter.create_record(5, 1, 0, &[]).unwrap();
        assert!(adapter.get_record(5).is_ok());
    }
}

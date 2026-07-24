//! Port of `ghidra.program.database.symbol.VariableStorageDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter` helper it delegates to) selects and migrates between concrete
//! version-specific implementations (`VariableStorageDBAdapterV2`, `VariableStorageDBAdapterNoTable`).
//! Those concrete adapters have not been ported yet, so this port only models the abstract
//! instance API each version implements, as an object-safe trait; the version-selection/upgrade
//! logic belongs with whichever type ends up owning the concrete adapters. This follows the same
//! convention already used for
//! [`FromAdapter`](crate::program::database::references::FromAdapter) and
//! [`CommentsDBAdapter`](crate::program::database::code::CommentsDBAdapter). This trait was
//! itself selected as a dependency-cycle cut-point.
//!
//! Likewise left out: the `VARIABLE_STORAGE_TABLE_NAME`/`VARIABLE_STORAGE_SCHEMA`/
//! `HASH_COL`/`STORAGE_COL` constants, since they describe a concrete table layout rather than
//! this trait's dynamic-dispatch surface; left for whichever concrete subclass is ported first.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};

/// Adapter to access the variable storage table, which maps a storage-address hash to its
/// serialized [`VariableStorage`](crate::program::seam_stubs::VariableStorage) representation.
///
/// Port of `ghidra.program.database.symbol.VariableStorageDBAdapter`. See the module docs for
/// what was intentionally left out (the static factory and table-layout constants).
pub trait VariableStorageDBAdapter {
    /// Update the given record in the table.
    ///
    /// Stands in for `VariableStorageDBAdapter.updateRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Get the record with the given key, or `None` if there is no such record.
    ///
    /// Stands in for `VariableStorageDBAdapter.getRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>>;

    /// Locate the record key which corresponds to the specified hash value, or `-1` if not
    /// found.
    ///
    /// Stands in for `VariableStorageDBAdapter.findRecordKey(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn find_record_key(&self, hash: i64) -> io::Result<i64>;

    /// Get the next available storage ID (record key).
    ///
    /// Stands in for `VariableStorageDBAdapter.getNextStorageID()`.
    fn get_next_storage_id(&mut self) -> i64;

    /// Delete the record with the given key.
    ///
    /// Stands in for `VariableStorageDBAdapter.deleteRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn delete_record(&mut self, key: i64) -> io::Result<()>;

    /// Get an iterator over all records in the table.
    ///
    /// Stands in for `VariableStorageDBAdapter.getRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns the number of records in the table.
    ///
    /// Stands in for `VariableStorageDBAdapter.getRecordCount()`.
    fn get_record_count(&self) -> i32;

    /// Delete the entire table.
    ///
    /// Stands in for `VariableStorageDBAdapter.deleteTable()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn delete_table(&mut self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            2,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long, FieldType::String],
            vec!["Hash".to_string(), "Storage".to_string()],
            vec![],
        ))
    }

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

    struct MockVariableStorageDBAdapter {
        schema: Arc<Schema>,
        records: HashMap<i64, DBRecord>,
        next_key: i64,
    }

    impl MockVariableStorageDBAdapter {
        fn new() -> Self {
            MockVariableStorageDBAdapter {
                schema: test_schema(),
                records: HashMap::new(),
                next_key: 0,
            }
        }

        fn add(&mut self, hash: i64, storage: &str) -> i64 {
            let key = self.get_next_storage_id();
            let mut record = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            record.set_long(0, hash);
            record.set_string(1, Some(storage.to_string()));
            self.records.insert(key, record);
            key
        }
    }

    impl VariableStorageDBAdapter for MockVariableStorageDBAdapter {
        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = record.get_key().get_long_value();
            self.records.insert(key, record.clone());
            Ok(())
        }

        fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&key).cloned())
        }

        fn find_record_key(&self, hash: i64) -> io::Result<i64> {
            for (key, record) in &self.records {
                if record.get_long(0) == Some(hash) {
                    return Ok(*key);
                }
            }
            Ok(-1)
        }

        fn get_next_storage_id(&mut self) -> i64 {
            let key = self.next_key;
            self.next_key += 1;
            key
        }

        fn delete_record(&mut self, key: i64) -> io::Result<()> {
            self.records.remove(&key);
            Ok(())
        }

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let mut records: Vec<DBRecord> = self.records.values().cloned().collect();
            records.sort_by_key(|r| r.get_key().get_long_value());
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_record_count(&self) -> i32 {
            self.records.len() as i32
        }

        fn delete_table(&mut self) -> io::Result<()> {
            self.records.clear();
            Ok(())
        }
    }

    #[test]
    fn create_lookup_and_delete_round_trip() {
        let mut adapter = MockVariableStorageDBAdapter::new();
        let key = adapter.add(0xdead_beef, "stack:-0x10:4");

        let record = adapter.get_record(key).unwrap().expect("record present");
        assert_eq!(record.get_string(1), Some("stack:-0x10:4"));

        assert_eq!(adapter.find_record_key(0xdead_beef).unwrap(), key);
        assert_eq!(adapter.find_record_key(0x1234).unwrap(), -1);

        assert_eq!(adapter.get_record_count(), 1);
        adapter.delete_record(key).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
        assert!(adapter.get_record(key).unwrap().is_none());
    }

    #[test]
    fn object_safety_via_trait_object() {
        let mut adapter: Box<dyn VariableStorageDBAdapter> =
            Box::new(MockVariableStorageDBAdapter::new());

        let key = adapter.get_next_storage_id();
        let mut record = DBRecord::new(test_schema(), Field::Long(Some(key)));
        record.set_long(0, 42);
        record.set_string(1, Some("register:EAX:4".to_string()));
        adapter.update_record(&record).unwrap();

        assert_eq!(adapter.get_record_count(), 1);

        let mut seen = 0;
        {
            let mut iter = adapter.get_records().unwrap();
            while let Some(_rec) = iter.next().unwrap() {
                seen += 1;
            }
        }
        assert_eq!(seen, 1);

        adapter.delete_table().unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }
}

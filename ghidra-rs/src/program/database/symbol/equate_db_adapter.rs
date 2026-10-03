//! Port of `ghidra.program.database.symbol.EquateDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`) selects between
//! concrete version-specific implementations (`EquateDBAdapterV0`). That concrete adapter has not
//! been ported yet, so this port only models the abstract instance API it implements, as an
//! object-safe trait; the version-selection logic belongs with whichever type ends up owning the
//! concrete adapter. This follows the same convention already used for
//! [`VariableStorageDBAdapter`](crate::program::database::symbol::VariableStorageDBAdapter) and
//! [`SymbolDatabaseAdapter`](crate::program::database::symbol::SymbolDatabaseAdapter). This trait
//! was itself selected as a dependency-cycle cut-point.
//!
//! Likewise left out: the `EQUATES_TABLE_NAME`/`EQUATES_SCHEMA`/`NAME_COL`/`VALUE_COL` constants,
//! since they describe a concrete table layout rather than this trait's dynamic-dispatch surface;
//! left for whichever concrete subclass is ported first.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::util::exception::NotFoundException;

/// Error returned by [`EquateDBAdapter::get_record_key`].
///
/// Stands in for the `IOException`/`NotFoundException` pair thrown by
/// `EquateDBAdapter.getRecordKey(String)`.
#[derive(Debug, thiserror::Error)]
pub enum GetRecordKeyError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    NotFound(#[from] NotFoundException),
}

/// Adapter to access records in the Equate table.
///
/// Port of `ghidra.program.database.symbol.EquateDBAdapter`. See the module docs for what was
/// intentionally left out (the static factory and table-layout constants).
pub trait EquateDBAdapter {
    /// Get the record key for the given name.
    ///
    /// Stands in for `EquateDBAdapter.getRecordKey(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database, or if there is no equate
    /// with the given name.
    fn get_record_key(&self, name: &str) -> Result<i64, GetRecordKeyError>;

    /// Get the record for the given key.
    ///
    /// Stands in for `EquateDBAdapter.getRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no equate with the given key.
    fn get_record(&self, key: i64) -> io::Result<DBRecord>;

    /// Remove the record with the given key.
    ///
    /// Stands in for `EquateDBAdapter.removeRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_record(&mut self, key: i64) -> io::Result<()>;

    /// Update the table with the given record.
    ///
    /// Stands in for `EquateDBAdapter.updateRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Create a new record for the equate.
    ///
    /// Stands in for `EquateDBAdapter.createEquate(String, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_equate(&mut self, name: &str, value: i64) -> io::Result<DBRecord>;

    /// Get an iterator over all the equate records.
    ///
    /// Stands in for `EquateDBAdapter.getRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns true if an equate record exists with the given name.
    ///
    /// Stands in for `EquateDBAdapter.hasRecord(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn has_record(&self, name: &str) -> io::Result<bool>;
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
            vec![FieldType::String, FieldType::Long],
            vec!["Equate Name".to_string(), "Equate Value".to_string()],
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

    struct MockEquateDBAdapter {
        schema: Arc<Schema>,
        records: HashMap<i64, DBRecord>,
        next_key: i64,
    }

    impl MockEquateDBAdapter {
        fn new() -> Self {
            MockEquateDBAdapter {
                schema: test_schema(),
                records: HashMap::new(),
                next_key: 0,
            }
        }
    }

    impl EquateDBAdapter for MockEquateDBAdapter {
        fn get_record_key(&self, name: &str) -> Result<i64, GetRecordKeyError> {
            for (key, record) in &self.records {
                if record.get_string(0) == Some(name) {
                    return Ok(*key);
                }
            }
            Err(GetRecordKeyError::NotFound(NotFoundException::with_message(format!(
                "No equate named {name}"
            ))))
        }

        fn get_record(&self, key: i64) -> io::Result<DBRecord> {
            self.records
                .get(&key)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such equate record"))
        }

        fn remove_record(&mut self, key: i64) -> io::Result<()> {
            self.records.remove(&key);
            Ok(())
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = record.get_key().get_long_value();
            self.records.insert(key, record.clone());
            Ok(())
        }

        fn create_equate(&mut self, name: &str, value: i64) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            let mut record = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            record.set_string(0, Some(name.to_string()));
            record.set_long(1, value);
            self.records.insert(key, record.clone());
            Ok(record)
        }

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let mut records: Vec<DBRecord> = self.records.values().cloned().collect();
            records.sort_by_key(|r| r.get_key().get_long_value());
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn has_record(&self, name: &str) -> io::Result<bool> {
            Ok(self.records.values().any(|r| r.get_string(0) == Some(name)))
        }
    }

    #[test]
    fn create_lookup_and_remove_round_trip() {
        let mut adapter = MockEquateDBAdapter::new();
        let record = adapter.create_equate("FOO", 42).unwrap();
        let key = record.get_key().get_long_value();

        assert!(adapter.has_record("FOO").unwrap());
        assert!(!adapter.has_record("BAR").unwrap());

        let key2 = adapter.get_record_key("FOO").unwrap();
        assert_eq!(key, key2);

        let fetched = adapter.get_record(key).unwrap();
        assert_eq!(fetched.get_long(1), Some(42));

        adapter.remove_record(key).unwrap();
        assert!(!adapter.has_record("FOO").unwrap());
        assert!(matches!(
            adapter.get_record_key("FOO"),
            Err(GetRecordKeyError::NotFound(_))
        ));
    }

    #[test]
    fn object_safety_via_trait_object() {
        let mut adapter: Box<dyn EquateDBAdapter> = Box::new(MockEquateDBAdapter::new());

        adapter.create_equate("ONE", 1).unwrap();
        adapter.create_equate("TWO", 2).unwrap();

        let mut seen = 0;
        {
            let mut iter = adapter.get_records().unwrap();
            while let Some(_rec) = iter.next().unwrap() {
                seen += 1;
            }
        }
        assert_eq!(seen, 2);

        let key = adapter.get_record_key("TWO").unwrap();
        let mut record = adapter.get_record(key).unwrap();
        record.set_long(1, 22);
        adapter.update_record(&record).unwrap();
        assert_eq!(adapter.get_record(key).unwrap().get_long(1), Some(22));
    }
}

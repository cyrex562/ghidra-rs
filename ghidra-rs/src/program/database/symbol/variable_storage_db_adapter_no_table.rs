//! Port of `ghidra.program.database.symbol.VariableStorageDBAdapterNoTable`.
//!
//! Adapter used when a program is being opened read-only and the variable storage table does not
//! exist in the program.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::database::symbol::VariableStorageDBAdapter;

/// A `RecordIterator` that never yields any records, used in place of the unported
/// `ghidra.program.database.util.EmptyRecordIterator`, mirroring the convention already used by
/// e.g. [`EnumDBAdapterNoTable`](crate::program::database::data::enum_db_adapter_no_table).
struct EmptyRecordIterator;

impl RecordIterator for EmptyRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn has_next(&self) -> bool {
        false
    }
}

/// Adapter needed when a program is being opened read-only and the variable storage table does
/// not exist in the program.
///
/// Port of `ghidra.program.database.symbol.VariableStorageDBAdapterNoTable`.
#[derive(Debug, Default)]
pub struct VariableStorageDBAdapterNoTable;

impl VariableStorageDBAdapterNoTable {
    /// Constructs a new adapter. The Java constructor takes no arguments either.
    pub fn new() -> Self {
        VariableStorageDBAdapterNoTable
    }
}

impl VariableStorageDBAdapter for VariableStorageDBAdapterNoTable {
    fn update_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no variable storage table exists",
        ))
    }

    fn get_record(&self, _key: i64) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn find_record_key(&self, _hash: i64) -> io::Result<i64> {
        Ok(-1)
    }

    fn get_next_storage_id(&mut self) -> i64 {
        // Stands in for `VariableStorageDBAdapterNoTable.getNextStorageID()`, which throws
        // `UnsupportedOperationException`; the trait method has no way to return an error here.
        panic!("no variable storage table exists")
    }

    fn delete_record(&mut self, _key: i64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no variable storage table exists",
        ))
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator))
    }

    fn get_record_count(&self) -> i32 {
        0
    }

    fn delete_table(&mut self) -> io::Result<()> {
        // do nothing
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups_are_empty_or_none() {
        let adapter = VariableStorageDBAdapterNoTable::new();
        assert!(adapter.get_record(0).unwrap().is_none());
        assert_eq!(adapter.find_record_key(42).unwrap(), -1);
        assert_eq!(adapter.get_record_count(), 0);

        let mut iter = adapter.get_records().unwrap();
        assert!(!iter.has_next());
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn mutations_are_unsupported_or_noop() {
        let mut adapter = VariableStorageDBAdapterNoTable::new();
        let schema = std::sync::Arc::new(crate::framework::db::Schema::new(
            2,
            crate::framework::db::FieldType::Long,
            "Key".to_string(),
            vec![],
            vec![],
            vec![],
        ));
        let record = DBRecord::new(schema, crate::framework::db::Field::Long(Some(0)));

        assert_eq!(
            adapter.update_record(&record).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.delete_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        adapter.delete_table().unwrap();
    }

    #[test]
    #[should_panic]
    fn get_next_storage_id_panics() {
        let mut adapter = VariableStorageDBAdapterNoTable::new();
        adapter.get_next_storage_id();
    }

    #[test]
    fn behaves_as_trait_object() {
        let adapter: Box<dyn VariableStorageDBAdapter> = Box::new(VariableStorageDBAdapterNoTable::new());
        assert_eq!(adapter.get_record_count(), 0);
    }
}

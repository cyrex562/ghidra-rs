//! Port of `ghidra.program.database.data.EnumValueDBAdapterNoTable`.
//!
//! Adapter needed for a read-only version of a data type manager that is not going to be
//! upgraded, and there is no Enumeration Data Type Values table in the data type manager.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator};
use crate::program::database::data::enum_value_db_adapter::EnumValueDBAdapter;
use crate::program::util::DBRecordAdapter;

/// A `RecordIterator` that never yields any records, used in place of the unported
/// `ghidra.program.database.util.EmptyRecordIterator`.
struct EmptyRecordIterator;

impl RecordIterator for EmptyRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn has_next(&self) -> bool {
        false
    }
}

/// Adapter needed for a read-only version of a data type manager that is not going to be
/// upgraded, and there is no Enumeration Data Type Values table in the data type manager.
///
/// Port of `ghidra.program.database.data.EnumValueDBAdapterNoTable`.
#[derive(Debug, Default)]
pub struct EnumValueDBAdapterNoTable;

impl EnumValueDBAdapterNoTable {
    /// Gets a pre-table version of the adapter for the enumeration data type values database
    /// table.
    ///
    /// `_handle` is the handle to the database which doesn't contain the table (unused: no table
    /// is needed).
    pub fn new(_handle: &DBHandle) -> Self {
        EnumValueDBAdapterNoTable
    }
}

impl DBRecordAdapter for EnumValueDBAdapterNoTable {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator))
    }

    fn get_record_count(&self) -> usize {
        0
    }
}

impl RecordTranslator for EnumValueDBAdapterNoTable {
    fn translate_record(&self, _old_record: DBRecord) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no enumeration data type values table exists",
        ))
    }
}

impl EnumValueDBAdapter for EnumValueDBAdapterNoTable {
    fn create_record(
        &mut self,
        _enum_id: i64,
        _name: &str,
        _value: i64,
        _comment: Option<&str>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no enumeration data type values table exists",
        ))
    }

    fn get_record(&self, _value_id: i64) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
        // do nothing
        Ok(())
    }

    fn remove_record(&mut self, _value_id: i64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no enumeration data type values table exists",
        ))
    }

    fn update_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no enumeration data type values table exists",
        ))
    }

    fn get_value_ids_in_enum(&self, _enum_id: i64) -> io::Result<Vec<Field>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> EnumValueDBAdapterNoTable {
        EnumValueDBAdapterNoTable::new(&DBHandle::new().unwrap())
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let mut adapter = adapter();
        assert_eq!(
            adapter
                .create_record(1, "Red", 0, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let dummy = DBRecord::new(
            std::sync::Arc::new(crate::framework::db::Schema::new(
                1,
                crate::framework::db::FieldType::Long,
                "ID".to_string(),
                vec![],
                vec![],
                vec![],
            )),
            Field::Long(Some(0)),
        );
        assert_eq!(
            adapter.update_record(&dummy).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.translate_record(dummy).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn lookups_are_empty_or_none() {
        let adapter = adapter();
        assert!(adapter.get_record(0).unwrap().is_none());
        assert!(adapter.get_value_ids_in_enum(0).unwrap().is_empty());
        assert_eq!(adapter.get_record_count(), 0);
        let mut iter = adapter.get_records().unwrap();
        assert!(!iter.has_next());
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn delete_table_is_a_no_op() {
        let mut adapter = adapter();
        let mut handle = DBHandle::new().unwrap();
        adapter.delete_table(&mut handle).unwrap();
    }

    #[test]
    fn behaves_as_trait_object() {
        let adapter: Box<dyn EnumValueDBAdapter> = Box::new(adapter());
        assert!(adapter.get_record(0).unwrap().is_none());
    }
}

//! Port of `ghidra.program.database.data.FunctionParameterAdapterNoTable`.
//!
//! Adapter needed for a read-only version of a data type manager that is not going to be
//! upgraded, and there is no Function Definition Parameters table in the data type manager.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator};
use crate::program::database::data::function_parameter_adapter::FunctionParameterAdapter;

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
/// upgraded, and there is no Function Definition Parameters table in the data type manager.
///
/// Port of `ghidra.program.database.data.FunctionParameterAdapterNoTable`.
#[derive(Debug, Default)]
pub struct FunctionParameterAdapterNoTable;

impl FunctionParameterAdapterNoTable {
    /// Gets a pre-table version of the adapter for the Function Definition Parameters database
    /// table.
    ///
    /// `_handle` is the handle to the database which doesn't contain the table (unused: no table
    /// is required).
    pub fn new(_handle: &DBHandle) -> Self {
        FunctionParameterAdapterNoTable
    }
}

impl FunctionParameterAdapter for FunctionParameterAdapterNoTable {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator))
    }

    fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
        // do nothing
        Ok(())
    }

    fn create_record(
        &mut self,
        _data_type_id: i64,
        _parent_id: i64,
        _ordinal: i32,
        _name: Option<&str>,
        _comment: Option<&str>,
        _dt_length: i32,
    ) -> io::Result<DBRecord> {
        // The Java method returns `null` here rather than throwing, unlike its sibling
        // no-table adapters; since this trait's `create_record` cannot return null, we surface
        // an `Unsupported` error instead, matching the effective "this must never really be
        // called" intent.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no function definition parameters table exists",
        ))
    }

    fn get_record(&self, _parameter_id: i64) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn update_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no function definition parameters table exists",
        ))
    }

    fn remove_record(&mut self, _parameter_id: i64) -> io::Result<bool> {
        Ok(false)
    }

    fn get_parameter_ids_in_function_def(&self, _function_def_id: i64) -> io::Result<Vec<Field>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> FunctionParameterAdapterNoTable {
        FunctionParameterAdapterNoTable::new(&DBHandle::new().unwrap())
    }

    #[test]
    fn create_and_update_record_are_unsupported() {
        let mut adapter = adapter();
        assert_eq!(
            adapter
                .create_record(1, 2, 0, Some("p"), None, -1)
                .unwrap_err()
                .kind(),
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
    }

    #[test]
    fn lookups_are_empty_or_none() {
        let adapter = adapter();
        assert!(adapter.get_record(0).unwrap().is_none());
        assert!(adapter.get_parameter_ids_in_function_def(0).unwrap().is_empty());
        let mut iter = adapter.get_records().unwrap();
        assert!(!iter.has_next());
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn remove_record_and_delete_table_succeed_as_no_ops() {
        let mut adapter = adapter();
        assert!(!adapter.remove_record(0).unwrap());
        let mut handle = DBHandle::new().unwrap();
        adapter.delete_table(&mut handle).unwrap();
    }

    #[test]
    fn behaves_as_trait_object() {
        let adapter: Box<dyn FunctionParameterAdapter> = Box::new(adapter());
        assert!(adapter.get_record(0).unwrap().is_none());
    }
}

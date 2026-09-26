//! Port of `ghidra.program.database.function.FunctionTagMappingAdapterNoTable`.
//!
//! Adapter for the read-only version of the function tag mapping adapter that cannot be upgraded
//! (i.e. no Function Tags mapping table exists in the program). Mirrors the shape already
//! established by [`EnumValueDBAdapterNoTable`](crate::program::database::data::EnumValueDBAdapterNoTable)
//! and its siblings: mutating operations report [`io::ErrorKind::Unsupported`] (standing in for
//! Java's `UnsupportedOperationException`), lookups report "nothing found", and record iteration
//! is always empty.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, RecordIterator};
use crate::program::database::function::function_tag_mapping_adapter::FunctionTagMappingAdapter;

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

/// Adapter for the read-only version of the function tag mapping adapter that cannot be upgraded.
///
/// Port of `ghidra.program.database.function.FunctionTagMappingAdapterNoTable`.
#[derive(Debug, Default)]
pub struct FunctionTagMappingAdapterNoTable;

impl FunctionTagMappingAdapterNoTable {
    /// Gets a pre-table version of the adapter for the function tag mapping database table.
    ///
    /// `_handle` is the handle to the database which doesn't contain the table (unused: no table
    /// is needed).
    pub fn new(_handle: &DBHandle) -> Self {
        FunctionTagMappingAdapterNoTable
    }
}

impl FunctionTagMappingAdapter for FunctionTagMappingAdapterNoTable {
    fn get_records_by_function_id(&self, _function_id: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator))
    }

    fn get_record(&self, _function_id: i64, _tag_id: i64) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn create_function_tag_record(&mut self, _function_id: i64, _tag_id: i64) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "create record not supported",
        ))
    }

    fn remove_function_tag_record(&mut self, _function_id: i64, _tag_id: i64) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "remove record not supported",
        ))
    }

    fn remove_function_tag_records_for_tag(&mut self, _tag_id: i64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "remove record not supported",
        ))
    }

    fn is_tag_assigned(&self, _id: i64) -> io::Result<bool> {
        Ok(false)
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> FunctionTagMappingAdapterNoTable {
        FunctionTagMappingAdapterNoTable::new(&DBHandle::new().unwrap())
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let mut adapter = adapter();
        assert_eq!(
            adapter.create_function_tag_record(1, 2).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_function_tag_record(1, 2).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_function_tag_records_for_tag(2).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn lookups_are_empty_or_none() {
        let adapter = adapter();
        assert!(adapter.get_record(1, 2).unwrap().is_none());
        assert!(!adapter.is_tag_assigned(2).unwrap());

        let mut by_function = adapter.get_records_by_function_id(1).unwrap();
        assert!(!by_function.has_next());
        assert!(by_function.next().unwrap().is_none());

        let mut all = adapter.get_records().unwrap();
        assert!(!all.has_next());
        assert!(all.next().unwrap().is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let adapter: Box<dyn FunctionTagMappingAdapter> = Box::new(adapter());
        assert!(adapter.get_record(1, 2).unwrap().is_none());
    }
}

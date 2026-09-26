//! Port of `ghidra.program.database.data.FunctionDefinitionDBAdapterNoTable`.
//!
//! Adapter needed for a read-only version of a data type manager that is not going to be
//! upgraded, and there is no Function Signature Definition table in the data type manager.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator};
use crate::program::database::data::function_definition_db_adapter::FunctionDefinitionDBAdapter;
use crate::program::util::DBRecordAdapter;
use crate::util::UniversalID;

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
/// upgraded, and there is no Function Signature Definition table in the data type manager.
///
/// Port of `ghidra.program.database.data.FunctionDefinitionDBAdapterNoTable`.
#[derive(Debug, Default)]
pub struct FunctionDefinitionDBAdapterNoTable;

impl FunctionDefinitionDBAdapterNoTable {
    /// `_handle` is the handle to the database which doesn't contain the table (unused: no table
    /// is required).
    pub fn new(_handle: &DBHandle) -> Self {
        FunctionDefinitionDBAdapterNoTable
    }
}

impl DBRecordAdapter for FunctionDefinitionDBAdapterNoTable {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator))
    }

    fn get_record_count(&self) -> usize {
        0
    }
}

impl FunctionDefinitionDBAdapter for FunctionDefinitionDBAdapterNoTable {
    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        _name: &str,
        _comments: Option<&str>,
        _category_id: i64,
        _return_dt_id: i64,
        _has_no_return: bool,
        _has_var_args: bool,
        _calling_convention_id: u8,
        _source_archive_id: i64,
        _source_data_type_id: i64,
        _last_change_time: i64,
    ) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no function definitions table exists",
        ))
    }

    fn get_record(&self, _function_def_id: i64) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn remove_record(&mut self, _function_def_id: i64) -> io::Result<bool> {
        Ok(false)
    }

    fn update_record(&mut self, _record: &DBRecord, _set_last_change_time: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no function definitions table exists",
        ))
    }

    fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
        // do nothing
        Ok(())
    }

    fn get_record_ids_in_category(&self, _category_id: i64) -> io::Result<Vec<Field>> {
        Ok(Vec::new())
    }

    fn get_record_ids_for_source_archive(&self, _archive_id: i64) -> io::Result<Vec<Field>> {
        Ok(Vec::new())
    }

    fn get_record_with_ids(
        &self,
        _source_id: UniversalID,
        _datatype_id: UniversalID,
    ) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> FunctionDefinitionDBAdapterNoTable {
        FunctionDefinitionDBAdapterNoTable::new(&DBHandle::new().unwrap())
    }

    #[test]
    fn create_and_update_record_are_unsupported() {
        let mut adapter = adapter();
        assert_eq!(
            adapter
                .create_record("foo", None, 5, 42, false, false, 0, 0, 0, 0)
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
            adapter.update_record(&dummy, true).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn lookups_are_empty_or_none() {
        let adapter = adapter();
        assert!(adapter.get_record(0).unwrap().is_none());
        assert!(adapter.get_record_ids_in_category(0).unwrap().is_empty());
        assert!(adapter
            .get_record_ids_for_source_archive(0)
            .unwrap()
            .is_empty());
        assert!(adapter
            .get_record_with_ids(UniversalID::new(1), UniversalID::new(2))
            .unwrap()
            .is_none());
        assert_eq!(adapter.get_record_count(), 0);
        assert!(!adapter.uses_generic_calling_convention_id());
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
        let adapter: Box<dyn FunctionDefinitionDBAdapter> = Box::new(adapter());
        assert!(adapter.get_record(0).unwrap().is_none());
    }
}

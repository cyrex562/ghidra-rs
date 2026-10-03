//! Port of `ghidra.program.database.data.FunctionParameterAdapterV0`.
//!
//! Version 0 implementation for accessing the Function Definition Parameters database table.
//! This version's on-disk records have no "Data Type Length" column; [`translate_record`]
//! synthesizes a value of `1` for it (matching the Java `translateRecord`'s literal `1`, which
//! looks like a historical quirk since every other V0 adapter in this family synthesizes `-1`
//! for "unknown length" -- preserved here rather than "fixed", since this port mirrors observed
//! behavior).
//!
//! [`translate_record`]: RecordTranslator::translate_record
//!
//! The V0 table predates `tablePrefix` support (introduced in V1), so it is always looked up
//! under the bare [`PARAMETER_TABLE_NAME`] with no prefix.
//!
//! Unlike [`FunctionParameterAdapterV1`](super::function_parameter_adapter_v1::FunctionParameterAdapterV1),
//! this version is read-only: `create_record` and `update_record` mirror the Java
//! `UnsupportedOperationException`, while `remove_record` mirrors Java's `return false` (no
//! records are ever removable from a V0 table, but that isn't reported as an error).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::function_parameter_adapter::{
    self, FunctionParameterAdapter, PARAMETER_COMMENT_COL, PARAMETER_DT_ID_COL,
    PARAMETER_DT_LENGTH_COL, PARAMETER_NAME_COL, PARAMETER_ORDINAL_COL, PARAMETER_PARENT_ID_COL,
    PARAMETER_TABLE_NAME,
};
use crate::util::exception::VersionException;

/// Column index of the parameter's parent function definition ID, as defined by
/// `FunctionParameterAdapterV0`.
pub const V0_PARAMETER_PARENT_ID_COL: usize = 0;

/// Column index of the parameter's data type ID, as defined by `FunctionParameterAdapterV0`.
pub const V0_PARAMETER_DT_ID_COL: usize = 1;

/// Column index of the parameter's name, as defined by `FunctionParameterAdapterV0`.
pub const V0_PARAMETER_NAME_COL: usize = 2;

/// Column index of the parameter's comment, as defined by `FunctionParameterAdapterV0`.
pub const V0_PARAMETER_COMMENT_COL: usize = 3;

/// Column index of the parameter's ordinal, as defined by `FunctionParameterAdapterV0`.
pub const V0_PARAMETER_ORDINAL_COL: usize = 4;

/// A `RecordIterator` over an eagerly-collected, already-translated set of records.
struct VecRecordIterator {
    records: std::vec::IntoIter<DBRecord>,
}

impl RecordIterator for VecRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.records.next())
    }

    fn has_next(&self) -> bool {
        self.records.len() > 0
    }
}

/// Version 0 implementation for accessing the Function Definition Parameters database table.
///
/// Port of `ghidra.program.database.data.FunctionParameterAdapterV0`.
pub struct FunctionParameterAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl FunctionParameterAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the Function Definition Parameter database table.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle
            .get_table(PARAMETER_TABLE_NAME)
            .ok_or_else(|| VersionException::with_upgradeable(true))?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
        }
        Ok(FunctionParameterAdapterV0 { table })
    }
}

impl RecordTranslator for FunctionParameterAdapterV0 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(function_parameter_adapter::schema(), old_record.get_key().clone());
        rec.set_field(
            PARAMETER_PARENT_ID_COL,
            old_record.get_field(V0_PARAMETER_PARENT_ID_COL).clone(),
        );
        rec.set_field(
            PARAMETER_DT_ID_COL,
            old_record.get_field(V0_PARAMETER_DT_ID_COL).clone(),
        );
        rec.set_field(
            PARAMETER_NAME_COL,
            old_record.get_field(V0_PARAMETER_NAME_COL).clone(),
        );
        rec.set_field(
            PARAMETER_COMMENT_COL,
            old_record.get_field(V0_PARAMETER_COMMENT_COL).clone(),
        );
        rec.set_field(
            PARAMETER_ORDINAL_COL,
            old_record.get_field(V0_PARAMETER_ORDINAL_COL).clone(),
        );
        rec.set_field(PARAMETER_DT_LENGTH_COL, Field::Int(Some(1)));
        Ok(rec)
    }
}

impl FunctionParameterAdapter for FunctionParameterAdapterV0 {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut translated = Vec::new();
        while let Some(rec) = iter.next()? {
            translated.push(self.translate_record(rec)?);
        }
        Ok(Box::new(VecRecordIterator {
            records: translated.into_iter(),
        }))
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(PARAMETER_TABLE_NAME);
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
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot create records in Version 0",
        ))
    }

    fn get_record(&self, parameter_id: i64) -> io::Result<Option<DBRecord>> {
        let old = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(parameter_id)))?;
        match old {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

    fn update_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update records in Version 0",
        ))
    }

    fn remove_record(&mut self, _parameter_id: i64) -> io::Result<bool> {
        Ok(false)
    }

    fn get_parameter_ids_in_function_def(&self, function_def_id: i64) -> io::Result<Vec<Field>> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(V0_PARAMETER_PARENT_ID_COL), Field::Long(Some(v)) if *v == function_def_id)
            {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};

    fn v0_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Parameter ID".to_string(),
            vec![
                FieldType::Long,
                FieldType::Long,
                FieldType::String,
                FieldType::String,
                FieldType::Int,
            ],
            vec![
                "Parent ID".to_string(),
                "Data Type ID".to_string(),
                "Name".to_string(),
                "Comment".to_string(),
                "Ordinal".to_string(),
            ],
            vec![],
        ))
    }

    fn make_handle_with_v0_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(PARAMETER_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        for (parent_id, dt_id, name, ordinal) in
            [(5i64, 42i64, "param1", 0i32), (5, 43, "param2", 1), (9, 44, "param3", 0)]
        {
            let key = t.get_next_key();
            let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(key)));
            rec.set_field(V0_PARAMETER_PARENT_ID_COL, Field::Long(Some(parent_id)));
            rec.set_field(V0_PARAMETER_DT_ID_COL, Field::Long(Some(dt_id)));
            rec.set_field(
                V0_PARAMETER_NAME_COL,
                Field::String(Some(name.to_string())),
            );
            rec.set_field(V0_PARAMETER_COMMENT_COL, Field::String(None));
            rec.set_field(V0_PARAMETER_ORDINAL_COL, Field::Int(Some(ordinal)));
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(FunctionParameterAdapterV0::new(&handle).is_err());
    }

    #[test]
    fn get_record_translates_to_current_schema_with_synthesized_length() {
        let handle = make_handle_with_v0_table();
        let adapter = FunctionParameterAdapterV0::new(&handle).unwrap();

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(PARAMETER_NAME_COL),
            &Field::String(Some("param1".to_string()))
        );
        assert_eq!(rec.get_field(PARAMETER_DT_ID_COL), &Field::Long(Some(42)));
        assert_eq!(rec.get_field(PARAMETER_DT_LENGTH_COL), &Field::Int(Some(1)));
    }

    #[test]
    fn get_records_yields_translated_records() {
        let handle = make_handle_with_v0_table();
        let adapter = FunctionParameterAdapterV0::new(&handle).unwrap();

        let mut iter = adapter.get_records().unwrap();
        let mut count = 0;
        while let Some(rec) = iter.next().unwrap() {
            assert_eq!(rec.get_field(PARAMETER_DT_LENGTH_COL), &Field::Int(Some(1)));
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn get_parameter_ids_in_function_def_filters_by_parent() {
        let handle = make_handle_with_v0_table();
        let adapter = FunctionParameterAdapterV0::new(&handle).unwrap();

        assert_eq!(
            adapter.get_parameter_ids_in_function_def(5).unwrap().len(),
            2
        );
        assert_eq!(
            adapter.get_parameter_ids_in_function_def(9).unwrap().len(),
            1
        );
    }

    #[test]
    fn mutating_operations_are_unsupported_or_no_op() {
        let handle = make_handle_with_v0_table();
        let mut adapter = FunctionParameterAdapterV0::new(&handle).unwrap();

        assert_eq!(
            adapter
                .create_record(1, 2, 0, None, None, -1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let existing = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            adapter.update_record(&existing).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(adapter.remove_record(0).unwrap(), false);
    }

    #[test]
    fn delete_table_removes_it_from_handle() {
        let mut handle = make_handle_with_v0_table();
        let mut adapter = FunctionParameterAdapterV0::new(&handle).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table(PARAMETER_TABLE_NAME).is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_v0_table();
        let adapter: Box<dyn FunctionParameterAdapter> =
            Box::new(FunctionParameterAdapterV0::new(&handle).unwrap());
        let mut iter = adapter.get_records().unwrap();
        let mut count = 0;
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 3);
    }
}

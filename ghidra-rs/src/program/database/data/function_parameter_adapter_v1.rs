//! Port of `ghidra.program.database.data.FunctionParameterAdapterV1`.
//!
//! Version 1 (current, and so far only) implementation for accessing the Function Definition
//! Parameters database table, backed by a live, writable [`Table`]. `NOTE`: use of a table-name
//! prefix was introduced with this adapter version.
//!
//! The Java `createRecord` computes its key via `DataTypeManagerDB.createKey(PARAMETER,
//! table.getKey())`, tagging the raw table key with a datatype-kind bit pattern. That key-tagging
//! scheme is a `DataTypeManagerDB`-wide invariant (not specific to this table) and
//! `DataTypeManagerDB` has not been ported with that scheme yet, so this port uses the table's
//! own next-key sequence directly instead (same deviation as `PointerDBAdapterV2`).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::data::function_parameter_adapter::{
    self, FunctionParameterAdapter, PARAMETER_COMMENT_COL, PARAMETER_DT_ID_COL,
    PARAMETER_DT_LENGTH_COL, PARAMETER_NAME_COL, PARAMETER_ORDINAL_COL, PARAMETER_PARENT_ID_COL,
    PARAMETER_TABLE_NAME,
};
use crate::util::exception::VersionException;

/// Version 1 (current) implementation for accessing the Function Definition Parameters database
/// table.
///
/// Port of `ghidra.program.database.data.FunctionParameterAdapterV1`.
pub struct FunctionParameterAdapterV1 {
    table: Arc<RwLock<Table>>,
}

impl FunctionParameterAdapterV1 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = function_parameter_adapter::CURRENT_VERSION;

    /// Gets a version 1 adapter for the Function Definition Parameter database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{PARAMETER_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, function_parameter_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle
                .get_table(&table_name)
                .ok_or_else(|| VersionException::with_upgradeable(true))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(version < Self::VERSION));
            }
            table
        };
        Ok(FunctionParameterAdapterV1 { table })
    }
}

impl FunctionParameterAdapter for FunctionParameterAdapterV1 {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
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
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        let name = self.table.read().unwrap().get_name().to_string();
        handle.delete_table(&name);
        Ok(())
    }

    fn create_record(
        &mut self,
        data_type_id: i64,
        parent_id: i64,
        ordinal: i32,
        name: Option<&str>,
        comment: Option<&str>,
        dt_length: i32,
    ) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(function_parameter_adapter::schema(), Field::Long(Some(key)));
        record.set_field(PARAMETER_PARENT_ID_COL, Field::Long(Some(parent_id)));
        record.set_field(PARAMETER_DT_ID_COL, Field::Long(Some(data_type_id)));
        record.set_field(PARAMETER_NAME_COL, Field::String(name.map(str::to_string)));
        record.set_field(
            PARAMETER_COMMENT_COL,
            Field::String(comment.map(str::to_string)),
        );
        record.set_field(PARAMETER_ORDINAL_COL, Field::Int(Some(ordinal)));
        record.set_field(PARAMETER_DT_LENGTH_COL, Field::Int(Some(dt_length)));
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_record(&self, parameter_id: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(parameter_id)))
    }

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn remove_record(&mut self, parameter_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(parameter_id)))
    }

    fn get_parameter_ids_in_function_def(&self, function_def_id: i64) -> io::Result<Vec<Field>> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(PARAMETER_PARENT_ID_COL), Field::Long(Some(v)) if *v == function_def_id)
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

    #[test]
    fn create_table_and_round_trip_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = FunctionParameterAdapterV1::new(&mut handle, "", true).unwrap();

        let created = adapter
            .create_record(42, 5, 0, Some("param1"), Some("first param"), -1)
            .unwrap();
        let fetched = adapter
            .get_record(created.get_key().get_long_value())
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            fetched.get_field(PARAMETER_NAME_COL),
            &Field::String(Some("param1".to_string()))
        );
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = FunctionParameterAdapterV1::new(&mut handle, "", true).unwrap();
            adapter.create_record(1, 5, 0, None, None, -1).unwrap();
        }
        let adapter = FunctionParameterAdapterV1::new(&mut handle, "", false).unwrap();
        assert_eq!(
            adapter.get_parameter_ids_in_function_def(5).unwrap().len(),
            1
        );
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(FunctionParameterAdapterV1::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn update_and_remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = FunctionParameterAdapterV1::new(&mut handle, "", true).unwrap();
        let mut rec = adapter.create_record(1, 5, 0, None, None, -1).unwrap();

        rec.set_field(PARAMETER_NAME_COL, Field::String(Some("renamed".to_string())));
        adapter.update_record(&rec).unwrap();
        let refetched = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_eq!(
            refetched.get_field(PARAMETER_NAME_COL),
            &Field::String(Some("renamed".to_string()))
        );

        let removed = adapter
            .remove_record(rec.get_key().get_long_value())
            .unwrap();
        assert!(removed);
    }

    #[test]
    fn get_parameter_ids_in_function_def_filters_by_parent() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = FunctionParameterAdapterV1::new(&mut handle, "", true).unwrap();
        adapter.create_record(1, 5, 0, None, None, -1).unwrap();
        adapter.create_record(2, 5, 1, None, None, -1).unwrap();
        adapter.create_record(3, 9, 0, None, None, -1).unwrap();

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
    fn delete_table_removes_it_from_handle() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = FunctionParameterAdapterV1::new(&mut handle, "prefix_", true).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table("prefix_Function Parameters").is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn FunctionParameterAdapter> =
            Box::new(FunctionParameterAdapterV1::new(&mut handle, "", true).unwrap());
        assert!(adapter.get_records().unwrap().next().unwrap().is_none());
    }
}

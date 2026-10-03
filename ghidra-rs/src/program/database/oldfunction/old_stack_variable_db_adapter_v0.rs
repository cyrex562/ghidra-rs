//! Port of `ghidra.program.database.oldfunction.OldStackVariableDBAdapterV0`.
//!
//! Read-only legacy adapter for the version 0 (original) stack-variables table layout: five
//! columns only (no `DataType Length` column yet), so
//! [`translate_record`](OldStackVariableDBAdapterV0::translate_record) synthesizes a data type
//! length of `1` for every translated record, mirroring
//! `OldStackVariableDBAdapterV0.translateRecord`'s
//! `rec.setIntValue(STACK_VAR_DT_LENGTH_COL, 1)`. Opens the *same* table name as
//! [`OldStackVariableDBAdapterV1`](crate::program::database::oldfunction::OldStackVariableDBAdapterV1)
//! (`"Stack Variables"`), distinguished only by the schema version stamped on the table.
//!
//! See [`OldStackVariableDBAdapterV1`]'s module docs for why this port's constructor, like that
//! one, takes no `addr_map` parameter (Java accepts but never uses one), and for why
//! `getStackVariableKeys` is a linear scan rather than an indexed lookup.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::oldfunction::old_stack_variable_db_adapter::{
    OldStackVariableDBAdapter, STACK_VAR_COMMENT_COL, STACK_VAR_DATA_TYPE_ID_COL,
    STACK_VAR_DT_LENGTH_COL, STACK_VAR_FUNCTION_KEY_COL, STACK_VAR_NAME_COL, STACK_VAR_OFFSET_COL,
};
use crate::program::database::oldfunction::old_stack_variable_db_adapter_v1::{
    schema, STACK_VARS_TABLE_NAME,
};
use crate::util::exception::VersionException;

const V0_STACK_VAR_FUNCTION_KEY_COL: usize = 0;
const V0_STACK_VAR_OFFSET_COL: usize = 1;
const V0_STACK_VAR_DATA_TYPE_ID_COL: usize = 2;
const V0_STACK_VAR_NAME_COL: usize = 3;
const V0_STACK_VAR_COMMENT_COL: usize = 4;

/// Schema version implemented by this adapter. Mirrors the version checked by
/// `OldStackVariableDBAdapterV0`'s constructor (`table.getSchema().getVersion() != 0`).
pub const SCHEMA_VERSION: i32 = 0;

/// Build the version 0 stack-variables table schema, matching
/// `OldStackVariableDBAdapterV0.V0_STACK_VARS_SCHEMA`.
pub fn v0_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::Long, FieldType::Int, FieldType::Long, FieldType::String, FieldType::String],
        vec![
            "Function ID".to_string(),
            "Offset".to_string(),
            "DataType ID".to_string(),
            "Name".to_string(),
            "Comment".to_string(),
        ],
        vec![],
    ))
}

/// Read-only legacy adapter for the version 0 (original) stack-variables table layout.
///
/// Port of `ghidra.program.database.oldfunction.OldStackVariableDBAdapterV0`.
pub struct OldStackVariableDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl OldStackVariableDBAdapterV0 {
    /// Opens an existing version 0 stack-variables table for read access.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if the table is missing or its schema version is not
    /// [`SCHEMA_VERSION`].
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(STACK_VARS_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {STACK_VARS_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != SCHEMA_VERSION {
            return Err(VersionException::with_message(format!(
                "Expected version 0 for table {STACK_VARS_TABLE_NAME} but got {version}"
            )));
        }
        Ok(OldStackVariableDBAdapterV0 { table })
    }

    /// Port of `OldStackVariableDBAdapterV0.translateRecord(DBRecord)`.
    fn translate_record(&self, old_rec: DBRecord) -> DBRecord {
        let mut rec = DBRecord::new(schema(), old_rec.get_key().clone());
        rec.set_long(
            STACK_VAR_FUNCTION_KEY_COL,
            old_rec.get_long(V0_STACK_VAR_FUNCTION_KEY_COL).unwrap_or(0),
        );
        rec.set_string(
            STACK_VAR_NAME_COL,
            old_rec.get_string(V0_STACK_VAR_NAME_COL).map(str::to_string),
        );
        rec.set_long(
            STACK_VAR_DATA_TYPE_ID_COL,
            old_rec.get_long(V0_STACK_VAR_DATA_TYPE_ID_COL).unwrap_or(0),
        );
        rec.set_int(STACK_VAR_OFFSET_COL, old_rec.get_int(V0_STACK_VAR_OFFSET_COL).unwrap_or(0));
        rec.set_string(
            STACK_VAR_COMMENT_COL,
            old_rec.get_string(V0_STACK_VAR_COMMENT_COL).map(str::to_string),
        );
        rec.set_int(STACK_VAR_DT_LENGTH_COL, 1);
        rec
    }
}

impl OldStackVariableDBAdapter for OldStackVariableDBAdapterV0 {
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(STACK_VARS_TABLE_NAME);
        Ok(())
    }

    fn get_stack_variable_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        let old = self.table.read().unwrap().get_record(&Field::Long(Some(key)))?;
        Ok(old.map(|rec| self.translate_record(rec)))
    }

    fn get_stack_variable_keys(&self, function_key: i64) -> io::Result<Vec<Field>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(V0_STACK_VAR_FUNCTION_KEY_COL) == Some(function_key) {
                keys.push(rec.get_key().clone());
            }
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_table(handle: &mut DBHandle) {
        let table = handle.create_table(STACK_VARS_TABLE_NAME.to_string(), v0_schema()).unwrap();
        let mut t = table.write().unwrap();
        let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(1)));
        rec.set_long(V0_STACK_VAR_FUNCTION_KEY_COL, 100);
        rec.set_int(V0_STACK_VAR_OFFSET_COL, -12);
        rec.set_long(V0_STACK_VAR_DATA_TYPE_ID_COL, 9);
        rec.set_string(V0_STACK_VAR_NAME_COL, Some("local_c".to_string()));
        rec.set_string(V0_STACK_VAR_COMMENT_COL, Some("a comment".to_string()));
        t.put_record(rec).unwrap();
    }

    #[test]
    fn translate_record_synthesizes_unit_data_type_length() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let adapter = OldStackVariableDBAdapterV0::new(&handle).unwrap();

        let translated = adapter.get_stack_variable_record(1).unwrap().unwrap();
        assert_eq!(translated.get_long(STACK_VAR_FUNCTION_KEY_COL), Some(100));
        assert_eq!(translated.get_int(STACK_VAR_OFFSET_COL), Some(-12));
        assert_eq!(translated.get_long(STACK_VAR_DATA_TYPE_ID_COL), Some(9));
        assert_eq!(translated.get_string(STACK_VAR_NAME_COL), Some("local_c"));
        assert_eq!(translated.get_string(STACK_VAR_COMMENT_COL), Some("a comment"));
        assert_eq!(translated.get_int(STACK_VAR_DT_LENGTH_COL), Some(1));
    }

    #[test]
    fn get_stack_variable_keys_filters_by_function() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let adapter = OldStackVariableDBAdapterV0::new(&handle).unwrap();

        assert_eq!(adapter.get_stack_variable_keys(100).unwrap(), vec![Field::Long(Some(1))]);
        assert!(adapter.get_stack_variable_keys(200).unwrap().is_empty());
    }

    #[test]
    fn version_mismatch_is_reported() {
        let mut handle = DBHandle::new().unwrap();
        handle
            .create_table(
                STACK_VARS_TABLE_NAME.to_string(),
                Arc::new(Schema::new(1, FieldType::Long, "Key".to_string(), vec![], vec![], vec![])),
            )
            .unwrap();
        let err = match OldStackVariableDBAdapterV0::new(&handle) {
            Ok(_) => panic!("expected version mismatch"),
            Err(e) => e,
        };
        assert!(!err.is_upgradable());
    }

    #[test]
    fn delete_table_removes_underlying_table() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let mut adapter = OldStackVariableDBAdapterV0::new(&handle).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table(STACK_VARS_TABLE_NAME).is_none());
    }
}

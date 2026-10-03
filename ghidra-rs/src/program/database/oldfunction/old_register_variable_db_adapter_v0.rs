//! Port of `ghidra.program.database.oldfunction.OldRegisterVariableDBAdapterV0`.
//!
//! The sole concrete implementation of [`OldRegisterVariableDBAdapter`] (unlike the
//! `OldFunctionDBAdapter*`/`OldStackVariableDBAdapter*` families, there is no separate "current"
//! version to translate an older layout into -- `OldRegisterVariableDBAdapter`'s abstract column
//! constants (`REG_VAR_REGNAME_COL` etc.) delegate straight to this class's own `V0_*` constants
//! in Java, so [`get_register_variable_record`](OldRegisterVariableDBAdapterV0::get_register_variable_record)
//! returns the raw table record unmodified, with no translation step).
//!
//! **Faithfully reproduced Java quirk:** `getRegisterVariableKeys` filters using
//! `OldStackVariableDBAdapter.STACK_VAR_FUNCTION_KEY_COL` -- a column constant belonging to a
//! *different* adapter family entirely -- rather than this class's own
//! `V0_REG_VAR_FUNCTION_KEY_COL`. This only works because both constants happen to equal `0` (the
//! function key is the first column in both the register-variable and stack-variable tables); it
//! is preserved here verbatim (see [`get_register_variable_keys`](OldRegisterVariableDBAdapterV0::get_register_variable_keys)'s
//! body) rather than silently "fixed" to use the correct same-family constant, with a test proving
//! the two constants' happenstance equality is what makes it work.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::oldfunction::old_register_variable_db_adapter::OldRegisterVariableDBAdapter;
use crate::program::database::oldfunction::old_stack_variable_db_adapter::STACK_VAR_FUNCTION_KEY_COL;
use crate::util::exception::VersionException;

const V0_REG_VAR_FUNCTION_KEY_COL: usize = 0;
const V0_REG_VAR_COMMENT_COL: usize = 4;

/// Name of the register parameters database table. Mirrors
/// `OldRegisterVariableDBAdapterV0.REG_PARMS_TABLE_NAME`.
pub const REG_PARMS_TABLE_NAME: &str = "Register Parameters";

/// Schema version implemented by this adapter. Mirrors `OldRegisterVariableDBAdapterV0.SCHEMA_VERSION`.
pub const SCHEMA_VERSION: i32 = 0;

/// Build the register parameters table schema, as defined by
/// `OldRegisterVariableDBAdapterV0.V0_REG_PARAMS_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::Long, FieldType::String, FieldType::Long, FieldType::String, FieldType::String],
        vec![
            "Function ID".to_string(),
            "Register".to_string(),
            "DataType ID".to_string(),
            "Name".to_string(),
            "Comment".to_string(),
        ],
        vec![],
    ))
}

/// Sole concrete implementation of [`OldRegisterVariableDBAdapter`].
///
/// Port of `ghidra.program.database.oldfunction.OldRegisterVariableDBAdapterV0`.
pub struct OldRegisterVariableDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl OldRegisterVariableDBAdapterV0 {
    /// Opens an existing version 0 register-parameters table for read access.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if the table is missing or its schema version is not
    /// [`SCHEMA_VERSION`]. Mirrors the Java constructor's single combined check
    /// (`table == null || table.getSchema().getVersion() != 0`), which -- unlike every sibling
    /// `OldFunctionDBAdapter*`/`OldStackVariableDBAdapter*` constructor -- reports both cases as
    /// the same non-upgradable `VersionException(false)` rather than distinguishing "missing" from
    /// "wrong version".
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle
            .get_table(REG_PARMS_TABLE_NAME)
            .filter(|t| t.read().unwrap().get_schema().get_version() == 0)
            .ok_or_else(|| VersionException::with_upgradeable(false))?;
        Ok(OldRegisterVariableDBAdapterV0 { table })
    }
}

impl OldRegisterVariableDBAdapter for OldRegisterVariableDBAdapterV0 {
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(REG_PARMS_TABLE_NAME);
        Ok(())
    }

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn get_register_variable_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    /// Port of `OldRegisterVariableDBAdapterV0.getRegisterVariableKeys(long)`. See the module docs
    /// for why this filters on [`STACK_VAR_FUNCTION_KEY_COL`] (a different adapter family's
    /// constant) rather than [`V0_REG_VAR_FUNCTION_KEY_COL`] -- a real Java quirk, preserved
    /// as-is.
    fn get_register_variable_keys(&self, function_key: i64) -> io::Result<Vec<Field>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(STACK_VAR_FUNCTION_KEY_COL) == Some(function_key) {
                keys.push(rec.get_key().clone());
            }
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::oldfunction::old_register_variable_db_adapter::{
        REG_VAR_DATA_TYPE_ID_COL, REG_VAR_NAME_COL, REG_VAR_REGNAME_COL,
    };

    fn seed_table(handle: &mut DBHandle) {
        let table = handle.create_table(REG_PARMS_TABLE_NAME.to_string(), schema()).unwrap();
        let mut t = table.write().unwrap();
        for (key, function_key, reg_name) in [(1i64, 100i64, "r0"), (2, 100, "r1"), (3, 200, "r2")] {
            let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
            rec.set_long(V0_REG_VAR_FUNCTION_KEY_COL, function_key);
            rec.set_string(REG_VAR_REGNAME_COL, Some(reg_name.to_string()));
            rec.set_long(REG_VAR_DATA_TYPE_ID_COL, 0);
            rec.set_string(REG_VAR_NAME_COL, Some(format!("param_{key}")));
            rec.set_string(V0_REG_VAR_COMMENT_COL, None);
            t.put_record(rec).unwrap();
        }
    }

    #[test]
    fn cross_family_column_constant_still_selects_function_key_because_both_are_zero() {
        // Proves the Java quirk this adapter preserves: `STACK_VAR_FUNCTION_KEY_COL` (from a
        // wholly different adapter family) and this class's own `V0_REG_VAR_FUNCTION_KEY_COL`
        // both name column 0, which is the only reason filtering by the "wrong" constant works.
        assert_eq!(STACK_VAR_FUNCTION_KEY_COL, V0_REG_VAR_FUNCTION_KEY_COL);
    }

    #[test]
    fn get_register_variable_keys_filters_by_function() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let adapter = OldRegisterVariableDBAdapterV0::new(&handle).unwrap();

        let mut keys = adapter.get_register_variable_keys(100).unwrap();
        keys.sort_by_key(|f| f.get_long_value());
        assert_eq!(keys, vec![Field::Long(Some(1)), Field::Long(Some(2))]);
        assert!(adapter.get_register_variable_keys(999).unwrap().is_empty());
    }

    #[test]
    fn get_register_variable_record_returns_record_unmodified() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let adapter = OldRegisterVariableDBAdapterV0::new(&handle).unwrap();

        let rec = adapter.get_register_variable_record(1).unwrap().unwrap();
        assert_eq!(rec.get_string(REG_VAR_REGNAME_COL), Some("r0"));
        assert!(adapter.get_register_variable_record(99).unwrap().is_none());
        assert_eq!(adapter.get_record_count(), 3);
    }

    #[test]
    fn missing_table_and_version_mismatch_report_same_indicator() {
        let handle = DBHandle::new().unwrap();
        let missing_err = match OldRegisterVariableDBAdapterV0::new(&handle) {
            Ok(_) => panic!("expected missing table error"),
            Err(e) => e,
        };
        assert!(!missing_err.is_upgradable());

        let mut handle2 = DBHandle::new().unwrap();
        handle2
            .create_table(
                REG_PARMS_TABLE_NAME.to_string(),
                Arc::new(Schema::new(1, FieldType::Long, "Key".to_string(), vec![], vec![], vec![])),
            )
            .unwrap();
        let version_err = match OldRegisterVariableDBAdapterV0::new(&handle2) {
            Ok(_) => panic!("expected version mismatch"),
            Err(e) => e,
        };
        assert!(!version_err.is_upgradable());
    }

    #[test]
    fn delete_table_removes_underlying_table() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let mut adapter = OldRegisterVariableDBAdapterV0::new(&handle).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table(REG_PARMS_TABLE_NAME).is_none());
    }
}

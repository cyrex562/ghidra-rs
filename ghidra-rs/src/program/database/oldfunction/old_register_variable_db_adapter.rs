//! Port of `ghidra.program.database.oldfunction.OldRegisterVariableDBAdapter`.
//!
//! The Java type is an abstract, package-private class whose static factory method (`getAdapter`)
//! selects the sole concrete version-specific implementation (`OldRegisterVariableDBAdapterV0`).
//! That concrete adapter has not been ported yet, so this port only models the abstract instance
//! API it implements, as an object-safe trait; the version-selection logic belongs with whichever
//! type ends up owning the concrete adapter. This follows the same convention already used for
//! [`OldStackVariableDBAdapter`](crate::program::database::oldfunction::OldStackVariableDBAdapter)
//! and [`OldFunctionDBAdapter`](crate::program::database::oldfunction::OldFunctionDBAdapter). This
//! trait was itself selected as a dependency-cycle cut-point.
//!
//! Also left out: the `REG_PARAMS_SCHEMA` constant, since it describes a concrete table layout
//! (delegated to `OldRegisterVariableDBAdapterV0.V0_REG_PARAMS_SCHEMA`) used only by the
//! not-yet-ported `OldRegisterVariableDBAdapterV0` class itself, rather than this trait's
//! dynamic-dispatch surface -- the same reasoning that excluded `OldStackVariableDBAdapter`'s
//! `STACK_VARS_SCHEMA` and `OldFunctionDBAdapter`'s `FUNCTIONS_SCHEMA`.
//!
//! Kept, unlike that table-layout constant: the `REG_VAR_REGNAME_COL`, `REG_VAR_DATA_TYPE_ID_COL`,
//! and `REG_VAR_NAME_COL` column-index constants. These are read directly by
//! `ghidra.program.database.oldfunction.OldFunctionDataDB` (a real caller outside the
//! `OldRegisterVariableDBAdapter*` hierarchy, not yet ported) to interpret a register variable
//! record's columns, so they are part of this type's genuine public API surface -- the same
//! reasoning that kept `OldFunctionDBAdapter`'s `RETURN_DATA_TYPE_ID_COL` and friends. Left out for
//! the same reason `OldStackVariableDBAdapter` left out its column constants entirely:
//! `REG_VAR_FUNCTION_KEY_COL` and `REG_VAR_COMMENT_COL`, since neither is referenced outside the
//! `OldRegisterVariableDBAdapter*` hierarchy itself.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field};

/// Column index for a register variable record's register name. Stands in for
/// `OldRegisterVariableDBAdapter.REG_VAR_REGNAME_COL`.
pub const REG_VAR_REGNAME_COL: usize = 1;
/// Column index for a register variable record's data type ID. Stands in for
/// `OldRegisterVariableDBAdapter.REG_VAR_DATA_TYPE_ID_COL`.
pub const REG_VAR_DATA_TYPE_ID_COL: usize = 2;
/// Column index for a register variable record's name. Stands in for
/// `OldRegisterVariableDBAdapter.REG_VAR_NAME_COL`.
pub const REG_VAR_NAME_COL: usize = 3;

/// Database adapter for register variables.
///
/// Port of `ghidra.program.database.oldfunction.OldRegisterVariableDBAdapter`. See the module
/// docs for what was intentionally left out (the static factory/version-selection logic and the
/// concrete table-layout constant).
pub trait OldRegisterVariableDBAdapter {
    /// Deletes this adapter's underlying table from `handle`.
    ///
    /// Stands in for `OldRegisterVariableDBAdapter.deleteTable(DBHandle)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Returns a count of register variable records.
    ///
    /// Stands in for `OldRegisterVariableDBAdapter.getRecordCount()`.
    fn get_record_count(&self) -> i32;

    /// Gets a register variable record, or `None` if there is no record for `key`.
    ///
    /// Stands in for `OldRegisterVariableDBAdapter.getRegisterVariableRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_register_variable_record(&self, key: i64) -> io::Result<Option<DBRecord>>;

    /// Gets all register variable keys which correspond to a function.
    ///
    /// Stands in for `OldRegisterVariableDBAdapter.getRegisterVariableKeys(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_register_variable_keys(&self, function_key: i64) -> io::Result<Vec<Field>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Key".to_string(),
            vec![
                FieldType::Long,
                FieldType::String,
                FieldType::Long,
                FieldType::String,
                FieldType::String,
            ],
            vec![
                "Function Key".to_string(),
                "Register Name".to_string(),
                "DataType ID".to_string(),
                "Name".to_string(),
                "Comment".to_string(),
            ],
            vec![],
        ))
    }

    const REG_VAR_FUNCTION_KEY_COL: usize = 0;

    /// A minimal in-memory `OldRegisterVariableDBAdapter`, exercising object-safety and the
    /// record get/count/keys-by-function-key/delete contract described by the Java class.
    struct MockOldRegisterVariableDBAdapter {
        records: BTreeMap<i64, DBRecord>,
    }

    impl MockOldRegisterVariableDBAdapter {
        fn new() -> Self {
            MockOldRegisterVariableDBAdapter {
                records: BTreeMap::new(),
            }
        }

        fn insert(&mut self, key: i64, function_key: i64, reg_name: &str) {
            let mut record = DBRecord::new(test_schema(), Field::Long(Some(key)));
            record.set_long(REG_VAR_FUNCTION_KEY_COL, function_key);
            record.set_string(REG_VAR_REGNAME_COL, Some(reg_name.to_string()));
            self.records.insert(key, record);
        }
    }

    impl OldRegisterVariableDBAdapter for MockOldRegisterVariableDBAdapter {
        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            self.records.clear();
            Ok(())
        }

        fn get_record_count(&self) -> i32 {
            self.records.len() as i32
        }

        fn get_register_variable_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&key).cloned())
        }

        fn get_register_variable_keys(&self, function_key: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .values()
                .filter(|record| {
                    record.get_long(REG_VAR_FUNCTION_KEY_COL) == Some(function_key)
                })
                .map(|record| record.get_key().clone())
                .collect())
        }
    }

    #[test]
    fn object_safe_and_filters_keys_by_function() {
        let mut mock = MockOldRegisterVariableDBAdapter::new();
        mock.insert(1, 100, "r0");
        mock.insert(2, 100, "r1");
        mock.insert(3, 200, "r2");

        let adapter: Box<dyn OldRegisterVariableDBAdapter> = Box::new(mock);

        assert_eq!(adapter.get_record_count(), 3);

        let fetched = adapter.get_register_variable_record(1).unwrap().unwrap();
        assert_eq!(fetched.get_long(REG_VAR_FUNCTION_KEY_COL), Some(100));
        assert_eq!(fetched.get_string(REG_VAR_REGNAME_COL), Some("r0"));
        assert!(adapter.get_register_variable_record(99).unwrap().is_none());

        let mut keys = adapter.get_register_variable_keys(100).unwrap();
        keys.sort_by_key(|f| match f {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        });
        assert_eq!(keys, vec![Field::Long(Some(1)), Field::Long(Some(2))]);
    }

    #[test]
    fn delete_table_clears_all_records() {
        let mut mock = MockOldRegisterVariableDBAdapter::new();
        mock.insert(1, 100, "r0");
        assert_eq!(mock.get_record_count(), 1);

        let mut handle = DBHandle::new().unwrap();
        mock.delete_table(&mut handle).unwrap();
        assert_eq!(mock.get_record_count(), 0);
    }
}

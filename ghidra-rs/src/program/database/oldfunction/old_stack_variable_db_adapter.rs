//! Port of `ghidra.program.database.oldfunction.OldStackVariableDBAdapter`.
//!
//! The Java type is an abstract, package-private class whose static factory method (`getAdapter`)
//! selects between two concrete version-specific implementations
//! (`OldStackVariableDBAdapterV0`, `OldStackVariableDBAdapterV1`), retrying against the older
//! version on an upgradable `VersionException`. Those concrete adapters have not been ported yet,
//! so this port only models the abstract instance API each version implements, as an object-safe
//! trait; the version-selection logic belongs with whichever type ends up owning the concrete
//! adapters. This follows the same convention already used for
//! [`OldFunctionDBAdapter`](crate::program::database::oldfunction::OldFunctionDBAdapter).
//!
//! Also left out: the `STACK_VARS_SCHEMA` constant and the `STACK_VAR_*_COL` column-index
//! constants, since -- unlike `OldFunctionDBAdapter`'s column constants -- these are only ever
//! referenced from within the `OldStackVariableDBAdapter*` hierarchy itself (delegated to
//! `OldStackVariableDBAdapterV1.V1_STACK_VARS_SCHEMA`/`V1_STACK_VAR_*_COL`), not by any other
//! not-yet-ported caller, so there is no genuine public API surface to preserve here.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field};

/// Database adapter for stack variables.
///
/// Port of `ghidra.program.database.oldfunction.OldStackVariableDBAdapter`. See the module docs
/// for what was intentionally left out (the static factory/version-upgrade logic and the
/// concrete table-layout constants).
pub trait OldStackVariableDBAdapter {
    /// Deletes this adapter's underlying table from `handle`.
    ///
    /// Stands in for `OldStackVariableDBAdapter.deleteTable(DBHandle)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Gets a stack variable record, or `None` if there is no record for `key`.
    ///
    /// Stands in for `OldStackVariableDBAdapter.getStackVariableRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_stack_variable_record(&self, key: i64) -> io::Result<Option<DBRecord>>;

    /// Gets all stack variable keys which correspond to a function.
    ///
    /// Stands in for `OldStackVariableDBAdapter.getStackVariableKeys(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_stack_variable_keys(&self, function_key: i64) -> io::Result<Vec<Field>>;
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
            vec![FieldType::Long, FieldType::Int, FieldType::String],
            vec![
                "Function Key".to_string(),
                "Stack Offset".to_string(),
                "Name".to_string(),
            ],
            vec![],
        ))
    }

    const STACK_VAR_FUNCTION_KEY_COL: usize = 0;

    /// A minimal in-memory `OldStackVariableDBAdapter`, exercising object-safety and the
    /// record get/keys-by-function-key/delete contract described by the Java class.
    struct MockOldStackVariableDBAdapter {
        records: BTreeMap<i64, DBRecord>,
    }

    impl MockOldStackVariableDBAdapter {
        fn new() -> Self {
            MockOldStackVariableDBAdapter {
                records: BTreeMap::new(),
            }
        }

        fn insert(&mut self, key: i64, function_key: i64) {
            let mut record = DBRecord::new(test_schema(), Field::Long(Some(key)));
            record.set_long(STACK_VAR_FUNCTION_KEY_COL, function_key);
            self.records.insert(key, record);
        }
    }

    impl OldStackVariableDBAdapter for MockOldStackVariableDBAdapter {
        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            self.records.clear();
            Ok(())
        }

        fn get_stack_variable_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&key).cloned())
        }

        fn get_stack_variable_keys(&self, function_key: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .values()
                .filter(|record| record.get_long(STACK_VAR_FUNCTION_KEY_COL) == Some(function_key))
                .map(|record| record.get_key().clone())
                .collect())
        }
    }

    #[test]
    fn object_safe_and_filters_keys_by_function() {
        let mut mock = MockOldStackVariableDBAdapter::new();
        mock.insert(1, 100);
        mock.insert(2, 100);
        mock.insert(3, 200);

        let adapter: Box<dyn OldStackVariableDBAdapter> = Box::new(mock);

        let fetched = adapter.get_stack_variable_record(1).unwrap().unwrap();
        assert_eq!(fetched.get_long(STACK_VAR_FUNCTION_KEY_COL), Some(100));
        assert!(adapter.get_stack_variable_record(99).unwrap().is_none());

        let mut keys = adapter.get_stack_variable_keys(100).unwrap();
        keys.sort_by_key(|f| match f {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        });
        assert_eq!(keys, vec![Field::Long(Some(1)), Field::Long(Some(2))]);
    }

    #[test]
    fn delete_table_clears_all_records() {
        let mut mock = MockOldStackVariableDBAdapter::new();
        mock.insert(1, 100);
        assert_eq!(mock.get_stack_variable_keys(100).unwrap().len(), 1);

        let mut handle = DBHandle::new().unwrap();
        mock.delete_table(&mut handle).unwrap();
        assert!(mock.get_stack_variable_keys(100).unwrap().is_empty());
    }
}

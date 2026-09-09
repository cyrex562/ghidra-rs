//! Port of `ghidra.program.database.oldfunction.OldStackVariableDBAdapterV1`.
//!
//! The current (version 1) implementation of [`OldStackVariableDBAdapter`], backed by a live
//! [`Table`] whose layout matches [`OldStackVariableDBAdapter`]'s own column constants exactly (no
//! translation needed, unlike
//! [`OldStackVariableDBAdapterV0`](crate::program::database::oldfunction::OldStackVariableDBAdapterV0)).
//! [`STACK_VARS_TABLE_NAME`]/[`schema`] describe this concrete table's layout, mirroring
//! `OldStackVariableDBAdapterV1.STACK_VARS_TABLE_NAME`/`V1_STACK_VARS_SCHEMA`.
//!
//! `getStackVariableKeys` uses `Table.findRecords(Field, int)` in Java, an indexed lookup; this
//! port's [`Table`] has no index support, so [`get_stack_variable_keys`](OldStackVariableDBAdapterV1::get_stack_variable_keys)
//! (via [`OldStackVariableDBAdapter::get_stack_variable_keys`]) instead does a full linear scan
//! filtering on [`STACK_VAR_FUNCTION_KEY_COL`], which is observationally equivalent (same result
//! set, just without the index's speedup) -- the same tradeoff already made throughout this port
//! wherever `db.Table`'s indexed queries have no ported equivalent.
//!
//! Java's constructor accepts an `AddressMap addrMap` parameter (matching the sibling
//! `OldFunctionDBAdapter`/`OldRegisterVariableDBAdapter` constructors' shape) but -- unlike
//! `OldFunctionDBAdapter`, which stores it in a protected field read by
//! [`OldFunctionDBAdapter::get_address_map`] -- never stores or otherwise uses it: the abstract
//! `OldStackVariableDBAdapter` class declares no `addrMap` field, and [`OldStackVariableDBAdapter`]
//! (this port's trait) has no `get_address_map` method either. [`OldStackVariableDBAdapterV1::new`]
//! therefore takes no `addr_map` parameter at all, dropping this genuinely dead parameter rather
//! than accepting and discarding it.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::oldfunction::old_stack_variable_db_adapter::{
    OldStackVariableDBAdapter, STACK_VAR_FUNCTION_KEY_COL,
};
use crate::util::exception::VersionException;

/// Name of the stack variables database table. Mirrors `OldStackVariableDBAdapterV1.STACK_VARS_TABLE_NAME`
/// (and `OldStackVariableDBAdapterV0.STACK_VARS_TABLE_NAME`, which names the same table).
pub const STACK_VARS_TABLE_NAME: &str = "Stack Variables";

/// Schema version implemented by this adapter. Mirrors `OldStackVariableDBAdapterV1.SCHEMA_VERSION`.
pub const SCHEMA_VERSION: i32 = 1;

/// Build the current stack-variables table schema, as defined by
/// `OldStackVariableDBAdapterV1.V1_STACK_VARS_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::Long,
            FieldType::Int,
            FieldType::Long,
            FieldType::String,
            FieldType::String,
            FieldType::Int,
        ],
        vec![
            "Function ID".to_string(),
            "Offset".to_string(),
            "DataType ID".to_string(),
            "Name".to_string(),
            "Comment".to_string(),
            "DataType Length".to_string(),
        ],
        vec![],
    ))
}

/// Current (version 1) implementation of [`OldStackVariableDBAdapter`].
///
/// Port of `ghidra.program.database.oldfunction.OldStackVariableDBAdapterV1`.
pub struct OldStackVariableDBAdapterV1 {
    table: Arc<RwLock<Table>>,
}

impl OldStackVariableDBAdapterV1 {
    /// Opens an existing version 1 stack-variables table for read access.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if the table is missing, older (upgradable), or newer than
    /// [`SCHEMA_VERSION`].
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(STACK_VARS_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {STACK_VARS_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != SCHEMA_VERSION {
            if version < SCHEMA_VERSION {
                return Err(VersionException::with_upgradeable(true));
            }
            return Err(VersionException::with_version_indicator(
                VersionException::NEWER_VERSION,
                false,
            ));
        }
        Ok(OldStackVariableDBAdapterV1 { table })
    }
}

impl OldStackVariableDBAdapter for OldStackVariableDBAdapterV1 {
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(STACK_VARS_TABLE_NAME);
        Ok(())
    }

    fn get_stack_variable_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    fn get_stack_variable_keys(&self, function_key: i64) -> io::Result<Vec<Field>> {
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

    fn seed_table(handle: &mut DBHandle) {
        let table = handle.create_table(STACK_VARS_TABLE_NAME.to_string(), schema()).unwrap();
        let mut t = table.write().unwrap();
        for (key, function_key, offset, name) in
            [(1i64, 100i64, -4i32, "a"), (2, 100, -8, "b"), (3, 200, 4, "c")]
        {
            let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
            rec.set_long(0, function_key);
            rec.set_int(1, offset);
            rec.set_long(2, 0);
            rec.set_string(3, Some(name.to_string()));
            rec.set_string(4, None);
            rec.set_int(5, 1);
            t.put_record(rec).unwrap();
        }
    }

    #[test]
    fn get_stack_variable_keys_scans_and_filters_by_function() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let adapter = OldStackVariableDBAdapterV1::new(&handle).unwrap();

        let mut keys = adapter.get_stack_variable_keys(100).unwrap();
        keys.sort_by_key(|f| f.get_long_value());
        assert_eq!(keys, vec![Field::Long(Some(1)), Field::Long(Some(2))]);

        assert!(adapter.get_stack_variable_keys(999).unwrap().is_empty());
    }

    #[test]
    fn get_stack_variable_record_round_trips_without_translation() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let adapter = OldStackVariableDBAdapterV1::new(&handle).unwrap();

        let rec = adapter.get_stack_variable_record(1).unwrap().unwrap();
        assert_eq!(rec.get_int(1), Some(-4));
        assert_eq!(rec.get_string(3), Some("a"));
        assert!(adapter.get_stack_variable_record(99).unwrap().is_none());
    }

    #[test]
    fn delete_table_removes_underlying_table() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let mut adapter = OldStackVariableDBAdapterV1::new(&handle).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table(STACK_VARS_TABLE_NAME).is_none());
    }

    #[test]
    fn version_mismatch_is_reported() {
        let mut handle = DBHandle::new().unwrap();
        handle
            .create_table(
                STACK_VARS_TABLE_NAME.to_string(),
                Arc::new(Schema::new(0, FieldType::Long, "Key".to_string(), vec![], vec![], vec![])),
            )
            .unwrap();
        let err = match OldStackVariableDBAdapterV1::new(&handle) {
            Ok(_) => panic!("expected version mismatch"),
            Err(e) => e,
        };
        assert!(err.is_upgradable());
    }
}

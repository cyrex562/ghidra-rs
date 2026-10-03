//! Port of `ghidra.program.database.symbol.OldVariableStorageDBAdapterV0V1`.
//!
//! Provides legacy variable storage table support where each variable storage record was
//! namespace-specific and provided storage address only. In a later revision this was deemed
//! inadequate since size information and support for storage binding was needed.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};

/// Name of the legacy variable storage database table (note: no space in the name, unlike the
/// current `"Variable Storage"` table).
pub const VARIABLE_STORAGE_TABLE_NAME: &str = "VariableStorage";

/// Column index of the storage address. Mirrors `OldVariableStorageDBAdapterV0V1.STORAGE_ADDR_COL`.
pub const STORAGE_ADDR_COL: usize = 0;
/// Column index of the owning namespace's ID. Mirrors
/// `OldVariableStorageDBAdapterV0V1.NAMESPACE_ID_COL`.
pub const NAMESPACE_ID_COL: usize = 1;
/// Column index of the symbol count. Mirrors `OldVariableStorageDBAdapterV0V1.SYMBOL_COUNT_COL`.
pub const SYMBOL_COUNT_COL: usize = 2;

/// Build the legacy variable storage table schema, as defined by
/// `OldVariableStorageDBAdapterV0V1.VARIABLE_STORAGE_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        1,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::Long, FieldType::Long, FieldType::Int],
        vec![
            "Address".to_string(),
            "NamespaceID".to_string(),
            "SymCount".to_string(),
        ],
        vec![],
    ))
}

/// Provides legacy variable storage table support (schema versions 0 and 1) where each variable
/// storage record was namespace-specific and provided storage address only.
///
/// Port of `ghidra.program.database.symbol.OldVariableStorageDBAdapterV0V1`. Unlike the Java
/// class this is `pub` rather than package-private, since Rust has no package-private visibility
/// within a module; used only during upgrades by
/// [`OldVariableStorageManagerDB`](crate::program::database::symbol::OldVariableStorageManagerDB).
pub struct OldVariableStorageDBAdapterV0V1 {
    table: Arc<RwLock<Table>>,
}

impl OldVariableStorageDBAdapterV0V1 {
    /// Construct a legacy variable storage adapter. The old variable storage table must already
    /// exist (see [`VARIABLE_STORAGE_TABLE_NAME`]) with schema version 0 or 1.
    ///
    /// # Errors
    ///
    /// Returns an error if the table is missing or has an unsupported schema version.
    pub fn new(handle: &DBHandle) -> io::Result<Self> {
        let table = handle.get_table(VARIABLE_STORAGE_TABLE_NAME).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("No such table: {VARIABLE_STORAGE_TABLE_NAME}"),
            )
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 && version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("No such table schema version: {version}"),
            ));
        }
        Ok(OldVariableStorageDBAdapterV0V1 { table })
    }

    /// Get the record with the given key, or `None` if there is no such record.
    pub fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    /// Get all records for the given namespace ID.
    ///
    /// Note: the Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
    /// port's `Table` has no secondary-index support, so this scans linearly instead. Same
    /// observable result, just O(n) rather than indexed.
    pub fn get_records_for_namespace(&self, namespace_id: i64) -> io::Result<Vec<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(NAMESPACE_ID_COL) == Some(namespace_id) {
                records.push(rec);
            }
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(table: &mut Table, addr: i64, namespace_id: i64, sym_count: i32) -> DBRecord {
        let key = table.get_next_key();
        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_long(STORAGE_ADDR_COL, addr);
        record.set_long(NAMESPACE_ID_COL, namespace_id);
        record.set_int(SYMBOL_COUNT_COL, sym_count);
        table.put_record(record.clone()).unwrap();
        record
    }

    #[test]
    fn opens_existing_v1_table_and_reads_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let table = handle
                .create_table(VARIABLE_STORAGE_TABLE_NAME.to_string(), schema())
                .unwrap();
            let mut table = table.write().unwrap();
            make_record(&mut table, 0x1000, 5, 1);
            make_record(&mut table, 0x2000, 5, 2);
            make_record(&mut table, 0x3000, 6, 1);
        }

        let adapter = OldVariableStorageDBAdapterV0V1::new(&handle).unwrap();
        let ns5 = adapter.get_records_for_namespace(5).unwrap();
        assert_eq!(ns5.len(), 2);
        let ns6 = adapter.get_records_for_namespace(6).unwrap();
        assert_eq!(ns6.len(), 1);
        assert_eq!(ns6[0].get_long(STORAGE_ADDR_COL), Some(0x3000));

        let fetched = adapter.get_record(ns6[0].get_key().get_long_value()).unwrap();
        assert!(fetched.is_some());
    }

    #[test]
    fn opens_existing_v0_table() {
        let mut handle = DBHandle::new().unwrap();
        let v0_schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long, FieldType::Long, FieldType::Int],
            vec![
                "Address".to_string(),
                "NamespaceID".to_string(),
                "SymCount".to_string(),
            ],
            vec![],
        ));
        handle
            .create_table(VARIABLE_STORAGE_TABLE_NAME.to_string(), v0_schema)
            .unwrap();

        assert!(OldVariableStorageDBAdapterV0V1::new(&handle).is_ok());
    }

    #[test]
    fn missing_table_is_an_error() {
        let handle = DBHandle::new().unwrap();
        assert!(OldVariableStorageDBAdapterV0V1::new(&handle).is_err());
    }

    #[test]
    fn unsupported_version_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        let bad_schema = Arc::new(Schema::new(
            2,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long, FieldType::Long, FieldType::Int],
            vec![
                "Address".to_string(),
                "NamespaceID".to_string(),
                "SymCount".to_string(),
            ],
            vec![],
        ));
        handle
            .create_table(VARIABLE_STORAGE_TABLE_NAME.to_string(), bad_schema)
            .unwrap();

        assert!(OldVariableStorageDBAdapterV0V1::new(&handle).is_err());
    }
}

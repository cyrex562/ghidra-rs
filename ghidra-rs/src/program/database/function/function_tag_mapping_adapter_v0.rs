//! Port of `ghidra.program.database.function.FunctionTagMappingAdapterV0`.
//!
//! Initial (only) version of [`FunctionTagMappingAdapter`]. Mirrors
//! [`FunctionTagAdapterV0`](crate::program::database::function::FunctionTagAdapterV0)'s shape
//! exactly (same transient/lazy table, same `Arc<RwLock<DBHandle>>`-vs-`&mut DBHandle` deviation,
//! same omitted `DBListener` registration -- see that module's docs for the shared rationale).
//!
//! Java's `getRecord`/`getRecordsByFunctionID` use `Table.indexIterator(V0_FUNCTION_ID_COL, ...)`
//! for an indexed by-function-ID lookup; this port's [`Table`] has no secondary-index support, so
//! both scan every record and filter in memory instead, matching the established convention for
//! this DB-adapter family (see e.g.
//! [`SymbolDatabaseAdapterV5`](crate::program::database::symbol::SymbolDatabaseAdapterV5)'s module
//! docs). Likewise, `removeFunctionTagRecord(long)` (the single-tag-ID overload) uses
//! `RecordIterator.delete()` to remove matching rows in place during iteration; this port's
//! [`RecordIterator`] has no `delete`, so matching keys are collected first and then deleted in a
//! second pass.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::function::function_tag_mapping_adapter::{
    FunctionTagMappingAdapter, FUNCTION_ID_COL, TAG_ID_COL,
};
use crate::util::exception::VersionException;

/// Name of the function tag mapping database table. Mirrors
/// `FunctionTagMappingAdapter.TABLE_NAME`.
pub const TABLE_NAME: &str = "Function Tag Map";

/// Schema version implemented by this adapter. Mirrors
/// `FunctionTagMappingAdapterV0.SCHEMA_VERSION` (which also serves as
/// `FunctionTagMappingAdapter.CURRENT_VERSION`, since this is the only version).
pub const SCHEMA_VERSION: i32 = 0;

/// Build the function tag mapping table schema, as defined by `FunctionTagMappingAdapterV0.SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
        FieldType::Long,
        "ID".to_string(),
        vec![FieldType::Long, FieldType::Long],
        vec!["Function ID".to_string(), "Tag ID".to_string()],
        vec![],
    ))
}

struct EmptyRecordIterator;

impl RecordIterator for EmptyRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn has_next(&self) -> bool {
        false
    }
}

struct VecRecordIterator {
    records: std::vec::IntoIter<DBRecord>,
}

impl RecordIterator for VecRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.records.next())
    }

    fn has_next(&self) -> bool {
        self.records.as_slice().first().is_some()
    }
}

/// Initial (only) version of the [`FunctionTagMappingAdapter`].
///
/// Port of `ghidra.program.database.function.FunctionTagMappingAdapterV0`. See the module docs
/// for the `Arc<RwLock<DBHandle>>` deviation, the omitted `DBListener` registration, and the
/// linear-scan stand-ins for indexed lookups/in-place iterator deletion.
pub struct FunctionTagMappingAdapterV0 {
    dbhandle: Arc<RwLock<DBHandle>>,
    /// Lazily-created; `None` means "table not yet needed".
    table: Option<Arc<RwLock<Table>>>,
}

impl FunctionTagMappingAdapterV0 {
    /// Constructs a version 0 function tag mapping adapter. If `create` is `true`, table creation
    /// is deferred to the first write (the table is transient, mirroring
    /// [`FunctionTagAdapterV0::new`](crate::program::database::function::FunctionTagAdapterV0::new)).
    /// If `create` is `false`, an existing table is opened if present.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if an existing table's schema version does not match
    /// [`SCHEMA_VERSION`].
    pub fn new(dbhandle: Arc<RwLock<DBHandle>>, create: bool) -> Result<Self, VersionException> {
        let table = if create {
            None
        } else {
            let existing = dbhandle.read().unwrap().get_table(TABLE_NAME);
            match existing {
                None => None,
                Some(t) => {
                    let version = t.read().unwrap().get_schema().get_version();
                    if version != SCHEMA_VERSION {
                        return Err(VersionException::with_version_indicator(
                            VersionException::NEWER_VERSION,
                            false,
                        ));
                    }
                    Some(t)
                }
            }
        };
        Ok(FunctionTagMappingAdapterV0 { dbhandle, table })
    }

    /// Lazily creates the underlying table if it does not already exist. Stands in for the
    /// private `FunctionTagMappingAdapterV0.getTable()`.
    fn get_or_create_table(&mut self) -> io::Result<Arc<RwLock<Table>>> {
        if let Some(table) = &self.table {
            return Ok(table.clone());
        }
        let table = self
            .dbhandle
            .write()
            .unwrap()
            .create_table(TABLE_NAME.to_string(), schema())?;
        self.table = Some(table.clone());
        Ok(table)
    }
}

impl FunctionTagMappingAdapter for FunctionTagMappingAdapterV0 {
    fn get_records_by_function_id(&self, function_id: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
        let Some(table) = &self.table else {
            return Ok(Box::new(EmptyRecordIterator));
        };
        let table = table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(FUNCTION_ID_COL) == Some(function_id) {
                records.push(rec);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_record(&self, function_id: i64, tag_id: i64) -> io::Result<Option<DBRecord>> {
        let Some(table) = &self.table else {
            return Ok(None);
        };
        let table = table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_long(FUNCTION_ID_COL) == Some(function_id) && rec.get_long(TAG_ID_COL) == Some(tag_id) {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }

    fn create_function_tag_record(&mut self, function_id: i64, tag_id: i64) -> io::Result<DBRecord> {
        let table = self.get_or_create_table()?;
        let key = table.write().unwrap().get_next_key();
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_long(FUNCTION_ID_COL, function_id);
        rec.set_long(TAG_ID_COL, tag_id);
        table.write().unwrap().put_record(rec.clone())?;
        Ok(rec)
    }

    fn remove_function_tag_record(&mut self, function_id: i64, tag_id: i64) -> io::Result<bool> {
        let Some(record) = self.get_record(function_id, tag_id)? else {
            return Ok(false);
        };
        let Some(table) = &self.table else {
            return Ok(false);
        };
        table.write().unwrap().delete_record(record.get_key())
    }

    fn remove_function_tag_records_for_tag(&mut self, tag_id: i64) -> io::Result<()> {
        let Some(table) = &self.table else {
            return Ok(());
        };
        // Tag ID is not an indexed column in the mapping table, so this scans every record
        // (matches Java's own comment: only done when deleting a tag, so not performance
        // sensitive). `RecordIterator` has no in-place `delete()` here, so matching keys are
        // collected first and deleted in a second pass.
        let keys_to_delete: Vec<Field> = {
            let table = table.read().unwrap();
            let mut iter = table.get_record_iterator()?;
            let mut keys = Vec::new();
            while let Some(rec) = iter.next()? {
                if rec.get_long(TAG_ID_COL) == Some(tag_id) {
                    keys.push(rec.get_key().clone());
                }
            }
            keys
        };
        let mut table = table.write().unwrap();
        for key in keys_to_delete {
            table.delete_record(&key)?;
        }
        Ok(())
    }

    fn is_tag_assigned(&self, id: i64) -> io::Result<bool> {
        let Some(table) = &self.table else {
            return Ok(false);
        };
        let table = table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_long(TAG_ID_COL) == Some(id) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let Some(table) = &self.table else {
            return Ok(Box::new(EmptyRecordIterator));
        };
        let table = table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(create: bool) -> (Arc<RwLock<DBHandle>>, FunctionTagMappingAdapterV0) {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = FunctionTagMappingAdapterV0::new(handle.clone(), create).unwrap();
        (handle, adapter)
    }

    #[test]
    fn empty_adapter_degrades_gracefully_before_any_write() {
        let (_handle, adapter) = adapter(true);
        assert!(adapter.get_record(1, 100).unwrap().is_none());
        assert!(!adapter.is_tag_assigned(100).unwrap());
        let mut iter = adapter.get_records().unwrap();
        assert!(!iter.has_next());
        let mut by_fn = adapter.get_records_by_function_id(1).unwrap();
        assert!(by_fn.next().unwrap().is_none());
    }

    #[test]
    fn create_get_and_query_round_trip() {
        let (_handle, mut adapter) = adapter(true);
        adapter.create_function_tag_record(1, 100).unwrap();
        adapter.create_function_tag_record(1, 200).unwrap();
        adapter.create_function_tag_record(2, 100).unwrap();

        assert!(adapter.get_record(1, 100).unwrap().is_some());
        assert!(adapter.get_record(1, 300).unwrap().is_none());
        assert!(adapter.is_tag_assigned(100).unwrap());
        assert!(!adapter.is_tag_assigned(999).unwrap());

        let mut count = 0;
        let mut iter = adapter.get_records_by_function_id(1).unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn remove_by_function_and_tag_id() {
        let (_handle, mut adapter) = adapter(true);
        adapter.create_function_tag_record(1, 100).unwrap();

        assert!(adapter.remove_function_tag_record(1, 100).unwrap());
        assert!(adapter.get_record(1, 100).unwrap().is_none());
        assert!(!adapter.remove_function_tag_record(1, 100).unwrap());
    }

    #[test]
    fn remove_records_for_tag_deletes_every_matching_row() {
        let (_handle, mut adapter) = adapter(true);
        adapter.create_function_tag_record(1, 100).unwrap();
        adapter.create_function_tag_record(2, 100).unwrap();
        adapter.create_function_tag_record(3, 200).unwrap();

        adapter.remove_function_tag_records_for_tag(100).unwrap();
        assert!(!adapter.is_tag_assigned(100).unwrap());
        assert!(adapter.is_tag_assigned(200).unwrap());

        let mut count = 0;
        let mut iter = adapter.get_records().unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn reopening_existing_table_preserves_records() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        {
            let mut adapter = FunctionTagMappingAdapterV0::new(handle.clone(), true).unwrap();
            adapter.create_function_tag_record(1, 100).unwrap();
        }
        let reopened = FunctionTagMappingAdapterV0::new(handle, false).unwrap();
        assert!(reopened.get_record(1, 100).unwrap().is_some());
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let mut adapter: Box<dyn FunctionTagMappingAdapter> =
            Box::new(FunctionTagMappingAdapterV0::new(handle, true).unwrap());
        adapter.create_function_tag_record(1, 100).unwrap();
        assert!(adapter.get_record(1, 100).unwrap().is_some());
    }
}

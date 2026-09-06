//! Port of `ghidra.program.database.symbol.VariableStorageDBAdapterV2`.
//!
//! Version 2 (current) implementation for accessing the variable storage database table, backed
//! by a live, writable [`Table`].
//!
//! Also re-declares the `VariableStorageDBAdapter.VARIABLE_STORAGE_TABLE_NAME`/
//! `VARIABLE_STORAGE_SCHEMA`/`HASH_COL`/`STORAGE_COL` constants locally, since
//! [`VariableStorageDBAdapter`](crate::program::database::symbol::VariableStorageDBAdapter)'s own
//! port intentionally left the table-layout constants out.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::symbol::VariableStorageDBAdapter;
use crate::util::exception::VersionException;

/// Name of the variable storage database table.
pub const VARIABLE_STORAGE_TABLE_NAME: &str = "Variable Storage";
/// Column index of the storage hash. Mirrors `VariableStorageDBAdapter.HASH_COL`.
pub const HASH_COL: usize = 0;
/// Column index of the serialized storage. Mirrors `VariableStorageDBAdapter.STORAGE_COL`.
pub const STORAGE_COL: usize = 1;
/// Schema version implemented by this adapter.
pub const CURRENT_VERSION: i32 = 2;

/// Build the current variable storage table schema, as defined by
/// `VariableStorageDBAdapter.VARIABLE_STORAGE_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        CURRENT_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::Long, FieldType::String],
        vec!["Hash".to_string(), "Storage".to_string()],
        vec![],
    ))
}

/// Version 2 (current) implementation for accessing the variable storage database table.
///
/// Port of `ghidra.program.database.symbol.VariableStorageDBAdapterV2`.
pub struct VariableStorageDBAdapterV2 {
    table: Arc<RwLock<Table>>,
}

impl VariableStorageDBAdapterV2 {
    /// Gets a version 2 adapter for the variable storage database table. If `create` is `true`,
    /// the table is created, otherwise an existing table is opened.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if opening an existing table whose schema version does not
    /// match [`CURRENT_VERSION`].
    pub fn new(handle: &mut DBHandle, create: bool) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(VARIABLE_STORAGE_TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(VARIABLE_STORAGE_TABLE_NAME).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {VARIABLE_STORAGE_TABLE_NAME}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != CURRENT_VERSION {
                return Err(VersionException::with_upgradeable(version < CURRENT_VERSION));
            }
            table
        };
        Ok(VariableStorageDBAdapterV2 { table })
    }
}

impl VariableStorageDBAdapter for VariableStorageDBAdapterV2 {
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    fn find_record_key(&self, hash: i64) -> io::Result<i64> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_long(HASH_COL) == Some(hash) {
                return Ok(rec.get_key().get_long_value());
            }
        }
        Ok(-1)
    }

    fn get_next_storage_id(&mut self) -> i64 {
        let mut table = self.table.write().unwrap();
        let next_key = table.get_next_key();
        if next_key <= 0 {
            1
        } else {
            next_key
        }
    }

    fn delete_record(&mut self, key: i64) -> io::Result<()> {
        self.table.write().unwrap().delete_record(&Field::Long(Some(key)))?;
        Ok(())
    }

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

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn delete_table(&mut self) -> io::Result<()> {
        // `VariableStorageDBAdapter::delete_table` (as already ported) takes no `DBHandle`
        // parameter, but deleting the underlying named table is only possible via the owning
        // `DBHandle` (which Java's `VariableStorageDBAdapterV2` stashes as a field at
        // construction, but this port does not retain). Real deletion is exposed instead via the
        // inherent [`Self::delete_table_with_handle`] below, which takes the handle explicitly.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "use VariableStorageDBAdapterV2::delete_table_with_handle",
        ))
    }
}

impl VariableStorageDBAdapterV2 {
    /// Deletes the variable storage table. Stands in for `VariableStorageDBAdapterV2.deleteTable()`.
    ///
    /// Takes the owning `handle` explicitly, since this port (unlike Java) does not retain the
    /// `DBHandle` it was constructed with; see [`VariableStorageDBAdapter::delete_table`]'s trait
    /// method for the handle-less variant this struct's trait impl reports as unsupported.
    pub fn delete_table_with_handle(&mut self, handle: &mut DBHandle) {
        handle.delete_table(VARIABLE_STORAGE_TABLE_NAME);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_and_round_trip_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = VariableStorageDBAdapterV2::new(&mut handle, true).unwrap();

        let id = adapter.get_next_storage_id();
        let mut record = DBRecord::new(schema(), Field::Long(Some(id)));
        record.set_long(HASH_COL, 0xdead_beef);
        record.set_string(STORAGE_COL, Some("stack:-0x10:4".to_string()));
        adapter.update_record(&record).unwrap();

        assert_eq!(adapter.get_record_count(), 1);
        let fetched = adapter.get_record(id).unwrap().expect("record present");
        assert_eq!(fetched.get_string(STORAGE_COL), Some("stack:-0x10:4"));

        assert_eq!(adapter.find_record_key(0xdead_beef).unwrap(), id);
        assert_eq!(adapter.find_record_key(0x1234).unwrap(), -1);
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = VariableStorageDBAdapterV2::new(&mut handle, true).unwrap();
            let id = adapter.get_next_storage_id();
            let mut record = DBRecord::new(schema(), Field::Long(Some(id)));
            record.set_long(HASH_COL, 1);
            record.set_string(STORAGE_COL, Some("register:EAX:4".to_string()));
            adapter.update_record(&record).unwrap();
        }
        let adapter = VariableStorageDBAdapterV2::new(&mut handle, false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(VariableStorageDBAdapterV2::new(&mut handle, false).is_err());
    }

    #[test]
    fn delete_record_and_delete_table() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = VariableStorageDBAdapterV2::new(&mut handle, true).unwrap();
        let id = adapter.get_next_storage_id();
        let record = DBRecord::new(schema(), Field::Long(Some(id)));
        adapter.update_record(&record).unwrap();
        assert_eq!(adapter.get_record_count(), 1);

        adapter.delete_record(id).unwrap();
        assert_eq!(adapter.get_record_count(), 0);

        adapter.delete_table_with_handle(&mut handle);
        assert!(handle.get_table(VARIABLE_STORAGE_TABLE_NAME).is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn VariableStorageDBAdapter> =
            Box::new(VariableStorageDBAdapterV2::new(&mut handle, true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}

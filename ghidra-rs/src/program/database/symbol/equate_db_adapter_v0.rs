//! Port of `ghidra.program.database.symbol.EquateDBAdapterV0`.
//!
//! Implementation for version 0 of the adapter that accesses the equate record that has the
//! equate name and value, backed by a live, writable [`Table`].
//!
//! Also re-declares the `EquateDBAdapter.EQUATES_TABLE_NAME`/`EQUATES_SCHEMA`/`NAME_COL`/
//! `VALUE_COL` constants locally, since
//! [`EquateDBAdapter`](crate::program::database::symbol::EquateDBAdapter)'s own port
//! intentionally left the table-layout constants out.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::symbol::{EquateDBAdapter, GetRecordKeyError};
use crate::util::exception::{NotFoundException, VersionException};

/// Name of the equates database table.
pub const EQUATES_TABLE_NAME: &str = "Equates";
/// Column index of the equate name. Mirrors `EquateDBAdapter.NAME_COL`.
pub const NAME_COL: usize = 0;
/// Column index of the equate value. Mirrors `EquateDBAdapter.VALUE_COL`.
pub const VALUE_COL: usize = 1;
/// Schema version implemented by this adapter.
pub const CURRENT_VERSION: i32 = 0;

/// Build the equates table schema, as defined by `EquateDBAdapter.EQUATES_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        CURRENT_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::String, FieldType::Long],
        vec!["Equate Name".to_string(), "Equate Value".to_string()],
        vec![],
    ))
}

/// Implementation for version 0 of the adapter that accesses the equate record that has the
/// equate name and value.
///
/// Port of `ghidra.program.database.symbol.EquateDBAdapterV0`.
pub struct EquateDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl EquateDBAdapterV0 {
    /// Constructor. If `create` is `true`, the equates table is created, otherwise an existing
    /// table is opened.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if opening an existing table that is missing or whose
    /// schema version does not match [`CURRENT_VERSION`].
    pub fn new(handle: &mut DBHandle, create: bool) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(EQUATES_TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(EQUATES_TABLE_NAME).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {EQUATES_TABLE_NAME}"))
            })?;
            if table.read().unwrap().get_schema().get_version() != CURRENT_VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(EquateDBAdapterV0 { table })
    }
}

impl EquateDBAdapter for EquateDBAdapterV0 {
    fn get_record_key(&self, name: &str) -> Result<i64, GetRecordKeyError> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_string(NAME_COL) == Some(name) {
                return Ok(rec.get_key().get_long_value());
            }
        }
        Err(GetRecordKeyError::NotFound(NotFoundException::with_message(format!(
            "Equate named {name} was not found"
        ))))
    }

    fn get_record(&self, key: i64) -> io::Result<DBRecord> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such equate record"))
    }

    fn remove_record(&mut self, key: i64) -> io::Result<()> {
        self.table.write().unwrap().delete_record(&Field::Long(Some(key)))?;
        Ok(())
    }

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn create_equate(&mut self, name: &str, value: i64) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_string(NAME_COL, Some(name.to_string()));
        record.set_long(VALUE_COL, value);
        table.put_record(record.clone())?;
        Ok(record)
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

    fn has_record(&self, name: &str) -> io::Result<bool> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_string(NAME_COL) == Some(name) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_lookup_and_remove_round_trip() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EquateDBAdapterV0::new(&mut handle, true).unwrap();

        let record = adapter.create_equate("FOO", 42).unwrap();
        let key = record.get_key().get_long_value();

        assert!(adapter.has_record("FOO").unwrap());
        assert!(!adapter.has_record("BAR").unwrap());

        let key2 = adapter.get_record_key("FOO").unwrap();
        assert_eq!(key, key2);

        let fetched = adapter.get_record(key).unwrap();
        assert_eq!(fetched.get_long(VALUE_COL), Some(42));

        adapter.remove_record(key).unwrap();
        assert!(!adapter.has_record("FOO").unwrap());
        assert!(matches!(
            adapter.get_record_key("FOO"),
            Err(GetRecordKeyError::NotFound(_))
        ));
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = EquateDBAdapterV0::new(&mut handle, true).unwrap();
            adapter.create_equate("ONE", 1).unwrap();
            adapter.create_equate("TWO", 2).unwrap();
        }
        let adapter = EquateDBAdapterV0::new(&mut handle, false).unwrap();

        let mut seen = 0;
        {
            let mut iter = adapter.get_records().unwrap();
            while iter.next().unwrap().is_some() {
                seen += 1;
            }
        }
        assert_eq!(seen, 2);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(EquateDBAdapterV0::new(&mut handle, false).is_err());
    }

    #[test]
    fn update_record_round_trip() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EquateDBAdapterV0::new(&mut handle, true).unwrap();
        let mut record = adapter.create_equate("X", 1).unwrap();
        record.set_long(VALUE_COL, 99);
        adapter.update_record(&record).unwrap();

        let key = record.get_key().get_long_value();
        assert_eq!(adapter.get_record(key).unwrap().get_long(VALUE_COL), Some(99));
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn EquateDBAdapter> = Box::new(EquateDBAdapterV0::new(&mut handle, true).unwrap());
        assert!(!adapter.has_record("anything").unwrap());
    }
}

//! Port of `ghidra.program.database.data.BuiltinDBAdapterV0`.
//!
//! Version 0 (current, and so far only) implementation for accessing the built-in data types
//! table, backed by a live, writable [`Table`].
//!
//! The Java `createRecord` computes its key via `DataTypeManagerDB.createKey(BUILT_IN,
//! tableKey)`, tagging the raw table key (floored at 100, reserving lower IDs) with a
//! datatype-kind bit pattern. That key-tagging scheme is a `DataTypeManagerDB`-wide invariant
//! (not specific to this table) and `DataTypeManagerDB` has not been ported with that scheme
//! yet, so this port keeps the 100-floor but skips the tag, using the table's own next-key
//! sequence directly (same deviation as `PointerDBAdapterV2`/`EnumValueDBAdapterV1`).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::data::builtin_db_adapter::{
    self, BuiltinDBAdapter, BUILT_IN_CAT_COL, BUILT_IN_CLASSNAME_COL, BUILT_IN_NAME_COL,
    BUILT_IN_TABLE_NAME,
};
use crate::util::exception::VersionException;

/// Minimum key value assigned to built-in data type records (IDs below this are reserved).
pub const MIN_KEY: i64 = 100;

/// Version 0 (current) implementation for accessing the built-in data types table.
///
/// Port of `ghidra.program.database.data.BuiltinDBAdapterV0`.
pub struct BuiltinDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl BuiltinDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = builtin_db_adapter::CURRENT_VERSION;

    /// Gets a version 0 adapter for the built-ins database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{BUILT_IN_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, builtin_db_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(&table_name).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {table_name}"))
            })?;
            if table.read().unwrap().get_schema().get_version() != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(BuiltinDBAdapterV0 { table })
    }
}

impl BuiltinDBAdapter for BuiltinDBAdapterV0 {
    fn create_record(
        &mut self,
        name: &str,
        class_name: &str,
        category_id: i64,
    ) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = std::cmp::max(table.get_next_key(), MIN_KEY);
        table.ensure_next_key_at_least(key);
        let mut record = DBRecord::new(builtin_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(BUILT_IN_NAME_COL, Field::String(Some(name.to_string())));
        record.set_field(
            BUILT_IN_CLASSNAME_COL,
            Field::String(Some(class_name.to_string())),
        );
        record.set_field(BUILT_IN_CAT_COL, Field::Long(Some(category_id)));
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_record(&self, data_type_id: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(data_type_id)))
    }

    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(BUILT_IN_CAT_COL), Field::Long(Some(v)) if *v == category_id)
            {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn remove_record(&mut self, data_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(data_id)))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_and_round_trip_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = BuiltinDBAdapterV0::new(&mut handle, "", true).unwrap();

        let rec = adapter
            .create_record("undefined1", "ghidra.Undefined1", 42)
            .unwrap();
        assert_eq!(rec.get_key(), &Field::Long(Some(MIN_KEY)));
        assert_eq!(adapter.get_record_count(), 1);

        let fetched = adapter
            .get_record(MIN_KEY)
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            fetched.get_field(BUILT_IN_NAME_COL),
            &Field::String(Some("undefined1".to_string()))
        );
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = BuiltinDBAdapterV0::new(&mut handle, "", true).unwrap();
            adapter.create_record("a", "b", 1).unwrap();
        }
        let adapter = BuiltinDBAdapterV0::new(&mut handle, "", false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(BuiltinDBAdapterV0::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn update_and_remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = BuiltinDBAdapterV0::new(&mut handle, "", true).unwrap();
        let mut rec = adapter.create_record("a", "b", 1).unwrap();

        rec.set_field(BUILT_IN_NAME_COL, Field::String(Some("renamed".to_string())));
        adapter.update_record(&rec).unwrap();
        let refetched = adapter.get_record(MIN_KEY).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(BUILT_IN_NAME_COL),
            &Field::String(Some("renamed".to_string()))
        );

        let removed = adapter.remove_record(MIN_KEY).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_record_ids_in_category_filters_by_category() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = BuiltinDBAdapterV0::new(&mut handle, "", true).unwrap();
        adapter.create_record("a", "ca", 1).unwrap();
        adapter.create_record("b", "cb", 1).unwrap();
        adapter.create_record("c", "cc", 2).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(1).unwrap().len(), 2);
        assert_eq!(adapter.get_record_ids_in_category(2).unwrap().len(), 1);
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn BuiltinDBAdapter> =
            Box::new(BuiltinDBAdapterV0::new(&mut handle, "", true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}

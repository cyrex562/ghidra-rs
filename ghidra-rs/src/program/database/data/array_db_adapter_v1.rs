//! Port of `ghidra.program.database.data.ArrayDBAdapterV1`.
//!
//! Version 1 (current) implementation for accessing the Array database table, backed by a live,
//! writable [`Table`]. `NOTE`: use of a table-name prefix was introduced with this adapter
//! version.
//!
//! The Java `createRecord` computes its key via `DataTypeManagerDB.createKey(ARRAY,
//! table.getKey())`, tagging the raw table key with a datatype-kind bit pattern. That key-tagging
//! scheme is a `DataTypeManagerDB`-wide invariant (not specific to this table) and
//! `DataTypeManagerDB` has not been ported with that scheme yet, so this port uses the table's
//! own next-key sequence directly instead (same deviation as `PointerDBAdapterV2`).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::data::array_db_adapter::{
    self, ArrayDBAdapter, ARRAY_CAT_COL, ARRAY_DIM_COL, ARRAY_DT_ID_COL, ARRAY_ELEMENT_LENGTH_COL,
    ARRAY_TABLE_NAME,
};
use crate::util::exception::VersionException;

/// A `RecordIterator` over an eagerly-collected set of records.
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

/// Version 1 (current) implementation for accessing the Array database table.
///
/// Port of `ghidra.program.database.data.ArrayDBAdapterV1`.
pub struct ArrayDBAdapterV1 {
    table: Arc<RwLock<Table>>,
}

impl ArrayDBAdapterV1 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = array_db_adapter::CURRENT_VERSION;

    /// Gets a version 1 adapter for the Array database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{ARRAY_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, array_db_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(&table_name).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {table_name}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(version < Self::VERSION));
            }
            table
        };
        Ok(ArrayDBAdapterV1 { table })
    }
}

impl ArrayDBAdapter for ArrayDBAdapterV1 {
    fn create_record(
        &mut self,
        data_type_id: i64,
        number_of_elements: i32,
        length: i32,
        cat_id: i64,
    ) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(array_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(ARRAY_DT_ID_COL, Field::Long(Some(data_type_id)));
        record.set_field(ARRAY_DIM_COL, Field::Int(Some(number_of_elements)));
        record.set_field(ARRAY_ELEMENT_LENGTH_COL, Field::Int(Some(length)));
        record.set_field(ARRAY_CAT_COL, Field::Long(Some(cat_id)));
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_record(&self, array_id: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(array_id)))
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn remove_record(&mut self, data_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(data_id)))
    }

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        let name = self.table.read().unwrap().get_name().to_string();
        handle.delete_table(&name);
        Ok(())
    }

    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(ARRAY_CAT_COL), Field::Long(Some(v)) if *v == category_id) {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
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
        let mut adapter = ArrayDBAdapterV1::new(&mut handle, "", true).unwrap();

        let created = adapter.create_record(42, 4, 8, 5).unwrap();
        let fetched = adapter
            .get_record(created.get_key().get_long_value())
            .unwrap()
            .expect("record should exist");
        assert_eq!(fetched.get_field(ARRAY_DT_ID_COL), &Field::Long(Some(42)));
        assert_eq!(fetched.get_field(ARRAY_DIM_COL), &Field::Int(Some(4)));
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = ArrayDBAdapterV1::new(&mut handle, "", true).unwrap();
            adapter.create_record(1, 2, 4, 5).unwrap();
        }
        let adapter = ArrayDBAdapterV1::new(&mut handle, "", false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(ArrayDBAdapterV1::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn update_and_remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ArrayDBAdapterV1::new(&mut handle, "", true).unwrap();
        let mut rec = adapter.create_record(1, 2, 4, 5).unwrap();

        rec.set_field(ARRAY_DIM_COL, Field::Int(Some(9)));
        adapter.update_record(&rec).unwrap();
        let refetched = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_eq!(refetched.get_field(ARRAY_DIM_COL), &Field::Int(Some(9)));

        let removed = adapter.remove_record(rec.get_key().get_long_value()).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_record_ids_in_category_filters_by_category() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ArrayDBAdapterV1::new(&mut handle, "", true).unwrap();
        adapter.create_record(1, 2, 4, 5).unwrap();
        adapter.create_record(2, 3, 4, 5).unwrap();
        adapter.create_record(3, 4, 4, 9).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(adapter.get_record_ids_in_category(9).unwrap().len(), 1);
    }

    #[test]
    fn delete_table_removes_it_from_handle() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ArrayDBAdapterV1::new(&mut handle, "prefix_", true).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table("prefix_Arrays").is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn ArrayDBAdapter> =
            Box::new(ArrayDBAdapterV1::new(&mut handle, "", true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}

//! Port of `ghidra.program.database.data.PointerDBAdapterV2`.
//!
//! Version 2 (current) implementation for accessing the pointer database table, backed by a
//! live, writable [`Table`]. `NOTE`: use of a table-name prefix was introduced with this adapter
//! version, matching multiple data type managers sharing one underlying database.
//!
//! The Java `createRecord` computes its key via `DataTypeManagerDB.createKey(POINTER,
//! table.getKey())`, tagging the raw table key with a datatype-kind bit pattern. That key-tagging
//! scheme is a `DataTypeManagerDB`-wide invariant (not specific to this table) and
//! `DataTypeManagerDB` has not been ported with that scheme yet, so this port uses the table's
//! own next-key sequence directly instead.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::pointer_db_adapter::{
    self, PointerDBAdapter, POINTER_TABLE_NAME, PTR_CATEGORY_COL, PTR_DT_ID_COL, PTR_LENGTH_COL,
};
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;

/// Version 2 (current) implementation for accessing the pointer database table.
///
/// Port of `ghidra.program.database.data.PointerDBAdapterV2`.
pub struct PointerDBAdapterV2 {
    table: Arc<RwLock<Table>>,
}

impl PointerDBAdapterV2 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = pointer_db_adapter::CURRENT_VERSION;

    /// Gets a version 2 adapter for the pointer database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(handle: &mut DBHandle, table_prefix: &str, create: bool) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{POINTER_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, pointer_db_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle
                .get_table(&table_name)
                .ok_or_else(|| VersionException::with_message(format!("Missing Table: {table_name}")))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(version < Self::VERSION));
            }
            table
        };
        Ok(PointerDBAdapterV2 { table })
    }
}

impl DBRecordAdapter for PointerDBAdapterV2 {
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

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }
}

impl RecordTranslator for PointerDBAdapterV2 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        Ok(old_record)
    }
}

impl PointerDBAdapter for PointerDBAdapterV2 {
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        let name = self.table.read().unwrap().get_name().to_string();
        handle.delete_table(&name);
        Ok(())
    }

    fn create_record(
        &mut self,
        data_type_id: i64,
        category_id: i64,
        length: i32,
    ) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(pointer_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(PTR_DT_ID_COL, Field::Long(Some(data_type_id)));
        record.set_field(PTR_CATEGORY_COL, Field::Long(Some(category_id)));
        record.set_field(PTR_LENGTH_COL, Field::Byte(Some(length as i8)));
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_record(&self, pointer_id: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(pointer_id)))
    }

    fn remove_record(&mut self, pointer_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(pointer_id)))
    }

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(PTR_CATEGORY_COL), Field::Long(Some(v)) if *v == category_id)
            {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_and_round_trip_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = PointerDBAdapterV2::new(&mut handle, "", true).unwrap();

        let created = adapter.create_record(10, 5, 8).unwrap();
        assert_eq!(created.get_field(PTR_DT_ID_COL), &Field::Long(Some(10)));
        assert_eq!(adapter.get_record_count(), 1);

        let fetched = adapter
            .get_record(created.get_key().get_long_value())
            .unwrap()
            .expect("record should exist");
        assert_eq!(fetched.get_field(PTR_LENGTH_COL), &Field::Byte(Some(8)));
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = PointerDBAdapterV2::new(&mut handle, "", true).unwrap();
            adapter.create_record(1, 1, 4).unwrap();
        }
        let adapter = PointerDBAdapterV2::new(&mut handle, "", false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(PointerDBAdapterV2::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn update_and_remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = PointerDBAdapterV2::new(&mut handle, "", true).unwrap();
        let mut created = adapter.create_record(1, 1, 4).unwrap();

        created.set_field(PTR_LENGTH_COL, Field::Byte(Some(8)));
        adapter.update_record(&created).unwrap();
        let refetched = adapter
            .get_record(created.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_eq!(refetched.get_field(PTR_LENGTH_COL), &Field::Byte(Some(8)));

        let removed = adapter
            .remove_record(created.get_key().get_long_value())
            .unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_record_ids_in_category_filters_by_category() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = PointerDBAdapterV2::new(&mut handle, "", true).unwrap();
        adapter.create_record(1, 5, 4).unwrap();
        adapter.create_record(2, 5, 4).unwrap();
        adapter.create_record(3, 6, 4).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(adapter.get_record_ids_in_category(6).unwrap().len(), 1);
    }

    #[test]
    fn delete_table_removes_it_from_handle() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = PointerDBAdapterV2::new(&mut handle, "prefix_", true).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table("prefix_Pointers").is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn PointerDBAdapter> =
            Box::new(PointerDBAdapterV2::new(&mut handle, "", true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}

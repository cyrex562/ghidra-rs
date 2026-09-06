//! Port of `ghidra.program.database.data.EnumValueDBAdapterV1`.
//!
//! Version 1 (current) implementation for the enumeration data type values table adapter,
//! backed by a live, writable [`Table`]. `NOTE`: use of a table-name prefix was introduced with
//! this adapter version, matching multiple data type managers sharing one underlying database.
//!
//! The Java `createRecord` computes its key via `table.getKey()` (the table's own next-key
//! allocator), so unlike some sibling `V2` adapters in this package this one needs no additional
//! key-tagging scheme.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::enum_value_db_adapter::{
    self, EnumValueDBAdapter, ENUMVAL_COMMENT_COL, ENUMVAL_ID_COL, ENUMVAL_NAME_COL,
    ENUMVAL_VALUE_COL, ENUM_VALUE_TABLE_NAME,
};
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;

/// Version 1 (current) implementation for the enumeration data type values table adapter.
///
/// Port of `ghidra.program.database.data.EnumValueDBAdapterV1`.
pub struct EnumValueDBAdapterV1 {
    table: Arc<RwLock<Table>>,
}

impl EnumValueDBAdapterV1 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = enum_value_db_adapter::CURRENT_VERSION;

    /// Gets a version 1 adapter for the enumeration data type values database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{ENUM_VALUE_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, enum_value_db_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle
                .get_table(&table_name)
                .ok_or_else(|| VersionException::with_upgradeable(true))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(version < Self::VERSION));
            }
            table
        };
        Ok(EnumValueDBAdapterV1 { table })
    }
}

impl DBRecordAdapter for EnumValueDBAdapterV1 {
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

impl RecordTranslator for EnumValueDBAdapterV1 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        Ok(old_record)
    }
}

impl EnumValueDBAdapter for EnumValueDBAdapterV1 {
    fn create_record(
        &mut self,
        enum_id: i64,
        name: &str,
        value: i64,
        comment: Option<&str>,
    ) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(enum_value_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(ENUMVAL_ID_COL, Field::Long(Some(enum_id)));
        record.set_field(ENUMVAL_NAME_COL, Field::String(Some(name.to_string())));
        record.set_field(ENUMVAL_VALUE_COL, Field::Long(Some(value)));
        record.set_field(
            ENUMVAL_COMMENT_COL,
            Field::String(comment.map(str::to_string)),
        );
        table.put_record(record)
    }

    fn get_record(&self, value_id: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(value_id)))
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        let name = self.table.read().unwrap().get_name().to_string();
        handle.delete_table(&name);
        Ok(())
    }

    fn remove_record(&mut self, value_id: i64) -> io::Result<()> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(value_id)))?;
        Ok(())
    }

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn get_value_ids_in_enum(&self, enum_id: i64) -> io::Result<Vec<Field>> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(ENUMVAL_ID_COL), Field::Long(Some(v)) if *v == enum_id) {
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
        let mut adapter = EnumValueDBAdapterV1::new(&mut handle, "", true).unwrap();

        adapter.create_record(5, "Red", 0, Some("the color red")).unwrap();
        assert_eq!(adapter.get_record_count(), 1);

        let fetched = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            fetched.get_field(ENUMVAL_NAME_COL),
            &Field::String(Some("Red".to_string()))
        );
        assert_eq!(
            fetched.get_field(ENUMVAL_COMMENT_COL),
            &Field::String(Some("the color red".to_string()))
        );
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = EnumValueDBAdapterV1::new(&mut handle, "", true).unwrap();
            adapter.create_record(5, "Red", 0, None).unwrap();
        }
        let adapter = EnumValueDBAdapterV1::new(&mut handle, "", false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(EnumValueDBAdapterV1::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn update_and_remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EnumValueDBAdapterV1::new(&mut handle, "", true).unwrap();
        adapter.create_record(5, "Red", 0, None).unwrap();
        let mut fetched = adapter.get_record(0).unwrap().unwrap();

        fetched.set_field(ENUMVAL_NAME_COL, Field::String(Some("Crimson".to_string())));
        adapter.update_record(&fetched).unwrap();
        let refetched = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(ENUMVAL_NAME_COL),
            &Field::String(Some("Crimson".to_string()))
        );

        adapter.remove_record(0).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_value_ids_in_enum_filters_by_enum_id() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EnumValueDBAdapterV1::new(&mut handle, "", true).unwrap();
        adapter.create_record(5, "Red", 0, None).unwrap();
        adapter.create_record(5, "Green", 1, None).unwrap();
        adapter.create_record(7, "On", 1, None).unwrap();

        assert_eq!(adapter.get_value_ids_in_enum(5).unwrap().len(), 2);
        assert_eq!(adapter.get_value_ids_in_enum(7).unwrap().len(), 1);
    }

    #[test]
    fn delete_table_removes_it_from_handle() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EnumValueDBAdapterV1::new(&mut handle, "prefix_", true).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table("prefix_Enumeration Values").is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn EnumValueDBAdapter> =
            Box::new(EnumValueDBAdapterV1::new(&mut handle, "", true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}

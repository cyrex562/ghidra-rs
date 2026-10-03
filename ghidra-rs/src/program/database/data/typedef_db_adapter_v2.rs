//! Port of `ghidra.program.database.data.TypedefDBAdapterV2`.
//!
//! Version 2 (current) implementation for accessing the Typedef database table, backed by a
//! live, writable [`Table`]. `NOTE`: use of a table-name prefix was introduced with this adapter
//! version.
//!
//! The Java `createRecord` computes its key via `DataTypeManagerDB.createKey(TYPEDEF,
//! table.getKey())`, tagging the raw table key with a datatype-kind bit pattern. That key-tagging
//! scheme is a `DataTypeManagerDB`-wide invariant (not specific to this table) and
//! `DataTypeManagerDB` has not been ported with that scheme yet, so this port uses the table's
//! own next-key sequence directly instead (same deviation as `PointerDBAdapterV2`).
//!
//! Java's `createRecord` also stashes `lastChangeTime` into both the Source Sync Time and Last
//! Change Time columns -- preserved here as-is even though it looks like a copy/paste of the
//! Last Change Time value into Source Sync Time, since this port mirrors observed behavior.

use std::io;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::data::typedef_db_adapter::{
    self, TypedefDBAdapter, TYPEDEF_CAT_COL, TYPEDEF_DT_ID_COL, TYPEDEF_FLAGS_COL,
    TYPEDEF_LAST_CHANGE_TIME_COL, TYPEDEF_NAME_COL, TYPEDEF_SOURCE_ARCHIVE_ID_COL,
    TYPEDEF_SOURCE_SYNC_TIME_COL, TYPEDEF_TABLE_NAME, TYPEDEF_UNIVERSAL_DT_ID_COL,
};
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;
use crate::util::UniversalID;

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

fn current_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Version 2 (current) implementation for accessing the Typedef database table.
///
/// Port of `ghidra.program.database.data.TypedefDBAdapterV2`.
pub struct TypedefDBAdapterV2 {
    table: Arc<RwLock<Table>>,
}

impl TypedefDBAdapterV2 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = typedef_db_adapter::CURRENT_VERSION;

    /// Gets a version 2 adapter for the Typedef database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{TYPEDEF_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, typedef_db_adapter::schema())
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
        Ok(TypedefDBAdapterV2 { table })
    }
}

impl DBRecordAdapter for TypedefDBAdapterV2 {
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

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }
}

impl TypedefDBAdapter for TypedefDBAdapterV2 {
    fn create_record(
        &mut self,
        data_type_id: i64,
        name: &str,
        flags: i16,
        category_id: i64,
        source_archive_id: i64,
        source_data_type_id: i64,
        last_change_time: i64,
    ) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(typedef_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(TYPEDEF_DT_ID_COL, Field::Long(Some(data_type_id)));
        record.set_field(TYPEDEF_FLAGS_COL, Field::Short(Some(flags)));
        record.set_field(TYPEDEF_NAME_COL, Field::String(Some(name.to_string())));
        record.set_field(TYPEDEF_CAT_COL, Field::Long(Some(category_id)));
        record.set_field(
            TYPEDEF_SOURCE_ARCHIVE_ID_COL,
            Field::Long(Some(source_archive_id)),
        );
        record.set_field(
            TYPEDEF_UNIVERSAL_DT_ID_COL,
            Field::Long(Some(source_data_type_id)),
        );
        record.set_field(TYPEDEF_SOURCE_SYNC_TIME_COL, Field::Long(Some(last_change_time)));
        record.set_field(
            TYPEDEF_LAST_CHANGE_TIME_COL,
            Field::Long(Some(last_change_time)),
        );
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_record(&self, typedef_id: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(typedef_id)))
    }

    fn remove_record(&mut self, data_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(data_id)))
    }

    fn update_record(&mut self, record: &DBRecord, set_last_change_time: bool) -> io::Result<()> {
        let mut record = record.clone();
        if set_last_change_time {
            record.set_field(
                TYPEDEF_LAST_CHANGE_TIME_COL,
                Field::Long(Some(current_time_millis())),
            );
        }
        self.table.write().unwrap().put_record(record)
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
            if matches!(rec.get_field(TYPEDEF_CAT_COL), Field::Long(Some(v)) if *v == category_id)
            {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }

    fn get_record_ids_for_source_archive(&self, archive_id: i64) -> io::Result<Vec<Field>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(TYPEDEF_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == archive_id)
            {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }

    fn get_record_with_ids(
        &self,
        source_id: UniversalID,
        datatype_id: UniversalID,
    ) -> io::Result<Option<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(TYPEDEF_UNIVERSAL_DT_ID_COL), Field::Long(Some(v)) if *v == datatype_id.value())
                && matches!(rec.get_field(TYPEDEF_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == source_id.value())
            {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_and_round_trip_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = TypedefDBAdapterV2::new(&mut handle, "", true).unwrap();

        let created = adapter
            .create_record(10, "MyTypedef", 1, 5, 100, 200, 1000)
            .unwrap();
        let fetched = adapter
            .get_record(created.get_key().get_long_value())
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            fetched.get_field(TYPEDEF_NAME_COL),
            &Field::String(Some("MyTypedef".to_string()))
        );
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = TypedefDBAdapterV2::new(&mut handle, "", true).unwrap();
            adapter.create_record(1, "A", 0, 5, 100, 200, 1000).unwrap();
        }
        let adapter = TypedefDBAdapterV2::new(&mut handle, "", false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(TypedefDBAdapterV2::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn update_record_without_touching_last_change_time() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = TypedefDBAdapterV2::new(&mut handle, "", true).unwrap();
        let mut rec = adapter.create_record(1, "A", 0, 5, 100, 200, 1000).unwrap();

        rec.set_field(TYPEDEF_NAME_COL, Field::String(Some("Renamed".to_string())));
        adapter.update_record(&rec, false).unwrap();
        let refetched = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_eq!(
            refetched.get_field(TYPEDEF_NAME_COL),
            &Field::String(Some("Renamed".to_string()))
        );
        assert_eq!(
            refetched.get_field(TYPEDEF_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(1000))
        );
    }

    #[test]
    fn update_record_with_set_last_change_time_uses_wall_clock() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = TypedefDBAdapterV2::new(&mut handle, "", true).unwrap();
        let rec = adapter.create_record(1, "A", 0, 5, 100, 200, 1000).unwrap();

        adapter.update_record(&rec, true).unwrap();
        let refetched = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_ne!(
            refetched.get_field(TYPEDEF_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(1000))
        );
    }

    #[test]
    fn remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = TypedefDBAdapterV2::new(&mut handle, "", true).unwrap();
        let rec = adapter.create_record(1, "A", 0, 5, 100, 200, 1000).unwrap();

        let removed = adapter.remove_record(rec.get_key().get_long_value()).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_record_ids_in_category_and_for_source_archive() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = TypedefDBAdapterV2::new(&mut handle, "", true).unwrap();
        adapter.create_record(1, "A", 0, 5, 100, 200, 1000).unwrap();
        adapter.create_record(2, "B", 0, 5, 101, 201, 1001).unwrap();
        adapter.create_record(3, "C", 0, 6, 100, 202, 1002).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(adapter.get_record_ids_in_category(6).unwrap().len(), 1);
        assert_eq!(
            adapter.get_record_ids_for_source_archive(100).unwrap().len(),
            2
        );
    }

    #[test]
    fn get_record_with_ids_matches_source_and_datatype() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = TypedefDBAdapterV2::new(&mut handle, "", true).unwrap();
        adapter.create_record(1, "A", 0, 5, 100, 200, 1000).unwrap();
        adapter.create_record(2, "B", 0, 5, 101, 201, 1001).unwrap();

        let found = adapter
            .get_record_with_ids(UniversalID::new(101), UniversalID::new(201))
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            found.get_field(TYPEDEF_NAME_COL),
            &Field::String(Some("B".to_string()))
        );
        assert!(adapter
            .get_record_with_ids(UniversalID::new(999), UniversalID::new(999))
            .unwrap()
            .is_none());
    }

    #[test]
    fn delete_table_removes_it_from_handle() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = TypedefDBAdapterV2::new(&mut handle, "prefix_", true).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table("prefix_Typedefs").is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn TypedefDBAdapter> =
            Box::new(TypedefDBAdapterV2::new(&mut handle, "", true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}

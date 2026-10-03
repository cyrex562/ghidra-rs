//! Port of `ghidra.program.database.data.EnumDBAdapterV1`.
//!
//! Version 1 (current, and so far only live-writable) implementation for accessing the
//! Enumeration database table, backed by a live, writable [`Table`]. `NOTE`: use of a table-name
//! prefix was introduced with this adapter version.
//!
//! The Java `createRecord` computes its key via `DataTypeManagerDB.createKey(ENUM,
//! table.getKey())`, tagging the raw table key with a datatype-kind bit pattern. That key-tagging
//! scheme is a `DataTypeManagerDB`-wide invariant (not specific to this table) and
//! `DataTypeManagerDB` has not been ported with that scheme yet, so this port uses the table's
//! own next-key sequence directly instead (same deviation as `PointerDBAdapterV2`).
//!
//! Java's `createRecord` also stashes `lastChangeTime` into both the Source Sync Time and Last
//! Change Time columns -- preserved here as-is, matching observed behavior.
//!
//! `remove_record` here (like Java's) only removes this table's own record; associated
//! enumeration value records must be removed separately by the caller (Java has a `TODO Fix up
//! DataType Manager to remove associated value records` marker on this method).

use std::io;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::data::enum_db_adapter::{
    self, EnumDBAdapter, ENUM_CAT_COL, ENUM_COMMENT_COL, ENUM_LAST_CHANGE_TIME_COL, ENUM_NAME_COL,
    ENUM_SIZE_COL, ENUM_SOURCE_ARCHIVE_ID_COL, ENUM_SOURCE_SYNC_TIME_COL, ENUM_TABLE_NAME,
    ENUM_UNIVERSAL_DT_ID_COL,
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

/// Version 1 (current) implementation for accessing the Enumeration database table.
///
/// Port of `ghidra.program.database.data.EnumDBAdapterV1`.
pub struct EnumDBAdapterV1 {
    table: Arc<RwLock<Table>>,
}

impl EnumDBAdapterV1 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = enum_db_adapter::CURRENT_VERSION;

    /// Gets a version 1 adapter for the Enumeration database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{ENUM_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, enum_db_adapter::schema())
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
        Ok(EnumDBAdapterV1 { table })
    }
}

impl DBRecordAdapter for EnumDBAdapterV1 {
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

impl EnumDBAdapter for EnumDBAdapterV1 {
    fn create_record(
        &mut self,
        name: &str,
        comments: Option<&str>,
        category_id: i64,
        size: i8,
        source_archive_id: i64,
        source_data_type_id: i64,
        last_change_time: i64,
    ) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(enum_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(ENUM_NAME_COL, Field::String(Some(name.to_string())));
        record.set_field(ENUM_COMMENT_COL, Field::String(comments.map(str::to_string)));
        record.set_field(ENUM_CAT_COL, Field::Long(Some(category_id)));
        record.set_field(ENUM_SIZE_COL, Field::Byte(Some(size)));
        record.set_field(
            ENUM_SOURCE_ARCHIVE_ID_COL,
            Field::Long(Some(source_archive_id)),
        );
        record.set_field(
            ENUM_UNIVERSAL_DT_ID_COL,
            Field::Long(Some(source_data_type_id)),
        );
        record.set_field(ENUM_SOURCE_SYNC_TIME_COL, Field::Long(Some(last_change_time)));
        record.set_field(ENUM_LAST_CHANGE_TIME_COL, Field::Long(Some(last_change_time)));
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_record(&self, enum_id: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(enum_id)))
    }

    fn update_record(&mut self, record: &DBRecord, set_last_change_time: bool) -> io::Result<()> {
        let mut record = record.clone();
        if set_last_change_time {
            record.set_field(
                ENUM_LAST_CHANGE_TIME_COL,
                Field::Long(Some(current_time_millis())),
            );
        }
        self.table.write().unwrap().put_record(record)
    }

    fn remove_record(&mut self, enum_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(enum_id)))
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
            if matches!(rec.get_field(ENUM_CAT_COL), Field::Long(Some(v)) if *v == category_id) {
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
            if matches!(rec.get_field(ENUM_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == archive_id)
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
            if matches!(rec.get_field(ENUM_UNIVERSAL_DT_ID_COL), Field::Long(Some(v)) if *v == datatype_id.value())
                && matches!(rec.get_field(ENUM_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == source_id.value())
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
        let mut adapter = EnumDBAdapterV1::new(&mut handle, "", true).unwrap();

        let created = adapter
            .create_record("Colors", Some("an enum"), 5, 4, 10, 20, 100)
            .unwrap();
        let fetched = adapter
            .get_record(created.get_key().get_long_value())
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            fetched.get_field(ENUM_NAME_COL),
            &Field::String(Some("Colors".to_string()))
        );
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = EnumDBAdapterV1::new(&mut handle, "", true).unwrap();
            adapter.create_record("A", None, 5, 1, 0, 0, 0).unwrap();
        }
        let adapter = EnumDBAdapterV1::new(&mut handle, "", false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(EnumDBAdapterV1::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn update_record_with_and_without_last_change_time() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EnumDBAdapterV1::new(&mut handle, "", true).unwrap();
        let rec = adapter.create_record("A", None, 5, 1, 0, 0, 1000).unwrap();

        adapter.update_record(&rec, false).unwrap();
        let unchanged = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged.get_field(ENUM_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(1000))
        );

        adapter.update_record(&rec, true).unwrap();
        let changed = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_ne!(
            changed.get_field(ENUM_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(1000))
        );
    }

    #[test]
    fn remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EnumDBAdapterV1::new(&mut handle, "", true).unwrap();
        let rec = adapter.create_record("A", None, 5, 1, 0, 0, 0).unwrap();

        let removed = adapter.remove_record(rec.get_key().get_long_value()).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_record_ids_in_category_and_for_source_archive() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EnumDBAdapterV1::new(&mut handle, "", true).unwrap();
        adapter.create_record("A", None, 5, 1, 10, 20, 0).unwrap();
        adapter.create_record("B", None, 5, 1, 11, 21, 0).unwrap();
        adapter.create_record("C", None, 6, 1, 10, 22, 0).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(
            adapter.get_record_ids_for_source_archive(10).unwrap().len(),
            2
        );
    }

    #[test]
    fn get_record_with_ids_matches_source_and_datatype() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EnumDBAdapterV1::new(&mut handle, "", true).unwrap();
        adapter.create_record("A", None, 5, 1, 10, 20, 0).unwrap();
        adapter.create_record("B", None, 5, 1, 11, 21, 0).unwrap();

        let found = adapter
            .get_record_with_ids(UniversalID::new(11), UniversalID::new(21))
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            found.get_field(ENUM_NAME_COL),
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
        let mut adapter = EnumDBAdapterV1::new(&mut handle, "prefix_", true).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table("prefix_Enumeration Data Types").is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn EnumDBAdapter> =
            Box::new(EnumDBAdapterV1::new(&mut handle, "", true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}

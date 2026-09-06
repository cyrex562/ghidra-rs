//! Port of `ghidra.program.database.data.FunctionDefinitionDBAdapterV2`.
//!
//! Version 2 (current) implementation for accessing the Function Signature Definition database
//! table, backed by a live, writable [`Table`].
//!
//! The Java `createRecord` computes its key via `DataTypeManagerDB.createKey(FUNCTION_DEF,
//! table.getKey())`, tagging the raw table key with a datatype-kind bit pattern. That key-tagging
//! scheme is a `DataTypeManagerDB`-wide invariant (not specific to this table) and
//! `DataTypeManagerDB` has not been ported with that scheme yet, so this port uses the table's
//! own next-key sequence directly instead (same deviation as `PointerDBAdapterV2`).
//!
//! Java's `createRecord` also stashes `lastChangeTime` into both the Source Sync Time and Last
//! Change Time columns -- preserved here as-is, matching observed behavior.

use std::io;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::data::function_definition_db_adapter::{
    self, FunctionDefinitionDBAdapter, FUNCTION_DEF_CALLCONV_COL, FUNCTION_DEF_CAT_ID_COL,
    FUNCTION_DEF_COMMENT_COL, FUNCTION_DEF_FLAGS_COL, FUNCTION_DEF_LAST_CHANGE_TIME_COL,
    FUNCTION_DEF_NAME_COL, FUNCTION_DEF_NORETURN_FLAG, FUNCTION_DEF_RETURN_ID_COL,
    FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL, FUNCTION_DEF_SOURCE_DT_ID_COL,
    FUNCTION_DEF_SOURCE_SYNC_TIME_COL, FUNCTION_DEF_TABLE_NAME, FUNCTION_DEF_VARARG_FLAG,
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

/// Version 2 (current) implementation for accessing the Function Signature Definition database
/// table.
///
/// Port of `ghidra.program.database.data.FunctionDefinitionDBAdapterV2`.
pub struct FunctionDefinitionDBAdapterV2 {
    table: Arc<RwLock<Table>>,
}

impl FunctionDefinitionDBAdapterV2 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = function_definition_db_adapter::CURRENT_VERSION;

    /// Gets a version 2 adapter for the Function Definition database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{FUNCTION_DEF_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, function_definition_db_adapter::schema())
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
        Ok(FunctionDefinitionDBAdapterV2 { table })
    }
}

impl DBRecordAdapter for FunctionDefinitionDBAdapterV2 {
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

impl FunctionDefinitionDBAdapter for FunctionDefinitionDBAdapterV2 {
    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        name: &str,
        comments: Option<&str>,
        category_id: i64,
        return_dt_id: i64,
        has_no_return: bool,
        has_var_args: bool,
        calling_convention_id: u8,
        source_archive_id: i64,
        source_data_type_id: i64,
        last_change_time: i64,
    ) -> io::Result<DBRecord> {
        let mut flags = 0u8;
        if has_var_args {
            flags |= FUNCTION_DEF_VARARG_FLAG;
        }
        if has_no_return {
            flags |= FUNCTION_DEF_NORETURN_FLAG;
        }
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(function_definition_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(FUNCTION_DEF_NAME_COL, Field::String(Some(name.to_string())));
        record.set_field(
            FUNCTION_DEF_COMMENT_COL,
            Field::String(comments.map(str::to_string)),
        );
        record.set_field(FUNCTION_DEF_CAT_ID_COL, Field::Long(Some(category_id)));
        record.set_field(FUNCTION_DEF_RETURN_ID_COL, Field::Long(Some(return_dt_id)));
        record.set_field(FUNCTION_DEF_FLAGS_COL, Field::Byte(Some(flags as i8)));
        record.set_field(
            FUNCTION_DEF_CALLCONV_COL,
            Field::Byte(Some(calling_convention_id as i8)),
        );
        record.set_field(
            FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL,
            Field::Long(Some(source_archive_id)),
        );
        record.set_field(
            FUNCTION_DEF_SOURCE_DT_ID_COL,
            Field::Long(Some(source_data_type_id)),
        );
        record.set_field(
            FUNCTION_DEF_SOURCE_SYNC_TIME_COL,
            Field::Long(Some(last_change_time)),
        );
        record.set_field(
            FUNCTION_DEF_LAST_CHANGE_TIME_COL,
            Field::Long(Some(last_change_time)),
        );
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_record(&self, function_def_id: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(function_def_id)))
    }

    fn remove_record(&mut self, function_def_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(function_def_id)))
    }

    fn update_record(&mut self, record: &DBRecord, set_last_change_time: bool) -> io::Result<()> {
        let mut record = record.clone();
        if set_last_change_time {
            record.set_field(
                FUNCTION_DEF_LAST_CHANGE_TIME_COL,
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
            if matches!(rec.get_field(FUNCTION_DEF_CAT_ID_COL), Field::Long(Some(v)) if *v == category_id)
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
            if matches!(rec.get_field(FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == archive_id)
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
            if matches!(rec.get_field(FUNCTION_DEF_SOURCE_DT_ID_COL), Field::Long(Some(v)) if *v == datatype_id.value())
                && matches!(rec.get_field(FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == source_id.value())
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
        let mut adapter = FunctionDefinitionDBAdapterV2::new(&mut handle, "", true).unwrap();

        let created = adapter
            .create_record("foo", Some("a function"), 5, 42, false, true, 3, 10, 20, 100)
            .unwrap();
        let fetched = adapter
            .get_record(created.get_key().get_long_value())
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            fetched.get_field(FUNCTION_DEF_NAME_COL),
            &Field::String(Some("foo".to_string()))
        );
        assert_eq!(
            fetched.get_field(FUNCTION_DEF_FLAGS_COL),
            &Field::Byte(Some(FUNCTION_DEF_VARARG_FLAG as i8))
        );
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = FunctionDefinitionDBAdapterV2::new(&mut handle, "", true).unwrap();
            adapter
                .create_record("A", None, 5, 1, false, false, 0, 0, 0, 0)
                .unwrap();
        }
        let adapter = FunctionDefinitionDBAdapterV2::new(&mut handle, "", false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(FunctionDefinitionDBAdapterV2::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn update_record_with_and_without_last_change_time() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = FunctionDefinitionDBAdapterV2::new(&mut handle, "", true).unwrap();
        let rec = adapter
            .create_record("A", None, 5, 1, false, false, 0, 0, 0, 1000)
            .unwrap();

        adapter.update_record(&rec, false).unwrap();
        let unchanged = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged.get_field(FUNCTION_DEF_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(1000))
        );

        adapter.update_record(&rec, true).unwrap();
        let changed = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_ne!(
            changed.get_field(FUNCTION_DEF_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(1000))
        );
    }

    #[test]
    fn remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = FunctionDefinitionDBAdapterV2::new(&mut handle, "", true).unwrap();
        let rec = adapter
            .create_record("A", None, 5, 1, false, false, 0, 0, 0, 0)
            .unwrap();

        let removed = adapter.remove_record(rec.get_key().get_long_value()).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_record_ids_in_category_and_for_source_archive() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = FunctionDefinitionDBAdapterV2::new(&mut handle, "", true).unwrap();
        adapter
            .create_record("A", None, 5, 1, false, false, 0, 10, 20, 0)
            .unwrap();
        adapter
            .create_record("B", None, 5, 1, false, false, 0, 11, 21, 0)
            .unwrap();
        adapter
            .create_record("C", None, 6, 1, false, false, 0, 10, 22, 0)
            .unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(
            adapter.get_record_ids_for_source_archive(10).unwrap().len(),
            2
        );
    }

    #[test]
    fn get_record_with_ids_matches_source_and_datatype() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = FunctionDefinitionDBAdapterV2::new(&mut handle, "", true).unwrap();
        adapter
            .create_record("A", None, 5, 1, false, false, 0, 10, 20, 0)
            .unwrap();
        adapter
            .create_record("B", None, 5, 1, false, false, 0, 11, 21, 0)
            .unwrap();

        let found = adapter
            .get_record_with_ids(UniversalID::new(11), UniversalID::new(21))
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            found.get_field(FUNCTION_DEF_NAME_COL),
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
        let mut adapter = FunctionDefinitionDBAdapterV2::new(&mut handle, "prefix_", true).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table("prefix_Function Definitions").is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn FunctionDefinitionDBAdapter> =
            Box::new(FunctionDefinitionDBAdapterV2::new(&mut handle, "", true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}

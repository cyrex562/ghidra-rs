//! Port of `ghidra.program.database.data.TypedefDBAdapterV1`.
//!
//! Version 1 (read-only) implementation for accessing the Typedef database table. This version's
//! on-disk records have no "Flags" column; [`translate_record`] synthesizes a value of `0` for
//! it (matching Java's comment `// default TYPEDEF_FLAGS_COL to 0`).
//!
//! [`translate_record`]: RecordTranslator::translate_record
//!
//! The V1 table predates `tablePrefix` support (introduced in V2), so it is always looked up
//! under the bare [`TYPEDEF_TABLE_NAME`] with no prefix. Unlike
//! [`TypedefDBAdapterV0`](super::typedef_db_adapter_v0::TypedefDBAdapterV0), this version does
//! track source-archive and universal-datatype-ID columns, so `get_record_ids_for_source_archive`
//! and `get_record_with_ids` are fully functional here (rather than always-empty/always-`None`).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::typedef_db_adapter::{
    self, TypedefDBAdapter, TYPEDEF_CAT_COL, TYPEDEF_DT_ID_COL, TYPEDEF_FLAGS_COL,
    TYPEDEF_LAST_CHANGE_TIME_COL, TYPEDEF_NAME_COL, TYPEDEF_SOURCE_ARCHIVE_ID_COL,
    TYPEDEF_SOURCE_SYNC_TIME_COL, TYPEDEF_TABLE_NAME, TYPEDEF_UNIVERSAL_DT_ID_COL,
};
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;
use crate::util::UniversalID;

/// Column index of the typedef's referenced data type ID, as defined by `TypedefDBAdapterV1`.
pub const V1_TYPEDEF_DT_ID_COL: usize = 0;

/// Column index of the typedef's name, as defined by `TypedefDBAdapterV1`.
pub const V1_TYPEDEF_NAME_COL: usize = 1;

/// Column index of the typedef's category ID, as defined by `TypedefDBAdapterV1`.
pub const V1_TYPEDEF_CAT_COL: usize = 2;

/// Column index of the typedef's source archive ID, as defined by `TypedefDBAdapterV1`.
pub const V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL: usize = 3;

/// Column index of the typedef's universal data type ID, as defined by `TypedefDBAdapterV1`.
pub const V1_TYPEDEF_UNIVERSAL_DT_ID_COL: usize = 4;

/// Column index of the typedef's source sync time, as defined by `TypedefDBAdapterV1`.
pub const V1_TYPEDEF_SOURCE_SYNC_TIME_COL: usize = 5;

/// Column index of the typedef's last change time, as defined by `TypedefDBAdapterV1`.
pub const V1_TYPEDEF_LAST_CHANGE_TIME_COL: usize = 6;

/// A `RecordIterator` over an eagerly-collected, already-translated set of records.
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

/// Version 1 (read-only) implementation for accessing the Typedef database table.
///
/// Port of `ghidra.program.database.data.TypedefDBAdapterV1`.
pub struct TypedefDBAdapterV1 {
    table: Arc<RwLock<Table>>,
}

impl TypedefDBAdapterV1 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 1;

    /// Gets a version 1 adapter for the Typedef database table.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(TYPEDEF_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {TYPEDEF_TABLE_NAME}"))
        })?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(version < Self::VERSION));
            }
        }
        Ok(TypedefDBAdapterV1 { table })
    }
}

impl RecordTranslator for TypedefDBAdapterV1 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(typedef_db_adapter::schema(), old_record.get_key().clone());
        rec.set_field(
            TYPEDEF_DT_ID_COL,
            old_record.get_field(V1_TYPEDEF_DT_ID_COL).clone(),
        );
        rec.set_field(TYPEDEF_FLAGS_COL, Field::Short(Some(0)));
        rec.set_field(
            TYPEDEF_NAME_COL,
            old_record.get_field(V1_TYPEDEF_NAME_COL).clone(),
        );
        rec.set_field(
            TYPEDEF_CAT_COL,
            old_record.get_field(V1_TYPEDEF_CAT_COL).clone(),
        );
        rec.set_field(
            TYPEDEF_SOURCE_ARCHIVE_ID_COL,
            old_record.get_field(V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL).clone(),
        );
        rec.set_field(
            TYPEDEF_UNIVERSAL_DT_ID_COL,
            old_record.get_field(V1_TYPEDEF_UNIVERSAL_DT_ID_COL).clone(),
        );
        rec.set_field(
            TYPEDEF_SOURCE_SYNC_TIME_COL,
            old_record.get_field(V1_TYPEDEF_SOURCE_SYNC_TIME_COL).clone(),
        );
        rec.set_field(
            TYPEDEF_LAST_CHANGE_TIME_COL,
            old_record.get_field(V1_TYPEDEF_LAST_CHANGE_TIME_COL).clone(),
        );
        Ok(rec)
    }
}

impl DBRecordAdapter for TypedefDBAdapterV1 {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut translated = Vec::new();
        while let Some(rec) = iter.next()? {
            translated.push(self.translate_record(rec)?);
        }
        Ok(Box::new(VecRecordIterator {
            records: translated.into_iter(),
        }))
    }

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }
}

impl TypedefDBAdapter for TypedefDBAdapterV1 {
    fn create_record(
        &mut self,
        _data_type_id: i64,
        _name: &str,
        _flags: i16,
        _category_id: i64,
        _source_archive_id: i64,
        _source_data_type_id: i64,
        _last_change_time: i64,
    ) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot create records in Version 1",
        ))
    }

    fn get_record(&self, typedef_id: i64) -> io::Result<Option<DBRecord>> {
        let old = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(typedef_id)))?;
        match old {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

    fn remove_record(&mut self, _data_id: i64) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot remove records in Version 1",
        ))
    }

    fn update_record(&mut self, _record: &DBRecord, _set_last_change_time: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update records in Version 1",
        ))
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(TYPEDEF_TABLE_NAME);
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
            if matches!(rec.get_field(V1_TYPEDEF_CAT_COL), Field::Long(Some(v)) if *v == category_id)
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
            if matches!(rec.get_field(V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == archive_id)
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
            if matches!(rec.get_field(V1_TYPEDEF_UNIVERSAL_DT_ID_COL), Field::Long(Some(v)) if *v == datatype_id.value())
                && matches!(rec.get_field(V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == source_id.value())
            {
                return Ok(Some(self.translate_record(rec)?));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};

    fn v1_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Typedef ID".to_string(),
            vec![
                FieldType::Long,
                FieldType::String,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
            ],
            vec![
                "Data Type ID".to_string(),
                "Name".to_string(),
                "Category ID".to_string(),
                "Source Archive ID".to_string(),
                "Universal Data Type ID".to_string(),
                "Source Sync Time".to_string(),
                "Last Change Time".to_string(),
            ],
            vec![],
        ))
    }

    fn make_handle_with_v1_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(TYPEDEF_TABLE_NAME.to_string(), v1_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        for (dt_id, name, cat, source_archive, universal_dt, sync_time, change_time) in [
            (10i64, "A", 5i64, 100i64, 200i64, 0i64, 1000i64),
            (11, "B", 5, 101, 201, 0, 1001),
            (12, "C", 6, 100, 202, 0, 1002),
        ] {
            let key = t.get_next_key();
            let mut rec = DBRecord::new(v1_schema(), Field::Long(Some(key)));
            rec.set_field(V1_TYPEDEF_DT_ID_COL, Field::Long(Some(dt_id)));
            rec.set_field(V1_TYPEDEF_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(V1_TYPEDEF_CAT_COL, Field::Long(Some(cat)));
            rec.set_field(
                V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL,
                Field::Long(Some(source_archive)),
            );
            rec.set_field(
                V1_TYPEDEF_UNIVERSAL_DT_ID_COL,
                Field::Long(Some(universal_dt)),
            );
            rec.set_field(V1_TYPEDEF_SOURCE_SYNC_TIME_COL, Field::Long(Some(sync_time)));
            rec.set_field(
                V1_TYPEDEF_LAST_CHANGE_TIME_COL,
                Field::Long(Some(change_time)),
            );
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(TypedefDBAdapterV1::new(&handle).is_err());
    }

    #[test]
    fn get_record_translates_to_current_schema_with_default_flags() {
        let handle = make_handle_with_v1_table();
        let adapter = TypedefDBAdapterV1::new(&handle).unwrap();

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(TYPEDEF_NAME_COL),
            &Field::String(Some("A".to_string()))
        );
        assert_eq!(rec.get_field(TYPEDEF_FLAGS_COL), &Field::Short(Some(0)));
        assert_eq!(adapter.get_record_count(), 3);
    }

    #[test]
    fn get_record_ids_in_category_and_for_source_archive() {
        let handle = make_handle_with_v1_table();
        let adapter = TypedefDBAdapterV1::new(&handle).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(
            adapter.get_record_ids_for_source_archive(100).unwrap().len(),
            2
        );
    }

    #[test]
    fn get_record_with_ids_matches_source_and_datatype() {
        let handle = make_handle_with_v1_table();
        let adapter = TypedefDBAdapterV1::new(&handle).unwrap();

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
    fn mutating_operations_are_unsupported() {
        let handle = make_handle_with_v1_table();
        let mut adapter = TypedefDBAdapterV1::new(&handle).unwrap();

        assert_eq!(
            adapter
                .create_record(1, "x", 0, 5, 100, 200, 1000)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let existing = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            adapter.update_record(&existing, false).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_v1_table();
        let adapter: Box<dyn TypedefDBAdapter> = Box::new(TypedefDBAdapterV1::new(&handle).unwrap());
        assert_eq!(adapter.get_record_count(), 3);
    }
}

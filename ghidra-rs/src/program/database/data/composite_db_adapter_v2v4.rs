//! Port of `ghidra.program.database.data.CompositeDBAdapterV2V4`.
//!
//! Read-only implementation for accessing the Composite database table when its on-disk schema
//! version is anywhere in `[2, 4]` (the addition of flex-array and bitfield component support
//! did not change this table's physical column layout, only what earlier Ghidra versions could
//! safely read -- see the Java class comment). [`version`] reports the table's *actual* on-disk
//! version (2, 3, or 4), not a hardcoded constant, matching Java's `getVersion()`.
//!
//! [`version`]: CompositeDBAdapter::version
//!
//! This version's on-disk records have no dedicated Alignment column; [`translate_record`]
//! always writes `-1` (unknown/not-yet-computed) for it, matching Java's hardcoded
//! `setIntValue(COMPOSITE_ALIGNMENT_COL, -1)` (not a synthesized default -- this exact sentinel
//! is intentional, distinct from `CompositeInternal.DEFAULT_ALIGNMENT`).
//!
//! [`translate_record`]: RecordTranslator::translate_record

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::composite_db_adapter::{
    self, CompositeDBAdapter, COMPOSITE_ALIGNMENT_COL, COMPOSITE_CAT_COL, COMPOSITE_COMMENT_COL,
    COMPOSITE_IS_UNION_COL, COMPOSITE_LAST_CHANGE_TIME_COL, COMPOSITE_LENGTH_COL,
    COMPOSITE_MIN_ALIGN_COL, COMPOSITE_NAME_COL, COMPOSITE_NUM_COMPONENTS_COL,
    COMPOSITE_PACKING_COL, COMPOSITE_SOURCE_ARCHIVE_ID_COL, COMPOSITE_SOURCE_SYNC_TIME_COL,
    COMPOSITE_TABLE_NAME, COMPOSITE_UNIVERSAL_DT_ID_COL,
};
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;
use crate::util::UniversalID;

/// Highest schema version implemented by this (read-only) adapter.
const VERSION: i32 = 4;

/// Lowest schema version this (read-only) adapter accepts.
const MIN_READ_ONLY_VERSION: i32 = 2;

/// Column index of the composite's name, as defined by `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_NAME_COL: usize = 0;

/// Column index of the composite's comment, as defined by `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_COMMENT_COL: usize = 1;

/// Column index of the flag indicating whether the composite is a union, as defined by
/// `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_IS_UNION_COL: usize = 2;

/// Column index of the composite's category ID, as defined by `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_CAT_COL: usize = 3;

/// Column index of the composite's total length, as defined by `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_LENGTH_COL: usize = 4;

/// Column index of the composite's component count, as defined by `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_NUM_COMPONENTS_COL: usize = 5;

/// Column index of the composite's source archive ID, as defined by `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_SOURCE_ARCHIVE_ID_COL: usize = 6;

/// Column index of the composite's universal data type ID, as defined by
/// `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_UNIVERSAL_DT_ID_COL: usize = 7;

/// Column index of the composite's source sync time, as defined by `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_SOURCE_SYNC_TIME_COL: usize = 8;

/// Column index of the composite's last change time, as defined by `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_LAST_CHANGE_TIME_COL: usize = 9;

/// Column index of the composite's pack value (renamed from "Internal Alignment"), as defined by
/// `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_PACK_COL: usize = 10;

/// Column index of the composite's minimum alignment value (renamed from "External Alignment"),
/// as defined by `CompositeDBAdapterV2V4`.
pub const V2V4_COMPOSITE_MIN_ALIGN_COL: usize = 11;

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

/// Read-only implementation for accessing the Composite database table across schema versions
/// 2 through 4.
///
/// Port of `ghidra.program.database.data.CompositeDBAdapterV2V4`.
pub struct CompositeDBAdapterV2V4 {
    table: Arc<RwLock<Table>>,
}

impl CompositeDBAdapterV2V4 {
    /// Gets a read-only adapter for the Composite database table.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(COMPOSITE_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {COMPOSITE_TABLE_NAME}"))
        })?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version < MIN_READ_ONLY_VERSION {
                return Err(VersionException::with_version_indicator(
                    VersionException::OLDER_VERSION,
                    true,
                ));
            }
            if version > VERSION {
                return Err(VersionException::with_message_and_version(
                    format!(
                        "Expected version {VERSION} for table {COMPOSITE_TABLE_NAME} but got {version}"
                    ),
                    VersionException::NEWER_VERSION,
                    false,
                ));
            }
        }
        Ok(CompositeDBAdapterV2V4 { table })
    }
}

impl RecordTranslator for CompositeDBAdapterV2V4 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(composite_db_adapter::schema(), old_record.get_key().clone());
        rec.set_field(
            COMPOSITE_NAME_COL,
            old_record.get_field(V2V4_COMPOSITE_NAME_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_COMMENT_COL,
            old_record.get_field(V2V4_COMPOSITE_COMMENT_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_IS_UNION_COL,
            old_record.get_field(V2V4_COMPOSITE_IS_UNION_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_CAT_COL,
            old_record.get_field(V2V4_COMPOSITE_CAT_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_LENGTH_COL,
            old_record.get_field(V2V4_COMPOSITE_LENGTH_COL).clone(),
        );
        rec.set_field(COMPOSITE_ALIGNMENT_COL, Field::Int(Some(-1)));
        rec.set_field(
            COMPOSITE_NUM_COMPONENTS_COL,
            old_record.get_field(V2V4_COMPOSITE_NUM_COMPONENTS_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_SOURCE_ARCHIVE_ID_COL,
            old_record.get_field(V2V4_COMPOSITE_SOURCE_ARCHIVE_ID_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_UNIVERSAL_DT_ID_COL,
            old_record.get_field(V2V4_COMPOSITE_UNIVERSAL_DT_ID_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_SOURCE_SYNC_TIME_COL,
            old_record.get_field(V2V4_COMPOSITE_SOURCE_SYNC_TIME_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_LAST_CHANGE_TIME_COL,
            old_record.get_field(V2V4_COMPOSITE_LAST_CHANGE_TIME_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_PACKING_COL,
            old_record.get_field(V2V4_COMPOSITE_PACK_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_MIN_ALIGN_COL,
            old_record.get_field(V2V4_COMPOSITE_MIN_ALIGN_COL).clone(),
        );
        Ok(rec)
    }
}

impl DBRecordAdapter for CompositeDBAdapterV2V4 {
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

impl CompositeDBAdapter for CompositeDBAdapterV2V4 {
    fn version(&self) -> i32 {
        self.table.read().unwrap().get_schema().get_version()
    }

    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        _name: &str,
        _comments: Option<&str>,
        _is_union: bool,
        _category_id: i64,
        _length: i32,
        _computed_alignment: i32,
        _source_archive_id: i64,
        _source_data_type_id: i64,
        _last_change_time: i64,
        _pack_value: i32,
        _min_alignment: i32,
    ) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Not allowed to update prior version #{VERSION} of {COMPOSITE_TABLE_NAME} table."
            ),
        ))
    }

    fn get_record(&self, data_type_id: i64) -> io::Result<Option<DBRecord>> {
        let old = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(data_type_id)))?;
        match old {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

    fn update_record(&mut self, _record: &DBRecord, _set_last_change_time: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update records in this version",
        ))
    }

    fn remove_record(&mut self, _data_id: i64) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Not allowed to update prior version #{VERSION} of {COMPOSITE_TABLE_NAME} table."
            ),
        ))
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(COMPOSITE_TABLE_NAME);
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
            if matches!(rec.get_field(V2V4_COMPOSITE_CAT_COL), Field::Long(Some(v)) if *v == category_id)
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
            if matches!(rec.get_field(V2V4_COMPOSITE_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == archive_id)
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
            if matches!(rec.get_field(V2V4_COMPOSITE_UNIVERSAL_DT_ID_COL), Field::Long(Some(v)) if *v == datatype_id.value())
                && matches!(rec.get_field(V2V4_COMPOSITE_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == source_id.value())
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

    fn v2v4_schema(version: i32) -> Arc<Schema> {
        Arc::new(Schema::new(
            version,
            FieldType::Long,
            "Data Type ID".to_string(),
            vec![
                FieldType::String,
                FieldType::String,
                FieldType::Boolean,
                FieldType::Long,
                FieldType::Int,
                FieldType::Int,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Int,
                FieldType::Int,
            ],
            vec![
                "Name".to_string(),
                "Comment".to_string(),
                "Is Union".to_string(),
                "Category ID".to_string(),
                "Length".to_string(),
                "Number Of Components".to_string(),
                "Source Archive ID".to_string(),
                "Source Data Type ID".to_string(),
                "Source Sync Time".to_string(),
                "Last Change Time".to_string(),
                "Pack".to_string(),
                "MinAlign".to_string(),
            ],
            vec![],
        ))
    }

    fn make_handle_with_table(version: i32) -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(COMPOSITE_TABLE_NAME.to_string(), v2v4_schema(version))
            .unwrap();
        let mut t = table.write().unwrap();
        for (name, cat, source_archive, universal_dt) in
            [("Foo", 5i64, 10i64, 20i64), ("Bar", 5, 11, 21), ("Baz", 6, 10, 22)]
        {
            let key = t.get_next_key();
            let mut rec = DBRecord::new(v2v4_schema(version), Field::Long(Some(key)));
            rec.set_field(V2V4_COMPOSITE_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(V2V4_COMPOSITE_COMMENT_COL, Field::String(None));
            rec.set_field(V2V4_COMPOSITE_IS_UNION_COL, Field::Boolean(Some(false)));
            rec.set_field(V2V4_COMPOSITE_CAT_COL, Field::Long(Some(cat)));
            rec.set_field(V2V4_COMPOSITE_LENGTH_COL, Field::Int(Some(8)));
            rec.set_field(V2V4_COMPOSITE_NUM_COMPONENTS_COL, Field::Int(Some(2)));
            rec.set_field(
                V2V4_COMPOSITE_SOURCE_ARCHIVE_ID_COL,
                Field::Long(Some(source_archive)),
            );
            rec.set_field(
                V2V4_COMPOSITE_UNIVERSAL_DT_ID_COL,
                Field::Long(Some(universal_dt)),
            );
            rec.set_field(V2V4_COMPOSITE_SOURCE_SYNC_TIME_COL, Field::Long(Some(0)));
            rec.set_field(V2V4_COMPOSITE_LAST_CHANGE_TIME_COL, Field::Long(Some(0)));
            rec.set_field(V2V4_COMPOSITE_PACK_COL, Field::Int(Some(-1)));
            rec.set_field(V2V4_COMPOSITE_MIN_ALIGN_COL, Field::Int(Some(0)));
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(CompositeDBAdapterV2V4::new(&handle).is_err());
    }

    #[test]
    fn rejects_versions_outside_2_to_4() {
        let handle_v1 = make_handle_with_table(1);
        assert!(CompositeDBAdapterV2V4::new(&handle_v1).is_err());

        let handle_v5 = make_handle_with_table(5);
        assert!(CompositeDBAdapterV2V4::new(&handle_v5).is_err());
    }

    #[test]
    fn version_reports_actual_on_disk_version() {
        let handle = make_handle_with_table(3);
        let adapter = CompositeDBAdapterV2V4::new(&handle).unwrap();
        assert_eq!(adapter.version(), 3);
    }

    #[test]
    fn get_record_translates_to_current_schema_with_unknown_alignment() {
        let handle = make_handle_with_table(4);
        let adapter = CompositeDBAdapterV2V4::new(&handle).unwrap();

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(COMPOSITE_NAME_COL),
            &Field::String(Some("Foo".to_string()))
        );
        assert_eq!(rec.get_field(COMPOSITE_ALIGNMENT_COL), &Field::Int(Some(-1)));
        assert_eq!(adapter.get_record_count(), 3);
    }

    #[test]
    fn get_record_ids_in_category_and_for_source_archive() {
        let handle = make_handle_with_table(2);
        let adapter = CompositeDBAdapterV2V4::new(&handle).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(
            adapter.get_record_ids_for_source_archive(10).unwrap().len(),
            2
        );
    }

    #[test]
    fn get_record_with_ids_matches_and_translates() {
        let handle = make_handle_with_table(2);
        let adapter = CompositeDBAdapterV2V4::new(&handle).unwrap();

        let found = adapter
            .get_record_with_ids(UniversalID::new(11), UniversalID::new(21))
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            found.get_field(COMPOSITE_NAME_COL),
            &Field::String(Some("Bar".to_string()))
        );
        assert_eq!(found.get_field(COMPOSITE_ALIGNMENT_COL), &Field::Int(Some(-1)));
        assert!(adapter
            .get_record_with_ids(UniversalID::new(999), UniversalID::new(999))
            .unwrap()
            .is_none());
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let handle = make_handle_with_table(4);
        let mut adapter = CompositeDBAdapterV2V4::new(&handle).unwrap();

        assert_eq!(
            adapter
                .create_record("x", None, false, 5, 8, -1, 0, 0, 0, -1, -1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let existing = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            adapter
                .update_record(&existing, false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_table(4);
        let adapter: Box<dyn CompositeDBAdapter> =
            Box::new(CompositeDBAdapterV2V4::new(&handle).unwrap());
        assert_eq!(adapter.get_record_count(), 3);
    }
}

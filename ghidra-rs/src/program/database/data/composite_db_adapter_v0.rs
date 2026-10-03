//! Port of `ghidra.program.database.data.CompositeDBAdapterV0`.
//!
//! Version 0 (read-only) implementation for accessing the Composite database table. This
//! version's on-disk records only carry name, comment, union flag, category ID, length, and
//! component count; [`translate_record`] synthesizes the remaining current-schema columns:
//! Source Archive ID to [`LOCAL_ARCHIVE_KEY`], Source Sync/Last Change Time to the `DataType` "no
//! value" sentinels, Universal Data Type ID (Source Data Type ID) to a freshly minted
//! [`next_id`], Pack to [`NO_PACKING`], and MinAlign to [`DEFAULT_ALIGNMENT`]. Note that -- unlike
//! every other adapter in this family -- Alignment is *not* explicitly set at all, matching
//! Java's `translateRecord` (which never calls `setIntValue` for that column); this port relies
//! on [`DBRecord::new`]'s zero-initialization of unset `Int` fields to reproduce the same `0`
//! value Java's `Schema.createRecord` would leave in place.
//!
//! [`translate_record`]: RecordTranslator::translate_record
//!
//! Note that -- matching Java's `translateRecord`, which is re-invoked on every `getRecord`/
//! `getRecords` call rather than cached -- each translation mints a *new* universal ID via
//! [`next_id`], so repeated lookups of the same underlying V0 record do not return a stable
//! universal ID. This looks like a latent quirk in the original, but this port mirrors observed
//! behavior rather than "fixing" it.
//!
//! `get_record_ids_for_source_archive` always returns empty (V0 has no such column) and
//! `get_record_with_ids` always returns `None` (matching Java's unconditional `return null`).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::composite_db_adapter::{
    self, CompositeDBAdapter, COMPOSITE_CAT_COL, COMPOSITE_COMMENT_COL, COMPOSITE_IS_UNION_COL,
    COMPOSITE_LAST_CHANGE_TIME_COL, COMPOSITE_LENGTH_COL, COMPOSITE_MIN_ALIGN_COL,
    COMPOSITE_NAME_COL, COMPOSITE_NUM_COMPONENTS_COL, COMPOSITE_PACKING_COL,
    COMPOSITE_SOURCE_ARCHIVE_ID_COL, COMPOSITE_SOURCE_SYNC_TIME_COL, COMPOSITE_TABLE_NAME,
    COMPOSITE_UNIVERSAL_DT_ID_COL,
};
use crate::program::model::data::composite_internal::{DEFAULT_ALIGNMENT, NO_PACKING};
use crate::program::model::data::data_type::{NO_LAST_CHANGE_TIME, NO_SOURCE_SYNC_TIME};
use crate::program::model::data::data_type_manager::LOCAL_ARCHIVE_KEY;
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;
use crate::util::universal_id_generator::next_id;
use crate::util::UniversalID;

const VERSION: i32 = 0;

/// Column index of the composite's name, as defined by `CompositeDBAdapterV0`.
pub const V0_COMPOSITE_NAME_COL: usize = 0;

/// Column index of the composite's comment, as defined by `CompositeDBAdapterV0`.
pub const V0_COMPOSITE_COMMENT_COL: usize = 1;

/// Column index of the flag indicating whether the composite is a union, as defined by
/// `CompositeDBAdapterV0`.
pub const V0_COMPOSITE_IS_UNION_COL: usize = 2;

/// Column index of the composite's category ID, as defined by `CompositeDBAdapterV0`.
pub const V0_COMPOSITE_CAT_COL: usize = 3;

/// Column index of the composite's total length, as defined by `CompositeDBAdapterV0`.
pub const V0_COMPOSITE_LENGTH_COL: usize = 4;

/// Column index of the composite's component count, as defined by `CompositeDBAdapterV0`.
pub const V0_COMPOSITE_NUM_COMPONENTS_COL: usize = 5;

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

/// Version 0 (read-only) implementation for accessing the Composite database table.
///
/// Port of `ghidra.program.database.data.CompositeDBAdapterV0`.
pub struct CompositeDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl CompositeDBAdapterV0 {
    /// Gets a version 0 adapter for the Composite database table.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(COMPOSITE_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {COMPOSITE_TABLE_NAME}"))
        })?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version != VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
        }
        Ok(CompositeDBAdapterV0 { table })
    }
}

impl RecordTranslator for CompositeDBAdapterV0 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(composite_db_adapter::schema(), old_record.get_key().clone());
        rec.set_field(
            COMPOSITE_NAME_COL,
            old_record.get_field(V0_COMPOSITE_NAME_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_COMMENT_COL,
            old_record.get_field(V0_COMPOSITE_COMMENT_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_IS_UNION_COL,
            old_record.get_field(V0_COMPOSITE_IS_UNION_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_CAT_COL,
            old_record.get_field(V0_COMPOSITE_CAT_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_LENGTH_COL,
            old_record.get_field(V0_COMPOSITE_LENGTH_COL).clone(),
        );
        // NOTE: no COMPOSITE_ALIGNMENT_COL assignment here -- matches Java exactly (see module
        // docs); the freshly-created record's Int field default (`0`) is left in place.
        rec.set_field(
            COMPOSITE_NUM_COMPONENTS_COL,
            old_record.get_field(V0_COMPOSITE_NUM_COMPONENTS_COL).clone(),
        );
        rec.set_field(
            COMPOSITE_SOURCE_ARCHIVE_ID_COL,
            Field::Long(Some(LOCAL_ARCHIVE_KEY)),
        );
        rec.set_field(
            COMPOSITE_UNIVERSAL_DT_ID_COL,
            Field::Long(Some(next_id().value())),
        );
        rec.set_field(
            COMPOSITE_SOURCE_SYNC_TIME_COL,
            Field::Long(Some(NO_SOURCE_SYNC_TIME)),
        );
        rec.set_field(
            COMPOSITE_LAST_CHANGE_TIME_COL,
            Field::Long(Some(NO_LAST_CHANGE_TIME)),
        );
        rec.set_field(COMPOSITE_PACKING_COL, Field::Int(Some(NO_PACKING)));
        rec.set_field(COMPOSITE_MIN_ALIGN_COL, Field::Int(Some(DEFAULT_ALIGNMENT)));
        Ok(rec)
    }
}

impl DBRecordAdapter for CompositeDBAdapterV0 {
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

impl CompositeDBAdapter for CompositeDBAdapterV0 {
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
            if matches!(rec.get_field(V0_COMPOSITE_CAT_COL), Field::Long(Some(v)) if *v == category_id)
            {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }

    fn get_record_ids_for_source_archive(&self, _archive_id: i64) -> io::Result<Vec<Field>> {
        Ok(Vec::new())
    }

    fn get_record_with_ids(
        &self,
        _source_id: UniversalID,
        _datatype_id: UniversalID,
    ) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};

    fn v0_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            VERSION,
            FieldType::Long,
            "Data Type ID".to_string(),
            vec![
                FieldType::String,
                FieldType::String,
                FieldType::Boolean,
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
            ],
            vec![],
        ))
    }

    fn make_handle_with_v0_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(COMPOSITE_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        for (name, cat) in [("Foo", 5i64), ("Bar", 5), ("Baz", 6)] {
            let key = t.get_next_key();
            let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(key)));
            rec.set_field(V0_COMPOSITE_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(V0_COMPOSITE_COMMENT_COL, Field::String(None));
            rec.set_field(V0_COMPOSITE_IS_UNION_COL, Field::Boolean(Some(false)));
            rec.set_field(V0_COMPOSITE_CAT_COL, Field::Long(Some(cat)));
            rec.set_field(V0_COMPOSITE_LENGTH_COL, Field::Int(Some(8)));
            rec.set_field(V0_COMPOSITE_NUM_COMPONENTS_COL, Field::Int(Some(2)));
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(CompositeDBAdapterV0::new(&handle).is_err());
    }

    #[test]
    fn get_record_translates_to_current_schema_with_synthesized_columns() {
        let handle = make_handle_with_v0_table();
        let adapter = CompositeDBAdapterV0::new(&handle).unwrap();

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(COMPOSITE_NAME_COL),
            &Field::String(Some("Foo".to_string()))
        );
        assert_eq!(
            rec.get_field(COMPOSITE_SOURCE_ARCHIVE_ID_COL),
            &Field::Long(Some(LOCAL_ARCHIVE_KEY))
        );
        assert_eq!(
            rec.get_field(COMPOSITE_SOURCE_SYNC_TIME_COL),
            &Field::Long(Some(NO_SOURCE_SYNC_TIME))
        );
        assert_eq!(rec.get_field(COMPOSITE_PACKING_COL), &Field::Int(Some(NO_PACKING)));
        assert_eq!(
            rec.get_field(COMPOSITE_MIN_ALIGN_COL),
            &Field::Int(Some(DEFAULT_ALIGNMENT))
        );
        assert_eq!(adapter.get_record_count(), 3);
    }

    #[test]
    fn get_record_ids_in_category_filters_by_category() {
        let handle = make_handle_with_v0_table();
        let adapter = CompositeDBAdapterV0::new(&handle).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(adapter.get_record_ids_in_category(6).unwrap().len(), 1);
    }

    #[test]
    fn source_archive_and_universal_id_lookups_are_always_empty() {
        let handle = make_handle_with_v0_table();
        let adapter = CompositeDBAdapterV0::new(&handle).unwrap();

        assert!(adapter
            .get_record_ids_for_source_archive(100)
            .unwrap()
            .is_empty());
        assert!(adapter
            .get_record_with_ids(UniversalID::new(1), UniversalID::new(2))
            .unwrap()
            .is_none());
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let handle = make_handle_with_v0_table();
        let mut adapter = CompositeDBAdapterV0::new(&handle).unwrap();

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
        let handle = make_handle_with_v0_table();
        let adapter: Box<dyn CompositeDBAdapter> =
            Box::new(CompositeDBAdapterV0::new(&handle).unwrap());
        assert_eq!(adapter.get_record_count(), 3);
    }
}

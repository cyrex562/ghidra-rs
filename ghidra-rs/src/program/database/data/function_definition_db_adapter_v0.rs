//! Port of `ghidra.program.database.data.FunctionDefinitionDBAdapterV0`.
//!
//! Version 0 (read-only) implementation for accessing the Function Signature Definition
//! database table. This version's on-disk records only carry name, comment, category ID, return
//! type ID, and flags; [`translate_record`] synthesizes the remaining current-schema columns:
//! Call Conv ID to [`UNKNOWN_CALLING_CONVENTION_ID`], Source Archive ID to
//! [`LOCAL_ARCHIVE_KEY`], Source Sync/Last Change Time to the `DataType` "no value" sentinels,
//! and Source Data Type ID (the universal data type ID column) to a freshly minted [`next_id`].
//!
//! [`translate_record`]: RecordTranslator::translate_record
//!
//! Note that -- matching Java's `translateRecord`, which is re-invoked on every `getRecord`/
//! `getRecords` call rather than cached -- each translation mints a *new* universal ID via
//! [`next_id`], so repeated lookups of the same underlying V0 record do not return a stable
//! universal ID. This looks like a latent quirk in the original, but this port mirrors observed
//! behavior rather than "fixing" it.
//!
//! `create_record`/`update_record`/`remove_record` all throw `UnsupportedOperationException` in
//! Java and are mirrored here as `Unsupported` errors. `get_record_ids_for_source_archive`
//! always returns empty (V0 has no such column) and `get_record_with_ids` always returns `None`
//! (matching Java's unconditional `return null`).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::calling_convention_db_adapter::UNKNOWN_CALLING_CONVENTION_ID;
use crate::program::database::data::function_definition_db_adapter::{
    self, FunctionDefinitionDBAdapter, FUNCTION_DEF_CALLCONV_COL, FUNCTION_DEF_CAT_ID_COL,
    FUNCTION_DEF_COMMENT_COL, FUNCTION_DEF_FLAGS_COL, FUNCTION_DEF_LAST_CHANGE_TIME_COL,
    FUNCTION_DEF_NAME_COL, FUNCTION_DEF_RETURN_ID_COL, FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL,
    FUNCTION_DEF_SOURCE_DT_ID_COL, FUNCTION_DEF_SOURCE_SYNC_TIME_COL, FUNCTION_DEF_TABLE_NAME,
};
use crate::program::model::data::data_type::{NO_LAST_CHANGE_TIME, NO_SOURCE_SYNC_TIME};
use crate::program::model::data::data_type_manager::LOCAL_ARCHIVE_KEY;
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;
use crate::util::universal_id_generator::next_id;
use crate::util::UniversalID;

/// Column index of the function definition's name, as defined by `FunctionDefinitionDBAdapterV0`.
pub const V0_FUNCTION_DEF_NAME_COL: usize = 0;

/// Column index of the function definition's comment, as defined by
/// `FunctionDefinitionDBAdapterV0`.
pub const V0_FUNCTION_DEF_COMMENT_COL: usize = 1;

/// Column index of the function definition's category ID, as defined by
/// `FunctionDefinitionDBAdapterV0`.
pub const V0_FUNCTION_DEF_CAT_ID_COL: usize = 2;

/// Column index of the function definition's return data type ID, as defined by
/// `FunctionDefinitionDBAdapterV0`.
pub const V0_FUNCTION_DEF_RETURN_ID_COL: usize = 3;

/// Column index of the function definition's flags, as defined by
/// `FunctionDefinitionDBAdapterV0`.
pub const V0_FUNCTION_DEF_FLAGS_COL: usize = 4;

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

/// Version 0 (read-only) implementation for accessing the Function Signature Definition
/// database table.
///
/// Port of `ghidra.program.database.data.FunctionDefinitionDBAdapterV0`.
pub struct FunctionDefinitionDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl FunctionDefinitionDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the Function Definition database table.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle
            .get_table(FUNCTION_DEF_TABLE_NAME)
            .ok_or_else(|| VersionException::with_upgradeable(true))?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
        }
        Ok(FunctionDefinitionDBAdapterV0 { table })
    }
}

impl RecordTranslator for FunctionDefinitionDBAdapterV0 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(
            function_definition_db_adapter::schema(),
            old_record.get_key().clone(),
        );
        rec.set_field(
            FUNCTION_DEF_NAME_COL,
            old_record.get_field(V0_FUNCTION_DEF_NAME_COL).clone(),
        );
        rec.set_field(
            FUNCTION_DEF_COMMENT_COL,
            old_record.get_field(V0_FUNCTION_DEF_COMMENT_COL).clone(),
        );
        rec.set_field(
            FUNCTION_DEF_CAT_ID_COL,
            old_record.get_field(V0_FUNCTION_DEF_CAT_ID_COL).clone(),
        );
        rec.set_field(
            FUNCTION_DEF_RETURN_ID_COL,
            old_record.get_field(V0_FUNCTION_DEF_RETURN_ID_COL).clone(),
        );
        rec.set_field(
            FUNCTION_DEF_FLAGS_COL,
            old_record.get_field(V0_FUNCTION_DEF_FLAGS_COL).clone(),
        );
        rec.set_field(
            FUNCTION_DEF_CALLCONV_COL,
            Field::Byte(Some(UNKNOWN_CALLING_CONVENTION_ID as i8)),
        );
        rec.set_field(
            FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL,
            Field::Long(Some(LOCAL_ARCHIVE_KEY)),
        );
        rec.set_field(
            FUNCTION_DEF_SOURCE_DT_ID_COL,
            Field::Long(Some(next_id().value())),
        );
        rec.set_field(
            FUNCTION_DEF_SOURCE_SYNC_TIME_COL,
            Field::Long(Some(NO_SOURCE_SYNC_TIME)),
        );
        rec.set_field(
            FUNCTION_DEF_LAST_CHANGE_TIME_COL,
            Field::Long(Some(NO_LAST_CHANGE_TIME)),
        );
        Ok(rec)
    }
}

impl DBRecordAdapter for FunctionDefinitionDBAdapterV0 {
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

impl FunctionDefinitionDBAdapter for FunctionDefinitionDBAdapterV0 {
    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        _name: &str,
        _comments: Option<&str>,
        _category_id: i64,
        _return_dt_id: i64,
        _has_no_return: bool,
        _has_var_args: bool,
        _calling_convention_id: u8,
        _source_archive_id: i64,
        _source_data_type_id: i64,
        _last_change_time: i64,
    ) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot create records in Version 0",
        ))
    }

    fn get_record(&self, function_def_id: i64) -> io::Result<Option<DBRecord>> {
        let old = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(function_def_id)))?;
        match old {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

    fn remove_record(&mut self, _function_def_id: i64) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot remove records in Version 0",
        ))
    }

    fn update_record(&mut self, _record: &DBRecord, _set_last_change_time: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update records in Version 0",
        ))
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(FUNCTION_DEF_TABLE_NAME);
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
            if matches!(rec.get_field(V0_FUNCTION_DEF_CAT_ID_COL), Field::Long(Some(v)) if *v == category_id)
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
            0,
            FieldType::Long,
            "Data Type ID".to_string(),
            vec![
                FieldType::String,
                FieldType::String,
                FieldType::Long,
                FieldType::Long,
                FieldType::Byte,
            ],
            vec![
                "Name".to_string(),
                "Comment".to_string(),
                "Category ID".to_string(),
                "Return Type ID".to_string(),
                "Flags".to_string(),
            ],
            vec![],
        ))
    }

    fn make_handle_with_v0_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(FUNCTION_DEF_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        for (name, cat, ret_id, flags) in [("foo", 5i64, 42i64, 1i8), ("bar", 5, 43, 0), ("baz", 6, 44, 0)]
        {
            let key = t.get_next_key();
            let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(key)));
            rec.set_field(V0_FUNCTION_DEF_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(V0_FUNCTION_DEF_COMMENT_COL, Field::String(None));
            rec.set_field(V0_FUNCTION_DEF_CAT_ID_COL, Field::Long(Some(cat)));
            rec.set_field(V0_FUNCTION_DEF_RETURN_ID_COL, Field::Long(Some(ret_id)));
            rec.set_field(V0_FUNCTION_DEF_FLAGS_COL, Field::Byte(Some(flags)));
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(FunctionDefinitionDBAdapterV0::new(&handle).is_err());
    }

    #[test]
    fn get_record_translates_to_current_schema_with_synthesized_columns() {
        let handle = make_handle_with_v0_table();
        let adapter = FunctionDefinitionDBAdapterV0::new(&handle).unwrap();

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(FUNCTION_DEF_NAME_COL),
            &Field::String(Some("foo".to_string()))
        );
        assert_eq!(
            rec.get_field(FUNCTION_DEF_CALLCONV_COL),
            &Field::Byte(Some(UNKNOWN_CALLING_CONVENTION_ID as i8))
        );
        assert_eq!(
            rec.get_field(FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL),
            &Field::Long(Some(LOCAL_ARCHIVE_KEY))
        );
        assert_eq!(adapter.get_record_count(), 3);
    }

    #[test]
    fn get_record_ids_in_category_filters_by_category() {
        let handle = make_handle_with_v0_table();
        let adapter = FunctionDefinitionDBAdapterV0::new(&handle).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(adapter.get_record_ids_in_category(6).unwrap().len(), 1);
    }

    #[test]
    fn source_archive_and_universal_id_lookups_are_always_empty() {
        let handle = make_handle_with_v0_table();
        let adapter = FunctionDefinitionDBAdapterV0::new(&handle).unwrap();

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
        let mut adapter = FunctionDefinitionDBAdapterV0::new(&handle).unwrap();

        assert_eq!(
            adapter
                .create_record("x", None, 5, 1, false, false, 0, 0, 0, 0)
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
        let adapter: Box<dyn FunctionDefinitionDBAdapter> =
            Box::new(FunctionDefinitionDBAdapterV0::new(&handle).unwrap());
        assert_eq!(adapter.get_record_count(), 3);
    }
}

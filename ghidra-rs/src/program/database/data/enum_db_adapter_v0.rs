//! Port of `ghidra.program.database.data.EnumDBAdapterV0`.
//!
//! Version 0 (mostly read-only) implementation for accessing the Enumeration database table.
//! This version's on-disk records only carry name, comment, category ID, and size; [`translate_record`]
//! synthesizes the remaining current-schema columns: `Source Archive ID` to
//! [`LOCAL_ARCHIVE_KEY`], `Source Sync Time`/`Last Change Time` to the `DataType` "no value"
//! sentinels, and `Source Data Type ID` (the universal data type ID column) to a freshly minted
//! [`next_id`].
//!
//! [`translate_record`]: RecordTranslator::translate_record
//!
//! Note that -- matching Java's `translateRecord`, which is re-invoked on every `getRecord`/
//! `getRecords` call rather than cached -- each translation mints a *new* universal ID via
//! [`next_id`], so repeated lookups of the same underlying V0 record do not return a stable
//! universal ID. This looks like a latent quirk in the original, but this port mirrors observed
//! behavior rather than "fixing" it.
//!
//! Unlike the sibling V0 adapters in this porting batch (e.g.
//! [`TypedefDBAdapterV0`](super::typedef_db_adapter_v0::TypedefDBAdapterV0)), `remove_record`
//! here genuinely deletes the underlying record (matching Java, which has a `// TODO make sure
//! that the enum value records are getting deleted in the datatype manager` marker but still
//! performs the delete) -- it is not a read-only stub. `create_record`/`update_record` do throw
//! `Unsupported`, matching Java's `UnsupportedOperationException`.
//! `get_record_ids_for_source_archive` always returns empty (V0 has no such column) and
//! `get_record_with_ids` always returns `None` (matching Java's unconditional `return null`).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::enum_db_adapter::{
    self, EnumDBAdapter, ENUM_CAT_COL, ENUM_COMMENT_COL, ENUM_LAST_CHANGE_TIME_COL, ENUM_NAME_COL,
    ENUM_SIZE_COL, ENUM_SOURCE_ARCHIVE_ID_COL, ENUM_SOURCE_SYNC_TIME_COL, ENUM_TABLE_NAME,
    ENUM_UNIVERSAL_DT_ID_COL,
};
use crate::program::model::data::data_type::{NO_LAST_CHANGE_TIME, NO_SOURCE_SYNC_TIME};
use crate::program::model::data::data_type_manager::LOCAL_ARCHIVE_KEY;
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;
use crate::util::universal_id_generator::next_id;
use crate::util::UniversalID;

/// Column index of the enum's name, as defined by `EnumDBAdapterV0`.
pub const V0_ENUM_NAME_COL: usize = 0;

/// Column index of the enum's comment, as defined by `EnumDBAdapterV0`.
pub const V0_ENUM_COMMENT_COL: usize = 1;

/// Column index of the enum's category ID, as defined by `EnumDBAdapterV0`.
pub const V0_ENUM_CAT_COL: usize = 2;

/// Column index of the enum's total length, as defined by `EnumDBAdapterV0`.
pub const V0_ENUM_SIZE_COL: usize = 3;

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

/// Version 0 implementation for accessing the Enumeration database table.
///
/// Port of `ghidra.program.database.data.EnumDBAdapterV0`.
pub struct EnumDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl EnumDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the Enumeration database table.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle
            .get_table(ENUM_TABLE_NAME)
            .ok_or_else(|| VersionException::with_upgradeable(true))?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
        }
        Ok(EnumDBAdapterV0 { table })
    }
}

impl RecordTranslator for EnumDBAdapterV0 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(enum_db_adapter::schema(), old_record.get_key().clone());
        rec.set_field(ENUM_NAME_COL, old_record.get_field(V0_ENUM_NAME_COL).clone());
        rec.set_field(
            ENUM_COMMENT_COL,
            old_record.get_field(V0_ENUM_COMMENT_COL).clone(),
        );
        rec.set_field(ENUM_CAT_COL, old_record.get_field(V0_ENUM_CAT_COL).clone());
        rec.set_field(ENUM_SIZE_COL, old_record.get_field(V0_ENUM_SIZE_COL).clone());
        rec.set_field(
            ENUM_SOURCE_ARCHIVE_ID_COL,
            Field::Long(Some(LOCAL_ARCHIVE_KEY)),
        );
        rec.set_field(
            ENUM_UNIVERSAL_DT_ID_COL,
            Field::Long(Some(next_id().value())),
        );
        rec.set_field(
            ENUM_SOURCE_SYNC_TIME_COL,
            Field::Long(Some(NO_SOURCE_SYNC_TIME)),
        );
        rec.set_field(
            ENUM_LAST_CHANGE_TIME_COL,
            Field::Long(Some(NO_LAST_CHANGE_TIME)),
        );
        Ok(rec)
    }
}

impl DBRecordAdapter for EnumDBAdapterV0 {
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

impl EnumDBAdapter for EnumDBAdapterV0 {
    fn create_record(
        &mut self,
        _name: &str,
        _comments: Option<&str>,
        _category_id: i64,
        _size: i8,
        _source_archive_id: i64,
        _source_data_type_id: i64,
        _last_change_time: i64,
    ) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Not allowed to update prior version #{} of {ENUM_TABLE_NAME} table.",
                Self::VERSION
            ),
        ))
    }

    fn get_record(&self, enum_id: i64) -> io::Result<Option<DBRecord>> {
        let old = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(enum_id)))?;
        match old {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

    fn update_record(&mut self, _record: &DBRecord, _set_last_change_time: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update records in Version 0",
        ))
    }

    fn remove_record(&mut self, enum_id: i64) -> io::Result<bool> {
        // TODO make sure that the enum value records are getting deleted in the datatype
        // manager (same unresolved marker as Java).
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(enum_id)))
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(ENUM_TABLE_NAME);
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
            if matches!(rec.get_field(V0_ENUM_CAT_COL), Field::Long(Some(v)) if *v == category_id)
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
            "Enum ID".to_string(),
            vec![
                FieldType::String,
                FieldType::String,
                FieldType::Long,
                FieldType::Byte,
            ],
            vec![
                "Name".to_string(),
                "Comment".to_string(),
                "Category ID".to_string(),
                "Size".to_string(),
            ],
            vec![],
        ))
    }

    fn make_handle_with_v0_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(ENUM_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        for (name, comment, cat, size) in [
            ("Colors", "an enum", 5i64, 4i8),
            ("Flags", "", 5, 1),
            ("Other", "", 6, 1),
        ] {
            let key = t.get_next_key();
            let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(key)));
            rec.set_field(V0_ENUM_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(V0_ENUM_COMMENT_COL, Field::String(Some(comment.to_string())));
            rec.set_field(V0_ENUM_CAT_COL, Field::Long(Some(cat)));
            rec.set_field(V0_ENUM_SIZE_COL, Field::Byte(Some(size)));
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(EnumDBAdapterV0::new(&handle).is_err());
    }

    #[test]
    fn get_record_translates_to_current_schema_with_synthesized_columns() {
        let handle = make_handle_with_v0_table();
        let adapter = EnumDBAdapterV0::new(&handle).unwrap();

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(ENUM_NAME_COL),
            &Field::String(Some("Colors".to_string()))
        );
        assert_eq!(rec.get_field(ENUM_SIZE_COL), &Field::Byte(Some(4)));
        assert_eq!(
            rec.get_field(ENUM_SOURCE_ARCHIVE_ID_COL),
            &Field::Long(Some(LOCAL_ARCHIVE_KEY))
        );
        assert_eq!(
            rec.get_field(ENUM_SOURCE_SYNC_TIME_COL),
            &Field::Long(Some(NO_SOURCE_SYNC_TIME))
        );
        assert_eq!(adapter.get_record_count(), 3);
    }

    #[test]
    fn get_record_ids_in_category_filters_by_category() {
        let handle = make_handle_with_v0_table();
        let adapter = EnumDBAdapterV0::new(&handle).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(adapter.get_record_ids_in_category(6).unwrap().len(), 1);
    }

    #[test]
    fn source_archive_and_universal_id_lookups_are_always_empty() {
        let handle = make_handle_with_v0_table();
        let adapter = EnumDBAdapterV0::new(&handle).unwrap();

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
    fn remove_record_actually_deletes() {
        let handle = make_handle_with_v0_table();
        let mut adapter = EnumDBAdapterV0::new(&handle).unwrap();

        let removed = adapter.remove_record(0).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 2);
        assert!(adapter.get_record(0).unwrap().is_none());
    }

    #[test]
    fn create_and_update_are_unsupported() {
        let handle = make_handle_with_v0_table();
        let mut adapter = EnumDBAdapterV0::new(&handle).unwrap();

        assert_eq!(
            adapter
                .create_record("x", None, 5, 1, 0, 0, 0)
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
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_v0_table();
        let adapter: Box<dyn EnumDBAdapter> = Box::new(EnumDBAdapterV0::new(&handle).unwrap());
        assert_eq!(adapter.get_record_count(), 3);
    }
}

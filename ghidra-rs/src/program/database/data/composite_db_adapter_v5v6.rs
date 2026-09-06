//! Port of `ghidra.program.database.data.CompositeDBAdapterV5V6`.
//!
//! Version 5/6 (current) implementation for accessing the Composite database table, backed by a
//! live [`Table`]. Version 5 introduced the retained computed alignment column; version 6 did
//! not change the physical schema at all -- it only marks the elimination of Structure
//! flex-array components, which are still supported in read-only mode under a table actually
//! persisted at version 5. `NOTE`: use of a table-name prefix was introduced with adapter V6.
//!
//! An already-existing table found at schema version 5, opened with [`OpenMode::Immutable`], is
//! accepted without error (mirroring Java's early `return` for that combination -- "StructureDB
//! handles read-only flex-array migration"); the adapter subsequently reports [`version`] as the
//! table's *actual* on-disk version (5 or 6), not a hardcoded constant, and `create_record`/
//! `update_record`/`remove_record` all reject mutation with an `Unsupported` error whenever
//! backed by a version-5 table, matching Java's per-call `UnsupportedOperationException` guard.
//!
//! [`version`]: CompositeDBAdapter::version
//!
//! The Java `createRecord` computes its key via `DataTypeManagerDB.createKey(COMPOSITE,
//! table.getKey())`, tagging the raw table key with a datatype-kind bit pattern. That key-tagging
//! scheme is a `DataTypeManagerDB`-wide invariant (not specific to this table) and
//! `DataTypeManagerDB` has not been ported with that scheme yet, so this port uses the table's
//! own next-key sequence directly instead (same deviation as `PointerDBAdapterV2`).
//!
//! `create_record` also mirrors a real Java quirk: if the requested `pack_value` indicates
//! explicit/aligned packing (`>= DEFAULT_PACKING`), the record's `Length` is forced to `0`
//! ("aligned structures always start empty") *and* `Number Of Components` is then set from that
//! same (now-zeroed) `length` variable -- so an aligned composite's initial "Number Of
//! Components" is always `0` regardless of the `length` argument passed in, not a copy of the
//! original `length`.

use std::io;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::data::composite_db_adapter::{
    self, CompositeDBAdapter, COMPOSITE_ALIGNMENT_COL, COMPOSITE_CAT_COL, COMPOSITE_COMMENT_COL,
    COMPOSITE_IS_UNION_COL, COMPOSITE_LAST_CHANGE_TIME_COL, COMPOSITE_LENGTH_COL,
    COMPOSITE_MIN_ALIGN_COL, COMPOSITE_NAME_COL, COMPOSITE_NUM_COMPONENTS_COL,
    COMPOSITE_PACKING_COL, COMPOSITE_SOURCE_ARCHIVE_ID_COL, COMPOSITE_SOURCE_SYNC_TIME_COL,
    COMPOSITE_TABLE_NAME, COMPOSITE_UNIVERSAL_DT_ID_COL,
};
use crate::program::model::data::composite_internal::{DEFAULT_PACKING, NO_PACKING};
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;
use crate::util::UniversalID;

/// Schema version at which the computed-alignment column was introduced.
const V5_VERSION: i32 = 5;

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

/// Version 5/6 (current) implementation for accessing the Composite database table.
///
/// Port of `ghidra.program.database.data.CompositeDBAdapterV5V6`.
pub struct CompositeDBAdapterV5V6 {
    table: Arc<RwLock<Table>>,
}

impl CompositeDBAdapterV5V6 {
    /// Schema version implemented by this adapter when creating a new table.
    pub const VERSION: i32 = composite_db_adapter::CURRENT_VERSION;

    /// Gets an adapter for the Composite database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name.
    pub fn new(
        handle: &mut DBHandle,
        open_mode: OpenMode,
        table_prefix: &str,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{COMPOSITE_TABLE_NAME}");
        let table = if open_mode == OpenMode::Create {
            handle
                .create_table(table_name, composite_db_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(&table_name).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {table_name}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION
                && !(version == V5_VERSION && open_mode == OpenMode::Immutable)
            {
                return Err(VersionException::with_upgradeable(version < Self::VERSION));
            }
            table
        };
        Ok(CompositeDBAdapterV5V6 { table })
    }

    fn is_v5_only(&self) -> bool {
        self.table.read().unwrap().get_schema().get_version() == V5_VERSION
    }
}

impl DBRecordAdapter for CompositeDBAdapterV5V6 {
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

impl CompositeDBAdapter for CompositeDBAdapterV5V6 {
    fn version(&self) -> i32 {
        self.table.read().unwrap().get_schema().get_version()
    }

    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        name: &str,
        comments: Option<&str>,
        is_union: bool,
        category_id: i64,
        mut length: i32,
        computed_alignment: i32,
        source_archive_id: i64,
        source_data_type_id: i64,
        last_change_time: i64,
        pack_value: i32,
        min_alignment: i32,
    ) -> io::Result<DBRecord> {
        if self.is_v5_only() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Cannot create records against a Version 5 table",
            ));
        }
        let pack_value = if pack_value < DEFAULT_PACKING {
            NO_PACKING
        } else {
            length = 0; // aligned structures always start empty
            pack_value
        };

        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(composite_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(COMPOSITE_NAME_COL, Field::String(Some(name.to_string())));
        record.set_field(
            COMPOSITE_COMMENT_COL,
            Field::String(comments.map(str::to_string)),
        );
        record.set_field(COMPOSITE_IS_UNION_COL, Field::Boolean(Some(is_union)));
        record.set_field(COMPOSITE_CAT_COL, Field::Long(Some(category_id)));
        record.set_field(COMPOSITE_LENGTH_COL, Field::Int(Some(length)));
        record.set_field(COMPOSITE_ALIGNMENT_COL, Field::Int(Some(computed_alignment)));
        // Matches Java precisely: Number Of Components is set from `length` *after* the
        // aligned-packing branch above may have zeroed it, not from the original argument.
        record.set_field(COMPOSITE_NUM_COMPONENTS_COL, Field::Int(Some(length)));
        record.set_field(
            COMPOSITE_SOURCE_ARCHIVE_ID_COL,
            Field::Long(Some(source_archive_id)),
        );
        record.set_field(
            COMPOSITE_UNIVERSAL_DT_ID_COL,
            Field::Long(Some(source_data_type_id)),
        );
        record.set_field(
            COMPOSITE_SOURCE_SYNC_TIME_COL,
            Field::Long(Some(last_change_time)),
        );
        record.set_field(
            COMPOSITE_LAST_CHANGE_TIME_COL,
            Field::Long(Some(last_change_time)),
        );
        record.set_field(COMPOSITE_PACKING_COL, Field::Int(Some(pack_value)));
        record.set_field(COMPOSITE_MIN_ALIGN_COL, Field::Int(Some(min_alignment)));
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_record(&self, data_type_id: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(data_type_id)))
    }

    fn update_record(&mut self, record: &DBRecord, set_last_change_time: bool) -> io::Result<()> {
        if self.is_v5_only() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Cannot update records against a Version 5 table",
            ));
        }
        let mut record = record.clone();
        if set_last_change_time {
            record.set_field(
                COMPOSITE_LAST_CHANGE_TIME_COL,
                Field::Long(Some(current_time_millis())),
            );
        }
        self.table.write().unwrap().put_record(record)
    }

    fn remove_record(&mut self, data_id: i64) -> io::Result<bool> {
        if self.is_v5_only() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Cannot remove records against a Version 5 table",
            ));
        }
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(data_id)))
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
            if matches!(rec.get_field(COMPOSITE_CAT_COL), Field::Long(Some(v)) if *v == category_id)
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
            if matches!(rec.get_field(COMPOSITE_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == archive_id)
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
            if matches!(rec.get_field(COMPOSITE_UNIVERSAL_DT_ID_COL), Field::Long(Some(v)) if *v == datatype_id.value())
                && matches!(rec.get_field(COMPOSITE_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == source_id.value())
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
        let mut adapter =
            CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Create, "").unwrap();
        assert_eq!(adapter.version(), CompositeDBAdapterV5V6::VERSION);

        let created = adapter
            .create_record("Foo", Some("a struct"), false, 5, 8, 4, 10, 20, 100, NO_PACKING, -1)
            .unwrap();
        let fetched = adapter
            .get_record(created.get_key().get_long_value())
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            fetched.get_field(COMPOSITE_NAME_COL),
            &Field::String(Some("Foo".to_string()))
        );
        assert_eq!(fetched.get_field(COMPOSITE_LENGTH_COL), &Field::Int(Some(8)));
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn create_record_with_aligned_packing_forces_zero_length_and_components() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter =
            CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Create, "").unwrap();

        let created = adapter
            .create_record("Foo", None, false, 5, 8, 4, 10, 20, 100, DEFAULT_PACKING, -1)
            .unwrap();
        assert_eq!(created.get_field(COMPOSITE_LENGTH_COL), &Field::Int(Some(0)));
        assert_eq!(
            created.get_field(COMPOSITE_NUM_COMPONENTS_COL),
            &Field::Int(Some(0))
        );
        assert_eq!(
            created.get_field(COMPOSITE_PACKING_COL),
            &Field::Int(Some(DEFAULT_PACKING))
        );
    }

    #[test]
    fn create_record_with_negative_pack_value_normalizes_to_no_packing() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter =
            CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Create, "").unwrap();

        let created = adapter
            .create_record("Foo", None, false, 5, 8, 4, 10, 20, 100, -5, -1)
            .unwrap();
        assert_eq!(
            created.get_field(COMPOSITE_PACKING_COL),
            &Field::Int(Some(NO_PACKING))
        );
        // Not aligned packing, so length is untouched.
        assert_eq!(created.get_field(COMPOSITE_LENGTH_COL), &Field::Int(Some(8)));
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Update, "").is_err());
    }

    #[test]
    fn opening_a_v5_table_immutable_succeeds_but_rejects_mutation() {
        let mut handle = DBHandle::new().unwrap();
        {
            let v5_schema = {
                use crate::framework::db::{FieldType, Schema};
                Arc::new(Schema::new(
                    5,
                    FieldType::Long,
                    "Data Type ID".to_string(),
                    vec![
                        FieldType::String,
                        FieldType::String,
                        FieldType::Boolean,
                        FieldType::Long,
                        FieldType::Int,
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
                        "Alignment".to_string(),
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
            };
            handle
                .create_table(COMPOSITE_TABLE_NAME.to_string(), v5_schema)
                .unwrap();
        }

        let mut adapter =
            CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Immutable, "").unwrap();
        assert_eq!(adapter.version(), 5);

        assert_eq!(
            adapter
                .create_record("x", None, false, 0, 0, 0, 0, 0, 0, NO_PACKING, -1)
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
    fn opening_a_v5_table_for_update_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        {
            use crate::framework::db::{FieldType, Schema};
            let v5_schema = Arc::new(Schema::new(
                5,
                FieldType::Long,
                "Data Type ID".to_string(),
                vec![FieldType::String],
                vec!["Name".to_string()],
                vec![],
            ));
            handle
                .create_table(COMPOSITE_TABLE_NAME.to_string(), v5_schema)
                .unwrap();
        }
        assert!(CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Update, "").is_err());
    }

    #[test]
    fn update_record_with_and_without_last_change_time() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter =
            CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Create, "").unwrap();
        let rec = adapter
            .create_record("A", None, false, 5, 8, 4, 0, 0, 1000, NO_PACKING, -1)
            .unwrap();

        adapter.update_record(&rec, false).unwrap();
        let unchanged = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged.get_field(COMPOSITE_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(1000))
        );

        adapter.update_record(&rec, true).unwrap();
        let changed = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_ne!(
            changed.get_field(COMPOSITE_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(1000))
        );
    }

    #[test]
    fn remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter =
            CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Create, "").unwrap();
        let rec = adapter
            .create_record("A", None, false, 5, 8, 4, 0, 0, 0, NO_PACKING, -1)
            .unwrap();

        let removed = adapter.remove_record(rec.get_key().get_long_value()).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_record_ids_in_category_and_for_source_archive() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter =
            CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Create, "").unwrap();
        adapter
            .create_record("A", None, false, 5, 8, 4, 10, 20, 0, NO_PACKING, -1)
            .unwrap();
        adapter
            .create_record("B", None, false, 5, 8, 4, 11, 21, 0, NO_PACKING, -1)
            .unwrap();
        adapter
            .create_record("C", None, false, 6, 8, 4, 10, 22, 0, NO_PACKING, -1)
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
        let mut adapter =
            CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Create, "").unwrap();
        adapter
            .create_record("A", None, false, 5, 8, 4, 10, 20, 0, NO_PACKING, -1)
            .unwrap();
        adapter
            .create_record("B", None, false, 5, 8, 4, 11, 21, 0, NO_PACKING, -1)
            .unwrap();

        let found = adapter
            .get_record_with_ids(UniversalID::new(11), UniversalID::new(21))
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            found.get_field(COMPOSITE_NAME_COL),
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
        let mut adapter =
            CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Create, "prefix_").unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table("prefix_Composite Data Types").is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn CompositeDBAdapter> =
            Box::new(CompositeDBAdapterV5V6::new(&mut handle, OpenMode::Create, "").unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}

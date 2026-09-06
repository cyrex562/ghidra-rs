//! Port of `ghidra.program.database.data.SourceArchiveAdapterV0`.
//!
//! Version 0 (current, and so far only) implementation for accessing the Data Type Archive ID
//! database table, backed by a live, writable [`Table`]. `NOTE`: use of a table-name prefix was
//! introduced with this adapter version.
//!
//! On table creation, a standard entry corresponding to the local data type manager is seeded
//! immediately (keyed by [`LOCAL_ARCHIVE_KEY`], with only Last Sync Time populated -- to the
//! current wall-clock time, matching Java's `(new Date()).getTime()`).
//!
//! `create_record`'s Dirty Flag column is always written as `false`, regardless of the source
//! archive's actual [`SourceArchive::is_dirty`] value -- matching Java's `createRecord`, which
//! hardcodes `setBooleanValue(V0_ARCHIVE_ID_DIRTY_FLAG_COL, false)` rather than reading the
//! archive's dirty flag. Preserved here as observed behavior.

use std::io;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::data::source_archive_adapter::{
    self, SourceArchiveAdapter, ARCHIVE_ID_DIRTY_FLAG_COL, ARCHIVE_ID_DOMAIN_FILE_ID_COL,
    ARCHIVE_ID_LAST_SYNC_TIME_COL, ARCHIVE_ID_NAME_COL, ARCHIVE_ID_TYPE_COL,
    SOURCE_ARCHIVE_TABLE_NAME,
};
use crate::program::model::data::data_type_manager::LOCAL_ARCHIVE_KEY;
use crate::program::model::data::source_archive::SourceArchive;
use crate::util::exception::VersionException;
use crate::util::UniversalID;

fn current_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Version 0 (current) implementation for accessing the Data Type Archive ID database table.
///
/// Port of `ghidra.program.database.data.SourceArchiveAdapterV0`.
pub struct SourceArchiveAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl SourceArchiveAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = source_archive_adapter::CURRENT_VERSION;

    /// Gets a version 0 adapter for the Data Type Archive ID table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created (and seeded with the local-archive record), otherwise an
    /// existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{SOURCE_ARCHIVE_TABLE_NAME}");
        let table = if create {
            let table = handle
                .create_table(table_name, source_archive_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?;
            let mut record = DBRecord::new(
                source_archive_adapter::schema(),
                Field::Long(Some(LOCAL_ARCHIVE_KEY)),
            );
            record.set_field(
                ARCHIVE_ID_LAST_SYNC_TIME_COL,
                Field::Long(Some(current_time_millis())),
            );
            table
                .write()
                .unwrap()
                .put_record(record)
                .map_err(|e| VersionException::with_message(e.to_string()))?;
            table
        } else {
            let table = handle
                .get_table(&table_name)
                .ok_or_else(|| VersionException::with_upgradeable(true))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(SourceArchiveAdapterV0 { table })
    }
}

impl SourceArchiveAdapter for SourceArchiveAdapterV0 {
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        let name = self.table.read().unwrap().get_name().to_string();
        handle.delete_table(&name);
        Ok(())
    }

    fn create_record(&mut self, source_archive: &dyn SourceArchive) -> io::Result<DBRecord> {
        let key = source_archive.source_archive_id().value();
        let mut record = DBRecord::new(source_archive_adapter::schema(), Field::Long(Some(key)));
        record.set_field(
            ARCHIVE_ID_DOMAIN_FILE_ID_COL,
            Field::String(Some(source_archive.domain_file_id())),
        );
        record.set_field(
            ARCHIVE_ID_NAME_COL,
            Field::String(Some(source_archive.name())),
        );
        record.set_field(
            ARCHIVE_ID_TYPE_COL,
            Field::Byte(Some(source_archive.archive_type() as i8)),
        );
        // This should be the local archive record, so the "last sync time" is really the last
        // change time.
        record.set_field(
            ARCHIVE_ID_LAST_SYNC_TIME_COL,
            Field::Long(Some(source_archive.last_sync_time())),
        );
        record.set_field(ARCHIVE_ID_DIRTY_FLAG_COL, Field::Boolean(Some(false)));
        self.table.write().unwrap().put_record(record.clone())?;
        Ok(record)
    }

    fn get_records(&self) -> io::Result<Vec<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(records)
    }

    fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn remove_record(&mut self, key: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(key)))
    }

    fn delete_record(&mut self, source_archive_id: UniversalID) -> io::Result<()> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(source_archive_id.value())))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::archive_type::ArchiveType;

    struct MockSourceArchive {
        id: UniversalID,
        domain_file_id: String,
        archive_type: ArchiveType,
        name: String,
        last_sync_time: i64,
        dirty: bool,
    }

    impl SourceArchive for MockSourceArchive {
        fn source_archive_id(&self) -> UniversalID {
            self.id
        }

        fn domain_file_id(&self) -> String {
            self.domain_file_id.clone()
        }

        fn archive_type(&self) -> ArchiveType {
            self.archive_type
        }

        fn name(&self) -> String {
            self.name.clone()
        }

        fn last_sync_time(&self) -> i64 {
            self.last_sync_time
        }

        fn is_dirty(&self) -> bool {
            self.dirty
        }

        fn set_last_sync_time(&mut self, time: i64) {
            self.last_sync_time = time;
        }

        fn set_name(&mut self, name: String) {
            self.name = name;
        }

        fn set_dirty_flag(&mut self, dirty: bool) {
            self.dirty = dirty;
        }
    }

    #[test]
    fn create_table_seeds_local_archive_record() {
        let mut handle = DBHandle::new().unwrap();
        let adapter = SourceArchiveAdapterV0::new(&mut handle, "", true).unwrap();

        let local = adapter
            .get_record(LOCAL_ARCHIVE_KEY)
            .unwrap()
            .expect("local archive record should exist");
        assert!(matches!(
            local.get_field(ARCHIVE_ID_LAST_SYNC_TIME_COL),
            Field::Long(Some(_))
        ));
    }

    #[test]
    fn create_record_ignores_dirty_flag_input() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = SourceArchiveAdapterV0::new(&mut handle, "", true).unwrap();

        let archive = MockSourceArchive {
            id: UniversalID::new(7),
            domain_file_id: "domain-7".to_string(),
            archive_type: ArchiveType::Project,
            name: "proj-archive".to_string(),
            last_sync_time: 100,
            dirty: true,
        };
        let created = adapter.create_record(&archive).unwrap();
        assert_eq!(
            created.get_field(ARCHIVE_ID_NAME_COL),
            &Field::String(Some("proj-archive".to_string()))
        );
        assert_eq!(
            created.get_field(ARCHIVE_ID_DIRTY_FLAG_COL),
            &Field::Boolean(Some(false))
        );
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = SourceArchiveAdapterV0::new(&mut handle, "", true).unwrap();
            let archive = MockSourceArchive {
                id: UniversalID::new(7),
                domain_file_id: "domain-7".to_string(),
                archive_type: ArchiveType::Project,
                name: "proj-archive".to_string(),
                last_sync_time: 100,
                dirty: false,
            };
            adapter.create_record(&archive).unwrap();
        }
        let adapter = SourceArchiveAdapterV0::new(&mut handle, "", false).unwrap();
        // Local archive record plus the one created above.
        assert_eq!(adapter.get_records().unwrap().len(), 2);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(SourceArchiveAdapterV0::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn update_remove_and_delete_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = SourceArchiveAdapterV0::new(&mut handle, "", true).unwrap();
        let archive = MockSourceArchive {
            id: UniversalID::new(7),
            domain_file_id: "domain-7".to_string(),
            archive_type: ArchiveType::Project,
            name: "proj-archive".to_string(),
            last_sync_time: 100,
            dirty: false,
        };
        let mut rec = adapter.create_record(&archive).unwrap();

        rec.set_field(ARCHIVE_ID_DIRTY_FLAG_COL, Field::Boolean(Some(true)));
        adapter.update_record(&rec).unwrap();
        let refetched = adapter.get_record(7).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(ARCHIVE_ID_DIRTY_FLAG_COL),
            &Field::Boolean(Some(true))
        );

        adapter.delete_record(UniversalID::new(7)).unwrap();
        assert!(adapter.get_record(7).unwrap().is_none());

        let archive2 = MockSourceArchive {
            id: UniversalID::new(8),
            domain_file_id: "domain-8".to_string(),
            archive_type: ArchiveType::File,
            name: "file-archive".to_string(),
            last_sync_time: 5,
            dirty: true,
        };
        adapter.create_record(&archive2).unwrap();
        let removed = adapter.remove_record(8).unwrap();
        assert!(removed);
        assert!(adapter.get_record(8).unwrap().is_none());
    }

    #[test]
    fn delete_table_removes_it_from_handle() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = SourceArchiveAdapterV0::new(&mut handle, "prefix_", true).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table("prefix_Data Type Archive IDs").is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn SourceArchiveAdapter> =
            Box::new(SourceArchiveAdapterV0::new(&mut handle, "", true).unwrap());
        assert_eq!(adapter.get_records().unwrap().len(), 1);
    }
}

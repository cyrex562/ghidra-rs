//! Port of `ghidra.program.database.data.SourceArchiveAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects and migrates between concrete
//! version-specific implementations (`SourceArchiveAdapterV0`/`SourceArchiveAdapterNoTable`).
//! Those concrete adapters have not been ported yet, so this port only models the abstract
//! instance API each version implements, as an object-safe trait; the version-selection/upgrade
//! logic belongs with whichever type ends up owning the concrete adapters. This trait was itself
//! selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBHandle, DBRecord};
use crate::program::model::data::source_archive::SourceArchive;
use crate::util::UniversalID;

/// Name of the database table used to store data type archive ID entries.
pub const SOURCE_ARCHIVE_TABLE_NAME: &str = "Data Type Archive IDs";

/// Column index of the archive's domain file ID, as defined by `SourceArchiveAdapterV0`.
pub const ARCHIVE_ID_DOMAIN_FILE_ID_COL: usize = 0;

/// Column index of the archive's name, as defined by `SourceArchiveAdapterV0`.
pub const ARCHIVE_ID_NAME_COL: usize = 1;

/// Column index of the archive's type, as defined by `SourceArchiveAdapterV0`.
pub const ARCHIVE_ID_TYPE_COL: usize = 2;

/// Column index of the archive's last sync time, as defined by `SourceArchiveAdapterV0`.
pub const ARCHIVE_ID_LAST_SYNC_TIME_COL: usize = 3;

/// Column index of the archive's dirty flag, as defined by `SourceArchiveAdapterV0`.
pub const ARCHIVE_ID_DIRTY_FLAG_COL: usize = 4;

/// Adapter to access the data type archive identifier table.
///
/// This table holds an ID entry for each archive that has provided a data type to the data type
/// manager for the program.
///
/// Port of `ghidra.program.database.data.SourceArchiveAdapter`.
pub trait SourceArchiveAdapter {
    /// Delete the underlying database table; used when upgrading.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Creates a new source archive record using the information from the given source archive.
    fn create_record(&mut self, source_archive: &dyn SourceArchive) -> io::Result<DBRecord>;

    /// Returns a list containing all records in the archive table.
    fn get_records(&self) -> io::Result<Vec<DBRecord>>;

    /// Returns the record for the given key (source archive ID), or `None` if not found.
    fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>>;

    /// Updates the data type archive ID table with the provided record.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Remove the record for the given data type archive ID. Returns `true` if the record was
    /// deleted.
    fn remove_record(&mut self, key: i64) -> io::Result<bool>;

    /// Removes the record for the given source archive ID.
    fn delete_record(&mut self, source_archive_id: UniversalID) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::archive_type::ArchiveType;
    use std::cell::RefCell;

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

    struct MockSourceArchiveAdapter {
        records: RefCell<Vec<DBRecord>>,
        deleted: RefCell<bool>,
    }

    impl MockSourceArchiveAdapter {
        fn new() -> Self {
            MockSourceArchiveAdapter {
                records: RefCell::new(Vec::new()),
                deleted: RefCell::new(false),
            }
        }

        fn schema() -> std::sync::Arc<crate::framework::db::Schema> {
            use crate::framework::db::{FieldType, Schema};
            std::sync::Arc::new(Schema::new(
                0,
                FieldType::Long,
                "Archive ID".to_string(),
                vec![
                    FieldType::String,
                    FieldType::String,
                    FieldType::Byte,
                    FieldType::Long,
                    FieldType::Boolean,
                ],
                vec![
                    "Domain File ID".to_string(),
                    "Name".to_string(),
                    "Type".to_string(),
                    "Last Sync Time".to_string(),
                    "Dirty".to_string(),
                ],
                vec![],
            ))
        }
    }

    impl SourceArchiveAdapter for MockSourceArchiveAdapter {
        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            *self.deleted.borrow_mut() = true;
            self.records.borrow_mut().clear();
            Ok(())
        }

        fn create_record(&mut self, source_archive: &dyn SourceArchive) -> io::Result<DBRecord> {
            use crate::framework::db::Field;

            let key = source_archive.source_archive_id().value();
            let mut rec = DBRecord::new(Self::schema(), Field::Long(Some(key)));
            rec.set_field(
                ARCHIVE_ID_DOMAIN_FILE_ID_COL,
                Field::String(Some(source_archive.domain_file_id())),
            );
            rec.set_field(
                ARCHIVE_ID_NAME_COL,
                Field::String(Some(source_archive.name())),
            );
            rec.set_field(
                ARCHIVE_ID_TYPE_COL,
                Field::Byte(Some(source_archive.archive_type() as i8)),
            );
            rec.set_field(
                ARCHIVE_ID_LAST_SYNC_TIME_COL,
                Field::Long(Some(source_archive.last_sync_time())),
            );
            rec.set_field(
                ARCHIVE_ID_DIRTY_FLAG_COL,
                Field::Boolean(Some(source_archive.is_dirty())),
            );
            self.records.borrow_mut().push(rec.clone());
            Ok(rec)
        }

        fn get_records(&self) -> io::Result<Vec<DBRecord>> {
            Ok(self.records.borrow().clone())
        }

        fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
            use crate::framework::db::Field;
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(key)))
                .cloned())
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                *existing = record.clone();
            }
            Ok(())
        }

        fn remove_record(&mut self, key: i64) -> io::Result<bool> {
            use crate::framework::db::Field;
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(key)));
            Ok(records.len() != len_before)
        }

        fn delete_record(&mut self, source_archive_id: UniversalID) -> io::Result<()> {
            use crate::framework::db::Field;
            self.records
                .borrow_mut()
                .retain(|r| r.get_key() != &Field::Long(Some(source_archive_id.value())));
            Ok(())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_archives() {
        let mut adapter: Box<dyn SourceArchiveAdapter> = Box::new(MockSourceArchiveAdapter::new());

        let archive = MockSourceArchive {
            id: UniversalID::new(7),
            domain_file_id: "domain-7".to_string(),
            archive_type: ArchiveType::Project,
            name: "proj-archive".to_string(),
            last_sync_time: 100,
            dirty: false,
        };

        let created = adapter.create_record(&archive).unwrap();
        assert_eq!(
            created.get_field(ARCHIVE_ID_NAME_COL),
            &crate::framework::db::Field::String(Some("proj-archive".to_string()))
        );

        assert_eq!(adapter.get_records().unwrap().len(), 1);

        let fetched = adapter.get_record(7).unwrap().expect("record should exist");
        assert_eq!(
            fetched.get_field(ARCHIVE_ID_LAST_SYNC_TIME_COL),
            &crate::framework::db::Field::Long(Some(100))
        );

        let mut updated = fetched.clone();
        updated.set_field(
            ARCHIVE_ID_DIRTY_FLAG_COL,
            crate::framework::db::Field::Boolean(Some(true)),
        );
        adapter.update_record(&updated).unwrap();
        let refetched = adapter.get_record(7).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(ARCHIVE_ID_DIRTY_FLAG_COL),
            &crate::framework::db::Field::Boolean(Some(true))
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
        assert_eq!(adapter.get_records().unwrap().len(), 0);

        let mut handle = DBHandle::new().unwrap();
        adapter.delete_table(&mut handle).unwrap();
    }
}

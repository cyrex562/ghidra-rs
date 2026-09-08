//! Port of `ghidra.program.database.data.SourceArchiveDB`, the database-backed implementation of
//! [`SourceArchive`].
//!
//! `SourceArchiveDB` is a flat record -- unlike [`CategoryDb`](super::category_db::CategoryDb) or
//! [`TypedefDb`](super::typedef_db::TypedefDb) it is not a tree node and has no dependent-type
//! bookkeeping; its only cross-cutting behavior is the "local archive" special case (see below)
//! and persisting edits back through [`SourceArchiveAdapter`].
//!
//! # Owner storage and locking
//!
//! Follows the same convention as [`TypedefDb`](super::typedef_db::TypedefDb): the owning
//! `DataTypeManagerDB` is stored as `Arc<Mutex<dyn DataTypeManagerDb + Send>>` (rather than
//! `Rc<RefCell<...>>`, since [`SourceArchive`] carries no `Send`/`Sync` requirement itself but
//! this crate's convention keeps DB-backed model objects `Send`-capable where cheaply possible),
//! and the shared `dataMgr.lock` field is passed in separately as `Arc<ReentrantLock>` rather than
//! reached through the owner trait (which has no `lock()` accessor).
//!
//! # The "local archive" special case
//!
//! When this record's key equals [`LOCAL_ARCHIVE_KEY`](crate::program::model::data::data_type_manager::LOCAL_ARCHIVE_KEY)
//! (`0`), this `SourceArchiveDB` instance represents the *owning* data type manager's own local
//! archive rather than an external one: [`SourceArchive::source_archive_id`],
//! [`SourceArchive::domain_file_id`], [`SourceArchive::archive_type`], and
//! [`SourceArchive::name`] all delegate to the owning manager directly instead of reading the
//! backing record, exactly mirroring `SourceArchiveDB.isLocal()`'s effect on each of those Java
//! getters. A zero-valued [`UniversalID`] stands in for Java's `null` throughout this crate (see
//! `data_type_utilities.rs`'s `is_same_data_type`), so `getSourceArchiveID()`'s
//! `if (universalID != null)` check becomes `if universal_id.value() != 0`.
//!
//! # `getArchiveType`'s byte-to-enum decode
//!
//! Java's `ArchiveType.values()[byteValue]` indexes the enum's declaration order
//! (`BUILT_IN, FILE, PROJECT, PROGRAM, TEMPORARY`), which is exactly the declaration order of
//! this crate's [`ArchiveType`] (`BuiltIn, File, Project, Program, Temporary`) -- so the ported
//! [`archive_type_from_byte`] helper below is a faithful index-for-index decode, including
//! panicking (mirroring Java's unchecked `ArrayIndexOutOfBoundsException`) for an out-of-range
//! stored byte, which should never occur for a record this adapter itself wrote.

use std::io;
use std::sync::{Arc, Mutex};

use crate::framework::db::DBRecord;
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::database::data::source_archive_adapter::{
    SourceArchiveAdapter, ARCHIVE_ID_DIRTY_FLAG_COL, ARCHIVE_ID_DOMAIN_FILE_ID_COL,
    ARCHIVE_ID_LAST_SYNC_TIME_COL, ARCHIVE_ID_NAME_COL, ARCHIVE_ID_TYPE_COL,
};
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::data::archive_type::ArchiveType;
use crate::program::model::data::data_type_manager::LOCAL_ARCHIVE_KEY;
use crate::program::model::data::source_archive::SourceArchive;
use crate::util::lock::ReentrantLock;
use crate::util::UniversalID;

/// Decodes a stored archive-type byte back into an [`ArchiveType`]. Port of
/// `ArchiveType.values()[byteValue]`. See the module docs for why index-for-index decode is
/// faithful here, and why an out-of-range value panics rather than silently substituting a
/// default (mirroring Java's unchecked `ArrayIndexOutOfBoundsException`).
fn archive_type_from_byte(byte_value: i8) -> ArchiveType {
    match byte_value {
        0 => ArchiveType::BuiltIn,
        1 => ArchiveType::File,
        2 => ArchiveType::Project,
        3 => ArchiveType::Program,
        4 => ArchiveType::Temporary,
        other => panic!(
            "ArrayIndexOutOfBoundsException: Index {other} out of bounds for length 5"
        ),
    }
}

/// Database implementation of [`SourceArchive`].
///
/// Port of `ghidra.program.database.data.SourceArchiveDB`. See the module documentation for what
/// was ported, and for the local-archive special case shared by several getters.
pub struct SourceArchiveDb {
    db_state: DbObjectState,
    source_id: UniversalID,
    record: Mutex<DBRecord>,
    adapter: Arc<Mutex<dyn SourceArchiveAdapter + Send>>,
    dt_mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
    lock: Arc<ReentrantLock>,
}

impl SourceArchiveDb {
    /// Constructs a source-archive view over `record`, backed by `dt_mgr` and `adapter`.
    ///
    /// Port of `SourceArchiveDB(DataTypeManagerDB, SourceArchiveAdapter, DBRecord)`. `lock`
    /// stands in for the shared `dtMgr.lock` field -- see the module documentation.
    pub fn new(
        dt_mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
        adapter: Arc<Mutex<dyn SourceArchiveAdapter + Send>>,
        lock: Arc<ReentrantLock>,
        record: DBRecord,
    ) -> Self {
        let key = record.get_key().get_long_value();
        SourceArchiveDb {
            db_state: DbObjectState::new(key),
            source_id: UniversalID::new(key),
            record: Mutex::new(record),
            adapter,
            dt_mgr,
            lock,
        }
    }

    /// Port of the private `SourceArchiveDB.isLocal()`.
    fn is_local(&self) -> bool {
        self.record.lock().unwrap().get_key().get_long_value() == LOCAL_ARCHIVE_KEY
    }

    /// Persists the current in-memory record via the adapter and notifies the owning manager,
    /// reporting any failure via `dtMgr.dbError(...)`. Stands in for the repeated `try {
    /// adapter.updateRecord(record); dtMgr.sourceArchiveChanged(getSourceArchiveID()); } catch
    /// (IOException e) { dtMgr.dbError(e); }` pattern used throughout `SourceArchiveDB.java`'s
    /// setters.
    fn persist_and_notify(&self) {
        let rec = self.record.lock().unwrap().clone();
        match self.adapter.lock().unwrap().update_record(&rec) {
            Ok(()) => {
                let id = SourceArchive::source_archive_id(self);
                self.dt_mgr.lock().unwrap().source_archive_changed(id);
            }
            Err(e) => {
                self.dt_mgr.lock().unwrap().db_error(e);
            }
        }
    }
}

impl DbObject for SourceArchiveDb {
    fn state(&self) -> &DbObjectState {
        &self.db_state
    }

    /// Port of the protected `SourceArchiveDB.refresh(DBRecord)`.
    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        let rec = match record {
            Some(r) => Some(r.clone()),
            None => {
                let key = self.get_key();
                match self.adapter.lock().unwrap().get_record(key) {
                    Ok(r) => r,
                    Err(e) => {
                        self.dt_mgr.lock().unwrap().db_error(e);
                        return false;
                    }
                }
            }
        };
        match rec {
            Some(r) => {
                *self.record.lock().unwrap() = r;
                true
            }
            None => false,
        }
    }
}

impl SourceArchive for SourceArchiveDb {
    fn source_archive_id(&self) -> UniversalID {
        if self.is_local() {
            // if this sourceArchive represents the local archive (id == LOCAL_ARCHIVE_KEY)
            // the sourceArchiveID is this dataTypeManager's universal ID; if the universalID is
            // null (a zero value here -- see the module docs), then this is from a
            // non-upgraded archive, so fall through to the stored sourceID.
            let universal_id = self.dt_mgr.lock().unwrap().get_universal_id();
            if universal_id.value() != 0 {
                return universal_id;
            }
        }
        self.source_id
    }

    fn domain_file_id(&self) -> String {
        if self.is_local() {
            return self.dt_mgr.lock().unwrap().get_domain_file_id();
        }
        self.record
            .lock()
            .unwrap()
            .get_string(ARCHIVE_ID_DOMAIN_FILE_ID_COL)
            .unwrap_or_default()
            .to_string()
    }

    fn archive_type(&self) -> ArchiveType {
        if self.is_local() {
            return self.dt_mgr.lock().unwrap().get_type();
        }
        let byte_value = self
            .record
            .lock()
            .unwrap()
            .get_byte(ARCHIVE_ID_TYPE_COL)
            .unwrap_or(0);
        archive_type_from_byte(byte_value)
    }

    fn name(&self) -> String {
        if self.is_local() {
            return self.dt_mgr.lock().unwrap().get_name();
        }
        self.record
            .lock()
            .unwrap()
            .get_string(ARCHIVE_ID_NAME_COL)
            .unwrap_or_default()
            .to_string()
    }

    fn last_sync_time(&self) -> i64 {
        self.record
            .lock()
            .unwrap()
            .get_long(ARCHIVE_ID_LAST_SYNC_TIME_COL)
            .unwrap_or(0)
    }

    fn is_dirty(&self) -> bool {
        self.record
            .lock()
            .unwrap()
            .get_bool(ARCHIVE_ID_DIRTY_FLAG_COL)
            .unwrap_or(false)
    }

    fn set_last_sync_time(&mut self, time: i64) {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_long(ARCHIVE_ID_LAST_SYNC_TIME_COL, time);
        }
        self.persist_and_notify();
    }

    fn set_name(&mut self, name: String) {
        if SourceArchive::name(self) == name {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_string(ARCHIVE_ID_NAME_COL, Some(name));
        }
        self.persist_and_notify();
    }

    fn set_dirty_flag(&mut self, dirty: bool) {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_bool(ARCHIVE_ID_DIRTY_FLAG_COL, dirty);
        }
        self.persist_and_notify();
    }
}

impl std::fmt::Display for SourceArchiveDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", SourceArchive::name(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::data::source_archive_adapter::schema;
    use crate::program::model::data::category::Category;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::framework::db::Field;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    struct TestSourceArchiveAdapter {
        records: StdMutex<HashMap<i64, DBRecord>>,
    }
    impl TestSourceArchiveAdapter {
        fn new() -> Self {
            TestSourceArchiveAdapter { records: StdMutex::new(HashMap::new()) }
        }
        fn insert(&self, rec: DBRecord) {
            self.records.lock().unwrap().insert(rec.get_key().get_long_value(), rec);
        }
    }
    impl SourceArchiveAdapter for TestSourceArchiveAdapter {
        fn delete_table(&mut self, _handle: &mut crate::framework::db::DBHandle) -> io::Result<()> {
            self.records.lock().unwrap().clear();
            Ok(())
        }
        fn create_record(&mut self, source_archive: &dyn SourceArchive) -> io::Result<DBRecord> {
            let key = source_archive.source_archive_id().value();
            let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
            rec.set_string(ARCHIVE_ID_DOMAIN_FILE_ID_COL, Some(source_archive.domain_file_id()));
            rec.set_string(ARCHIVE_ID_NAME_COL, Some(source_archive.name()));
            rec.set_byte(ARCHIVE_ID_TYPE_COL, source_archive.archive_type() as i8);
            rec.set_long(ARCHIVE_ID_LAST_SYNC_TIME_COL, source_archive.last_sync_time());
            rec.set_bool(ARCHIVE_ID_DIRTY_FLAG_COL, source_archive.is_dirty());
            self.insert(rec.clone());
            Ok(rec)
        }
        fn get_records(&self) -> io::Result<Vec<DBRecord>> {
            Ok(self.records.lock().unwrap().values().cloned().collect())
        }
        fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.lock().unwrap().get(&key).cloned())
        }
        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            self.records.lock().unwrap().insert(record.get_key().get_long_value(), record.clone());
            Ok(())
        }
        fn remove_record(&mut self, key: i64) -> io::Result<bool> {
            Ok(self.records.lock().unwrap().remove(&key).is_some())
        }
        fn delete_record(&mut self, source_archive_id: UniversalID) -> io::Result<()> {
            self.records.lock().unwrap().remove(&source_archive_id.value());
            Ok(())
        }
    }

    struct TestManager {
        universal_id: UniversalID,
        name: String,
        archive_type: ArchiveType,
        domain_file_id: String,
        errors: Vec<String>,
        changed_ids: Vec<UniversalID>,
    }
    impl TestManager {
        fn new() -> Self {
            TestManager {
                universal_id: UniversalID::new(0),
                name: "local-name".to_string(),
                archive_type: ArchiveType::Program,
                domain_file_id: "local-domain".to_string(),
                errors: Vec::new(),
                changed_ids: Vec::new(),
            }
        }
    }
    impl DataTypeManager for TestManager {
        fn get_universal_id(&self) -> UniversalID {
            self.universal_id
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_type(&self) -> ArchiveType {
            self.archive_type
        }
        fn get_root_category(&self) -> Box<dyn Category> {
            unimplemented!()
        }
    }
    impl DataTypeManagerDb for TestManager {
        fn db_error(&mut self, error: io::Error) {
            self.errors.push(error.to_string());
        }
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn crate::program::model::data::data_type::DataType>) {}
        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
        fn get_domain_file_id(&self) -> String {
            self.domain_file_id.clone()
        }
        fn source_archive_changed(&mut self, source_archive_id: UniversalID) {
            self.changed_ids.push(source_archive_id);
        }
    }

    fn make_record(key: i64, name: &str, domain_file_id: &str, archive_type: ArchiveType, last_sync: i64, dirty: bool) -> DBRecord {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_string(ARCHIVE_ID_DOMAIN_FILE_ID_COL, Some(domain_file_id.to_string()));
        rec.set_string(ARCHIVE_ID_NAME_COL, Some(name.to_string()));
        rec.set_byte(ARCHIVE_ID_TYPE_COL, archive_type as i8);
        rec.set_long(ARCHIVE_ID_LAST_SYNC_TIME_COL, last_sync);
        rec.set_bool(ARCHIVE_ID_DIRTY_FLAG_COL, dirty);
        rec
    }

    fn make_archive(
        mgr: &Arc<Mutex<dyn DataTypeManagerDb + Send>>,
        adapter: &Arc<Mutex<dyn SourceArchiveAdapter + Send>>,
        record: DBRecord,
    ) -> SourceArchiveDb {
        SourceArchiveDb::new(mgr.clone(), adapter.clone(), Arc::new(ReentrantLock::new("SourceArchiveDbTest")), record)
    }

    #[test]
    fn construction_round_trips_name_universal_id_and_archive_type() {
        let mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>> = Arc::new(Mutex::new(TestManager::new()));
        let adapter: Arc<Mutex<dyn SourceArchiveAdapter + Send>> = Arc::new(Mutex::new(TestSourceArchiveAdapter::new()));
        let rec = make_record(42, "my-archive", "domain-42", ArchiveType::File, 100, false);
        let archive = make_archive(&mgr, &adapter, rec);

        assert_eq!(SourceArchive::name(&archive), "my-archive");
        assert_eq!(SourceArchive::source_archive_id(&archive), UniversalID::new(42));
        assert_eq!(SourceArchive::domain_file_id(&archive), "domain-42");
        assert_eq!(SourceArchive::archive_type(&archive), ArchiveType::File);
        assert_eq!(SourceArchive::last_sync_time(&archive), 100);
        assert!(!SourceArchive::is_dirty(&archive));
    }

    #[test]
    fn set_last_sync_time_persists_and_notifies() {
        let mgr_concrete = Arc::new(Mutex::new(TestManager::new()));
        let mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>> = mgr_concrete.clone();
        let adapter: Arc<Mutex<dyn SourceArchiveAdapter + Send>> = Arc::new(Mutex::new(TestSourceArchiveAdapter::new()));
        let rec = make_record(7, "archive", "domain", ArchiveType::Project, 0, false);
        adapter.lock().unwrap().update_record(&rec).unwrap();
        let mut archive = make_archive(&mgr, &adapter, rec);

        SourceArchive::set_last_sync_time(&mut archive, 555);
        assert_eq!(SourceArchive::last_sync_time(&archive), 555);

        let persisted = adapter.lock().unwrap().get_record(7).unwrap().unwrap();
        assert_eq!(persisted.get_long(ARCHIVE_ID_LAST_SYNC_TIME_COL), Some(555));

        let notified = mgr_concrete.lock().unwrap().changed_ids.clone();
        assert_eq!(notified, vec![UniversalID::new(7)]);
    }

    #[test]
    fn set_dirty_flag_persists_and_notifies() {
        let mgr_concrete = Arc::new(Mutex::new(TestManager::new()));
        let mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>> = mgr_concrete.clone();
        let adapter: Arc<Mutex<dyn SourceArchiveAdapter + Send>> = Arc::new(Mutex::new(TestSourceArchiveAdapter::new()));
        let rec = make_record(8, "archive", "domain", ArchiveType::Project, 0, false);
        adapter.lock().unwrap().update_record(&rec).unwrap();
        let mut archive = make_archive(&mgr, &adapter, rec);

        assert!(!SourceArchive::is_dirty(&archive));
        SourceArchive::set_dirty_flag(&mut archive, true);
        assert!(SourceArchive::is_dirty(&archive));

        let persisted = adapter.lock().unwrap().get_record(8).unwrap().unwrap();
        assert_eq!(persisted.get_bool(ARCHIVE_ID_DIRTY_FLAG_COL), Some(true));
    }

    #[test]
    fn set_name_renames_and_is_a_no_op_when_unchanged() {
        let mgr_concrete = Arc::new(Mutex::new(TestManager::new()));
        let mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>> = mgr_concrete.clone();
        let adapter: Arc<Mutex<dyn SourceArchiveAdapter + Send>> = Arc::new(Mutex::new(TestSourceArchiveAdapter::new()));
        let rec = make_record(9, "old-name", "domain", ArchiveType::Project, 0, false);
        adapter.lock().unwrap().update_record(&rec).unwrap();
        let mut archive = make_archive(&mgr, &adapter, rec);

        // No-op rename: must not touch the adapter/manager at all.
        SourceArchive::set_name(&mut archive, "old-name".to_string());
        assert!(mgr_concrete.lock().unwrap().changed_ids.is_empty());

        SourceArchive::set_name(&mut archive, "new-name".to_string());
        assert_eq!(SourceArchive::name(&archive), "new-name");
        let persisted = adapter.lock().unwrap().get_record(9).unwrap().unwrap();
        assert_eq!(persisted.get_string(ARCHIVE_ID_NAME_COL), Some("new-name"));
        assert_eq!(mgr_concrete.lock().unwrap().changed_ids, vec![UniversalID::new(9)]);
    }

    #[test]
    fn local_archive_delegates_getters_to_owning_manager() {
        let mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>> = Arc::new(Mutex::new(TestManager::new()));
        let adapter: Arc<Mutex<dyn SourceArchiveAdapter + Send>> = Arc::new(Mutex::new(TestSourceArchiveAdapter::new()));
        // key == LOCAL_ARCHIVE_KEY (0) marks this as the local archive.
        let rec = make_record(LOCAL_ARCHIVE_KEY, "record-name-ignored", "record-domain-ignored", ArchiveType::File, 0, false);
        let archive = make_archive(&mgr, &adapter, rec);

        assert_eq!(SourceArchive::name(&archive), "local-name");
        assert_eq!(SourceArchive::domain_file_id(&archive), "local-domain");
        assert_eq!(SourceArchive::archive_type(&archive), ArchiveType::Program);
        // universal_id is 0 (Java `null`), so getSourceArchiveID falls back to the stored sourceID
        // (also 0 here, since the record's key is LOCAL_ARCHIVE_KEY).
        assert_eq!(SourceArchive::source_archive_id(&archive), UniversalID::new(0));
    }

    #[test]
    fn local_archive_uses_managers_universal_id_when_present() {
        let mut mgr_inner = TestManager::new();
        mgr_inner.universal_id = UniversalID::new(9999);
        let mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>> = Arc::new(Mutex::new(mgr_inner));
        let adapter: Arc<Mutex<dyn SourceArchiveAdapter + Send>> = Arc::new(Mutex::new(TestSourceArchiveAdapter::new()));
        let rec = make_record(LOCAL_ARCHIVE_KEY, "ignored", "ignored", ArchiveType::File, 0, false);
        let archive = make_archive(&mgr, &adapter, rec);

        assert_eq!(SourceArchive::source_archive_id(&archive), UniversalID::new(9999));
    }

    #[test]
    fn display_matches_name() {
        let mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>> = Arc::new(Mutex::new(TestManager::new()));
        let adapter: Arc<Mutex<dyn SourceArchiveAdapter + Send>> = Arc::new(Mutex::new(TestSourceArchiveAdapter::new()));
        let rec = make_record(3, "display-name", "domain", ArchiveType::Project, 0, false);
        let archive = make_archive(&mgr, &adapter, rec);
        assert_eq!(format!("{archive}"), "display-name");
    }
}

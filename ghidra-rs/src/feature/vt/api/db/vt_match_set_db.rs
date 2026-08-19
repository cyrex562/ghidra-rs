//! Port of `ghidra.feature.vt.api.db.VTMatchSetDB`.
//!
//! Concrete, database-backed [`VTMatchSet`]: one row of the `MatchSetTable` (the correlator run
//! that produced the matches) plus the `MatchTable<id>` holding those matches.
//!
//! Deviations from the Java source, all forced by types that are not ported yet (see
//! [`crate::feature::seam_stubs`]):
//!
//! * Java's `VTMatchSetDB` keeps the `DBHandle` it was constructed with as a field purely so the
//!   two `createTableAdapters`/`getTableAdapters` helpers can reach it after construction. The two
//!   Rust factories build the adapter eagerly, so the handle is borrowed for the call and not
//!   retained -- which also keeps the struct free of a database handle it would otherwise have to
//!   share.
//! * The `VTMatchSet` trait's signatures are written in terms of seam stubs that carry no data yet
//!   (`VtMatchInfo` is a fieldless placeholder, and the `VTSessionDB -> VTSession` bridge does not
//!   exist -- the same gap already documented on
//!   [`VTAssociationDB`](crate::feature::vt::api::db::vt_association_db::VTAssociationDB)). The real
//!   port therefore lives on concretely-typed inherent methods; the trait impl forwards the four
//!   methods it can express and points at those inherent methods for the rest.
//! * `VTMatchDB` and `ProgramCorrelatorInfoImpl` both hold a `VTMatchSetDB` back-reference in Java.
//!   Their stubs deliberately do not (see their docs): the match cache below owns its matches
//!   strongly, and this type owns its correlator info, so either back-reference would be an
//!   unreclaimable cycle.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::feature::seam_stubs::{
    ProgramCorrelatorInfoImpl, VTMatchDB, VTMatchInfo, VTSessionDB, VtAssociation,
};
use crate::feature::vt::api::db::vt_association_db::VTAssociationDB;
use crate::feature::vt::api::implementation::vt_program_correlator_info::VtProgramCorrelatorInfo;
use crate::feature::vt::api::main::db::association_database_manager::AssociationDatabaseManager;
use crate::feature::vt::api::main::db::deleted_match::DeletedMatch;
use crate::feature::vt::api::main::db::vt_match_set_table_db_adapter::ColumnDescription as MatchSetColumn;
use crate::feature::vt::api::main::db::vt_match_table_db_adapter::{
    VTMatchTableDBAdapter, VTMatchTableDBAdapterBase,
};
use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
use crate::feature::vt::api::main::vt_match_set::VTMatchSet;
use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord};
use crate::framework::options::Options;
use crate::program::database::db_cache::{DbCache, DbCacheHandle};
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::address::key_range::KeyRange;
use crate::program::model::address::{Address, AddressSet};
use crate::util::exception::VersionException;
use crate::util::lock::ReentrantLock;
use crate::util::task::TaskMonitor;

/// Java: `VTMatchSetDB.getOptions()`'s `new ToolOptions("EMPTY_OPTIONS_NAME")` fallback name.
const EMPTY_OPTIONS_NAME: &str = "EMPTY_OPTIONS_NAME";

/// Java: the initial capacity `VTMatchSetDB` gives its `DbCache<VTMatchDB>`.
const MATCH_CACHE_HARD_CACHE_SIZE: usize = 10;

/// Stands in for `new ToolOptions(...)`: `ghidra.framework.options.ToolOptions` is not ported yet,
/// so this carries the options object's name plus the raw XML the Java constructor would have
/// deserialized, and otherwise behaves as an [`Options`] with no properties. Nothing is lost --
/// the XML is exactly what the record stores -- but option lookups return their defaults until the
/// real `ToolOptions` port lands.
struct StoredToolOptions {
    name: String,
    xml: Option<String>,
}

impl Options for StoredToolOptions {
    fn get_name(&self) -> String {
        self.name.clone()
    }
}

impl StoredToolOptions {
    /// The un-deserialized XML this options object was stored as, or `None` for the
    /// [`EMPTY_OPTIONS_NAME`] fallback. Has no Java counterpart; it exists so the raw column value
    /// stays reachable while `ToolOptions` is unported.
    #[cfg(test)]
    fn xml(&self) -> Option<&str> {
        self.xml.as_deref()
    }
}

/// The `DbCache<VTMatchDB>` that `VTMatchSetDB` builds with its `MatchFactory`.
///
/// `ghidra.program.database.DbCache` is ported as a trait with no concrete implementation, so the
/// cache itself is spelled out here. One deviation:
/// [`DbCache::get_cached_instance`] cannot re-read a missing row, because Java's `MatchFactory`
/// does that through the owning match set's `getMatchRecord(key)` and giving this cache that
/// back-reference would be a cycle. Callers that have a record in hand -- which is every caller in
/// this module, since all of them iterate records -- use
/// [`DbCache::get_cached_instance_for_record`], which does instantiate.
struct MatchCache {
    match_set_id: i64,
    matches: Mutex<HashMap<i64, Arc<VTMatchDB>>>,
    modification_count: AtomicI32,
    self_handle: std::sync::Weak<MatchCache>,
}

impl MatchCache {
    fn new(match_set_id: i64) -> Arc<Self> {
        Arc::new_cyclic(|weak| MatchCache {
            match_set_id,
            matches: Mutex::new(HashMap::with_capacity(MATCH_CACHE_HARD_CACHE_SIZE)),
            modification_count: AtomicI32::new(0),
            self_handle: weak.clone(),
        })
    }
}

impl DbCacheHandle for MatchCache {
    fn get_modification_count(&self) -> i32 {
        self.modification_count.load(Ordering::SeqCst)
    }

    fn delete(&self, key: i64) {
        if let Some(match_db) = self.matches.lock().unwrap().remove(&key) {
            match_db.set_deleted();
        }
    }

    fn key_changed(&self, old_key: i64, new_key: i64) {
        let mut matches = self.matches.lock().unwrap();
        if let Some(match_db) = matches.remove(&old_key) {
            match_db.set_invalid();
            matches.insert(new_key, match_db);
        }
    }
}

impl DbCache<VTMatchDB> for MatchCache {
    fn size(&self) -> usize {
        self.matches.lock().unwrap().len()
    }

    fn add(&self, db_object: VTMatchDB) -> Arc<VTMatchDB> {
        let match_db = Arc::new(db_object);
        if let Some(handle) = self.self_handle.upgrade() {
            match_db.set_cache(handle as Arc<dyn DbCacheHandle>);
        }
        self.matches.lock().unwrap().insert(match_db.get_key(), match_db.clone());
        match_db
    }

    fn get_cached_instance(&self, key: i64) -> Option<Arc<VTMatchDB>> {
        let cached = self.matches.lock().unwrap().get(&key).cloned()?;
        cached.refresh_if_needed().then_some(cached)
    }

    fn get_if_valid(&self, key: i64) -> Option<Arc<VTMatchDB>> {
        self.matches.lock().unwrap().get(&key).filter(|m| m.is_valid()).cloned()
    }

    fn get_raw(&self, key: i64) -> Option<Arc<VTMatchDB>> {
        self.matches.lock().unwrap().get(&key).cloned()
    }

    fn get_cached_instance_for_record(&self, record: &DBRecord) -> Option<Arc<VTMatchDB>> {
        let key = record.get_key().get_long_value();
        if let Some(cached) = self.matches.lock().unwrap().get(&key).cloned() {
            if cached.refresh_if_needed_with_record(Some(record)) {
                return Some(cached);
            }
        }
        Some(self.add(VTMatchDB::new(record.clone(), self.match_set_id)))
    }

    fn get_cached_objects(&self) -> Vec<Arc<VTMatchDB>> {
        self.matches.lock().unwrap().values().cloned().collect()
    }

    fn delete_key_ranges(&self, key_ranges: &[KeyRange]) {
        let mut matches = self.matches.lock().unwrap();
        let doomed: Vec<i64> = matches
            .keys()
            .copied()
            .filter(|key| key_ranges.iter().any(|range| range.contains(*key)))
            .collect();
        for key in doomed {
            if let Some(match_db) = matches.remove(&key) {
                match_db.set_deleted();
            }
        }
    }

    fn invalidate(&self) {
        self.modification_count.fetch_add(1, Ordering::SeqCst);
    }
}

/// All the matches generated from a single program correlator run, backed by the database.
///
/// Port of `ghidra.feature.vt.api.db.VTMatchSetDB`. See the module docs for the deviations this
/// port makes.
pub struct VTMatchSetDB {
    state: DbObjectState,
    match_set_record: DBRecord,
    session: Arc<dyn VTSessionDB>,
    match_table_adapter: Box<dyn VTMatchTableDBAdapter>,
    lock: Arc<ReentrantLock>,
    match_cache: Arc<MatchCache>,
    correlator_info: OnceLock<ProgramCorrelatorInfoImpl>,
    options: OnceLock<Box<dyn Options + Send + Sync>>,
}

impl VTMatchSetDB {
    /// Java: `VTMatchSetDB.createMatchSetDB(DBRecord, VTSessionDB, DBHandle, Lock)`, which creates
    /// the backing `MatchTable<id>`.
    pub fn create_match_set_db(
        record: DBRecord,
        session: Arc<dyn VTSessionDB>,
        db_handle: &mut DBHandle,
        lock: Arc<ReentrantLock>,
    ) -> io::Result<Self> {
        let table_id = record.get_key().get_long_value();
        let match_table_adapter = VTMatchTableDBAdapterBase::create_adapter(db_handle, table_id)?;
        Ok(Self::new(record, session, match_table_adapter, lock))
    }

    /// Java: `VTMatchSetDB.getMatchSetDB(DBRecord, VTSessionDB, DBHandle, OpenMode, TaskMonitor,
    /// Lock)`, which opens an existing `MatchTable<id>`.
    pub fn get_match_set_db(
        record: DBRecord,
        session: Arc<dyn VTSessionDB>,
        db_handle: &DBHandle,
        open_mode: OpenMode,
        monitor: &dyn TaskMonitor,
        lock: Arc<ReentrantLock>,
    ) -> Result<Self, VersionException> {
        let table_id = record.get_key().get_long_value();
        let match_table_adapter =
            VTMatchTableDBAdapterBase::get_adapter(db_handle, table_id, open_mode, monitor)?;
        Ok(Self::new(record, session, match_table_adapter, lock))
    }

    /// Java: the private `VTMatchSetDB(DBRecord, VTSessionDB, DBHandle, Lock)` constructor, with
    /// the already-built match table adapter passed in rather than the handle it was built from.
    fn new(
        record: DBRecord,
        session: Arc<dyn VTSessionDB>,
        match_table_adapter: Box<dyn VTMatchTableDBAdapter>,
        lock: Arc<ReentrantLock>,
    ) -> Self {
        let key = record.get_key().get_long_value();
        Self {
            // Java: `super(record.getKey())` -- "cache not supported", i.e. no owning DbCache.
            state: DbObjectState::new(key),
            match_set_record: record,
            session,
            match_table_adapter,
            lock,
            match_cache: MatchCache::new(key),
            correlator_info: OnceLock::new(),
            options: OnceLock::new(),
        }
    }

    /// Java: `VTMatchSetDB.dbError(IOException)` (package-private), which funnels through the
    /// session.
    pub(crate) fn db_error(&self, error: io::Error) {
        self.session.db_error(error);
    }

    /// Java: `getSession()`, before the `VTSession` widening this port cannot yet express (see the
    /// module docs). Named as on
    /// [`VTAssociationDB::get_session_db`](crate::feature::vt::api::main::vt_association::VtAssociation::get_session_db).
    pub fn get_session_db(&self) -> &Arc<dyn VTSessionDB> {
        &self.session
    }

    /// Java: `getMatchCount()`.
    pub fn get_match_count(&self) -> i32 {
        self.match_table_adapter.get_record_count() as i32
    }

    /// Java: `getID()`.
    pub fn get_id(&self) -> i32 {
        self.match_set_record.get_key().get_long_value() as i32
    }

    /// Java: `getProgramCorrelatorInfo()`, which lazily builds and caches a
    /// `ProgramCorrelatorInfoImpl` over this match set.
    pub fn get_program_correlator_info(&self) -> &ProgramCorrelatorInfoImpl {
        self.correlator_info.get_or_init(|| {
            ProgramCorrelatorInfoImpl::new(
                self.get_program_correlator_class_name().unwrap_or_default().to_string(),
                self.get_program_correlator_name().unwrap_or_default().to_string(),
                self.get_source_address_set().ok().flatten().unwrap_or_default(),
                self.get_destination_address_set().ok().flatten().unwrap_or_default(),
                self.build_options(),
            )
        })
    }

    /// Java: `getSourceAddressSet()`. `None` mirrors the adapter's own nullable return.
    pub fn get_source_address_set(&self) -> io::Result<Option<AddressSet>> {
        self.session.get_source_address_set(&self.match_set_record)
    }

    /// Java: `getDestinationAddressSet()`.
    pub fn get_destination_address_set(&self) -> io::Result<Option<AddressSet>> {
        self.session.get_destination_address_set(&self.match_set_record)
    }

    /// Java: `getProgramCorrelatorName()`.
    pub fn get_program_correlator_name(&self) -> Option<&str> {
        self.match_set_record.get_string(MatchSetColumn::CorrelatorNameCol.column())
    }

    /// Java: `getProgramCorrelatorClassName()`.
    pub fn get_program_correlator_class_name(&self) -> Option<&str> {
        self.match_set_record.get_string(MatchSetColumn::CorrelatorClassCol.column())
    }

    /// Java: `getOptions()`, which deserializes the stored XML into a `ToolOptions` (falling back
    /// to an empty `ToolOptions("EMPTY_OPTIONS_NAME")` when the column is null) and caches it.
    ///
    /// Deviation: Java caches only the deserialized case and rebuilds the empty fallback on every
    /// call; both are cached here, which is indistinguishable to callers since the fallback carries
    /// no state. See [`StoredToolOptions`] for what "deserializes" currently amounts to.
    pub fn get_options(&self) -> &(dyn Options + Send + Sync) {
        self.options.get_or_init(|| self.build_options()).as_ref()
    }

    fn build_options(&self) -> Box<dyn Options + Send + Sync> {
        match self.match_set_record.get_string(MatchSetColumn::OptionsCol.column()) {
            None => Box::new(StoredToolOptions {
                name: EMPTY_OPTIONS_NAME.to_string(),
                xml: None,
            }),
            Some(xml) => Box::new(StoredToolOptions {
                name: self.get_program_correlator_name().unwrap_or(EMPTY_OPTIONS_NAME).to_string(),
                xml: Some(xml.to_string()),
            }),
        }
    }

    /// Java: `addMatch(VTMatchInfo)`. Returns `None` when the insert failed, mirroring the `null`
    /// Java returns after routing the `IOException` through `dbError`.
    pub fn add_match(&self, info: &dyn VTMatchInfo) -> Option<Arc<VTMatchDB>> {
        let association_manager = self.session.get_association_manager_dbm();
        let association_db = association_manager.get_or_create_association_db(
            &info.get_source_address(),
            &info.get_destination_address(),
            info.get_association_type(),
        )?;

        let tag = info.get_tag();
        let new_match = {
            let _guard = self.lock.write();
            let tag_db = self.session.get_or_create_match_tag_db(&tag);
            match self.match_table_adapter.insert_match_record(
                info,
                self,
                &association_db,
                tag_db.as_deref(),
            ) {
                Ok(match_record) => {
                    Some(self.match_cache.add(VTMatchDB::new(match_record, self.get_id() as i64)))
                }
                Err(e) => {
                    self.db_error(e);
                    None
                }
            }
        };

        if let Some(new_match) = &new_match {
            self.session.match_added(new_match);
        }
        new_match
    }

    /// Java: `removeMatch(VTMatch)`. The `instanceof VTMatchDB` guard (and the
    /// `IllegalArgumentException` behind it) is enforced statically by the parameter type.
    ///
    /// Returns `false` without deleting anything when this is the association's last match and the
    /// association has been ACCEPTED: deleting it would silently discard information the user may
    /// still want. Un-accept the match first to work around that.
    pub fn remove_match(&self, match_db: &Arc<VTMatchDB>) -> bool {
        let Some(association) = self.association_of(match_db) else {
            return false;
        };

        let matches = self.session.get_matches_for_association(&association);
        if matches.len() == 1
            && association.get_association_status() == VtAssociationStatus::Accepted
        {
            return false;
        }

        self.delete_match(match_db);
        true
    }

    /// Java: `deleteMatch(VTMatch)`. As with [`remove_match`](Self::remove_match), the
    /// `instanceof VTMatchDB` guard is the parameter type.
    pub fn delete_match(&self, match_db: &Arc<VTMatchDB>) {
        // Java reads `match.getAssociation()` through the back-reference `VTMatchDB` holds to this
        // match set; the stub resolves the same association through its recorded key instead.
        let Some(association) = self.association_of(match_db) else {
            return;
        };
        let source_address = association.get_source_address();
        let destination_address = association.get_destination_address();

        {
            let _guard = self.lock.write();
            if let Err(message) = self.check_deleted() {
                // Java: the ConcurrentModificationException `checkDeleted()` throws.
                panic!("{message}");
            }
            let match_key = match_db.get_key();
            match self.match_table_adapter.delete_record(match_key) {
                Ok(true) => {
                    self.match_cache.delete(match_key);
                    if self.session.get_matches_for_association(&association).is_empty() {
                        // Last match for this association: the association goes too.
                        self.session
                            .get_association_manager_dbm()
                            .remove_association(&association);
                    }
                }
                Ok(false) => {}
                Err(e) => self.db_error(e),
            }
        }

        let deleted_match = DeletedMatch::new(source_address, destination_address);
        self.session.match_deleted(match_db, &deleted_match);
    }

    /// Java: `getMatches()`.
    pub fn get_matches(&self) -> Vec<Arc<VTMatchDB>> {
        let _guard = self.lock.read();
        match self.collect_matches(|adapter| adapter.get_records()) {
            Ok(matches) => matches,
            Err(e) => {
                self.db_error(e);
                Vec::new()
            }
        }
    }

    /// Java: `getMatches(VTAssociation)`.
    pub fn get_matches_for_association(&self, association: &VTAssociationDB) -> Vec<Arc<VTMatchDB>> {
        let _guard = self.lock.read();
        let association_key = association.get_key();
        match self.collect_matches(|adapter| adapter.get_records_for_association(association_key)) {
            Ok(matches) => matches,
            Err(e) => {
                self.db_error(e);
                Vec::new()
            }
        }
    }

    /// Java: `getMatches(Address, Address)`, which resolves the pair to an existing association and
    /// defers to [`get_matches_for_association`](Self::get_matches_for_association); an unknown
    /// pair yields no matches.
    pub fn get_matches_for_addresses(
        &self,
        source_address: &Address,
        destination_address: &Address,
    ) -> Vec<Arc<VTMatchDB>> {
        let association = {
            let _guard = self.lock.read();
            self.session
                .get_association_manager_dbm()
                .get_existing_association_db(source_address, destination_address)
        };
        match association {
            None => Vec::new(),
            Some(association) => self.get_matches_for_association(&association),
        }
    }

    /// Java: `getDestinationProgram()` (package-private).
    pub(crate) fn get_destination_program(
        &self,
    ) -> Arc<dyn crate::program::model::listing::program::Program> {
        self.session.get_destination_program()
    }

    /// Java: `getSourceProgram()` (package-private).
    pub(crate) fn get_source_program(
        &self,
    ) -> Arc<dyn crate::program::model::listing::program::Program> {
        self.session.get_source_program()
    }

    /// Java: `getAssociationManager()` (package-private).
    pub(crate) fn get_association_manager(&self) -> Arc<AssociationDatabaseManager> {
        self.session.get_association_manager_dbm()
    }

    /// Java: `getMatchTableAdapter()` (package-private).
    pub(crate) fn get_match_table_adapter(&self) -> &dyn VTMatchTableDBAdapter {
        self.match_table_adapter.as_ref()
    }

    /// Java: `invalidateCache()` (package-private).
    pub(crate) fn invalidate_cache(&self) {
        self.match_cache.invalidate();
    }

    /// Java: `getMatchRecord(long)` (package-private), which reports the `IOException` through the
    /// session and returns `null`.
    pub(crate) fn get_match_record(&self, match_key: i64) -> Option<DBRecord> {
        match self.match_table_adapter.get_match_record(match_key) {
            Ok(record) => record,
            Err(e) => {
                self.session.db_error(e);
                None
            }
        }
    }

    /// The `VTAssociationDB` a match points at, i.e. Java's `match.getAssociation()`.
    fn association_of(&self, match_db: &Arc<VTMatchDB>) -> Option<Arc<VTAssociationDB>> {
        self.session
            .get_association_manager_dbm()
            .get_association_db(match_db.get_association_key())
    }

    /// The record-iterating half shared by the two `getMatches` overloads.
    fn collect_matches<F>(&self, records: F) -> io::Result<Vec<Arc<VTMatchDB>>>
    where
        F: FnOnce(&dyn VTMatchTableDBAdapter) -> io::Result<Box<dyn crate::framework::db::RecordIterator>>,
    {
        let mut iterator = records(self.match_table_adapter.as_ref())?;
        let mut matches = Vec::new();
        while let Some(record) = iterator.next()? {
            if let Some(match_db) = self.match_cache.get_cached_instance_for_record(&record) {
                matches.push(match_db);
            }
        }
        Ok(matches)
    }
}

impl DbObject for VTMatchSetDB {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    /// Java: `refresh(DBRecord)` -- "MatchSets are not cached, so this method is not used".
    fn refresh(&self, _record: Option<&DBRecord>) -> bool {
        true
    }
}

impl VTMatchSet for VTMatchSetDB {
    fn get_session(&self) -> Box<dyn crate::feature::vt::api::main::vt_session::VTSession> {
        unimplemented!(
            "VTMatchSetDB::get_session requires the unported VTSessionDB -> VTSession bridge; use \
             VTMatchSetDB::get_session_db"
        )
    }

    fn add_match(
        &mut self,
        _info: crate::feature::seam_stubs::VtMatchInfo,
    ) -> Box<dyn crate::feature::seam_stubs::VtMatch> {
        unimplemented!(
            "VTMatchSetDB::add_match needs the real VTMatchInfo port (the seam placeholder carries \
             no addresses, type or tag); use the inherent VTMatchSetDB::add_match"
        )
    }

    fn get_matches(&self) -> Vec<Box<dyn crate::feature::seam_stubs::VtMatch>> {
        unimplemented!(
            "VTMatchSetDB::get_matches needs the real VTMatchDB port to implement VTMatch; use the \
             inherent VTMatchSetDB::get_matches"
        )
    }

    fn get_program_correlator_info(&self) -> &dyn VtProgramCorrelatorInfo {
        VTMatchSetDB::get_program_correlator_info(self)
    }

    fn get_match_count(&self) -> i32 {
        VTMatchSetDB::get_match_count(self)
    }

    fn get_id(&self) -> i32 {
        VTMatchSetDB::get_id(self)
    }

    fn get_matches_for_association(
        &self,
        _association: &dyn VtAssociation,
    ) -> Vec<Box<dyn crate::feature::seam_stubs::VtMatch>> {
        unimplemented!(
            "VTMatchSetDB::get_matches_for_association needs the real VTMatchDB port; use the \
             inherent VTMatchSetDB::get_matches_for_association"
        )
    }

    fn get_matches_for_addresses(
        &self,
        _source_address: &Address,
        _destination_address: &Address,
    ) -> Vec<Box<dyn crate::feature::seam_stubs::VtMatch>> {
        unimplemented!(
            "VTMatchSetDB::get_matches_for_addresses needs the real VTMatchDB port; use the \
             inherent VTMatchSetDB::get_matches_for_addresses"
        )
    }

    fn delete_match(&mut self, _match_item: &dyn crate::feature::seam_stubs::VtMatch) {
        unimplemented!(
            "VTMatchSetDB::delete_match only accepts matches saved to the database; use the \
             inherent VTMatchSetDB::delete_match, which takes a VTMatchDB"
        )
    }

    fn remove_match(&mut self, _match_item: &dyn crate::feature::seam_stubs::VtMatch) -> bool {
        unimplemented!(
            "VTMatchSetDB::remove_match only accepts matches saved to the database; use the \
             inherent VTMatchSetDB::remove_match, which takes a VTMatchDB"
        )
    }
}

impl std::fmt::Display for VTMatchSetDB {
    /// Java: `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Match Set {} - {} matches [Correlator={}]",
            self.get_id(),
            self.get_match_count(),
            self.get_program_correlator_info().get_name()
        )
    }
}

impl std::fmt::Debug for VTMatchSetDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Shared fixtures for building a real [`VTMatchSetDB`] in tests, here rather than in this file's
/// own `tests` module so that
/// [`vt_match_table_db_adapter`](crate::feature::vt::api::main::db::vt_match_table_db_adapter) --
/// whose `insert_match_record` takes one -- can use them too.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::feature::seam_stubs::{AddressType, VTMatchTagDB, VtMarkupItem};
    use crate::feature::vt::api::implementation::vt_event::VtEvent;
    use crate::feature::vt::api::main::db::vt_match_set_table_db_adapter::VTMatchSetTableDBAdapterBase;
    use crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus;
    use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
    use crate::feature::vt::api::main::vt_score::VtScore;
    use crate::framework::db::Field;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    /// A `VTSessionDB` that answers exactly the questions `VTMatchSetDB` asks of a session:
    /// address translation, the association manager, and the two match events.
    pub(crate) struct MockSession {
        space: Arc<AddressSpace>,
        manager: OnceLock<Arc<AssociationDatabaseManager>>,
        /// Matches the session reports for an association, keyed by association key.
        pub(crate) matches_by_association: Mutex<HashMap<i64, usize>>,
        pub(crate) added: Mutex<Vec<i64>>,
        pub(crate) deleted: Mutex<Vec<(i64, i64)>>,
    }

    impl MockSession {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(MockSession {
                space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1),
                manager: OnceLock::new(),
                matches_by_association: Mutex::new(HashMap::new()),
                added: Mutex::new(Vec::new()),
                deleted: Mutex::new(Vec::new()),
            })
        }

        pub(crate) fn address(&self, offset: i64) -> AddressType {
            AddressType::new(self.space.clone(), offset)
        }
    }

    impl VTSessionDB for MockSession {
        fn get_lock(&self) -> Arc<ReentrantLock> {
            Arc::new(ReentrantLock::new("test"))
        }

        fn db_error(&self, error: io::Error) {
            panic!("unexpected database error: {error}");
        }

        fn get_source_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by these tests")
        }

        fn get_destination_program(
            &self,
        ) -> Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by these tests")
        }

        fn get_long_from_source_address(&self, address: &AddressType) -> i64 {
            address.offset()
        }

        fn get_long_from_destination_address(&self, address: &AddressType) -> i64 {
            address.offset()
        }

        fn get_source_address_from_long(&self, value: i64) -> AddressType {
            self.address(value)
        }

        fn get_destination_address_from_long(&self, value: i64) -> AddressType {
            self.address(value)
        }

        fn set_changed(
            &self,
            _event_type: VtEvent,
            _old_value: Option<Arc<VTAssociationDB>>,
            _new_value: Option<Arc<VTAssociationDB>>,
        ) {
        }

        fn markup_item_status_changed(
            &self,
            _markup_item: &dyn VtMarkupItem,
            _old_status: VtMarkupItemStatus,
            _new_status: VtMarkupItemStatus,
        ) {
        }

        fn get_source_address_set(&self, _record: &DBRecord) -> io::Result<Option<AddressSet>> {
            Ok(Some(AddressSet::from_start_end(self.address(0x1000), self.address(0x1fff))))
        }

        fn get_destination_address_set(&self, _record: &DBRecord) -> io::Result<Option<AddressSet>> {
            Ok(Some(AddressSet::from_start_end(self.address(0x2000), self.address(0x2fff))))
        }

        fn get_association_manager_dbm(&self) -> Arc<AssociationDatabaseManager> {
            self.manager.get().expect("association manager not installed").clone()
        }

        fn get_or_create_match_tag_db(&self, _tag: &VtMatchTag) -> Option<Arc<dyn VTMatchTagDB>> {
            None
        }

        fn get_matches_for_association(
            &self,
            association: &Arc<VTAssociationDB>,
        ) -> Vec<Arc<VTMatchDB>> {
            let count = self
                .matches_by_association
                .lock()
                .unwrap()
                .get(&association.get_key())
                .copied()
                .unwrap_or(0);
            // Only the length of this list is ever read, so stand-in rows suffice.
            (0..count)
                .map(|i| {
                    Arc::new(VTMatchDB::new(
                        DBRecord::new(
                            VTMatchTableDBAdapterBase::table_schema(),
                            Field::Long(Some(i as i64)),
                        ),
                        0,
                    ))
                })
                .collect()
        }

        fn match_added(&self, match_db: &Arc<VTMatchDB>) {
            self.added.lock().unwrap().push(match_db.get_key());
        }

        fn match_deleted(&self, match_db: &Arc<VTMatchDB>, deleted_match: &DeletedMatch) {
            self.deleted.lock().unwrap().push((
                match_db.get_key(),
                deleted_match.source_address().offset(),
            ));
        }
    }

    use crate::feature::vt::api::main::db::vt_match_table_db_adapter::VTMatchTableDBAdapterBase;

    /// Builds a session with its association manager already installed.
    pub(crate) fn new_session_with_manager(db_handle: &mut DBHandle) -> Arc<MockSession> {
        let session = MockSession::new();
        let manager = AssociationDatabaseManager::create_association_manager(
            db_handle,
            session.clone() as Arc<dyn VTSessionDB>,
        )
        .expect("association manager");
        let _ = session.manager.set(Arc::new(manager));
        session
    }

    /// Builds the `MatchSetTable` row a `VTMatchSetDB` wraps.
    pub(crate) fn match_set_record(
        id: i64,
        correlator_class: &str,
        correlator_name: &str,
        options_xml: Option<&str>,
    ) -> DBRecord {
        let mut record = DBRecord::new(
            VTMatchSetTableDBAdapterBase::table_schema(),
            Field::Long(Some(id)),
        );
        record.set_string(
            MatchSetColumn::CorrelatorClassCol.column(),
            Some(correlator_class.to_string()),
        );
        record.set_string(
            MatchSetColumn::CorrelatorNameCol.column(),
            Some(correlator_name.to_string()),
        );
        record.set_string(
            MatchSetColumn::OptionsCol.column(),
            options_xml.map(str::to_string),
        );
        record
    }

    /// Builds a `VTMatchSetDB` over a freshly created `MatchTable<id>`.
    pub(crate) fn new_match_set(
        db_handle: &mut DBHandle,
        session: Arc<dyn VTSessionDB>,
        id: i64,
    ) -> VTMatchSetDB {
        VTMatchSetDB::create_match_set_db(
            match_set_record(id, "ghidra.MockCorrelator", "Mock Correlator", None),
            session,
            db_handle,
            Arc::new(ReentrantLock::new("test")),
        )
        .expect("match set")
    }

    /// A `VTMatchInfo` carrying every value `VTMatchSetDB::add_match` reads off it.
    pub(crate) struct FakeMatchInfo {
        pub(crate) source: AddressType,
        pub(crate) destination: AddressType,
        pub(crate) source_len: i32,
        pub(crate) dest_len: i32,
    }

    impl VTMatchInfo for FakeMatchInfo {
        fn get_similarity_score(&self) -> VtScore {
            VtScore::new(0.75)
        }
        fn get_confidence_score(&self) -> VtScore {
            VtScore::new(0.5)
        }
        fn get_source_length(&self) -> i32 {
            self.source_len
        }
        fn get_destination_length(&self) -> i32 {
            self.dest_len
        }
        fn get_source_address(&self) -> AddressType {
            self.source.clone()
        }
        fn get_destination_address(&self) -> AddressType {
            self.destination.clone()
        }
        fn get_association_type(
            &self,
        ) -> crate::feature::vt::api::main::vt_association_type::VtAssociationType {
            crate::feature::vt::api::main::vt_association_type::VtAssociationType::Function
        }
        fn get_tag(&self) -> VtMatchTag {
            VtMatchTag::Untagged
        }
    }

    /// The name of the `MatchTable` a match set with the given id owns (Java: `TABLE_NAME + id`).
    pub(crate) fn match_table_name(id: i64) -> String {
        VTMatchTableDBAdapterBase::table_name(id)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::feature::vt::api::main::db::vt_match_table_db_adapter::ColumnDescription as MatchColumn;
    use crate::feature::vt::api::main::vt_score::VtScore;

    fn fixture() -> (DBHandle, Arc<MockSession>, VTMatchSetDB) {
        let mut db_handle = DBHandle::new().unwrap();
        let session = new_session_with_manager(&mut db_handle);
        let match_set =
            new_match_set(&mut db_handle, session.clone() as Arc<dyn VTSessionDB>, 7);
        (db_handle, session, match_set)
    }

    fn info(session: &MockSession, source: i64, destination: i64) -> FakeMatchInfo {
        FakeMatchInfo {
            source: session.address(source),
            destination: session.address(destination),
            source_len: 10,
            dest_len: 20,
        }
    }

    /// Java: `getID()` is the match set record's key, and the record's correlator columns are
    /// surfaced verbatim.
    #[test]
    fn record_columns_are_surfaced() {
        let (_db, _session, match_set) = fixture();

        assert_eq!(match_set.get_id(), 7);
        assert_eq!(match_set.get_program_correlator_name(), Some("Mock Correlator"));
        assert_eq!(
            match_set.get_program_correlator_class_name(),
            Some("ghidra.MockCorrelator")
        );
        assert_eq!(match_set.get_match_count(), 0);
    }

    /// Java: `addMatch` writes a match row (scores, lengths and association key) and reports
    /// `VTEvent.MATCH_ADDED`; `getMatchCount`/`getMatches` then see it.
    #[test]
    fn add_match_inserts_a_row_and_fires_match_added() {
        let (_db, session, match_set) = fixture();

        let added = match_set
            .add_match(&info(&session, 0x1000, 0x2000))
            .expect("match should be added");

        assert_eq!(match_set.get_match_count(), 1);
        assert_eq!(*session.added.lock().unwrap(), vec![added.get_key()]);

        let record = added.get_record();
        assert_eq!(
            record.get_string(MatchColumn::SimilarityScoreCol.column()),
            Some(VtScore::new(0.75).to_storage_string().as_str())
        );
        assert_eq!(record.get_int(MatchColumn::SourceLengthCol.column()), Some(10));
        assert_eq!(record.get_int(MatchColumn::DestinationLengthCol.column()), Some(20));
        // Untagged: Java's getOrCreateMatchTagDB returns null, which the adapter stores as -1.
        assert_eq!(added.get_tag_key(), -1);

        let matches = match_set.get_matches();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_key(), added.get_key());
    }

    /// Java: `getMatches()` returns the *same* cached `VTMatchDB` instance across calls -- that is
    /// the whole point of the `DbCache<VTMatchDB>`.
    #[test]
    fn get_matches_returns_cached_instances() {
        let (_db, session, match_set) = fixture();
        let added = match_set.add_match(&info(&session, 0x1000, 0x2000)).unwrap();

        let first = match_set.get_matches();
        let second = match_set.get_matches();

        assert!(Arc::ptr_eq(&first[0], &added));
        assert!(Arc::ptr_eq(&first[0], &second[0]));
    }

    /// Java: `getMatches(VTAssociation)` filters by the association's key, and
    /// `getMatches(Address, Address)` resolves the pair first -- an unknown pair yields nothing.
    #[test]
    fn get_matches_filters_by_association_and_addresses() {
        let (_db, session, match_set) = fixture();
        match_set.add_match(&info(&session, 0x1000, 0x2000)).unwrap();
        match_set.add_match(&info(&session, 0x1100, 0x2100)).unwrap();

        let association = session
            .get_association_manager_dbm()
            .get_existing_association_db(&session.address(0x1000), &session.address(0x2000))
            .expect("association should exist");

        assert_eq!(match_set.get_matches_for_association(&association).len(), 1);
        assert_eq!(
            match_set
                .get_matches_for_addresses(&session.address(0x1000), &session.address(0x2000))
                .len(),
            1
        );
        assert!(match_set
            .get_matches_for_addresses(&session.address(0xdead), &session.address(0xbeef))
            .is_empty());
    }

    /// Java: `deleteMatch` drops the row, evicts the cache entry, and reports
    /// `VTEvent.MATCH_DELETED` carrying a `DeletedMatch` with the association's addresses.
    #[test]
    fn delete_match_removes_the_row_and_fires_match_deleted() {
        let (_db, session, match_set) = fixture();
        let added = match_set.add_match(&info(&session, 0x1000, 0x2000)).unwrap();

        match_set.delete_match(&added);

        assert_eq!(match_set.get_match_count(), 0);
        assert!(match_set.get_matches().is_empty());
        assert_eq!(*session.deleted.lock().unwrap(), vec![(added.get_key(), 0x1000)]);
        assert!(!added.is_valid());
    }

    /// Java: `removeMatch` refuses to delete the last match of an ACCEPTED association, and
    /// otherwise delegates to `deleteMatch`.
    #[test]
    fn remove_match_refuses_last_match_of_accepted_association() {
        let (_db, session, match_set) = fixture();
        let added = match_set.add_match(&info(&session, 0x1000, 0x2000)).unwrap();

        let manager = session.get_association_manager_dbm();
        let association = manager
            .get_existing_association_db(&session.address(0x1000), &session.address(0x2000))
            .unwrap();
        manager.set_association_accepted(&association).expect("accept");

        // The session reports exactly one match for this association.
        session
            .matches_by_association
            .lock()
            .unwrap()
            .insert(association.get_key(), 1);

        assert!(!match_set.remove_match(&added));
        assert_eq!(match_set.get_match_count(), 1);

        // With a second match sharing the association, removal is allowed again.
        session
            .matches_by_association
            .lock()
            .unwrap()
            .insert(association.get_key(), 2);
        assert!(match_set.remove_match(&added));
        assert_eq!(match_set.get_match_count(), 0);
    }

    /// Java: `getOptions()` falls back to `new ToolOptions("EMPTY_OPTIONS_NAME")` when the
    /// `OPTIONS_COL` is null, and otherwise deserializes the stored XML.
    #[test]
    fn options_fall_back_to_the_empty_options_name() {
        let (_db, _session, match_set) = fixture();
        assert_eq!(match_set.get_options().get_name(), EMPTY_OPTIONS_NAME);

        let stored = StoredToolOptions {
            name: "Mock Correlator".to_string(),
            xml: Some("<OPTIONS/>".to_string()),
        };
        assert_eq!(stored.get_name(), "Mock Correlator");
        assert_eq!(stored.xml(), Some("<OPTIONS/>"));
    }

    /// Java: `getProgramCorrelatorInfo()` builds a `ProgramCorrelatorInfoImpl` over this match set
    /// and caches it, so repeated calls hand back the same object.
    #[test]
    fn program_correlator_info_reflects_the_match_set_and_is_cached() {
        let (_db, _session, match_set) = fixture();

        let first = match_set.get_program_correlator_info();
        assert_eq!(first.get_name(), "Mock Correlator");
        assert_eq!(first.get_correlator_class_name(), "ghidra.MockCorrelator");
        assert_eq!(first.get_source_address_set().min_address().unwrap().offset(), 0x1000);
        assert_eq!(first.get_source_address_set().max_address().unwrap().offset(), 0x1fff);
        assert_eq!(first.get_destination_address_set().min_address().unwrap().offset(), 0x2000);

        let second = match_set.get_program_correlator_info();
        assert!(std::ptr::eq(first, second));
    }

    /// Java: `toString()` renders as `"Match Set <id> - <count> matches [Correlator=<name>]"`.
    #[test]
    fn display_matches_java_tostring() {
        let (_db, session, match_set) = fixture();
        match_set.add_match(&info(&session, 0x1000, 0x2000)).unwrap();

        assert_eq!(
            match_set.to_string(),
            "Match Set 7 - 1 matches [Correlator=Mock Correlator]"
        );
    }

    /// Java: `invalidateCache()` marks every cached match stale; a subsequent lookup revives it
    /// from its record rather than handing back a stale object.
    #[test]
    fn invalidate_cache_marks_matches_stale() {
        let (_db, session, match_set) = fixture();
        let added = match_set.add_match(&info(&session, 0x1000, 0x2000)).unwrap();
        assert!(added.is_valid());

        match_set.invalidate_cache();
        assert!(!added.is_valid());

        let matches = match_set.get_matches();
        assert!(Arc::ptr_eq(&matches[0], &added));
        assert!(added.is_valid());
    }

    /// Java: `getMatchRecord(long)` reads a single row back by key; a missing key is `null`.
    #[test]
    fn get_match_record_reads_a_row_by_key() {
        let (_db, session, match_set) = fixture();
        let added = match_set.add_match(&info(&session, 0x1000, 0x2000)).unwrap();

        let record = match_set.get_match_record(added.get_key()).expect("record");
        assert_eq!(record.get_key().get_long_value(), added.get_key());
        assert!(match_set.get_match_record(9999).is_none());
    }

    /// The match table this set owns is named after its id (Java: `TABLE_NAME + tableID`), which is
    /// what makes two match sets in one session independent.
    #[test]
    fn each_match_set_owns_its_own_match_table() {
        let mut db_handle = DBHandle::new().unwrap();
        let session = new_session_with_manager(&mut db_handle);
        let first = new_match_set(&mut db_handle, session.clone() as Arc<dyn VTSessionDB>, 1);
        let second = new_match_set(&mut db_handle, session.clone() as Arc<dyn VTSessionDB>, 2);

        first.add_match(&info(&session, 0x1000, 0x2000)).unwrap();

        assert_eq!(first.get_match_count(), 1);
        assert_eq!(second.get_match_count(), 0);
        assert_eq!(match_table_name(2), "MatchTable2");
    }
}

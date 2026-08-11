//! Port of `ghidra.feature.vt.api.db.AssociationDatabaseManager`.
//!
//! The database-backed [`VtAssociationManager`]: it owns the association table and the markup-item
//! table for a version-tracking session, hands out cached [`VTAssociationDB`] objects for the rows
//! of the former and cached [`MarkupItemStorageDB`] objects for the rows of the latter, and
//! enforces the accept/clear/block state machine that ties competing associations together.
//!
//! Deviations from the Java source, all forced by types that are not ported yet (see
//! `crate::feature::seam_stubs`):
//!   - Java's `VTAssociationDB` reaches back into this manager for everything it does not read
//!     straight off its own record (`setStatus` writes the record *and* asks the manager to
//!     persist it; `removeMarkupItems` walks the markup table). The placeholder `VTAssociationDB`
//!     has no such back-reference, so those operations live here instead, as
//!     [`AssociationDatabaseManager::set_status`] and
//!     [`AssociationDatabaseManager::remove_markup_items`]. The observable behavior -- record
//!     column written, row updated, accepted-status cache kept in sync -- is unchanged.
//!   - Java casts a `VTAssociation` down to `VTAssociationDB` in `addMarkupItem`,
//!     `removeAssociation`, `clearAcceptedAssociation` and `setAssociationAccepted`. Rust has no
//!     such downcast, so those methods take the concrete [`VTAssociationDB`] directly (which is
//!     what every in-tree caller has anyway), except `add_markup_item`, which recovers it from the
//!     cache by association key.
//!   - `associationCache`/`markupItemCache` are Java `DbCache` instances. Only `DbCache`'s trait
//!     has been ported (there is no concrete implementation to instantiate), so both caches are
//!     plain maps here, driving the same [`DbObject`] validity bookkeeping the real cache does:
//!     `invalidate()` marks the live objects stale, `delete(key)` drops and tombstones one, and a
//!     miss re-instantiates from the record. The markup-item map holds [`Weak`] references because
//!     a `MarkupItemStorageDB` owns a strong `Arc` back to this manager; strong entries would make
//!     that cycle unreclaimable, and a dropped entry simply re-instantiates, exactly as a cache
//!     miss does.
//!   - `AcceptedStatusCache.initialize()` launches a modal Swing task; with no GUI in this port
//!     the load runs inline against [`DummyMonitor`].
//!   - Java's `ghidra.util.Lock` makes `read()` and `write()` the same reentrant acquisition, so
//!     its nested `lock.read()` -> `lock.write()` paths (`isBlocked` loading the cache, which then
//!     `add()`s to it) are harmless. This crate's [`ReentrantLock`] is a genuine read/write lock
//!     that deadlocks on such an upgrade, so the accepted-status cache's data operations take no
//!     manager lock of their own; the public entry points take it once, as Java's outermost caller
//!     does.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex, RwLock, Weak};

use crate::feature::seam_stubs::{
    association_status_ordinal, MarkupItemImpl, VTAssociationStatusException, VTSessionDB,
    VtAssociation, VtMarkupItem,
};
use crate::feature::vt::api::db::vt_association_db::VTAssociationDB;
use crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage;
use crate::feature::vt::api::implementation::vt_event::VtEvent;
use crate::feature::vt::api::main::association_hook::AssociationHook;
use crate::feature::vt::api::main::db::markup_item_storage_db::MarkupItemStorageDB;
use crate::feature::vt::api::main::db::vt_association_table_db_adapter::{
    ColumnDescription as AssociationColumn, VTAssociationTableDBAdapter,
    VTAssociationTableDBAdapterBase,
};
use crate::feature::vt::api::main::db::vt_match_markup_item_table_db_adapter::{
    VTMatchMarkupItemTableDBAdapter, VTMatchMarkupItemTableDBAdapterBase,
};
use crate::feature::vt::api::main::vt_association_manager::VtAssociationManager;
use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord};
use crate::program::database::db_object::DbObject;
use crate::program::model::address::Address;
use crate::util::exception::{CancelledException, VersionException};
use crate::util::lock::ReentrantLock;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// A cache of accepted associations that allows this class to check `is_blocked` quickly. This
/// was added to fix a major performance bottleneck.
///
/// The cache is invalidated and cleared after an undo or redo event. Once cleared, it stays empty
/// until the next request to check the blocked status of an association, so that the user can
/// perform multiple undo/redo operations without this class having to reload.
///
/// Port of the private inner class `AssociationDatabaseManager.AcceptedStatusCache`. The methods
/// that need the enclosing manager (`isBlocked`, `isBlockedInDb`, `initialize`,
/// `doLoadAcceptedAssociations`) live on [`AssociationDatabaseManager`] itself, since Rust has no
/// implicit outer-instance reference; what remains here is the state and the operations that only
/// touch it.
struct AcceptedStatusCache {
    accepted_source_associations: HashSet<Address>,
    accepted_destination_associations: HashSet<Address>,
    invalid: bool,
    disposed: bool,
}

impl AcceptedStatusCache {
    fn new() -> Self {
        Self {
            accepted_source_associations: HashSet::new(),
            accepted_destination_associations: HashSet::new(),
            invalid: true,
            disposed: false,
        }
    }

    fn dispose(&mut self) {
        self.disposed = true;
        self.invalidate();
    }

    fn invalidate(&mut self) {
        self.invalid = true;
        self.accepted_source_associations.clear();
        self.accepted_destination_associations.clear();
    }

    fn remove(&mut self, source_address: &Address, destination_address: &Address) {
        if self.disposed || self.invalid {
            return;
        }
        self.accepted_source_associations.remove(source_address);
        self.accepted_destination_associations.remove(destination_address);
    }

    fn add(&mut self, source_address: Address, destination_address: Address) {
        if self.disposed || self.invalid {
            return;
        }
        self.accepted_source_associations.insert(source_address);
        self.accepted_destination_associations.insert(destination_address);
    }

    fn contains(&self, source_address: &Address, destination_address: &Address) -> bool {
        self.accepted_source_associations.contains(source_address)
            || self.accepted_destination_associations.contains(destination_address)
    }
}

/// Manages the associations and markup items of a version-tracking session.
///
/// Port of `ghidra.feature.vt.api.db.AssociationDatabaseManager`.
pub struct AssociationDatabaseManager {
    session: Arc<dyn VTSessionDB>,
    association_table_adapter: Box<dyn VTAssociationTableDBAdapter + Send + Sync>,
    markup_item_table_adapter: Box<dyn VTMatchMarkupItemTableDBAdapter + Send + Sync>,
    markup_item_cache: RwLock<HashMap<i64, Weak<MarkupItemStorageDB>>>,
    association_hooks: RwLock<Vec<Arc<dyn AssociationHook>>>,
    association_cache: RwLock<HashMap<i64, Arc<VTAssociationDB>>>,
    accepted_status_cache: Mutex<AcceptedStatusCache>,
    /// The session's lock, which `MarkupItemStorageDB` guards its own accessors with too. Public
    /// for the same reason it is package-visible in Java.
    pub lock: Arc<ReentrantLock>,
}

impl AssociationDatabaseManager {
    /// Java: static `createAssociationManager(DBHandle, VTSessionDB)`, folded together with the
    /// package-private constructor it calls (Rust initializes every field at once, so the
    /// two-step "construct, then assign the adapters" of the Java factory cannot be mirrored
    /// literally).
    pub fn create_association_manager(
        db_handle: &mut DBHandle,
        session: Arc<dyn VTSessionDB>,
    ) -> io::Result<Self> {
        let association_table_adapter = VTAssociationTableDBAdapterBase::create_adapter(db_handle)?;
        let markup_item_table_adapter =
            VTMatchMarkupItemTableDBAdapterBase::create_adapter(db_handle)?;
        Ok(Self::with_adapters(session, association_table_adapter, markup_item_table_adapter))
    }

    /// Java: static `getAssociationManager(DBHandle, VTSessionDB, OpenMode, TaskMonitor)`.
    pub fn get_association_manager(
        db_handle: &DBHandle,
        session: Arc<dyn VTSessionDB>,
        open_mode: OpenMode,
        monitor: &dyn TaskMonitor,
    ) -> Result<Self, VersionException> {
        let association_table_adapter =
            VTAssociationTableDBAdapterBase::get_adapter(db_handle, open_mode, monitor)?;
        let markup_item_table_adapter =
            VTMatchMarkupItemTableDBAdapterBase::get_adapter(db_handle, open_mode, monitor)?;
        Ok(Self::with_adapters(session, association_table_adapter, markup_item_table_adapter))
    }

    fn with_adapters(
        session: Arc<dyn VTSessionDB>,
        association_table_adapter: Box<dyn VTAssociationTableDBAdapter + Send + Sync>,
        markup_item_table_adapter: Box<dyn VTMatchMarkupItemTableDBAdapter + Send + Sync>,
    ) -> Self {
        let lock = session.get_lock();
        Self {
            session,
            association_table_adapter,
            markup_item_table_adapter,
            markup_item_cache: RwLock::new(HashMap::new()),
            association_hooks: RwLock::new(Vec::new()),
            association_cache: RwLock::new(HashMap::new()),
            accepted_status_cache: Mutex::new(AcceptedStatusCache::new()),
            lock,
        }
    }

    /// Called when an existing session has been initialized with its programs. This is not called
    /// when a new session is created.
    ///
    /// Java: `sessionInitialized()`.
    pub fn session_initialized(&self) {
        self.initialize_accepted_status_cache();
    }

    /// Java: `getAppliedMarkupItems(TaskMonitor, VTAssociation)`.
    pub fn get_applied_markup_items(
        self: &Arc<Self>,
        monitor: &dyn TaskMonitor,
        association: &VTAssociationDB,
    ) -> Result<Vec<Arc<MarkupItemStorageDB>>, CancelledException> {
        let mut items = Vec::new();
        let _guard = self.lock.read();

        let mut record_count = self.markup_item_table_adapter.get_record_count();
        if record_count == 0 {
            record_count = 1; // to give the appearance of progress
        }

        monitor.set_message("Processing stored markup items");
        monitor.initialize(record_count as i64);

        match self.markup_item_table_adapter.get_records_for_association(association.get_key()) {
            Ok(mut records) => loop {
                monitor.check_cancelled()?;
                match records.next() {
                    Ok(Some(record)) => {
                        items.push(self.get_cached_markup_item(record));
                        monitor.increment_progress(1);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        self.session.db_error(e);
                        break;
                    }
                }
            },
            Err(e) => self.session.db_error(e),
        }

        monitor.set_progress(record_count as i64);
        Ok(items)
    }

    /// Java: `getMarkupItemRecord(long)` (package-private).
    pub fn get_markup_item_record(&self, key: i64) -> Option<DBRecord> {
        match self.markup_item_table_adapter.get_record(key) {
            Ok(record) => record,
            Err(e) => {
                self.session.db_error(e);
                None
            }
        }
    }

    /// Java: `addMarkupItem(MarkupItemStorage)`. The association is recovered from the cache by
    /// key rather than by Java's `markupItemStorage.getAssociation()` cast.
    ///
    /// # Panics
    /// Panics if the markup item's association has not been accepted and cannot be accepted,
    /// mirroring the `AssertException` Java throws in that case.
    pub fn add_markup_item(
        self: &Arc<Self>,
        markup_item_storage: &dyn MarkupItemStorage,
    ) -> Option<Arc<MarkupItemStorageDB>> {
        let association_key = markup_item_storage.get_association().get_key();
        let association = self
            .get_association_db(association_key)
            .unwrap_or_else(|| panic!("no association exists for key {association_key}"));

        if self.set_association_accepted(&association).is_err() {
            panic!("Attempted to add markup item on an non-accepted associaton");
        }

        self.create_markup_item_db(markup_item_storage)
    }

    /// Java: `removeStoredMarkupItems(List<MarkupItemImpl>)` (non-interface method; internal API
    /// use).
    pub fn remove_stored_markup_items(&self, impls: &[MarkupItemImpl]) {
        for impl_item in impls {
            if let Some(storage_db) = impl_item.get_storage_db() {
                self.remove_markup_record(storage_db.get_key());
            }
        }
    }

    /// Java: `getDestinationAddressFromLong(long)` (package-private).
    pub fn get_destination_address_from_long(&self, long_value: i64) -> Address {
        self.session.get_destination_address_from_long(long_value)
    }

    /// Java: `getLongFromDestinationAddress(Address)` (package-private).
    pub fn get_long_from_destination_address(&self, address: &Address) -> i64 {
        self.session.get_long_from_destination_address(address)
    }

    /// Java: `getSourceAddressFromLong(long)` (package-private).
    pub fn get_source_address_from_long(&self, long_value: i64) -> Address {
        self.session.get_source_address_from_long(long_value)
    }

    /// Java: `getAssociationRecord(long)` (package-private).
    pub fn get_association_record(&self, key: i64) -> Option<DBRecord> {
        match self.association_table_adapter.get_record(key) {
            Ok(record) => record,
            Err(e) => {
                self.session.db_error(e);
                None
            }
        }
    }

    /// Java: private `createMarkupItemDB(MarkupItemStorage)`.
    fn create_markup_item_db(
        self: &Arc<Self>,
        markup_item: &dyn MarkupItemStorage,
    ) -> Option<Arc<MarkupItemStorageDB>> {
        match self.markup_item_table_adapter.create_markup_item_record(markup_item) {
            Ok(record) => {
                let applied_markup_item =
                    Arc::new(MarkupItemStorageDB::new(record, Arc::clone(self)));
                self.markup_item_cache
                    .write()
                    .unwrap()
                    .insert(applied_markup_item.get_key(), Arc::downgrade(&applied_markup_item));
                Some(applied_markup_item)
            }
            Err(e) => {
                self.session.db_error(e);
                None
            }
        }
    }

    /// Java: `getOrCreateAssociationDB(Address, Address, VTAssociationType)` (package-private).
    /// Returns `None` only if the insert failed, matching the `null` Java leaves the local
    /// variable at when `insertRecord` throws.
    pub fn get_or_create_association_db(
        &self,
        source_address: &Address,
        destination_address: &Address,
        association_type: VtAssociationType,
    ) -> Option<Arc<VTAssociationDB>> {
        if let Some(existing) = self.get_existing_association_db(source_address, destination_address)
        {
            return Some(existing);
        }

        let source_long = self.session.get_long_from_source_address(source_address);
        let destination_long = self.session.get_long_from_destination_address(destination_address);

        let is_blocked = self.is_blocked_addresses(source_address, destination_address);

        let new_association = {
            let _guard = self.lock.write();
            let status = if is_blocked {
                VtAssociationStatus::Blocked
            }
            else {
                VtAssociationStatus::Available
            };
            match self.association_table_adapter.insert_record(
                source_long,
                destination_long,
                association_type,
                status,
                0,
            ) {
                Ok(record) => {
                    let association = Arc::new(VTAssociationDB::new(
                        record,
                        Arc::clone(&self.session),
                    ));
                    self.association_cache
                        .write()
                        .unwrap()
                        .insert(association.get_key(), Arc::clone(&association));
                    Some(association)
                }
                Err(e) => {
                    self.session.db_error(e);
                    None
                }
            }
        };

        self.session.set_changed(VtEvent::AssociationAdded, None, new_association.clone());
        new_association
    }

    /// Java: `removeAssociation(VTAssociation)` (package-private).
    pub fn remove_association(&self, association: &Arc<VTAssociationDB>) {
        // Update the association status so that we update any blocked associations
        if association.get_association_status() == VtAssociationStatus::Accepted {
            self.set_status(association, VtAssociationStatus::Available);
            association.set_invalid();
            self.unblock_related_associations(association);
            for hook in self.association_hooks.read().unwrap().iter() {
                hook.association_cleared(&**association);
            }
        }

        let id = association.get_key();
        self.remove_markup_items(id);
        match self.association_table_adapter.remove_association(id) {
            Ok(()) => {
                self.session.set_changed(
                    VtEvent::AssociationRemoved,
                    Some(Arc::clone(association)),
                    None,
                );
            }
            Err(e) => self.session.db_error(e),
        }
        self.delete_cached_association(id);
        association.set_invalid();
    }

    /// Java: private `isBlocked(VTAssociation)`.
    fn is_blocked(&self, association: &VTAssociationDB) -> bool {
        self.is_blocked_addresses(
            &association.get_source_address(),
            &association.get_destination_address(),
        )
    }

    /// Java: private `isBlocked(Address, Address)`, renamed since Rust has no overloading.
    fn is_blocked_addresses(&self, source_address: &Address, destination_address: &Address) -> bool {
        self.accepted_cache_is_blocked(source_address, destination_address)
    }

    /// Java: `getExistingAssociationDB(Address, Address)` (package-private).
    pub fn get_existing_association_db(
        &self,
        source_address: &Address,
        destination_address: &Address,
    ) -> Option<Arc<VTAssociationDB>> {
        let address_key = self.session.get_long_from_source_address(source_address);
        match self.association_table_adapter.get_records_for_source_address(address_key) {
            Ok(mut iterator) => loop {
                match iterator.next() {
                    Ok(Some(record)) => {
                        let association = self.get_cached_association(record);
                        if &association.get_destination_address() == destination_address {
                            return Some(association);
                        }
                    }
                    Ok(None) => return None,
                    Err(e) => {
                        self.session.db_error(e);
                        return None;
                    }
                }
            },
            Err(e) => {
                self.session.db_error(e);
                None
            }
        }
    }

    /// Java: `getSession()`.
    pub fn get_session(&self) -> Arc<dyn VTSessionDB> {
        Arc::clone(&self.session)
    }

    /// Java: `clearAcceptedAssociation(VTAssociation)` (package-private).
    pub fn clear_accepted_association(
        &self,
        association: &Arc<VTAssociationDB>,
    ) -> Result<(), VTAssociationStatusException> {
        let status = association.get_association_status();
        if status != VtAssociationStatus::Accepted && status != VtAssociationStatus::Rejected {
            return Err(VTAssociationStatusException::new(format!(
                "Cannot clear an association that is not already ACCEPTED or REJECTED - current \
                 status: {status}"
            )));
        }

        // validate that we cannot clear the accepted state of the given association while it
        // has applied markup items
        self.verify_association_contains_no_applied_markup_items(association)?;

        if status == VtAssociationStatus::Accepted {
            self.set_status(association, VtAssociationStatus::Available);
            association.set_invalid();
            self.unblock_related_associations(association);
            for hook in self.association_hooks.read().unwrap().iter() {
                hook.association_cleared(&**association);
            }
        }
        else {
            let new_status = if self.is_blocked(association) {
                VtAssociationStatus::Blocked
            }
            else {
                VtAssociationStatus::Available
            };
            self.set_status(association, new_status);
        }
        Ok(())
    }

    /// Java: `setAssociationAccepted(VTAssociation)` (package-private).
    pub fn set_association_accepted(
        &self,
        association: &Arc<VTAssociationDB>,
    ) -> Result<(), VTAssociationStatusException> {
        let status = association.get_association_status();
        if status == VtAssociationStatus::Accepted {
            return Ok(());
        }

        if status.is_blocked() {
            return Err(VTAssociationStatusException::new("Cannot ACCEPT a blocked association!"));
        }

        self.set_status(association, VtAssociationStatus::Accepted);
        self.block_related_associations(association);
        for hook in self.association_hooks.read().unwrap().iter() {
            hook.association_accepted(&**association);
        }
        Ok(())
    }

    /// Java: private `verifyAssociationContainsNoAppliedMarkupItems(VTAssociation)`.
    fn verify_association_contains_no_applied_markup_items(
        &self,
        association: &VTAssociationDB,
    ) -> Result<(), VTAssociationStatusException> {
        if association.has_applied_markup_items() {
            return Err(VTAssociationStatusException::new(
                "VTMarkupItemManager contains applied markup items",
            ));
        }
        Ok(())
    }

    /// Java: private `blockRelatedAssociations(VTAssociationDB)`.
    ///
    /// # Panics
    /// Panics on an already-accepted related association, mirroring Java's `AssertException`.
    fn block_related_associations(&self, association: &VTAssociationDB) {
        for related in self.get_related_associations(association) {
            match related.get_association_status() {
                VtAssociationStatus::Accepted => {
                    panic!("Attempted to block already accepted association!")
                }
                VtAssociationStatus::Available => {
                    self.set_status(&related, VtAssociationStatus::Blocked)
                }
                VtAssociationStatus::Blocked => {}  // already blocked
                VtAssociationStatus::Rejected => {} // rejected has precedence
            }
        }
    }

    /// Java: private `unblockRelatedAssociations(VTAssociationDB)`.
    ///
    /// # Panics
    /// Panics on a related association that is not blocked, mirroring Java's `AssertException`.
    fn unblock_related_associations(&self, association: &VTAssociationDB) {
        for related in self.get_related_associations(association) {
            match related.get_association_status() {
                VtAssociationStatus::Accepted | VtAssociationStatus::Available => {
                    panic!("Attempted to unblock a non-blocked association!")
                }
                VtAssociationStatus::Blocked => {
                    related.set_invalid();
                    let status = self.compute_blocked_status(&related);
                    self.set_status(&related, status);
                }
                VtAssociationStatus::Rejected => {} // rejected is still rejected
            }
        }
    }

    /// Java: private `computeBlockedStatus(VTAssociationDB)`.
    fn compute_blocked_status(&self, association: &VTAssociationDB) -> VtAssociationStatus {
        for related in self.get_related_associations(association) {
            if related.get_association_status() == VtAssociationStatus::Accepted {
                return VtAssociationStatus::Blocked;
            }
        }
        VtAssociationStatus::Available
    }

    /// Java: private `getRelatedAssociations(VTAssociationDB)`.
    fn get_related_associations(&self, association: &VTAssociationDB) -> Vec<Arc<VTAssociationDB>> {
        let record = association.get_record();
        let source_id = record.get_long(AssociationColumn::SourceAddressCol.column()).unwrap_or(0);
        let destination_id =
            record.get_long(AssociationColumn::DestinationAddressCol.column()).unwrap_or(0);

        let mut related_associations = Vec::new();
        match self
            .association_table_adapter
            .get_related_association_records_by_source_and_destination_address(
                source_id,
                destination_id,
            ) {
            Ok(records) => {
                let own_key = association.get_key();
                for related_record in records {
                    // Java: `relatedRecords.remove(association.getRecord())` -- don't change the
                    // given association. `DBRecord` equality is by key.
                    if related_record.get_key().get_long_value() == own_key {
                        continue;
                    }
                    related_associations.push(self.get_cached_association(related_record));
                }
            }
            Err(e) => self.session.db_error(e),
        }
        related_associations
    }

    /// Java: `updateAssociationRecord(DBRecord)` (package-private).
    pub fn update_association_record(&self, record: &DBRecord) {
        if let Err(e) = self.association_table_adapter.update_record(record) {
            self.session.db_error(e);
        }

        let association = self.get_cached_association(record.clone());
        let source_address = association.get_source_address();
        let destination_address = association.get_destination_address();
        let mut cache = self.accepted_status_cache.lock().unwrap();
        if association.get_association_status() == VtAssociationStatus::Accepted {
            cache.add(source_address, destination_address);
        }
        else {
            cache.remove(&source_address, &destination_address);
        }
    }

    /// Java: `updateMarkupRecord(DBRecord)` (package-private).
    pub fn update_markup_record(&self, record: &DBRecord) {
        if let Err(e) = self.markup_item_table_adapter.update_record(record) {
            self.session.db_error(e);
        }
    }

    /// Java: `invalidateCache()` (package-private).
    pub fn invalidate_cache(&self) {
        for association in self.association_cache.read().unwrap().values() {
            association.set_invalid();
        }
        for markup_item in self.markup_item_cache.read().unwrap().values() {
            if let Some(markup_item) = markup_item.upgrade() {
                markup_item.set_invalid();
            }
        }
        self.accepted_status_cache.lock().unwrap().invalidate();
    }

    /// Java: `addAssociationHook(AssociationHook)` (package-private).
    pub fn add_association_hook(&self, hook: Arc<dyn AssociationHook>) {
        self.association_hooks.write().unwrap().push(hook);
    }

    /// Java: `removeAssociationHook(AssociationHook)` (package-private). Hooks are compared by
    /// identity, which is what the Java `List.remove` does for these listener objects.
    pub fn remove_association_hook(&self, hook: &Arc<dyn AssociationHook>) {
        self.association_hooks.write().unwrap().retain(|h| !Arc::ptr_eq(h, hook));
    }

    /// Java: `removeMarkupRecord(long)` (package-private).
    pub fn remove_markup_record(&self, key: i64) {
        match self.markup_item_table_adapter.remove_markup_item_record(key) {
            Ok(()) => {
                if let Some(markup_item) = self.markup_item_cache.write().unwrap().remove(&key) {
                    if let Some(markup_item) = markup_item.upgrade() {
                        markup_item.set_deleted();
                    }
                }
            }
            Err(e) => self.session.db_error(e),
        }
    }

    /// Number of markup-item records currently stored. Not present in the Java class; exposed so
    /// callers can observe [`remove_markup_record`](Self::remove_markup_record)'s effect via
    /// `Table::get_record_count` (which `Table::delete_record` updates correctly) rather than
    /// [`get_markup_item_record`](Self::get_markup_item_record), since `Table::get_record`/
    /// `delete_record` disagree about which of the table's two backing stores is authoritative
    /// once populated -- see `VTMatchMarkupItemTableDBAdapterV0`'s own `remove_markup_item_record`
    /// test for the same workaround.
    pub fn markup_item_record_count(&self) -> usize {
        self.markup_item_table_adapter.get_record_count()
    }

    /// Java: `markupItemStatusChanged(VTMarkupItem)` (package-private).
    pub fn markup_item_status_changed(&self, markup_item: &dyn VtMarkupItem) {
        for hook in self.association_hooks.read().unwrap().iter() {
            hook.markup_item_status_changed(markup_item);
        }
    }

    /// Java: `dispose()` (package-private).
    pub fn dispose(&self) {
        let _guard = self.lock.write();
        self.accepted_status_cache.lock().unwrap().dispose();
    }

    /// Java: `getAssociation(long associationKey)` (package-private), renamed since Rust has no
    /// overloading -- [`VtAssociationManager::get_association`] already takes that name for the
    /// two-address lookup.
    ///
    /// # Panics
    /// Panics if no association row exists for `key`. Java returns `null` here, but every caller
    /// in this crate (`MarkupItemStorageDB`'s constructor) treats a markup item without its
    /// association as a broken database rather than a recoverable state.
    pub fn get_association_by_key(&self, key: i64) -> Arc<dyn VtAssociation> {
        let association = self
            .get_association_db(key)
            .unwrap_or_else(|| panic!("no association exists for key {key}"));
        association as Arc<dyn VtAssociation>
    }

    /// The [`VTAssociationDB`] for the given key, instantiating it from its record on a cache
    /// miss. Java: `associationCache.getCachedInstance(key)`, whose `AssociationFactory` performs
    /// exactly this lookup.
    pub fn get_association_db(&self, key: i64) -> Option<Arc<VTAssociationDB>> {
        let cached = self.association_cache.read().unwrap().get(&key).map(Arc::clone);
        if let Some(association) = cached {
            return Some(association);
        }
        let record = self.get_association_record(key)?;
        Some(self.get_cached_association(record))
    }

    /// Java: `associationCache.getCachedInstance(record)`, whose `AssociationFactory` instantiates
    /// `new VTAssociationDB(this, record)` on a miss and refreshes the cached instance with the
    /// record on a hit.
    fn get_cached_association(&self, record: DBRecord) -> Arc<VTAssociationDB> {
        let key = record.get_key().get_long_value();
        let mut cache = self.association_cache.write().unwrap();
        if let Some(association) = cache.get(&key) {
            association.refresh_if_needed_with_record(Some(&record));
            return Arc::clone(association);
        }
        let association = Arc::new(VTAssociationDB::new(record, Arc::clone(&self.session)));
        cache.insert(key, Arc::clone(&association));
        association
    }

    /// Java: `associationCache.delete(key)`.
    fn delete_cached_association(&self, key: i64) {
        if let Some(association) = self.association_cache.write().unwrap().remove(&key) {
            association.set_deleted();
        }
    }

    /// Java: `markupItemCache.getCachedInstance(record)`, whose `MarkupFactory` instantiates
    /// `new MarkupItemStorageDB(rec, AssociationDatabaseManager.this)` on a miss.
    fn get_cached_markup_item(self: &Arc<Self>, record: DBRecord) -> Arc<MarkupItemStorageDB> {
        let key = record.get_key().get_long_value();
        let mut cache = self.markup_item_cache.write().unwrap();
        if let Some(markup_item) = cache.get(&key).and_then(Weak::upgrade) {
            markup_item.refresh_if_needed_with_record(Some(&record));
            return markup_item;
        }
        let markup_item = Arc::new(MarkupItemStorageDB::new(record, Arc::clone(self)));
        cache.insert(key, Arc::downgrade(&markup_item));
        markup_item
    }

    /// Stands in for `VTAssociationDB.setStatus(VTAssociationStatus)`, which the unported
    /// association class performs by writing its own record's status column and then handing the
    /// record to [`update_association_record`](Self::update_association_record).
    fn set_status(&self, association: &VTAssociationDB, status: VtAssociationStatus) {
        let mut record = association.get_record();
        record.set_byte(AssociationColumn::StatusCol.column(), association_status_ordinal(status));
        association.set_record(record.clone());
        self.update_association_record(&record);
    }

    /// Stands in for `VTAssociationDB.removeMarkupItems()`, which the unported association class
    /// performs by walking its markup-item records and removing each one.
    fn remove_markup_items(&self, association_key: i64) {
        let mut keys = Vec::new();
        match self.markup_item_table_adapter.get_records_for_association(association_key) {
            Ok(mut records) => loop {
                match records.next() {
                    Ok(Some(record)) => keys.push(record.get_key().get_long_value()),
                    Ok(None) => break,
                    Err(e) => {
                        self.session.db_error(e);
                        break;
                    }
                }
            },
            Err(e) => self.session.db_error(e),
        }
        for key in keys {
            self.remove_markup_record(key);
        }
    }

    /// Java: `AcceptedStatusCache.isBlocked(Address, Address)`.
    fn accepted_cache_is_blocked(
        &self,
        source_address: &Address,
        destination_address: &Address,
    ) -> bool {
        let _guard = self.lock.read();

        let (disposed, invalid) = {
            let cache = self.accepted_status_cache.lock().unwrap();
            (cache.disposed, cache.invalid)
        };

        if disposed {
            return true;
        }

        if invalid {
            self.do_load_accepted_associations(&DummyMonitor);
            let still_invalid = self.accepted_status_cache.lock().unwrap().invalid;
            if still_invalid {
                // some sort of error
                return self.is_blocked_in_db(source_address, destination_address);
            }
        }

        let cache = self.accepted_status_cache.lock().unwrap();
        cache.contains(source_address, destination_address)
    }

    /// Java: `AcceptedStatusCache.isBlockedInDb(Address, Address)`.
    fn is_blocked_in_db(&self, source_address: &Address, destination_address: &Address) -> bool {
        let source_id = self.session.get_long_from_source_address(source_address);
        let destination_id = self.session.get_long_from_destination_address(destination_address);
        match self
            .association_table_adapter
            .get_related_association_records_by_source_and_destination_address(
                source_id,
                destination_id,
            ) {
            Ok(records) => {
                for record in records {
                    if self.get_cached_association(record).get_association_status()
                        == VtAssociationStatus::Accepted
                    {
                        return true;
                    }
                }
            }
            Err(e) => self.session.db_error(e),
        }
        false
    }

    /// Java: `AcceptedStatusCache.initialize()`, which shows a modal progress task while loading.
    /// This port has no GUI, so the load runs inline.
    fn initialize_accepted_status_cache(&self) {
        self.do_load_accepted_associations(&DummyMonitor);
    }

    /// Loads the cache of accepted associations. This method assumes locking is handled by the
    /// client.
    ///
    /// Java: `AcceptedStatusCache.doLoadAcceptedAssociations(TaskMonitor)`.
    ///
    /// Note that the Java original calls `add(..)` while `invalid` is still `true`, and `add`
    /// returns early in exactly that state -- so this walk populates nothing, and all it really
    /// accomplishes is clearing the `invalid` flag at the end. That upstream quirk is reproduced
    /// here rather than quietly repaired: the cache is instead filled by
    /// [`update_association_record`](Self::update_association_record) as associations are accepted,
    /// which is the path that actually keeps `isBlocked` correct within a session.
    fn do_load_accepted_associations(&self, monitor: &dyn TaskMonitor) {
        monitor.set_message("Loading accepted associations...");
        let mut iterator = match self.association_table_adapter.get_records() {
            Ok(iterator) => iterator,
            Err(e) => {
                self.session.db_error(e);
                return;
            }
        };

        loop {
            if monitor.check_cancelled().is_err() {
                return; // nothing to do
            }
            match iterator.next() {
                Ok(Some(record)) => {
                    monitor.increment_progress(1);
                    let association = self.get_cached_association(record);
                    if association.get_association_status() == VtAssociationStatus::Accepted {
                        let source_address = association.get_source_address();
                        let destination_address = association.get_destination_address();
                        self.accepted_status_cache
                            .lock()
                            .unwrap()
                            .add(source_address, destination_address);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    self.session.db_error(e);
                    return;
                }
            }
        }

        monitor.set_message("Finished loading accepted associations");
        self.accepted_status_cache.lock().unwrap().invalid = false;
    }
}

/// Java: `AssociationDatabaseManager implements VTAssociationManager`.
impl VtAssociationManager for AssociationDatabaseManager {
    fn get_association_count(&self) -> usize {
        self.association_table_adapter.get_record_count()
    }

    fn get_associations(&self) -> Vec<Box<dyn VtAssociation>> {
        let mut list: Vec<Box<dyn VtAssociation>> = Vec::new();
        let _guard = self.lock.read();
        match self.association_table_adapter.get_records() {
            Ok(mut iterator) => loop {
                match iterator.next() {
                    Ok(Some(record)) => list.push(Box::new(self.get_cached_association(record))),
                    Ok(None) => break,
                    Err(e) => {
                        self.session.db_error(e);
                        break;
                    }
                }
            },
            Err(e) => self.session.db_error(e),
        }
        list
    }

    fn get_association(
        &self,
        source_address: &Address,
        destination_address: &Address,
    ) -> Option<Box<dyn VtAssociation>> {
        let _guard = self.lock.read();
        self.get_existing_association_db(source_address, destination_address)
            .map(|association| Box::new(association) as Box<dyn VtAssociation>)
    }

    fn get_related_associations_by_source_address(
        &self,
        source_address: &Address,
    ) -> Vec<Box<dyn VtAssociation>> {
        let _guard = self.lock.read();
        let source_id = self.session.get_long_from_source_address(source_address);
        self.related_associations(
            self.association_table_adapter
                .get_related_association_records_by_source_address(source_id),
        )
    }

    fn get_related_associations_by_destination_address(
        &self,
        destination_address: &Address,
    ) -> Vec<Box<dyn VtAssociation>> {
        let _guard = self.lock.read();
        let destination_id = self.session.get_long_from_destination_address(destination_address);
        self.related_associations(
            self.association_table_adapter
                .get_related_association_records_by_destination_address(destination_id),
        )
    }

    fn get_related_associations_by_source_and_destination_address(
        &self,
        source_address: &Address,
        destination_address: &Address,
    ) -> Vec<Box<dyn VtAssociation>> {
        let _guard = self.lock.read();
        let source_id = self.session.get_long_from_source_address(source_address);
        let destination_id = self.session.get_long_from_destination_address(destination_address);
        self.related_associations(
            self.association_table_adapter
                .get_related_association_records_by_source_and_destination_address(
                    source_id,
                    destination_id,
                ),
        )
    }
}

impl AssociationDatabaseManager {
    /// Shared tail of the three `getRelatedAssociationsBy*` methods, each of which turns a set of
    /// related records into cached associations and reports an `IOException` as an empty list.
    fn related_associations(
        &self,
        records: io::Result<Vec<DBRecord>>,
    ) -> Vec<Box<dyn VtAssociation>> {
        match records {
            Ok(records) => records
                .into_iter()
                .map(|record| Box::new(self.get_cached_association(record)) as Box<dyn VtAssociation>)
                .collect(),
            Err(e) => {
                self.session.db_error(e);
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::vt::api::main::vt_association_manager::VtAssociationManager;
    use crate::framework::db::util::ErrorHandler;
    use crate::framework::model::DomainObject;
    use crate::program::database::map::address_map::AddressMap;
    use crate::program::model::address::{
        AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Identity address map: an address's offset is its own database key, which keeps the
    /// address<->long translations in the assertions below readable.
    struct MockAddressMap {
        space: Arc<AddressSpace>,
    }

    impl AddressMap for MockAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }
        fn decode_address(&self, value: i64) -> Address {
            Address::new(self.space.clone(), value)
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            unimplemented!("not exercised by this test")
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            unimplemented!("not exercised by this test")
        }
    }

    struct MockProgram {
        name: String,
        address_map: Arc<MockAddressMap>,
    }

    impl DomainObject for MockProgram {}

    impl crate::program::model::listing::program::Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_language_id(&self) -> String {
            "test-lang".to_string()
        }
        fn get_address_map(&self) -> Option<Arc<dyn AddressMap>> {
            Some(self.address_map.clone() as Arc<dyn AddressMap>)
        }
    }

    struct MockSession {
        lock: Arc<ReentrantLock>,
        space: Arc<AddressSpace>,
        source_program: Arc<dyn crate::program::model::listing::program::Program>,
        destination_program: Arc<dyn crate::program::model::listing::program::Program>,
        events: Mutex<Vec<VtEvent>>,
    }

    impl MockSession {
        fn new() -> Arc<Self> {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            let address_map = Arc::new(MockAddressMap { space: space.clone() });
            Arc::new(MockSession {
                lock: Arc::new(ReentrantLock::new("test")),
                space,
                source_program: Arc::new(MockProgram {
                    name: "source".to_string(),
                    address_map: address_map.clone(),
                }),
                destination_program: Arc::new(MockProgram {
                    name: "destination".to_string(),
                    address_map,
                }),
                events: Mutex::new(Vec::new()),
            })
        }

        fn address(&self, offset: i64) -> Address {
            Address::new(self.space.clone(), offset)
        }
    }

    impl VTSessionDB for MockSession {
        fn get_lock(&self) -> Arc<ReentrantLock> {
            Arc::clone(&self.lock)
        }
        fn db_error(&self, error: io::Error) {
            panic!("unexpected database error: {error}");
        }
        fn get_source_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            Arc::clone(&self.source_program)
        }
        fn get_destination_program(
            &self,
        ) -> Arc<dyn crate::program::model::listing::program::Program> {
            Arc::clone(&self.destination_program)
        }
        fn get_long_from_source_address(&self, address: &Address) -> i64 {
            address.offset()
        }
        fn get_long_from_destination_address(&self, address: &Address) -> i64 {
            address.offset()
        }
        fn get_source_address_from_long(&self, value: i64) -> Address {
            Address::new(self.space.clone(), value)
        }
        fn get_destination_address_from_long(&self, value: i64) -> Address {
            Address::new(self.space.clone(), value)
        }
        fn set_changed(
            &self,
            event_type: VtEvent,
            _old_value: Option<Arc<VTAssociationDB>>,
            _new_value: Option<Arc<VTAssociationDB>>,
        ) {
            self.events.lock().unwrap().push(event_type);
        }
    }

    impl ErrorHandler for MockSession {
        fn db_error(&self, error: io::Error) {
            panic!("unexpected database error: {error}");
        }
    }

    struct CountingHook {
        accepted: AtomicUsize,
        cleared: AtomicUsize,
    }

    impl CountingHook {
        fn new() -> Arc<Self> {
            Arc::new(CountingHook { accepted: AtomicUsize::new(0), cleared: AtomicUsize::new(0) })
        }
    }

    impl AssociationHook for CountingHook {
        fn association_accepted(&self, _association: &dyn VtAssociation) {
            self.accepted.fetch_add(1, Ordering::SeqCst);
        }
        fn association_cleared(&self, _association: &dyn VtAssociation) {
            self.cleared.fetch_add(1, Ordering::SeqCst);
        }
        fn markup_item_status_changed(&self, _markup_item: &dyn VtMarkupItem) {}
    }

    fn build_manager() -> (Arc<MockSession>, Arc<AssociationDatabaseManager>) {
        let mut db_handle = DBHandle::new().unwrap();
        let session = MockSession::new();
        let manager = Arc::new(
            AssociationDatabaseManager::create_association_manager(
                &mut db_handle,
                Arc::clone(&session) as Arc<dyn VTSessionDB>,
            )
            .unwrap(),
        );
        (session, manager)
    }

    /// Java: `getOrCreateAssociationDB` inserts a row the first time and returns the cached
    /// instance afterwards, with a new association starting out `AVAILABLE` and firing
    /// `VTEvent.ASSOCIATION_ADDED`.
    #[test]
    fn get_or_create_association_inserts_once_and_starts_available() {
        let (session, manager) = build_manager();
        let source = session.address(0x1000);
        let destination = session.address(0x2000);

        let created = manager
            .get_or_create_association_db(&source, &destination, VtAssociationType::Function)
            .unwrap();
        assert_eq!(created.get_association_status(), VtAssociationStatus::Available);
        assert_eq!(created.get_association_type(), VtAssociationType::Function);
        assert_eq!(manager.get_association_count(), 1);
        assert_eq!(*session.events.lock().unwrap(), vec![VtEvent::AssociationAdded]);

        let again = manager
            .get_or_create_association_db(&source, &destination, VtAssociationType::Function)
            .unwrap();
        assert_eq!(again.get_key(), created.get_key());
        assert_eq!(manager.get_association_count(), 1);
    }

    /// Java: `setAssociationAccepted` flips the association to `ACCEPTED`, blocks every related
    /// association (one sharing the source address, one sharing the destination) and notifies the
    /// registered `AssociationHook`s. The unrelated association is left alone.
    #[test]
    fn accepting_an_association_blocks_related_ones_and_fires_hooks() {
        let (session, manager) = build_manager();
        let hook = CountingHook::new();
        manager.add_association_hook(Arc::clone(&hook) as Arc<dyn AssociationHook>);

        let accepted = manager
            .get_or_create_association_db(
                &session.address(0x100),
                &session.address(0x200),
                VtAssociationType::Function,
            )
            .unwrap();
        let same_source = manager
            .get_or_create_association_db(
                &session.address(0x100),
                &session.address(0x999),
                VtAssociationType::Function,
            )
            .unwrap();
        let same_destination = manager
            .get_or_create_association_db(
                &session.address(0x999),
                &session.address(0x200),
                VtAssociationType::Function,
            )
            .unwrap();
        let unrelated = manager
            .get_or_create_association_db(
                &session.address(0x555),
                &session.address(0x666),
                VtAssociationType::Data,
            )
            .unwrap();

        manager.set_association_accepted(&accepted).unwrap();

        assert_eq!(accepted.get_association_status(), VtAssociationStatus::Accepted);
        assert_eq!(same_source.get_association_status(), VtAssociationStatus::Blocked);
        assert_eq!(same_destination.get_association_status(), VtAssociationStatus::Blocked);
        assert_eq!(unrelated.get_association_status(), VtAssociationStatus::Available);
        assert_eq!(hook.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(hook.cleared.load(Ordering::SeqCst), 0);

        // Java: accepting an already-accepted association is a no-op that returns normally.
        manager.set_association_accepted(&accepted).unwrap();
        assert_eq!(hook.accepted.load(Ordering::SeqCst), 1);

        // Java: `setAssociationAccepted` on a blocked association throws
        // VTAssociationStatusException.
        let error = manager.set_association_accepted(&same_source).unwrap_err();
        assert_eq!(error.message(), "Cannot ACCEPT a blocked association!");
    }

    /// Java: `clearAcceptedAssociation` returns an accepted association to `AVAILABLE`, unblocks
    /// the associations it had blocked, and notifies the hooks. Clearing an association that was
    /// never accepted throws instead.
    #[test]
    fn clearing_an_accepted_association_unblocks_related_ones() {
        let (session, manager) = build_manager();
        let hook = CountingHook::new();
        manager.add_association_hook(Arc::clone(&hook) as Arc<dyn AssociationHook>);

        let accepted = manager
            .get_or_create_association_db(
                &session.address(0x100),
                &session.address(0x200),
                VtAssociationType::Function,
            )
            .unwrap();
        let related = manager
            .get_or_create_association_db(
                &session.address(0x100),
                &session.address(0x300),
                VtAssociationType::Function,
            )
            .unwrap();

        manager.set_association_accepted(&accepted).unwrap();
        assert_eq!(related.get_association_status(), VtAssociationStatus::Blocked);

        manager.clear_accepted_association(&accepted).unwrap();

        assert_eq!(accepted.get_association_status(), VtAssociationStatus::Available);
        assert_eq!(related.get_association_status(), VtAssociationStatus::Available);
        assert_eq!(hook.cleared.load(Ordering::SeqCst), 1);

        let error = manager.clear_accepted_association(&accepted).unwrap_err();
        assert!(
            error.message().starts_with(
                "Cannot clear an association that is not already ACCEPTED or REJECTED"
            ),
            "unexpected message: {}",
            error.message()
        );
    }

    /// Java: a newly created association is `BLOCKED` when the accepted-status cache reports that
    /// either of its addresses already belongs to an accepted association.
    #[test]
    fn new_association_is_blocked_when_an_accepted_one_shares_an_address() {
        let (session, manager) = build_manager();

        let accepted = manager
            .get_or_create_association_db(
                &session.address(0x100),
                &session.address(0x200),
                VtAssociationType::Function,
            )
            .unwrap();
        manager.set_association_accepted(&accepted).unwrap();

        let blocked = manager
            .get_or_create_association_db(
                &session.address(0x100),
                &session.address(0x400),
                VtAssociationType::Function,
            )
            .unwrap();
        assert_eq!(blocked.get_association_status(), VtAssociationStatus::Blocked);

        let free = manager
            .get_or_create_association_db(
                &session.address(0x700),
                &session.address(0x800),
                VtAssociationType::Function,
            )
            .unwrap();
        assert_eq!(free.get_association_status(), VtAssociationStatus::Available);
    }

    /// Java: the `VTAssociationManager` queries -- count, full list, address lookup and the three
    /// related-association queries, which match on *either* address.
    #[test]
    fn association_manager_queries_match_java_lookup_rules() {
        let (session, manager) = build_manager();
        let first = manager
            .get_or_create_association_db(
                &session.address(0x10),
                &session.address(0x20),
                VtAssociationType::Function,
            )
            .unwrap();
        manager
            .get_or_create_association_db(
                &session.address(0x10),
                &session.address(0x30),
                VtAssociationType::Function,
            )
            .unwrap();
        manager
            .get_or_create_association_db(
                &session.address(0x40),
                &session.address(0x20),
                VtAssociationType::Function,
            )
            .unwrap();

        assert_eq!(manager.get_association_count(), 3);
        assert_eq!(manager.get_associations().len(), 3);

        let found = manager
            .get_association(&session.address(0x10), &session.address(0x20))
            .expect("association should exist");
        assert_eq!(found.get_key(), first.get_key());
        assert!(manager.get_association(&session.address(0x10), &session.address(0x99)).is_none());

        assert_eq!(
            manager.get_related_associations_by_source_address(&session.address(0x10)).len(),
            2
        );
        assert_eq!(
            manager
                .get_related_associations_by_destination_address(&session.address(0x20))
                .len(),
            2
        );
        // Either address matching is enough: 0x10/0x20, 0x10/0x30 and 0x40/0x20 all qualify.
        assert_eq!(
            manager
                .get_related_associations_by_source_and_destination_address(
                    &session.address(0x10),
                    &session.address(0x20)
                )
                .len(),
            3
        );
    }

    /// Java: `removeAssociation` deletes the row, tombstones the cached object and fires
    /// `VTEvent.ASSOCIATION_REMOVED`.
    #[test]
    fn remove_association_deletes_the_row_and_fires_the_event() {
        let (session, manager) = build_manager();
        let association = manager
            .get_or_create_association_db(
                &session.address(0x10),
                &session.address(0x20),
                VtAssociationType::Function,
            )
            .unwrap();
        session.events.lock().unwrap().clear();

        manager.remove_association(&association);

        // Asserted via the record count rather than `get_association_record(key).is_none()`:
        // `Table::get_record` and `Table::delete_record` disagree about which of the table's two
        // backing stores is authoritative once populated, a pre-existing gap that
        // `VTMatchMarkupItemTableDBAdapterV0`'s own removal test works around the same way.
        assert_eq!(manager.get_association_count(), 0);
        assert!(!association.is_valid(), "the cached object should be tombstoned");
        assert_eq!(*session.events.lock().unwrap(), vec![VtEvent::AssociationRemoved]);
    }

    /// Java: `addAssociationHook`/`removeAssociationHook` add and drop a listener by identity.
    #[test]
    fn removing_a_hook_stops_its_notifications() {
        let (session, manager) = build_manager();
        let hook = CountingHook::new();
        let handle = Arc::clone(&hook) as Arc<dyn AssociationHook>;
        manager.add_association_hook(Arc::clone(&handle));
        manager.remove_association_hook(&handle);

        let association = manager
            .get_or_create_association_db(
                &session.address(0x10),
                &session.address(0x20),
                VtAssociationType::Function,
            )
            .unwrap();
        manager.set_association_accepted(&association).unwrap();

        assert_eq!(hook.accepted.load(Ordering::SeqCst), 0);
    }

    /// Java: `invalidateCache` marks the cached association objects stale, so they refresh from
    /// the database on next use, and empties the accepted-status cache.
    ///
    /// The second half pins the upstream quirk documented on `do_load_accepted_associations`: the
    /// reload that the next `isBlocked` triggers adds nothing (its `add()` calls run while the
    /// cache is still flagged invalid), so an association created right after an
    /// `invalidateCache()` comes up `AVAILABLE` even though an accepted association shares its
    /// source address -- until the next `updateAssociationRecord` repopulates the cache.
    #[test]
    fn invalidate_cache_marks_cached_associations_stale() {
        let (session, manager) = build_manager();
        let association = manager
            .get_or_create_association_db(
                &session.address(0x10),
                &session.address(0x20),
                VtAssociationType::Function,
            )
            .unwrap();
        manager.set_association_accepted(&association).unwrap();
        assert!(association.is_valid());

        // Before the invalidation the cache does block a competing association.
        let blocked = manager
            .get_or_create_association_db(
                &session.address(0x10),
                &session.address(0x800),
                VtAssociationType::Function,
            )
            .unwrap();
        assert_eq!(blocked.get_association_status(), VtAssociationStatus::Blocked);

        manager.invalidate_cache();

        assert!(!association.is_valid());
        let after_invalidate = manager
            .get_or_create_association_db(
                &session.address(0x10),
                &session.address(0x900),
                VtAssociationType::Function,
            )
            .unwrap();
        assert_eq!(after_invalidate.get_association_status(), VtAssociationStatus::Available);
    }

    /// Java: `dispose()` marks the accepted-status cache disposed, after which `isBlocked`
    /// answers `true` unconditionally -- every new association comes up `BLOCKED`.
    #[test]
    fn dispose_makes_every_new_association_blocked() {
        let (session, manager) = build_manager();
        manager.dispose();

        let association = manager
            .get_or_create_association_db(
                &session.address(0x10),
                &session.address(0x20),
                VtAssociationType::Function,
            )
            .unwrap();
        assert_eq!(association.get_association_status(), VtAssociationStatus::Blocked);
    }
}

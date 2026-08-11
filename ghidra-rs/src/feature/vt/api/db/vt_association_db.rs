//! Port of `ghidra.feature.vt.api.db.VTAssociationDB`.
//!
//! Concrete, database-backed [`VtAssociation`] object: one row of the `AssociationTable` that
//! [`AssociationDatabaseManager`](crate::feature::vt::api::main::db::association_database_manager::AssociationDatabaseManager)
//! owns and caches.
//!
//! Deviation from the Java source, forced by types that are not ported yet (see
//! `crate::feature::seam_stubs`): Java's `VTAssociationDB` holds a `public final
//! AssociationDatabaseManager associationDBM` back-reference and delegates everything it does not
//! read straight off its own record to it (`setStatus` writes the record *and* asks the manager to
//! persist it; `getMarkupItems`/`hasAppliedMarkupItems` go through its `MarkupItemManagerImpl`;
//! `getRelatedAssociations`/`setAccepted`/`clearStatus`/`setRejected`/`setVoteCount`/
//! `setMarkupStatus` all call back into the manager). Storing that back-reference here would make
//! the manager's own `association_cache` (a *strong* `HashMap<i64, Arc<VTAssociationDB>>`) an
//! unreclaimable reference cycle -- unlike `MarkupItemStorageDB`, which holds the same kind of
//! back-reference but is only ever cached *weakly*, for exactly this reason. So, as already
//! documented on `AssociationDatabaseManager` itself, those operations live on the manager instead,
//! taking this type as a parameter (`AssociationDatabaseManager::set_status`,
//! `AssociationDatabaseManager::remove_association`,
//! `AssociationDatabaseManager::get_applied_markup_items`, etc.). `MarkupItemManagerImpl` --
//! unported, and in Java itself holding a back-reference to its owning `VTAssociationDB` -- is
//! never instantiated here for the same reason; `hasAppliedMarkupItems` instead reads the cached
//! applied-status column directly, which is exactly what the real `MarkupItemManagerImpl` is itself
//! backed by.

use std::sync::{Arc, Mutex};

use crate::feature::seam_stubs::{
    association_status_from_ordinal, association_type_from_ordinal, AddressType, TaskMonitor,
    VTSessionDB, VtAssociation, VtAssociationMarkupStatus, VtAssociationStatus, VtAssociationType,
    VtMarkupItem,
};
use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;
use crate::framework::db::DBRecord;
use crate::program::database::db_object::{DbObject, DbObjectState};

/// Database-backed version-tracking association: one row of the `AssociationTable`.
///
/// Port of `ghidra.feature.vt.api.db.VTAssociationDB`. See the module docs for why this type holds
/// the session it needs for address translation rather than a back-reference to its owning
/// [`AssociationDatabaseManager`](crate::feature::vt::api::main::db::association_database_manager::AssociationDatabaseManager).
pub struct VTAssociationDB {
    state: DbObjectState,
    record: Mutex<DBRecord>,
    session: Option<Arc<dyn VTSessionDB>>,
}

impl VTAssociationDB {
    /// Java: package-private constructor `VTAssociationDB(AssociationDatabaseManager, DBRecord)`,
    /// with the manager narrowed to the session it would have been asked for address translation.
    pub fn new(record: DBRecord, session: Arc<dyn VTSessionDB>) -> Self {
        let key = record.get_key().get_long_value();
        Self { state: DbObjectState::new(key), record: Mutex::new(record), session: Some(session) }
    }

    /// Builds a session-less association, for callers that only read the columns of the record
    /// itself. Has no Java counterpart -- the real `VTAssociationDB` always has its manager --
    /// and exists for tests and adapters (e.g.
    /// [`VTMatchTableDBAdapter::insert_match_record`](crate::feature::vt::api::main::db::vt_match_table_db_adapter::VTMatchTableDBAdapter::insert_match_record))
    /// that read nothing but `getKey()`. The address accessors panic on an association built this
    /// way.
    pub fn from_record(record: DBRecord) -> Self {
        let key = record.get_key().get_long_value();
        Self { state: DbObjectState::new(key), record: Mutex::new(record), session: None }
    }

    /// Java: `DBObject.getKey()`.
    pub fn get_key(&self) -> i64 {
        self.state.get_key()
    }

    /// Java: `VTAssociationDB.getRecord()` (package-private).
    pub fn get_record(&self) -> DBRecord {
        self.record.lock().unwrap().clone()
    }

    /// Replaces this association's cached record. Stands in for the record write-back that the
    /// real `VTAssociationDB.setStatus`/`setVoteCount` perform on their own record before handing
    /// it to `associationManager.updateAssociationRecord`; used by
    /// [`AssociationDatabaseManager::set_status`](crate::feature::vt::api::main::db::association_database_manager::AssociationDatabaseManager),
    /// which drives that persistence for the reasons documented on the module.
    pub fn set_record(&self, record: DBRecord) {
        *self.record.lock().unwrap() = record;
    }

    /// Java: `VTAssociationDB.getStatus()`, returning the real ported enum rather than the
    /// [`VtAssociationStatus`] placeholder trait that the `VtAssociation` seam still speaks in. The
    /// `VtAssociation::get_status` impl below wraps this value. Named apart from the trait method
    /// so that a shared `Arc<VTAssociationDB>` -- for which both this type's and `Arc`'s
    /// `VtAssociation` impls are in scope -- resolves unambiguously.
    pub fn get_association_status(
        &self,
    ) -> crate::feature::vt::api::main::vt_association_status::VtAssociationStatus {
        association_status_from_ordinal(
            self.record.lock().unwrap().get_byte(ColumnDescription::StatusCol.column()).unwrap_or(0),
        )
    }

    /// Java: `VTAssociationDB.getType()`.
    pub fn get_association_type(
        &self,
    ) -> crate::feature::vt::api::main::vt_association_type::VtAssociationType {
        association_type_from_ordinal(
            self.record.lock().unwrap().get_byte(ColumnDescription::TypeCol.column()).unwrap_or(0),
        )
    }

    /// Java: `VTAssociationDB.getMarkupStatus()`.
    pub fn get_association_markup_status(
        &self,
    ) -> crate::feature::vt::api::main::vt_association_markup_status::VtAssociationMarkupStatus {
        crate::feature::vt::api::main::vt_association_markup_status::VtAssociationMarkupStatus::from_status(
            self.record
                .lock()
                .unwrap()
                .get_byte(ColumnDescription::AppliedStatusCol.column())
                .unwrap_or(0) as i32,
        )
    }

    /// Java: `VTAssociationDB.getVoteCount()`.
    pub fn get_vote_count(&self) -> i32 {
        self.record.lock().unwrap().get_int(ColumnDescription::VoteCountCol.column()).unwrap_or(0)
    }

    fn session(&self) -> &Arc<dyn VTSessionDB> {
        self.session
            .as_ref()
            .expect("VTAssociationDB was built without a session; address accessors are unavailable")
    }
}

impl DbObject for VTAssociationDB {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    /// Java: `VTAssociationDB.refresh(DBRecord)`, minus the `record == null` branch that re-reads
    /// the row through `associationManager.getAssociationRecord(key)` -- that fallback is instead
    /// performed by the manager's own cache lookup
    /// ([`AssociationDatabaseManager::get_association_db`](crate::feature::vt::api::main::db::association_database_manager::AssociationDatabaseManager::get_association_db)),
    /// which always has a record in hand by the time it calls `refresh_if_needed_with_record`.
    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        if let Some(record) = record {
            *self.record.lock().unwrap() = record.clone();
        }
        true
    }
}

impl VtAssociation for VTAssociationDB {
    fn get_type(&self) -> Box<dyn VtAssociationType> {
        Box::new(self.get_association_type())
    }

    fn get_session(&self) -> Box<dyn crate::feature::vt::api::main::vt_session::VTSession> {
        unimplemented!(
            "VTAssociationDB::get_session requires the unported VTSessionDB -> VTSession bridge"
        )
    }

    fn get_markup_items(
        &self,
        _monitor: &dyn TaskMonitor,
    ) -> std::io::Result<Vec<Box<dyn VtMarkupItem>>> {
        unimplemented!(
            "VTAssociationDB::get_markup_items requires the unported MarkupItemManagerImpl; use \
             AssociationDatabaseManager::get_applied_markup_items"
        )
    }

    /// Java: `VTAssociationDB.hasAppliedMarkupItems()`, which reads the cached markup status held
    /// by `markupManager` -- itself just a cache of this same applied-status column.
    fn has_applied_markup_items(&self) -> bool {
        self.get_association_markup_status().has_applied_markup()
    }

    fn get_source_address(&self) -> AddressType {
        let value = self
            .record
            .lock()
            .unwrap()
            .get_long(ColumnDescription::SourceAddressCol.column())
            .unwrap_or(0);
        self.session().get_source_address_from_long(value)
    }

    fn get_destination_address(&self) -> AddressType {
        let value = self
            .record
            .lock()
            .unwrap()
            .get_long(ColumnDescription::DestinationAddressCol.column())
            .unwrap_or(0);
        self.session().get_destination_address_from_long(value)
    }

    fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>> {
        unimplemented!(
            "VTAssociationDB::get_related_associations requires the association manager; use \
             AssociationDatabaseManager::get_related_associations_by_source_and_destination_address"
        )
    }

    fn set_markup_status(&self, _markup_items_status: &dyn VtAssociationMarkupStatus) {
        unimplemented!("VTAssociationDB::set_markup_status must persist through the manager")
    }

    fn get_markup_status(&self) -> Box<dyn VtAssociationMarkupStatus> {
        Box::new(self.get_association_markup_status())
    }

    fn get_status(&self) -> Box<dyn VtAssociationStatus> {
        Box::new(self.get_association_status())
    }

    fn set_accepted(&self) -> std::io::Result<()> {
        unimplemented!("VTAssociationDB::set_accepted must go through AssociationDatabaseManager")
    }

    fn clear_status(&self) -> std::io::Result<()> {
        unimplemented!("VTAssociationDB::clear_status must go through AssociationDatabaseManager")
    }

    fn set_rejected(&self) -> std::io::Result<()> {
        unimplemented!("VTAssociationDB::set_rejected must go through AssociationDatabaseManager")
    }

    fn get_vote_count(&self) -> i32 {
        VTAssociationDB::get_vote_count(self)
    }

    fn set_vote_count(&self, _vote_count: i32) {
        unimplemented!("VTAssociationDB::set_vote_count must persist through the manager")
    }

    fn get_key(&self) -> i64 {
        VTAssociationDB::get_key(self)
    }

    /// Java: the `(VTSessionDB) association.getSession()` cast that `MarkupItemImpl` performs.
    /// Unlike [`get_session`](VtAssociation::get_session), which would need the missing
    /// `VTSessionDB -> VTSession` bridge, this association already holds the very `VTSessionDB`
    /// the cast is after -- unless it was built by [`VTAssociationDB::from_record`], which has no
    /// session at all.
    fn get_session_db(&self) -> Option<Arc<dyn VTSessionDB>> {
        self.session.clone()
    }
}

/// Lets a shared, cached [`VTAssociationDB`] be handed out as an owned `Box<dyn VtAssociation>`
/// (which is what the ported `VTAssociationManager` seam returns) without cloning the underlying
/// object, mirroring how `MarkupItemStorageDB` forwards through its own `Arc`.
impl VtAssociation for Arc<VTAssociationDB> {
    fn get_type(&self) -> Box<dyn VtAssociationType> {
        (**self).get_type()
    }

    fn get_session(&self) -> Box<dyn crate::feature::vt::api::main::vt_session::VTSession> {
        VtAssociation::get_session(&**self)
    }

    fn get_markup_items(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> std::io::Result<Vec<Box<dyn VtMarkupItem>>> {
        (**self).get_markup_items(monitor)
    }

    fn has_applied_markup_items(&self) -> bool {
        (**self).has_applied_markup_items()
    }

    fn get_source_address(&self) -> AddressType {
        (**self).get_source_address()
    }

    fn get_destination_address(&self) -> AddressType {
        (**self).get_destination_address()
    }

    fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>> {
        (**self).get_related_associations()
    }

    fn set_markup_status(&self, markup_items_status: &dyn VtAssociationMarkupStatus) {
        (**self).set_markup_status(markup_items_status)
    }

    fn get_markup_status(&self) -> Box<dyn VtAssociationMarkupStatus> {
        (**self).get_markup_status()
    }

    fn get_status(&self) -> Box<dyn VtAssociationStatus> {
        VtAssociation::get_status(&**self)
    }

    fn set_accepted(&self) -> std::io::Result<()> {
        (**self).set_accepted()
    }

    fn clear_status(&self) -> std::io::Result<()> {
        (**self).clear_status()
    }

    fn set_rejected(&self) -> std::io::Result<()> {
        (**self).set_rejected()
    }

    fn get_vote_count(&self) -> i32 {
        (**self).get_vote_count()
    }

    fn set_vote_count(&self, vote_count: i32) {
        (**self).set_vote_count(vote_count)
    }

    fn get_key(&self) -> i64 {
        VTAssociationDB::get_key(self)
    }

    fn get_session_db(&self) -> Option<Arc<dyn VTSessionDB>> {
        (**self).get_session_db()
    }
}

impl std::fmt::Display for VTAssociationDB {
    /// Java: `VTAssociationDB.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VTAssociation[{} <-> {}]", self.get_source_address(), self.get_destination_address())
    }
}

impl std::fmt::Debug for VTAssociationDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl PartialEq for VTAssociationDB {
    /// Java: `VTAssociationDB.equals(Object)`, narrowed to two `VTAssociationDB`s. Java compares
    /// against any `VTAssociation` implementor via `instanceof`; Rust's static dispatch has no
    /// equivalent without `Any`-based downcasting, so this covers the same-concrete-type case that
    /// every in-tree comparison actually needs.
    fn eq(&self, other: &Self) -> bool {
        self.get_source_address() == other.get_source_address()
            && self.get_destination_address() == other.get_destination_address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::vt::api::main::db::vt_association_table_db_adapter::VTAssociationTableDBAdapterBase;
    use crate::feature::vt::api::main::vt_association_markup_status::VtAssociationMarkupStatus as RealMarkupStatus;
    use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus as RealStatus;
    use crate::feature::vt::api::main::vt_association_type::VtAssociationType as RealType;
    use crate::framework::db::Field;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockSession {
        space: Arc<AddressSpace>,
    }

    impl VTSessionDB for MockSession {
        fn get_lock(&self) -> Arc<crate::util::lock::ReentrantLock> {
            Arc::new(crate::util::lock::ReentrantLock::new("test"))
        }
        fn db_error(&self, error: std::io::Error) {
            panic!("unexpected database error: {error}");
        }
        fn get_source_program(
            &self,
        ) -> Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this test")
        }
        fn get_destination_program(
            &self,
        ) -> Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this test")
        }
        fn get_long_from_source_address(&self, address: &AddressType) -> i64 {
            address.offset()
        }
        fn get_long_from_destination_address(&self, address: &AddressType) -> i64 {
            address.offset()
        }
        fn get_source_address_from_long(&self, value: i64) -> AddressType {
            AddressType::new(self.space.clone(), value)
        }
        fn get_destination_address_from_long(&self, value: i64) -> AddressType {
            AddressType::new(self.space.clone(), value)
        }
        fn set_changed(
            &self,
            _event_type: crate::feature::vt::api::implementation::vt_event::VtEvent,
            _old_value: Option<Arc<VTAssociationDB>>,
            _new_value: Option<Arc<VTAssociationDB>>,
        ) {
        }
    }

    fn build_record(
        source: i64,
        destination: i64,
        association_type: RealType,
        status: RealStatus,
        applied_status: i32,
        vote_count: i32,
    ) -> DBRecord {
        let schema = VTAssociationTableDBAdapterBase::table_schema();
        let mut record = DBRecord::new(schema, Field::Long(Some(1)));
        record.set_long(ColumnDescription::SourceAddressCol.column(), source);
        record.set_long(ColumnDescription::DestinationAddressCol.column(), destination);
        record.set_byte(
            ColumnDescription::TypeCol.column(),
            match association_type {
                RealType::Function => 0,
                RealType::Data => 1,
            },
        );
        record.set_byte(
            ColumnDescription::StatusCol.column(),
            match status {
                RealStatus::Available => 0,
                RealStatus::Accepted => 1,
                RealStatus::Blocked => 2,
                RealStatus::Rejected => 3,
            },
        );
        record.set_byte(ColumnDescription::AppliedStatusCol.column(), applied_status as i8);
        record.set_int(ColumnDescription::VoteCountCol.column(), vote_count);
        record
    }

    fn session() -> Arc<dyn VTSessionDB> {
        Arc::new(MockSession { space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1) })
    }

    /// Java: `getType()`/`getStatus()`/`getVoteCount()`/`getSourceAddress()`/
    /// `getDestinationAddress()` all read straight off the record's columns, translating addresses
    /// through the session.
    #[test]
    fn accessors_read_record_columns() {
        let record = build_record(0x1000, 0x2000, RealType::Data, RealStatus::Accepted, 0, 3);
        let association = VTAssociationDB::new(record, session());

        assert_eq!(association.get_association_type(), RealType::Data);
        assert_eq!(association.get_association_status(), RealStatus::Accepted);
        assert_eq!(association.get_vote_count(), 3);
        assert_eq!(association.get_source_address().offset(), 0x1000);
        assert_eq!(association.get_destination_address().offset(), 0x2000);
        assert_eq!(association.get_key(), 1);
    }

    /// Java: `hasAppliedMarkupItems()` reflects the packed applied-status column via
    /// `VTAssociationMarkupStatus.hasAppliedMarkup()`.
    #[test]
    fn has_applied_markup_items_reads_markup_status_column() {
        let applied = RealMarkupStatus::from_flags(false, true, false, false, false, false);
        let record = build_record(
            0,
            0,
            RealType::Function,
            RealStatus::Available,
            applied.status_value(),
            0,
        );
        let association = VTAssociationDB::new(record, session());

        assert!(association.has_applied_markup_items());
        assert!(VtAssociation::has_applied_markup_items(&association));
    }

    /// Java: `toString()` formats as `"VTAssociation[source <-> destination]"`.
    #[test]
    fn display_matches_java_tostring_shape() {
        let record = build_record(0x10, 0x20, RealType::Function, RealStatus::Available, 0, 0);
        let association = VTAssociationDB::new(record, session());

        let text = association.to_string();
        assert!(text.starts_with("VTAssociation["));
        assert!(text.contains("<->"));
    }

    /// Java: `equals(Object)` compares by source and destination address.
    #[test]
    fn equals_compares_by_address() {
        let same_addresses_a =
            VTAssociationDB::new(build_record(0x10, 0x20, RealType::Function, RealStatus::Available, 0, 0), session());
        let same_addresses_b =
            VTAssociationDB::new(build_record(0x10, 0x20, RealType::Data, RealStatus::Accepted, 0, 5), session());
        let different =
            VTAssociationDB::new(build_record(0x10, 0x99, RealType::Function, RealStatus::Available, 0, 0), session());

        assert_eq!(same_addresses_a, same_addresses_b);
        assert_ne!(same_addresses_a, different);
    }

    /// `from_record` builds a session-less association whose key-only accessors still work,
    /// matching how `VTMatchTableDBAdapter`'s own tests build a fake association.
    #[test]
    fn from_record_supports_key_only_access() {
        let record = build_record(0, 0, RealType::Function, RealStatus::Available, 0, 0);
        let association = VTAssociationDB::from_record(record);

        assert_eq!(association.get_key(), 1);
        assert!(association.is_valid());
    }
}

//! Port of `ghidra.feature.vt.api.db.MarkupItemStorageDB`.
//!
//! Concrete, database-backed implementation of
//! [`MarkupItemStorage`](crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage).
//! Every accessor mirrors the Java method's `associationManager.lock.read()`/`refreshIfNeeded()`
//! preamble; [`MarkupItemStorageDB::reset`] and [`MarkupItemStorageDB::set_status`]/
//! [`MarkupItemStorageDB::set_destination_address`] mirror the `lock.write()`/
//! `associationManager.updateMarkupRecord(record)` postamble.
//!
//! Two deliberate deviations from the Java source, both forced by the already-ported
//! [`MarkupItemStorage`] trait's signatures (fixed before this port started, so not renegotiable
//! here):
//!   - Java's `reset()` returns a brand-new, purely in-memory `MarkupItemStorageImpl` (a
//!     different concrete type) and leaves the original `MarkupItemStorageDB` object as an inert
//!     husk the caller is expected to discard. The trait's `reset(&mut self)` has no return value
//!     and cannot swap `self`'s concrete type, so this port instead removes the underlying DB
//!     record (the one real, observable side effect) and marks `self` deleted via
//!     [`DbObject::set_deleted`], which is the closest in-place equivalent: any further use of
//!     this object behaves as Java's discarded original would once its row is gone. Because of
//!     this, `MarkupItemStorageImpl` (a concrete, unported Java class) is never actually
//!     constructed and needs no placeholder here.
//!   - `getMarkupType()`/`getAssociation()` return the same cached `VTMarkupType`/`VTAssociation`
//!     instance on every call in Java. The already-ported trait returns owned `Box<dyn _>`
//!     values, so each call here hands back a fresh forwarding wrapper
//!     ([`ArcMarkupType`]/[`ArcVtAssociation`]) around the same shared `Arc`, which is
//!     behaviorally equivalent (same underlying data, same identity via `Arc`) without requiring
//!     `Clone` on either trait.
//!
//! `getSourceValue`/`getDestinationValue`/`setSourceDestinationValues` go through
//! [`RawStringable`], a minimal `Stringable` wrapping the raw stored string column, matching the
//! same simplification already used by `VTMatchMarkupItemTableDBAdapterV0::create_markup_item_record`
//! (the ported `Stringable` stub has no program-aware parse/serialize machinery yet).

use std::sync::{Arc, Mutex};

use crate::feature::seam_stubs::{AssociationDatabaseManager, Stringable, VtAssociation, VtMarkupType};
use crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage;
use crate::feature::vt::api::main::db::vt_match_markup_item_table_db_adapter_v0::ColumnDescription;
use crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus;
use crate::feature::vt::api::main::vt_session::VTSession;
use crate::feature::vt::api::markuptype::vt_markup_type_factory;
use crate::framework::db::{DBRecord, Field};
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::address::Address;

/// Forwards [`VtMarkupType`] to a shared `Arc`, letting [`MarkupItemStorageDB::get_markup_type`]
/// hand back an owned `Box<dyn VtMarkupType>` on every call without cloning the registry
/// singleton it points at. See the module docs for why this is needed.
struct ArcMarkupType(Arc<dyn VtMarkupType>);

impl VtMarkupType for ArcMarkupType {
    fn get_name(&self) -> &str {
        self.0.get_name()
    }
}

/// Forwards [`VtAssociation`] to a shared `Arc`, letting [`MarkupItemStorageDB::get_association`]
/// hand back an owned `Box<dyn VtAssociation>` on every call. See the module docs for why this is
/// needed.
struct ArcVtAssociation(Arc<dyn VtAssociation>);

impl VtAssociation for ArcVtAssociation {
    fn get_type(&self) -> Box<dyn crate::feature::seam_stubs::VtAssociationType> {
        self.0.get_type()
    }

    fn get_session(&self) -> Box<dyn VTSession> {
        self.0.get_session()
    }

    fn get_markup_items(
        &self,
        monitor: &dyn crate::feature::seam_stubs::TaskMonitor,
    ) -> std::io::Result<Vec<Box<dyn crate::feature::seam_stubs::VtMarkupItem>>> {
        self.0.get_markup_items(monitor)
    }

    fn has_applied_markup_items(&self) -> bool {
        self.0.has_applied_markup_items()
    }

    fn get_source_address(&self) -> Address {
        self.0.get_source_address()
    }

    fn get_destination_address(&self) -> Address {
        self.0.get_destination_address()
    }

    fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>> {
        self.0.get_related_associations()
    }

    fn set_markup_status(&self, markup_items_status: &dyn crate::feature::seam_stubs::VtAssociationMarkupStatus) {
        self.0.set_markup_status(markup_items_status)
    }

    fn get_markup_status(&self) -> Box<dyn crate::feature::seam_stubs::VtAssociationMarkupStatus> {
        self.0.get_markup_status()
    }

    fn get_status(&self) -> Box<dyn crate::feature::seam_stubs::VtAssociationStatus> {
        self.0.get_status()
    }

    fn set_accepted(&self) -> std::io::Result<()> {
        self.0.set_accepted()
    }

    fn clear_status(&self) -> std::io::Result<()> {
        self.0.clear_status()
    }

    fn set_rejected(&self) -> std::io::Result<()> {
        self.0.set_rejected()
    }

    fn get_vote_count(&self) -> i32 {
        self.0.get_vote_count()
    }

    fn set_vote_count(&self, vote_count: i32) {
        self.0.set_vote_count(vote_count)
    }

    fn get_key(&self) -> i64 {
        self.0.get_key()
    }
}

/// Minimal [`Stringable`] wrapping a raw stored string, standing in for the program-aware
/// `Stringable.getStringable(String, Program)`/`Stringable.getString(Stringable, Program)`
/// round-trip that Java performs (see the module docs).
struct RawStringable(String);

impl Stringable for RawStringable {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

/// Java: `VTMarkupItemStatus.ordinal()`, mirroring the enum's declaration order (matches the
/// identically-ordered `status_ordinal` helper in `vt_match_markup_item_table_db_adapter_v0`).
fn status_ordinal(status: VtMarkupItemStatus) -> i8 {
    match status {
        VtMarkupItemStatus::Unapplied => 0,
        VtMarkupItemStatus::Added => 1,
        VtMarkupItemStatus::Replaced => 2,
        VtMarkupItemStatus::FailedApply => 3,
        VtMarkupItemStatus::DontCare => 4,
        VtMarkupItemStatus::DontKnow => 5,
        VtMarkupItemStatus::Rejected => 6,
        VtMarkupItemStatus::Same => 7,
        VtMarkupItemStatus::Conflict => 8,
    }
}

/// Java: `VTMarkupItemStatus.values()[ordinal]`.
fn status_from_ordinal(ordinal: i8) -> VtMarkupItemStatus {
    match ordinal {
        0 => VtMarkupItemStatus::Unapplied,
        1 => VtMarkupItemStatus::Added,
        2 => VtMarkupItemStatus::Replaced,
        3 => VtMarkupItemStatus::FailedApply,
        4 => VtMarkupItemStatus::DontCare,
        5 => VtMarkupItemStatus::DontKnow,
        6 => VtMarkupItemStatus::Rejected,
        7 => VtMarkupItemStatus::Same,
        8 => VtMarkupItemStatus::Conflict,
        other => panic!("invalid VTMarkupItemStatus ordinal {other}"),
    }
}

/// Database-backed markup item storage.
///
/// Port of `ghidra.feature.vt.api.db.MarkupItemStorageDB`. See the module docs for the two
/// deviations forced by the already-ported [`MarkupItemStorage`] trait's shape.
pub struct MarkupItemStorageDB {
    state: DbObjectState,
    record: Mutex<DBRecord>,
    association_manager: Arc<AssociationDatabaseManager>,
    association: Arc<dyn VtAssociation>,
    session: Arc<dyn VTSession>,
}

impl MarkupItemStorageDB {
    /// Java: package-private constructor `MarkupItemStorageDB(DBRecord, AssociationDatabaseManager)`.
    pub fn new(record: DBRecord, association_manager: Arc<AssociationDatabaseManager>) -> Self {
        let key = record.get_key().get_long_value();
        let session = association_manager.get_session();
        let association_key = record.get_long(ColumnDescription::AssociationKeyCol.column()).unwrap_or(0);
        let association = association_manager.get_association(association_key);
        MarkupItemStorageDB {
            state: DbObjectState::new(key),
            record: Mutex::new(record),
            association_manager,
            association,
            session,
        }
    }
}

impl DbObject for MarkupItemStorageDB {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    /// Java: `MarkupItemStorageDB.refresh(DBRecord)`.
    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        let refreshed = match record {
            Some(r) => Some(r.clone()),
            None => self.association_manager.get_markup_item_record(self.state.get_key()),
        };
        match refreshed {
            Some(r) => {
                *self.record.lock().unwrap() = r;
                true
            }
            None => false,
        }
    }
}

impl MarkupItemStorage for MarkupItemStorageDB {
    fn get_markup_type(&self) -> Box<dyn VtMarkupType> {
        let ordinal = match self.record.lock().unwrap().get_field(ColumnDescription::MarkupTypeCol.column()) {
            Field::Short(Some(v)) => i32::from(*v),
            _ => 0,
        };
        let markup_type = vt_markup_type_factory::get_markup_type(ordinal)
            .unwrap_or_else(|| panic!("unregistered VTMarkupType id {ordinal}"));
        Box::new(ArcMarkupType(markup_type))
    }

    fn get_association(&self) -> Box<dyn VtAssociation> {
        Box::new(ArcVtAssociation(self.association.clone()))
    }

    fn get_source_address(&self) -> Address {
        let _guard = self.association_manager.lock.read();
        self.refresh_if_needed();
        let address_long = self.record.lock().unwrap().get_long(ColumnDescription::SourceAddressCol.column()).unwrap_or(0);
        let program = self.session.get_source_program();
        let address_map = program.get_address_map().expect("source program has no address map");
        address_map.decode_address(address_long)
    }

    fn get_destination_address(&self) -> Address {
        let _guard = self.association_manager.lock.read();
        self.refresh_if_needed();
        let address_long =
            self.record.lock().unwrap().get_long(ColumnDescription::DestinationAddressCol.column()).unwrap_or(0);
        let program = self.session.get_destination_program();
        let address_map = program.get_address_map().expect("destination program has no address map");
        address_map.decode_address(address_long)
    }

    fn get_destination_address_source(&self) -> String {
        let _guard = self.association_manager.lock.read();
        self.refresh_if_needed();
        self.record
            .lock()
            .unwrap()
            .get_string(ColumnDescription::AddressSourceCol.column())
            .unwrap_or_default()
            .to_string()
    }

    fn get_status(&self) -> VtMarkupItemStatus {
        let _guard = self.association_manager.lock.read();
        self.refresh_if_needed();
        let ordinal = self.record.lock().unwrap().get_byte(ColumnDescription::StatusCol.column()).unwrap_or(0);
        status_from_ordinal(ordinal)
    }

    fn get_status_description(&self) -> String {
        let _guard = self.association_manager.lock.read();
        self.refresh_if_needed();
        self.record
            .lock()
            .unwrap()
            .get_string(ColumnDescription::StatusDescriptionCol.column())
            .unwrap_or_default()
            .to_string()
    }

    fn get_source_value(&self) -> Box<dyn Stringable> {
        let _guard = self.association_manager.lock.read();
        self.refresh_if_needed();
        let value = self
            .record
            .lock()
            .unwrap()
            .get_string(ColumnDescription::SourceValueCol.column())
            .unwrap_or_default()
            .to_string();
        Box::new(RawStringable(value))
    }

    fn get_destination_value(&self) -> Box<dyn Stringable> {
        let _guard = self.association_manager.lock.read();
        self.refresh_if_needed();
        let value = self
            .record
            .lock()
            .unwrap()
            .get_string(ColumnDescription::OriginalDestinationValueCol.column())
            .unwrap_or_default()
            .to_string();
        Box::new(RawStringable(value))
    }

    fn set_source_destination_values(
        &mut self,
        source_value: Box<dyn Stringable>,
        destination_value: Box<dyn Stringable>,
    ) {
        // Java doesn't call `associationManager.updateMarkupRecord` here either -- the in-memory
        // `record` fields are updated but not flushed back to the table, matching the source.
        let mut record = self.record.lock().unwrap();
        record.set_string(ColumnDescription::SourceValueCol.column(), Some(source_value.to_string()));
        record.set_string(
            ColumnDescription::OriginalDestinationValueCol.column(),
            Some(destination_value.to_string()),
        );
    }

    fn set_status(&mut self, status: VtMarkupItemStatus) {
        let updated = {
            let mut record = self.record.lock().unwrap();
            record.set_byte(ColumnDescription::StatusCol.column(), status_ordinal(status));
            record.clone()
        };
        self.association_manager.update_markup_record(&updated);
    }

    fn set_apply_failed(&mut self, message: String) {
        {
            let mut record = self.record.lock().unwrap();
            record.set_string(ColumnDescription::StatusDescriptionCol.column(), Some(message));
        }
        self.set_status(VtMarkupItemStatus::FailedApply);
    }

    /// Java: `MarkupItemStorageDB.reset()`. See the module docs for how this differs from the
    /// Java method's type-swapping return value.
    fn reset(&mut self) {
        let _guard = self.association_manager.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        let key = self.get_key();
        self.association_manager.remove_markup_record(key);
        self.state.set_deleted();
    }

    fn set_destination_address(&mut self, address: Address, address_source: String) {
        let program = self.session.get_destination_program();
        let address_map = program.get_address_map().expect("destination program has no address map");
        let address_id = address_map.get_key(&address, false);

        let updated = {
            let mut record = self.record.lock().unwrap();
            record.set_long(ColumnDescription::DestinationAddressCol.column(), address_id);
            record.set_string(ColumnDescription::AddressSourceCol.column(), Some(address_source));
            record.clone()
        };
        self.association_manager.update_markup_record(&updated);
    }
}

impl std::fmt::Display for MarkupItemStorageDB {
    /// Java: `MarkupItemStorageDB.toString()`. Prints the association's key rather than calling
    /// into an arbitrary `VtAssociation` implementor's own formatting (unlike Java's fully-ported
    /// `VTAssociationDB.toString()`, this crate's `VtAssociation` seam has no `Display`/`toString`
    /// contract yet).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "MarkupItemStorageDB")?;
        writeln!(f, "\tSource Address          = {}", self.get_source_address())?;
        writeln!(f, "\tDest Address            = {}", self.get_destination_address())?;
        writeln!(f, "\tMarkup Class            = {}", self.get_markup_type().get_name())?;
        writeln!(f, "\tStatus                  = {}", self.get_status())?;
        writeln!(f, "\tSource Value            = {}", self.get_source_value().to_string())?;
        writeln!(f, "\tDest Value              = {}", self.get_destination_value().to_string())?;
        writeln!(f, "\tAssociation Key         = {}", self.association.get_key())?;
        write!(f, "\tAlgorithm               = {}", self.get_destination_address_source())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::vt::api::main::association_hook::AssociationHook;
    use crate::feature::vt::api::main::vt_association_manager::VtAssociationManager;
    use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
    use crate::feature::vt::api::main::vt_program_correlator::VTProgramCorrelator;
    use crate::framework::db::util::ErrorHandler;
    use crate::framework::db::DBHandle;
    use crate::framework::model::DomainObject;
    use crate::program::database::map::address_map::AddressMap;
    use crate::program::model::address::{AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange};
    use std::collections::HashSet;

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

    struct MockVtSession {
        source_program: Arc<dyn crate::program::model::listing::program::Program>,
        destination_program: Arc<dyn crate::program::model::listing::program::Program>,
    }

    impl DomainObject for MockVtSession {}

    impl ErrorHandler for MockVtSession {
        fn db_error(&self, _e: std::io::Error) {}
    }

    impl VTSession for MockVtSession {
        fn get_association_manager(&self) -> &dyn VtAssociationManager {
            unimplemented!("not exercised by this test")
        }
        fn create_match_set(
            &mut self,
            _correlator: &dyn VTProgramCorrelator,
        ) -> Box<dyn crate::feature::seam_stubs::VtMatchSet> {
            unimplemented!("not exercised by this test")
        }
        fn get_match_sets(&self) -> Vec<Box<dyn crate::feature::seam_stubs::VtMatchSet>> {
            Vec::new()
        }
        fn get_source_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            self.source_program.clone()
        }
        fn get_destination_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            self.destination_program.clone()
        }
        fn save_session(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        fn create_match_tag(&mut self, _name: &str) -> VtMatchTag {
            unimplemented!("not exercised by this test")
        }
        fn delete_match_tag(&mut self, _tag: &VtMatchTag) {}
        fn get_match_tags(&self) -> HashSet<VtMatchTag> {
            HashSet::new()
        }
        fn get_manual_match_set(&self) -> &dyn crate::feature::seam_stubs::VtMatchSet {
            unimplemented!("not exercised by this test")
        }
        fn get_implied_match_set(&self) -> &dyn crate::feature::seam_stubs::VtMatchSet {
            unimplemented!("not exercised by this test")
        }
        fn get_matches(&self, _association: &dyn VtAssociation) -> Vec<Box<dyn crate::feature::seam_stubs::VtMatch>> {
            Vec::new()
        }
        fn add_association_hook(&mut self, _hook: Box<dyn AssociationHook>) {}
        fn remove_association_hook(&mut self, _hook: &dyn AssociationHook) {}
        fn update_source_program(&mut self, _new_program: Arc<dyn crate::program::model::listing::program::Program>) {}
        fn update_destination_program(
            &mut self,
            _new_program: Arc<dyn crate::program::model::listing::program::Program>,
        ) {
        }
    }

    struct MockAssociation {
        key: i64,
    }

    impl VtAssociation for MockAssociation {
        fn get_type(&self) -> Box<dyn crate::feature::seam_stubs::VtAssociationType> {
            unimplemented!("not exercised by this test")
        }
        fn get_session(&self) -> Box<dyn VTSession> {
            unimplemented!("not exercised by this test")
        }
        fn get_markup_items(
            &self,
            _monitor: &dyn crate::feature::seam_stubs::TaskMonitor,
        ) -> std::io::Result<Vec<Box<dyn crate::feature::seam_stubs::VtMarkupItem>>> {
            unimplemented!("not exercised by this test")
        }
        fn has_applied_markup_items(&self) -> bool {
            false
        }
        fn get_source_address(&self) -> Address {
            unimplemented!("not exercised by this test")
        }
        fn get_destination_address(&self) -> Address {
            unimplemented!("not exercised by this test")
        }
        fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }
        fn set_markup_status(&self, _status: &dyn crate::feature::seam_stubs::VtAssociationMarkupStatus) {}
        fn get_markup_status(&self) -> Box<dyn crate::feature::seam_stubs::VtAssociationMarkupStatus> {
            unimplemented!("not exercised by this test")
        }
        fn get_status(&self) -> Box<dyn crate::feature::seam_stubs::VtAssociationStatus> {
            unimplemented!("not exercised by this test")
        }
        fn set_accepted(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_status(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn set_rejected(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn get_vote_count(&self) -> i32 {
            0
        }
        fn set_vote_count(&self, _vote_count: i32) {}
        fn get_key(&self) -> i64 {
            self.key
        }
    }

    /// Builds an `AssociationDatabaseManager` plus a freshly-seeded (but not yet persisted)
    /// record, mirroring the fields the Java `MarkupItemStorageDB` constructor reads: association
    /// key, markup type id, source/destination address (identity-mapped through
    /// `MockAddressMap`), status, and both value strings.
    fn build_manager_and_record(
        association_key: i64,
        source_offset: i64,
        destination_offset: i64,
        markup_type_id: i32,
        status: VtMarkupItemStatus,
    ) -> (Arc<AssociationDatabaseManager>, DBRecord) {
        let mut db_handle = DBHandle::new().unwrap();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let address_map = Arc::new(MockAddressMap { space });

        let source_program = Arc::new(MockProgram {
            name: "source".to_string(),
            address_map: address_map.clone(),
        }) as Arc<dyn crate::program::model::listing::program::Program>;
        let destination_program = Arc::new(MockProgram {
            name: "destination".to_string(),
            address_map,
        }) as Arc<dyn crate::program::model::listing::program::Program>;

        let session: Arc<dyn VTSession> = Arc::new(MockVtSession { source_program, destination_program });
        let association_manager = Arc::new(AssociationDatabaseManager::new(&mut db_handle, session).unwrap());
        association_manager.register_association(association_key, Arc::new(MockAssociation { key: association_key }));

        let schema = crate::feature::vt::api::main::db::vt_match_markup_item_table_db_adapter_v0::VTMatchMarkupItemTableDBAdapterV0::table_schema();
        let mut record = DBRecord::new(schema, crate::framework::db::Field::Long(Some(1)));
        record.set_long(ColumnDescription::AssociationKeyCol.column(), association_key);
        record.set_long(ColumnDescription::SourceAddressCol.column(), source_offset);
        record.set_long(ColumnDescription::DestinationAddressCol.column(), destination_offset);
        record.set_string(ColumnDescription::AddressSourceCol.column(), Some("Analysis".to_string()));
        record.set_field(ColumnDescription::MarkupTypeCol.column(), Field::Short(Some(markup_type_id as i16)));
        record.set_string(ColumnDescription::SourceValueCol.column(), Some("src-val".to_string()));
        record.set_string(ColumnDescription::OriginalDestinationValueCol.column(), Some("dst-val".to_string()));
        record.set_byte(ColumnDescription::StatusCol.column(), status_ordinal(status));
        record.set_string(ColumnDescription::StatusDescriptionCol.column(), Some(status.description().to_string()));

        (association_manager, record)
    }

    /// Builds a `MarkupItemStorageDB` backed by a record that has already been persisted into its
    /// `AssociationDatabaseManager`'s table.
    fn build_storage(
        association_key: i64,
        source_offset: i64,
        destination_offset: i64,
        markup_type_id: i32,
        status: VtMarkupItemStatus,
    ) -> MarkupItemStorageDB {
        let (association_manager, record) =
            build_manager_and_record(association_key, source_offset, destination_offset, markup_type_id, status);
        association_manager.update_markup_record(&record);
        MarkupItemStorageDB::new(record, association_manager)
    }

    /// Exercises the read-side accessors against known Java behavior: `getSourceAddress`/
    /// `getDestinationAddress` decode through the program's address map, `getMarkupType` resolves
    /// through the real `VTMarkupTypeFactory` registry (id 12 = EOL comment), `getStatus` inverts
    /// `VTMarkupItemStatus.ordinal()`, and the value/description getters read their raw columns
    /// straight through -- all matching `MarkupItemStorageDB`'s Java getters.
    #[test]
    fn accessors_match_java_behavior() {
        let storage = build_storage(42, 0x1000, 0x2000, 12, VtMarkupItemStatus::Unapplied);

        assert_eq!(storage.get_source_address().offset(), 0x1000);
        assert_eq!(storage.get_destination_address().offset(), 0x2000);
        assert_eq!(storage.get_destination_address_source(), "Analysis");
        assert_eq!(storage.get_markup_type().get_name(), "EOL Comment");
        assert_eq!(storage.get_status(), VtMarkupItemStatus::Unapplied);
        assert_eq!(storage.get_status_description(), "Unapplied");
        assert_eq!(storage.get_source_value().to_string(), "src-val");
        assert_eq!(storage.get_destination_value().to_string(), "dst-val");
        assert_eq!(storage.get_association().get_key(), 42);
        assert_eq!(storage.get_key(), 1);
    }

    /// Java: `setStatus(VTMarkupItemStatus)` persists the new status ordinal via
    /// `associationManager.updateMarkupRecord`, which this test observes by fetching the record
    /// back out of the association manager's (real, table-backed) adapter.
    #[test]
    fn set_status_persists_through_association_manager() {
        let mut storage = build_storage(1, 0, 0, 13, VtMarkupItemStatus::Unapplied);

        storage.set_status(VtMarkupItemStatus::Added);
        assert_eq!(storage.get_status(), VtMarkupItemStatus::Added);

        let persisted = storage.association_manager.get_markup_item_record(storage.get_key()).unwrap();
        assert_eq!(persisted.get_byte(ColumnDescription::StatusCol.column()), Some(status_ordinal(VtMarkupItemStatus::Added)));
    }

    /// Java: `setApplyFailed(String)` stores the message in `STATUS_DESCRIPTION_COL` and then
    /// calls `setStatus(FAILED_APPLY)`.
    #[test]
    fn set_apply_failed_records_message_and_status() {
        let mut storage = build_storage(1, 0, 0, 13, VtMarkupItemStatus::Unapplied);

        storage.set_apply_failed("boom".to_string());

        assert_eq!(storage.get_status(), VtMarkupItemStatus::FailedApply);
        assert_eq!(storage.get_status_description(), "boom");
    }

    /// Java: `setDestinationAddress(Address, String)` re-encodes the address through the
    /// destination program's address map and persists both columns.
    #[test]
    fn set_destination_address_updates_and_persists() {
        let mut storage = build_storage(1, 0, 0x2000, 13, VtMarkupItemStatus::Unapplied);
        let space = storage.get_destination_address().space().clone();

        storage.set_destination_address(Address::new(space, 0x3000), "Manual".to_string());

        assert_eq!(storage.get_destination_address().offset(), 0x3000);
        assert_eq!(storage.get_destination_address_source(), "Manual");
    }

    /// Java: `setSourceDestinationValues` updates the in-memory record's value columns but --
    /// unlike `setStatus`/`setDestinationAddress` -- never calls `updateMarkupRecord`, so the
    /// change is visible on `self` but not yet flushed to the table.
    #[test]
    fn set_source_destination_values_updates_in_memory_only() {
        let mut storage = build_storage(1, 0, 0, 13, VtMarkupItemStatus::Unapplied);

        storage.set_source_destination_values(
            Box::new(RawStringable("new-src".to_string())),
            Box::new(RawStringable("new-dst".to_string())),
        );

        assert_eq!(storage.get_source_value().to_string(), "new-src");
        assert_eq!(storage.get_destination_value().to_string(), "new-dst");

        let persisted = storage.association_manager.get_markup_item_record(storage.get_key()).unwrap();
        assert_eq!(persisted.get_string(ColumnDescription::SourceValueCol.column()), Some("src-val"));
    }

    /// Java: `reset()` removes the underlying markup-item record from the table. This port also
    /// marks `self` deleted in place of Java's type-swapping return value (see the module docs).
    ///
    /// Asserted via `markup_item_record_count` rather than `get_markup_item_record(key).is_none()`
    /// -- see [`AssociationDatabaseManager::markup_item_record_count`]'s docs for why.
    #[test]
    fn reset_removes_record_and_marks_self_deleted() {
        let mut storage = build_storage(1, 0, 0, 13, VtMarkupItemStatus::Unapplied);
        assert_eq!(storage.association_manager.markup_item_record_count(), 1);

        storage.reset();

        assert_eq!(storage.association_manager.markup_item_record_count(), 0);
        assert!(storage.state().is_deleted_flag());
    }

    /// `refresh(None)` re-fetches the current record from the association manager by key,
    /// mirroring `MarkupItemStorageDB.refresh(null)` falling back to
    /// `associationManager.getMarkupItemRecord(key)`.
    #[test]
    fn refresh_without_record_reloads_from_association_manager() {
        let storage = build_storage(1, 0, 0, 13, VtMarkupItemStatus::Unapplied);
        let mut newer = storage.record.lock().unwrap().clone();
        newer.set_byte(ColumnDescription::StatusCol.column(), status_ordinal(VtMarkupItemStatus::Rejected));
        storage.association_manager.update_markup_record(&newer);

        assert!(storage.refresh(None));
        assert_eq!(storage.get_status(), VtMarkupItemStatus::Rejected);
    }

    /// `refresh(None)` returns `false` when the backing record was never persisted, matching
    /// Java's `MarkupItemStorageDB.refresh` returning `false` when `getMarkupItemRecord` comes
    /// back null. (Exercised via a record that's never `update_markup_record`-ed rather than one
    /// that's persisted-then-removed, since `Table::delete_record`'s pre-existing gap -- see
    /// [`AssociationDatabaseManager::markup_item_record_count`]'s docs -- would leave the removed
    /// record visible to `get_record` anyway.)
    #[test]
    fn refresh_returns_false_when_record_was_never_persisted() {
        let (association_manager, record) =
            build_manager_and_record(1, 0, 0, 13, VtMarkupItemStatus::Unapplied);
        let storage = MarkupItemStorageDB::new(record, association_manager);

        assert!(!storage.refresh(None));
    }

    #[test]
    fn display_matches_java_tostring_shape() {
        let storage = build_storage(7, 0x10, 0x20, 12, VtMarkupItemStatus::Unapplied);
        let text = storage.to_string();

        assert!(text.starts_with('\n'));
        assert!(text.contains("MarkupItemStorageDB"));
        assert!(text.contains("Source Address"));
        assert!(text.contains("Dest Address"));
        assert!(text.contains("Association Key         = 7"));
    }
}

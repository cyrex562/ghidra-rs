//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

pub use crate::program::model::address::Address as AddressType;
pub use crate::feature::vt::api::markuptype::vt_markup_type::{VtMarkupType, VtMarkupTypeBase};
pub use crate::feature::vt::api::main::vt_association::VtAssociation;
pub use crate::feature::vt::api::main::vt_markup_item::VtMarkupItem;
pub use crate::feature::vt::api::main::vt_match::VtMatch;
pub use crate::feature::bsim::query::protocol::{QueryResponseRecord, QueryResponseRecordBase};
pub use crate::util::seam_stubs::XmlPullParser;

use crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage;
use crate::feature::vt::api::main::vt_association_markup_status::VtAssociationMarkupStatus;
use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
use crate::feature::vt::api::util::version_tracking_apply_exception::VersionTrackingApplyException;
use crate::framework::remote::User;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use std::sync::Arc;

/// Placeholder for `VTSession`.
pub trait VtSession: Send + Sync {
    fn get_name(&self) -> &str;
}

/// Placeholder for `ToolOptions`.
pub trait ToolOptions: Send + Sync {
    fn get_option(&self, key: &str) -> Option<String>;
}

/// Placeholder for `VTMarkupItemConsideredStatus`.
pub trait VtMarkupItemConsideredStatus: Send + Sync {
    fn is_considered(&self) -> bool;

    /// Java: `VTMarkupItemConsideredStatus.getMarkupItemStatus()`, the status
    /// `MarkupItemImpl.setConsidered` writes to the item's storage. Grown for the
    /// [`MarkupItemImpl`] port.
    fn get_markup_item_status(
        &self,
    ) -> crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus;
}

/// Placeholder for `ProgramLocation`.
pub trait ProgramLocation: Send + Sync {
    fn get_address(&self) -> AddressType;
}

/// Placeholder for `Stringable`.
pub trait Stringable: Send + Sync {
    fn to_string(&self) -> String;
}

/// Placeholder for the unported Java type `VTMatchInfo`, referenced by `VTMatchSet::add_match`.
/// `VTMatchInfo` is a concrete Java class (not an interface), so this stub is a struct rather
/// than a trait. Generated stub: shape hint only, no fields yet since nothing in the crate reads
/// them. Replace with the real port when available.
#[derive(Debug, Default, Clone)]
pub struct VtMatchInfo;

/// Placeholder for the unported Java type `VTMatchSet`, referenced by `VTSession`.
/// Generated stub: only a shape hint. `add_match`/`get_program_correlator_info` are omitted
/// pending ports of `VTMatchInfo`/`VTProgramCorrelatorInfo`, which have no known shape yet.
/// Replace with the real port when available.
pub trait VtMatchSet: Send + Sync {
    fn get_session(&self) -> Box<dyn VtSession>;
    fn get_matches(&self) -> Vec<Box<dyn VtMatch>>;
    fn get_match_count(&self) -> i32;
    fn get_id(&self) -> i32;
    fn delete_match(&self, match_item: &dyn VtMatch);
    fn remove_match(&self, match_item: &dyn VtMatch) -> bool;
    fn has_removable_matches(&self) -> bool;
}

/// Placeholder for the unported Java type `VTOptions`, referenced by `VTProgramCorrelatorFactory`.
/// `VTOptions` is a concrete Java class (not an interface), so this stub is a struct rather than a
/// trait. Generated stub: shape hint only, no fields yet since nothing in the crate reads them.
/// Replace with the real port when available.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct VtOptions;

/// Placeholder for the unported Java type `VTMatchTagDBAdapterV0`, referenced by
/// `VTMatchTagDBAdapterBase::create_adapter`/`get_adapter` in
/// `crate::feature::vt::api::main::db::vt_match_tag_db_adapter`. `VTMatchTagDBAdapterV0` is a
/// concrete Java class (not an interface), so this stub is a struct that implements the real
/// `VTMatchTagDBAdapter` trait using already-ported `Table`/`DBHandle` machinery. Replace with the
/// real port when `VTMatchTagDBAdapterV0.java` is ported.
pub struct VTMatchTagDBAdapterV0 {
    table: std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>>,
}

impl VTMatchTagDBAdapterV0 {
    pub fn create(
        db_handle: &mut crate::framework::db::DBHandle,
        table_name: &str,
        schema: std::sync::Arc<crate::framework::db::Schema>,
    ) -> std::io::Result<Self> {
        let table = db_handle.create_table(table_name.to_string(), schema)?;
        Ok(Self { table })
    }

    pub fn open(
        db_handle: &crate::framework::db::DBHandle,
        table_name: &str,
    ) -> Result<Self, crate::util::exception::VersionException> {
        let table = db_handle.get_table(table_name).ok_or_else(|| {
            crate::util::exception::VersionException::with_message(format!(
                "Missing Table: {table_name}"
            ))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(crate::util::exception::VersionException::with_message(format!(
                "Expected version 0 for table {table_name} but got {version}"
            )));
        }
        Ok(Self { table })
    }
}

/// Placeholder for the unported Java type `VTMatchInfo`, referenced by
/// `VTMatchTableDBAdapter::insert_match_record`. Trimmed to the accessors that
/// `VTMatchTableDBAdapterV0.insertMatchRecord` actually reads (similarity/confidence score,
/// source/destination length); see `VTMatchInfo.java` for the type's full public surface.
/// Replace with the real port when available.
pub trait VTMatchInfo: Send + Sync {
    fn get_similarity_score(&self) -> crate::feature::vt::api::main::vt_score::VtScore;
    fn get_confidence_score(&self) -> crate::feature::vt::api::main::vt_score::VtScore;
    fn get_source_length(&self) -> i32;
    fn get_destination_length(&self) -> i32;
}

/// Placeholder for the unported Java type `VTMatchSetDB`, referenced by
/// `VTMatchTableDBAdapter::insert_match_record`. The parameter is unused by
/// `VTMatchTableDBAdapterV0.insertMatchRecord` in the real Java implementation, so this stub
/// carries no members. Replace with the real port when available.
pub trait VTMatchSetDB: Send + Sync {}

/// Java: `VTAssociationStatus.values()[ordinal]`, mirroring the ported enum's declaration order
/// (the ported enum exposes no `ordinal()`, so the mapping is spelled out, matching
/// `VTAssociationTableDBAdapterV0`'s own hand-rolled mapping above).
pub fn association_status_from_ordinal(
    ordinal: i8,
) -> crate::feature::vt::api::main::vt_association_status::VtAssociationStatus {
    use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus as Status;
    match ordinal {
        0 => Status::Available,
        1 => Status::Accepted,
        2 => Status::Blocked,
        3 => Status::Rejected,
        other => panic!("invalid VTAssociationStatus ordinal {other}"),
    }
}

/// Java: `VTAssociationStatus.ordinal()`. Inverse of [`association_status_from_ordinal`].
pub fn association_status_ordinal(
    status: crate::feature::vt::api::main::vt_association_status::VtAssociationStatus,
) -> i8 {
    use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus as Status;
    match status {
        Status::Available => 0,
        Status::Accepted => 1,
        Status::Blocked => 2,
        Status::Rejected => 3,
    }
}

/// Java: `VTAssociationType.values()[ordinal]`.
pub fn association_type_from_ordinal(
    ordinal: i8,
) -> crate::feature::vt::api::main::vt_association_type::VtAssociationType {
    use crate::feature::vt::api::main::vt_association_type::VtAssociationType as Type;
    match ordinal {
        0 => Type::Function,
        1 => Type::Data,
        other => panic!("invalid VTAssociationType ordinal {other}"),
    }
}

/// Placeholder for the unported Java type `VTSessionDB`, the concrete session that owns an
/// [`AssociationDatabaseManager`](crate::feature::vt::api::main::db::association_database_manager::AssociationDatabaseManager).
/// `VTSessionDB` is a concrete Java class (`extends DomainObjectAdapterDB implements VTSession`),
/// but it sits on the far side of a dependency cycle from the manager, so it is stubbed here as a
/// trait: the manager only ever calls it, never constructs it, and a trait keeps the two ports
/// decoupled until the real class lands.
///
/// Trimmed to the members `AssociationDatabaseManager` (and, through it, `MarkupItemStorageDB`)
/// actually calls: the shared [`ReentrantLock`](crate::util::lock::ReentrantLock) both classes
/// guard their records with, the four address<->long translations, the two program accessors, the
/// `dbError` funnel every swallowed `IOException` goes through, and `setChanged`. Replace with the
/// real port when `VTSessionDB.java` is ported.
pub trait VTSessionDB: Send + Sync {
    /// Java: `VTSessionDB.getLock()`.
    fn get_lock(&self) -> std::sync::Arc<crate::util::lock::ReentrantLock>;

    /// Java: `DomainObjectAdapterDB.dbError(IOException)`, which wraps and rethrows. Ports that
    /// call it treat the failure as swallowed, matching how the Java callers here proceed.
    fn db_error(&self, error: std::io::Error);

    /// Java: `VTSessionDB.getSourceProgram()`.
    fn get_source_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::program::Program>;

    /// Java: `VTSessionDB.getDestinationProgram()`.
    fn get_destination_program(
        &self,
    ) -> std::sync::Arc<dyn crate::program::model::listing::program::Program>;

    /// Java: `VTSessionDB.getLongFromSourceAddress(Address)`.
    fn get_long_from_source_address(&self, address: &AddressType) -> i64;

    /// Java: `VTSessionDB.getLongFromDestinationAddress(Address)`.
    fn get_long_from_destination_address(&self, address: &AddressType) -> i64;

    /// Java: `VTSessionDB.getSourceAddressFromLong(long)`.
    fn get_source_address_from_long(&self, value: i64) -> AddressType;

    /// Java: `VTSessionDB.getDestinationAddressFromLong(long)`.
    fn get_destination_address_from_long(&self, value: i64) -> AddressType;

    /// Java: `VTSessionDB.setChanged(VTEvent, Object, Object)`. The generic `Object` values are
    /// narrowed to associations, which is all `AssociationDatabaseManager` ever passes.
    fn set_changed(
        &self,
        event_type: crate::feature::vt::api::implementation::vt_event::VtEvent,
        old_value: Option<
            std::sync::Arc<crate::feature::vt::api::db::vt_association_db::VTAssociationDB>,
        >,
        new_value: Option<
            std::sync::Arc<crate::feature::vt::api::db::vt_association_db::VTAssociationDB>,
        >,
    );

    /// Java: `setObjectChanged(VTEvent.MARKUP_ITEM_STATUS_CHANGED, markupItemStorage, oldStatus,
    /// newStatus)`, fired by `MarkupItemImpl.fireMarkupItemStatusChanged`. Narrowed to that one
    /// event the way [`set_changed`](Self::set_changed) above is narrowed to associations, with
    /// the affected object reported as the markup item rather than the storage behind it (the two
    /// are one-to-one, and the item is the handle every consumer can use). Defaulted to a no-op so
    /// existing implementors keep compiling.
    ///
    /// Grown for the [`MarkupItemImpl`] port.
    fn markup_item_status_changed(
        &self,
        markup_item: &dyn VtMarkupItem,
        old_status: crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus,
        new_status: crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus,
    ) {
        let _ = (markup_item, old_status, new_status);
    }

    /// Java: `setObjectChanged(VTEvent.MARKUP_ITEM_DESTINATION_CHANGED, markupItem,
    /// oldDestinationAddress, newDestinationAddress)`, fired by
    /// `MarkupItemImpl.doSetDestinationAddress`. See
    /// [`markup_item_status_changed`](Self::markup_item_status_changed).
    ///
    /// Grown for the [`MarkupItemImpl`] port.
    fn markup_item_destination_changed(
        &self,
        markup_item: &dyn VtMarkupItem,
        old_destination: Option<&AddressType>,
        new_destination: &AddressType,
    ) {
        let _ = (markup_item, old_destination, new_destination);
    }
}

/// Placeholder for the unported Java type `ghidra.feature.vt.api.util.VTAssociationStatusException`,
/// the checked exception `AssociationDatabaseManager.setAssociationAccepted`/
/// `clearAcceptedAssociation` throw when a status transition is not legal. The Java class carries
/// nothing but its message. Replace with the real port when `VTAssociationStatusException.java` is
/// ported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VTAssociationStatusException {
    message: String,
}

impl VTAssociationStatusException {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for VTAssociationStatusException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VTAssociationStatusException {}

/// Placeholder for the unported Java type `MarkupItemStorageImpl`, the purely in-memory
/// [`MarkupItemStorage`] that [`MarkupItemImpl::new`] builds for a markup item that has no
/// database row yet.
///
/// `MarkupItemStorageImpl` is a concrete Java class (not an interface), so this stub is a struct
/// implementing the already-ported [`MarkupItemStorage`] trait. One deliberate deviation, forced
/// by that trait's signatures: in Java each setter returns a `MarkupItemStorage` and returns
/// `associationDBM.addMarkupItem(this)` -- i.e. it *promotes* the item into the database and hands
/// back a `MarkupItemStorageDB` in its place. The ported setters return `()` and cannot swap the
/// caller's storage for one of a different concrete type, so this stub records the change in
/// memory only; the promotion is left for the real port. Replace with the real port when
/// `MarkupItemStorageImpl.java` is ported.
pub struct MarkupItemStorageImpl {
    association: std::sync::Arc<dyn VtAssociation>,
    markup_type: std::sync::Arc<dyn VtMarkupType>,
    source_address: AddressType,
    destination_address: std::sync::Mutex<Option<AddressType>>,
    destination_address_source: std::sync::Mutex<Option<String>>,
    status: std::sync::Mutex<crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus>,
    status_description: std::sync::Mutex<Option<String>>,
    source_value: std::sync::Mutex<Option<String>>,
    destination_value: std::sync::Mutex<Option<String>>,
}

impl MarkupItemStorageImpl {
    /// Java: `MarkupItemStorageImpl(VTAssociation, VTMarkupType, Address)`, which delegates to the
    /// five-argument constructor with a null destination address and address source.
    pub fn new(
        association: std::sync::Arc<dyn VtAssociation>,
        markup_type: std::sync::Arc<dyn VtMarkupType>,
        source_address: AddressType,
    ) -> Self {
        Self::with_destination(association, markup_type, source_address, None, None)
    }

    /// Java: `MarkupItemStorageImpl(VTAssociation, VTMarkupType, Address, Address, String)`.
    pub fn with_destination(
        association: std::sync::Arc<dyn VtAssociation>,
        markup_type: std::sync::Arc<dyn VtMarkupType>,
        source_address: AddressType,
        destination_address: Option<AddressType>,
        destination_address_source: Option<String>,
    ) -> Self {
        Self {
            association,
            markup_type,
            source_address,
            destination_address: std::sync::Mutex::new(destination_address),
            destination_address_source: std::sync::Mutex::new(destination_address_source),
            status: std::sync::Mutex::new(
                crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus::Unapplied,
            ),
            status_description: std::sync::Mutex::new(None),
            source_value: std::sync::Mutex::new(None),
            destination_value: std::sync::Mutex::new(None),
        }
    }
}

impl MarkupItemStorage for MarkupItemStorageImpl {
    fn get_markup_type(&self) -> Box<dyn VtMarkupType> {
        Box::new(self.markup_type.clone())
    }

    fn get_association(&self) -> Box<dyn VtAssociation> {
        Box::new(ArcVtAssociation(self.association.clone()))
    }

    fn get_source_address(&self) -> AddressType {
        self.source_address.clone()
    }

    fn has_destination_address(&self) -> bool {
        self.destination_address.lock().unwrap().is_some()
    }

    fn get_destination_address(&self) -> AddressType {
        self.destination_address
            .lock()
            .unwrap()
            .clone()
            .expect("MarkupItemStorageImpl has no destination address; check has_destination_address")
    }

    fn get_destination_address_source(&self) -> String {
        self.destination_address_source.lock().unwrap().clone().unwrap_or_default()
    }

    fn get_status(&self) -> crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus {
        *self.status.lock().unwrap()
    }

    fn get_status_description(&self) -> String {
        self.status_description.lock().unwrap().clone().unwrap_or_default()
    }

    fn get_source_value(&self) -> Box<dyn Stringable> {
        Box::new(PlainStringable(self.source_value.lock().unwrap().clone().unwrap_or_default()))
    }

    fn get_destination_value(&self) -> Box<dyn Stringable> {
        Box::new(PlainStringable(self.destination_value.lock().unwrap().clone().unwrap_or_default()))
    }

    fn set_status(
        &mut self,
        status: crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus,
    ) {
        *self.status.lock().unwrap() = status;
    }

    fn reset(&mut self) {
        // Java: `reset()` returns `this` -- an in-memory item has no database row to drop.
    }

    fn set_destination_address(&mut self, address: AddressType, address_source: String) {
        *self.destination_address.lock().unwrap() = Some(address);
        *self.destination_address_source.lock().unwrap() = Some(address_source);
    }

    fn set_apply_failed(&mut self, message: String) {
        *self.status.lock().unwrap() =
            crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus::FailedApply;
        *self.status_description.lock().unwrap() = Some(message);
    }

    fn set_source_destination_values(
        &mut self,
        source_value: Box<dyn Stringable>,
        destination_value: Box<dyn Stringable>,
    ) {
        *self.source_value.lock().unwrap() = Some(source_value.to_string());
        *self.destination_value.lock().unwrap() = Some(destination_value.to_string());
    }
}

/// Hands a shared [`VtAssociation`] back as the owned `Box<dyn VtAssociation>` that
/// [`MarkupItemStorage::get_association`] returns, without requiring `Clone` on the trait. Mirrors
/// the wrapper `MarkupItemStorageDB` uses for the same purpose.
struct ArcVtAssociation(std::sync::Arc<dyn VtAssociation>);

impl VtAssociation for ArcVtAssociation {
    fn get_type(&self) -> VtAssociationType {
        self.0.get_type()
    }

    fn get_session(&self) -> Box<dyn crate::feature::vt::api::main::vt_session::VTSession> {
        self.0.get_session()
    }

    fn get_markup_items(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<Box<dyn VtMarkupItem>>, CancelledException> {
        self.0.get_markup_items(monitor)
    }

    fn has_applied_markup_items(&self) -> bool {
        self.0.has_applied_markup_items()
    }

    fn get_source_address(&self) -> AddressType {
        self.0.get_source_address()
    }

    fn get_destination_address(&self) -> AddressType {
        self.0.get_destination_address()
    }

    fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>> {
        self.0.get_related_associations()
    }

    fn set_markup_status(&self, markup_items_status: VtAssociationMarkupStatus) {
        self.0.set_markup_status(markup_items_status)
    }

    fn get_markup_status(&self) -> VtAssociationMarkupStatus {
        self.0.get_markup_status()
    }

    fn get_status(&self) -> VtAssociationStatus {
        self.0.get_status()
    }

    fn set_accepted(&self) -> Result<(), VTAssociationStatusException> {
        self.0.set_accepted()
    }

    fn clear_status(&self) -> Result<(), VTAssociationStatusException> {
        self.0.clear_status()
    }

    fn set_rejected(&self) -> Result<(), VTAssociationStatusException> {
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

    fn get_session_db(&self) -> Option<std::sync::Arc<dyn VTSessionDB>> {
        self.0.get_session_db()
    }

    fn markup_item_status_changed(&self, markup_item: &dyn VtMarkupItem) {
        self.0.markup_item_status_changed(markup_item)
    }
}

/// The minimal [`Stringable`] this file needs: a value that is already just its rendered string.
/// Mirrors `MarkupItemStorageDB`'s `RawStringable`.
struct PlainStringable(String);

impl Stringable for PlainStringable {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

/// Placeholder for the unported Java type `VTMatchTagDB`, referenced by
/// `VTMatchTableDBAdapter::insert_match_record`. Trimmed to `get_key`, the (inherited
/// `DBAnnotatedObject`) accessor that `VTMatchTableDBAdapterV0.insertMatchRecord` actually reads;
/// see `VTMatchTagDB.java` for the type's full public surface. Replace with the real port when
/// available.
pub trait VTMatchTagDB: Send + Sync {
    fn get_key(&self) -> i64;
}

/// Placeholder for the unported Java type `VTMatchTableDBAdapterV0`, referenced by
/// `VTMatchTableDBAdapterBase::create_adapter`/`get_adapter` in
/// `crate::feature::vt::api::main::db::vt_match_table_db_adapter`. `VTMatchTableDBAdapterV0` is a
/// concrete Java class (not an interface), so this stub is a struct that implements the real
/// `VTMatchTableDBAdapter` trait using already-ported `Table`/`DBHandle` machinery. Replace with
/// the real port when `VTMatchTableDBAdapterV0.java` is ported.
pub struct VTMatchTableDBAdapterV0 {
    table: std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>>,
}

impl VTMatchTableDBAdapterV0 {
    pub fn create(
        db_handle: &mut crate::framework::db::DBHandle,
        table_name: &str,
        schema: std::sync::Arc<crate::framework::db::Schema>,
    ) -> std::io::Result<Self> {
        let table = db_handle.create_table(table_name.to_string(), schema)?;
        Ok(Self { table })
    }

    pub fn open(
        db_handle: &crate::framework::db::DBHandle,
        table_name: &str,
    ) -> Result<Self, crate::util::exception::VersionException> {
        let table = db_handle.get_table(table_name).ok_or_else(|| {
            crate::util::exception::VersionException::with_message(format!(
                "Missing Table: {table_name}"
            ))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(crate::util::exception::VersionException::with_message(format!(
                "Expected version 0 for table {table_name} but got {version}"
            )));
        }
        Ok(Self { table })
    }
}

impl crate::feature::vt::api::main::db::vt_match_table_db_adapter::VTMatchTableDBAdapter
    for VTMatchTableDBAdapterV0
{
    fn insert_match_record(
        &self,
        info: &dyn VTMatchInfo,
        _match_set: &dyn VTMatchSetDB,
        association: &crate::feature::vt::api::db::vt_association_db::VTAssociationDB,
        tag: Option<&dyn VTMatchTagDB>,
    ) -> std::io::Result<crate::framework::db::DBRecord> {
        use crate::feature::vt::api::main::db::vt_match_table_db_adapter::ColumnDescription;

        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let schema = table.get_schema();
        let mut record = crate::framework::db::DBRecord::new(
            schema,
            crate::framework::db::Field::Long(Some(key)),
        );
        record.set_long(ColumnDescription::TagKeyCol.column(), tag.map_or(-1, |t| t.get_key()));
        record.set_string(
            ColumnDescription::SimilarityScoreCol.column(),
            Some(info.get_similarity_score().to_storage_string()),
        );
        record.set_string(
            ColumnDescription::ConfidenceScoreCol.column(),
            Some(info.get_confidence_score().to_storage_string()),
        );
        record.set_long(ColumnDescription::AssociationCol.column(), association.get_key());
        record.set_int(ColumnDescription::SourceLengthCol.column(), info.get_source_length());
        record.set_int(
            ColumnDescription::DestinationLengthCol.column(),
            info.get_destination_length(),
        );

        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_records(&self) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            records.push(record);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_match_record(
        &self,
        match_record_key: i64,
    ) -> std::io::Result<Option<crate::framework::db::DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&crate::framework::db::Field::Long(Some(match_record_key)))
    }

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }

    fn update_record(&self, record: &crate::framework::db::DBRecord) -> std::io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn delete_record(&self, match_record_key: i64) -> std::io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&crate::framework::db::Field::Long(Some(match_record_key)))
    }

    fn get_records_for_association(
        &self,
        association_id: i64,
    ) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        use crate::feature::vt::api::main::db::vt_match_table_db_adapter::ColumnDescription;

        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            if record.get_long(ColumnDescription::AssociationCol.column()) == Some(association_id)
            {
                records.push(record);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }
}

/// Owned (non-borrowing) record iterator used by [`VTMatchTagDBAdapterV0::get_records`], since
/// `Table::get_record_iterator` borrows the `RwLockReadGuard` it is called on.
struct VecRecordIterator {
    records: std::vec::IntoIter<crate::framework::db::DBRecord>,
}

impl crate::framework::db::RecordIterator for VecRecordIterator {
    fn next(&mut self) -> std::io::Result<Option<crate::framework::db::DBRecord>> {
        Ok(self.records.next())
    }
    fn has_next(&self) -> bool {
        self.records.len() > 0
    }
}

impl crate::feature::vt::api::main::db::vt_match_tag_db_adapter::VTMatchTagDBAdapter
    for VTMatchTagDBAdapterV0
{
    fn insert_record(&self, tag_name: &str) -> std::io::Result<crate::framework::db::DBRecord> {
        if tag_name.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot create an empty string tag",
            ));
        }

        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let schema = table.get_schema();
        let mut record = crate::framework::db::DBRecord::new(
            schema,
            crate::framework::db::Field::Long(Some(key)),
        );
        record.set_string(
            crate::feature::vt::api::main::db::vt_match_tag_db_adapter::ColumnDescription::TagNameCol
                .column(),
            Some(tag_name.to_string()),
        );
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_records(
        &self,
    ) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            records.push(record);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_record(
        &self,
        tag_record_key: i64,
    ) -> std::io::Result<Option<crate::framework::db::DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&crate::framework::db::Field::Long(Some(tag_record_key)))
    }

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }

    fn update_record(&self, record: &crate::framework::db::DBRecord) -> std::io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn delete_record(&self, tag_record_key: i64) -> std::io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&crate::framework::db::Field::Long(Some(tag_record_key)))
    }
}

/// Placeholder for the unported Java type `VTMatchSetTableDBAdapterV0`, referenced by
/// `VTMatchSetTableDBAdapterBase::create_adapter`/`get_adapter` in
/// `crate::feature::vt::api::main::db::vt_match_set_table_db_adapter`. `VTMatchSetTableDBAdapterV0`
/// is a concrete Java class (not an interface), so this stub is a struct that implements the real
/// `VTMatchSetTableDBAdapter` trait using already-ported `Table`/`DBHandle` machinery.
///
/// Two simplifications versus the real Java `VTMatchSetTableDBAdapterV0`:
///   - `CORRELATOR_CLASS_COL` stores the correlator's display name (`get_name()`) rather than a
///     reflected Java class name, since `VTProgramCorrelator` (the already-ported trait) has no
///     class-name accessor.
///   - `create_match_set_record` does not persist the source/destination address-range sub-tables
///     that the Java version writes via `program.getAddressMap()`, since the ported `Program`
///     trait does not yet expose an address map accessor; `get_source_address_set` /
///     `get_destination_address_set` still read those tables back correctly if/when something
///     populates them.
/// Replace with the real port when `VTMatchSetTableDBAdapterV0.java` is ported.
pub struct VTMatchSetTableDBAdapterV0 {
    db_handle: std::sync::Arc<std::sync::RwLock<crate::framework::db::DBHandle>>,
    table: std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>>,
}

impl VTMatchSetTableDBAdapterV0 {
    pub fn create(
        db_handle: std::sync::Arc<std::sync::RwLock<crate::framework::db::DBHandle>>,
        table_name: &str,
        schema: std::sync::Arc<crate::framework::db::Schema>,
    ) -> std::io::Result<Self> {
        let table = db_handle
            .write()
            .unwrap()
            .create_table(table_name.to_string(), schema)?;
        Ok(Self { db_handle, table })
    }

    pub fn open(
        db_handle: std::sync::Arc<std::sync::RwLock<crate::framework::db::DBHandle>>,
        table_name: &str,
    ) -> Result<Self, crate::util::exception::VersionException> {
        let table = {
            let dbh = db_handle.read().unwrap();
            dbh.get_table(table_name).ok_or_else(|| {
                crate::util::exception::VersionException::with_message(format!(
                    "Missing Table: {table_name}"
                ))
            })?
        };
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(crate::util::exception::VersionException::with_message(format!(
                "Expected version 0 for table {table_name} but got {version}"
            )));
        }
        Ok(Self { db_handle, table })
    }

    fn source_table_name(record: &crate::framework::db::DBRecord) -> String {
        format!("Source Address Set {}", record.get_key().get_long_value())
    }

    fn destination_table_name(record: &crate::framework::db::DBRecord) -> String {
        format!("Destination Address Set {}", record.get_key().get_long_value())
    }

    fn read_address_set(
        &self,
        table_name: &str,
        address_map: &dyn crate::program::database::map::address_map::AddressMap,
    ) -> std::io::Result<Option<crate::program::model::address::AddressSet>> {
        let addr_table = {
            let dbh = self.db_handle.read().unwrap();
            match dbh.get_table(table_name) {
                Some(t) => t,
                None => return Ok(None),
            }
        };

        let mut address_set = crate::program::model::address::AddressSet::new();
        let table = addr_table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            let addr1 = address_map.decode_address(rec.get_long(0).unwrap_or(0));
            let addr2 = address_map.decode_address(rec.get_long(1).unwrap_or(0));
            address_set.add_range(&addr1, &addr2);
        }
        Ok(Some(address_set))
    }
}

impl crate::feature::vt::api::main::db::vt_match_set_table_db_adapter::VTMatchSetTableDBAdapter
    for VTMatchSetTableDBAdapterV0
{
    fn create_match_set_record(
        &self,
        key: i64,
        correlator: &dyn crate::feature::vt::api::main::vt_program_correlator::VTProgramCorrelator,
    ) -> std::io::Result<crate::framework::db::DBRecord> {
        use crate::feature::vt::api::main::db::vt_match_set_table_db_adapter::ColumnDescription;

        let mut table = self.table.write().unwrap();
        let schema = table.get_schema();
        let mut record = crate::framework::db::DBRecord::new(
            schema,
            crate::framework::db::Field::Long(Some(key)),
        );
        record.set_string(
            ColumnDescription::CorrelatorClassCol.column(),
            Some(correlator.get_name()),
        );
        record.set_string(
            ColumnDescription::CorrelatorNameCol.column(),
            Some(correlator.get_name()),
        );
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_records(&self) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            records.push(record);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_source_address_set(
        &self,
        record: &crate::framework::db::DBRecord,
        address_map: &dyn crate::program::database::map::address_map::AddressMap,
    ) -> std::io::Result<Option<crate::program::model::address::AddressSet>> {
        self.read_address_set(&Self::source_table_name(record), address_map)
    }

    fn get_destination_address_set(
        &self,
        record: &crate::framework::db::DBRecord,
        address_map: &dyn crate::program::database::map::address_map::AddressMap,
    ) -> std::io::Result<Option<crate::program::model::address::AddressSet>> {
        self.read_address_set(&Self::destination_table_name(record), address_map)
    }

    fn get_next_match_set_id(&self) -> i64 {
        self.table.write().unwrap().get_next_key()
    }

    fn get_record(&self, key: i64) -> std::io::Result<Option<crate::framework::db::DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&crate::framework::db::Field::Long(Some(key)))
    }
}

/// Placeholder for the unported Java type `VTAssociationTableDBAdapterV0`, referenced by
/// `VTAssociationTableDBAdapterBase::create_adapter`/`get_adapter` in
/// `crate::feature::vt::api::main::db::vt_association_table_db_adapter`.
/// `VTAssociationTableDBAdapterV0` is a concrete Java class (not an interface), so this stub is a
/// struct that implements the real `VTAssociationTableDBAdapter` trait using already-ported
/// `Table`/`DBHandle` machinery. `getRecordsForSourceAddress`/`getRecordsForDestinationAddress`
/// use `Table.indexIterator` in the real Java implementation; since the ported `Table` has no
/// field-index support yet, these scan and filter instead (same simplification already used by
/// `VTMatchTableDBAdapterV0::get_records_for_association` above). Replace with the real port when
/// `VTAssociationTableDBAdapterV0.java` is ported.
pub struct VTAssociationTableDBAdapterV0 {
    table: std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>>,
}

impl VTAssociationTableDBAdapterV0 {
    pub fn create(
        db_handle: &mut crate::framework::db::DBHandle,
        table_name: &str,
        schema: std::sync::Arc<crate::framework::db::Schema>,
    ) -> std::io::Result<Self> {
        let table = db_handle.create_table(table_name.to_string(), schema)?;
        Ok(Self { table })
    }

    pub fn open(
        db_handle: &crate::framework::db::DBHandle,
        table_name: &str,
    ) -> Result<Self, crate::util::exception::VersionException> {
        let table = db_handle.get_table(table_name).ok_or_else(|| {
            crate::util::exception::VersionException::with_message(format!(
                "Missing Table: {table_name}"
            ))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(crate::util::exception::VersionException::with_message(format!(
                "Expected version 0 for table {table_name} but got {version}"
            )));
        }
        Ok(Self { table })
    }

    fn scan_by_long_column(
        &self,
        column: usize,
        value: i64,
    ) -> std::io::Result<Vec<crate::framework::db::DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            if record.get_long(column) == Some(value) {
                records.push(record);
            }
        }
        Ok(records)
    }
}

impl crate::feature::vt::api::main::db::vt_association_table_db_adapter::VTAssociationTableDBAdapter
    for VTAssociationTableDBAdapterV0
{
    fn insert_record(
        &self,
        source_address_id: i64,
        destination_address_id: i64,
        association_type: crate::feature::vt::api::main::vt_association_type::VtAssociationType,
        status: crate::feature::vt::api::main::vt_association_status::VtAssociationStatus,
        vote_count: i32,
    ) -> std::io::Result<crate::framework::db::DBRecord> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;
        use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
        use crate::feature::vt::api::main::vt_association_type::VtAssociationType;

        // Java: `type.ordinal()` / `lockedStatus.ordinal()`. Neither ported enum exposes an
        // `ordinal()` accessor, so the enum-declaration order is mirrored here by hand.
        let type_ordinal: i8 = match association_type {
            VtAssociationType::Function => 0,
            VtAssociationType::Data => 1,
        };
        let status_ordinal: i8 = match status {
            VtAssociationStatus::Available => 0,
            VtAssociationStatus::Accepted => 1,
            VtAssociationStatus::Blocked => 2,
            VtAssociationStatus::Rejected => 3,
        };

        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let schema = table.get_schema();
        let mut record = crate::framework::db::DBRecord::new(
            schema,
            crate::framework::db::Field::Long(Some(key)),
        );
        record.set_long(ColumnDescription::SourceAddressCol.column(), source_address_id);
        record.set_long(ColumnDescription::DestinationAddressCol.column(), destination_address_id);
        record.set_byte(ColumnDescription::TypeCol.column(), type_ordinal);
        record.set_byte(ColumnDescription::StatusCol.column(), status_ordinal);
        record.set_int(ColumnDescription::VoteCountCol.column(), vote_count);

        table.put_record(record.clone())?;
        Ok(record)
    }

    fn delete_record(&self, key: i64) -> std::io::Result<()> {
        self.table
            .write()
            .unwrap()
            .delete_record(&crate::framework::db::Field::Long(Some(key)))?;
        Ok(())
    }

    fn get_records_for_source_address(
        &self,
        address_id: i64,
    ) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;

        let records =
            self.scan_by_long_column(ColumnDescription::SourceAddressCol.column(), address_id)?;
        Ok(Box::new(VecRecordIterator { records: records.into_iter() }))
    }

    fn get_records_for_destination_address(
        &self,
        address_id: i64,
    ) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;

        let records = self
            .scan_by_long_column(ColumnDescription::DestinationAddressCol.column(), address_id)?;
        Ok(Box::new(VecRecordIterator { records: records.into_iter() }))
    }

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }

    fn get_records(&self) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            records.push(record);
        }
        Ok(Box::new(VecRecordIterator { records: records.into_iter() }))
    }

    fn get_record(&self, key: i64) -> std::io::Result<Option<crate::framework::db::DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&crate::framework::db::Field::Long(Some(key)))
    }

    fn get_related_association_records_by_source_and_destination_address(
        &self,
        source_address_id: i64,
        destination_address_id: i64,
    ) -> std::io::Result<Vec<crate::framework::db::DBRecord>> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;

        let mut records =
            self.scan_by_long_column(ColumnDescription::SourceAddressCol.column(), source_address_id)?;
        records.extend(self.scan_by_long_column(
            ColumnDescription::DestinationAddressCol.column(),
            destination_address_id,
        )?);
        dedupe_records_by_key(&mut records);
        Ok(records)
    }

    fn get_related_association_records_by_source_address(
        &self,
        source_address_id: i64,
    ) -> std::io::Result<Vec<crate::framework::db::DBRecord>> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;

        let mut records =
            self.scan_by_long_column(ColumnDescription::SourceAddressCol.column(), source_address_id)?;
        dedupe_records_by_key(&mut records);
        Ok(records)
    }

    fn get_related_association_records_by_destination_address(
        &self,
        destination_address_id: i64,
    ) -> std::io::Result<Vec<crate::framework::db::DBRecord>> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;

        let mut records = self.scan_by_long_column(
            ColumnDescription::DestinationAddressCol.column(),
            destination_address_id,
        )?;
        dedupe_records_by_key(&mut records);
        Ok(records)
    }

    fn update_record(&self, record: &crate::framework::db::DBRecord) -> std::io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn remove_association(&self, id: i64) -> std::io::Result<()> {
        self.table
            .write()
            .unwrap()
            .delete_record(&crate::framework::db::Field::Long(Some(id)))?;
        Ok(())
    }
}

/// Java: `HashSet<DBRecord>` construction, where `DBRecord.equals()`/`hashCode()` compare by key
/// (see `db.DBRecord`). Deduplicates by primary key, which is equivalent here since two records
/// sharing a key are necessarily the same row.
fn dedupe_records_by_key(records: &mut Vec<crate::framework::db::DBRecord>) {
    let mut seen = std::collections::HashSet::new();
    records.retain(|r| seen.insert(r.get_key().get_long_value()));
}

/// Placeholder for the unported Java type `VTAddressCorrelationAdapterV0`, referenced by
/// `VTAddressCorrelatorAdapterBase::create_adapter`/`get_adapter` in
/// `crate::feature::vt::api::main::db::vt_address_correlator_adapter`.
/// `VTAddressCorrelationAdapterV0` is a concrete Java class (not an interface), so this stub is a
/// struct that implements the real `VTAddressCorrelatorAdapter` trait using already-ported
/// `Table`/`DBHandle` machinery. Replace with the real port when
/// `VTAddressCorrelationAdapterV0.java` is ported.
pub struct VTAddressCorrelationAdapterV0 {
    base: crate::feature::vt::api::main::db::vt_address_correlator_adapter::VTAddressCorrelatorAdapterBase,
    table: std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>>,
}

impl VTAddressCorrelationAdapterV0 {
    pub fn create(
        db_handle: std::sync::Arc<std::sync::RwLock<crate::framework::db::DBHandle>>,
        table_name: &str,
        schema: std::sync::Arc<crate::framework::db::Schema>,
    ) -> std::io::Result<Self> {
        let table = db_handle
            .write()
            .unwrap()
            .create_table(table_name.to_string(), schema)?;
        Ok(Self {
            base: crate::feature::vt::api::main::db::vt_address_correlator_adapter::VTAddressCorrelatorAdapterBase::new(db_handle),
            table,
        })
    }

    pub fn open(
        db_handle: std::sync::Arc<std::sync::RwLock<crate::framework::db::DBHandle>>,
        table_name: &str,
    ) -> Result<Self, crate::util::exception::VersionException> {
        let table = {
            let dbh = db_handle.read().unwrap();
            dbh.get_table(table_name).ok_or_else(|| {
                crate::util::exception::VersionException::with_message(format!(
                    "Missing Table: {table_name}"
                ))
            })?
        };
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(crate::util::exception::VersionException::with_message(format!(
                "Expected version 0 for table {table_name} but got {version}"
            )));
        }
        Ok(Self {
            base: crate::feature::vt::api::main::db::vt_address_correlator_adapter::VTAddressCorrelatorAdapterBase::new(db_handle),
            table,
        })
    }
}

impl crate::feature::vt::api::main::db::vt_address_correlator_adapter::VTAddressCorrelatorAdapter
    for VTAddressCorrelationAdapterV0
{
    fn base(
        &self,
    ) -> &crate::feature::vt::api::main::db::vt_address_correlator_adapter::VTAddressCorrelatorAdapterBase
    {
        &self.base
    }

    fn create_address_record(
        &self,
        _source_entry_long: i64,
        source_long: i64,
        destination_long: i64,
    ) -> std::io::Result<()> {
        use crate::feature::vt::api::main::db::vt_address_correlator_adapter::ColumnDescription;

        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let schema = table.get_schema();
        let mut record = crate::framework::db::DBRecord::new(
            schema,
            crate::framework::db::Field::Long(Some(key)),
        );
        // Faithful port of the Java source: SOURCE_ENTRY_COL is populated with `source_long`,
        // not `source_entry_long` -- see `VTAddressCorrelationAdapterV0.createAddressRecord`.
        record.set_long(ColumnDescription::SourceEntryCol.column(), source_long);
        record.set_long(ColumnDescription::SourceAddressCol.column(), source_long);
        record.set_long(ColumnDescription::DestinationAddressCol.column(), destination_long);

        table.put_record(record)
    }

    fn get_address_records(
        &self,
        source_entry_long: i64,
    ) -> std::io::Result<Vec<crate::framework::db::DBRecord>> {
        use crate::feature::vt::api::main::db::vt_address_correlator_adapter::ColumnDescription;

        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            if record.get_long(ColumnDescription::SourceEntryCol.column()) == Some(source_entry_long)
            {
                records.push(record);
            }
        }
        Ok(records)
    }
}


/// Placeholder for the unported Java type `EolCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). `EolCommentMarkupType`
/// is a concrete Java class (not an interface), so this is a unit struct rather than a trait.
/// Trimmed to implementing the already-ported [`VtMarkupType`] trait with the display name read
/// off the Java constructor (`super("EOL Comment")`), since that is all the factory needs.
/// Replace with the real port when `EolCommentMarkupType.java` is ported.
pub struct EolCommentMarkupType {
    base: VtMarkupTypeBase,
}

impl EolCommentMarkupType {
    pub fn new() -> Self {
        Self { base: VtMarkupTypeBase::new("EOL Comment") }
    }
}

impl Default for EolCommentMarkupType {
    fn default() -> Self {
        Self::new()
    }
}

impl VtMarkupType for EolCommentMarkupType {
    fn base(&self) -> &VtMarkupTypeBase {
        &self.base
    }
}

/// Placeholder for the unported Java type `FunctionNameMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `FunctionNameMarkupType.java` is ported.
pub struct FunctionNameMarkupType {
    base: VtMarkupTypeBase,
}

impl FunctionNameMarkupType {
    pub fn new() -> Self {
        Self { base: VtMarkupTypeBase::new("Function Name") }
    }
}

impl Default for FunctionNameMarkupType {
    fn default() -> Self {
        Self::new()
    }
}

impl VtMarkupType for FunctionNameMarkupType {
    fn base(&self) -> &VtMarkupTypeBase {
        &self.base
    }

    /// Java: `FunctionNameMarkupType extends FunctionEntryPointBasedAbstractMarkupType`.
    fn is_function_entry_point_based(&self) -> bool {
        true
    }
}

/// Placeholder for the unported Java type `FunctionSignatureMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `FunctionSignatureMarkupType.java` is ported.
pub struct FunctionSignatureMarkupType {
    base: VtMarkupTypeBase,
}

impl FunctionSignatureMarkupType {
    pub fn new() -> Self {
        Self { base: VtMarkupTypeBase::new("Function Signature") }
    }
}

impl Default for FunctionSignatureMarkupType {
    fn default() -> Self {
        Self::new()
    }
}

impl VtMarkupType for FunctionSignatureMarkupType {
    fn base(&self) -> &VtMarkupTypeBase {
        &self.base
    }

    /// Java: `FunctionSignatureMarkupType extends FunctionEntryPointBasedAbstractMarkupType`.
    fn is_function_entry_point_based(&self) -> bool {
        true
    }
}

/// Placeholder for the unported Java type `LabelMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `LabelMarkupType.java` is ported.
pub struct LabelMarkupType {
    base: VtMarkupTypeBase,
}

impl LabelMarkupType {
    pub fn new() -> Self {
        Self { base: VtMarkupTypeBase::new("Label") }
    }
}

impl Default for LabelMarkupType {
    fn default() -> Self {
        Self::new()
    }
}

impl VtMarkupType for LabelMarkupType {
    fn base(&self) -> &VtMarkupTypeBase {
        &self.base
    }
}

/// Placeholder for the unported Java type `PlateCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `PlateCommentMarkupType.java` is ported.
pub struct PlateCommentMarkupType {
    base: VtMarkupTypeBase,
}

impl PlateCommentMarkupType {
    pub fn new() -> Self {
        Self { base: VtMarkupTypeBase::new("Plate Comment") }
    }
}

impl Default for PlateCommentMarkupType {
    fn default() -> Self {
        Self::new()
    }
}

impl VtMarkupType for PlateCommentMarkupType {
    fn base(&self) -> &VtMarkupTypeBase {
        &self.base
    }
}

/// Placeholder for the unported Java type `PostCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `PostCommentMarkupType.java` is ported.
pub struct PostCommentMarkupType {
    base: VtMarkupTypeBase,
}

impl PostCommentMarkupType {
    pub fn new() -> Self {
        Self { base: VtMarkupTypeBase::new("Post Comment") }
    }
}

impl Default for PostCommentMarkupType {
    fn default() -> Self {
        Self::new()
    }
}

impl VtMarkupType for PostCommentMarkupType {
    fn base(&self) -> &VtMarkupTypeBase {
        &self.base
    }
}

/// Placeholder for the unported Java type `PreCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `PreCommentMarkupType.java` is ported.
pub struct PreCommentMarkupType {
    base: VtMarkupTypeBase,
}

impl PreCommentMarkupType {
    pub fn new() -> Self {
        Self { base: VtMarkupTypeBase::new("Pre Comment") }
    }
}

impl Default for PreCommentMarkupType {
    fn default() -> Self {
        Self::new()
    }
}

impl VtMarkupType for PreCommentMarkupType {
    fn base(&self) -> &VtMarkupTypeBase {
        &self.base
    }
}

/// Placeholder for the unported Java type `RepeatableCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `RepeatableCommentMarkupType.java` is ported.
pub struct RepeatableCommentMarkupType {
    base: VtMarkupTypeBase,
}

impl RepeatableCommentMarkupType {
    pub fn new() -> Self {
        Self { base: VtMarkupTypeBase::new("Repeatable Comment") }
    }
}

impl Default for RepeatableCommentMarkupType {
    fn default() -> Self {
        Self::new()
    }
}

impl VtMarkupType for RepeatableCommentMarkupType {
    fn base(&self) -> &VtMarkupTypeBase {
        &self.base
    }
}

/// Placeholder for the unported Java type `DataTypeMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `DataTypeMarkupType.java` is ported.
pub struct DataTypeMarkupType {
    base: VtMarkupTypeBase,
}

impl DataTypeMarkupType {
    pub fn new() -> Self {
        Self { base: VtMarkupTypeBase::new("Data Type") }
    }
}

impl Default for DataTypeMarkupType {
    fn default() -> Self {
        Self::new()
    }
}

impl VtMarkupType for DataTypeMarkupType {
    fn base(&self) -> &VtMarkupTypeBase {
        &self.base
    }

    /// Java: the `type instanceof DataTypeMarkupType` branch of
    /// `MarkupItemImpl.getDestinationAddressEditStatus()`.
    fn is_data_type_based(&self) -> bool {
        true
    }
}

/// Placeholder for the unported Java type `ghidra.app.util.dialog.CheckoutDialog`, referenced by
/// `do_optional_destination_program_checkout` in
/// [`vt_session_file_util`](crate::feature::vt::api::util::vt_session_file_util). Minimal
/// placeholder: only the members that call site needs. The real `CheckoutDialog` blocks on a
/// Swing modal dialog asking the user whether to check out a file; this port has no GUI to show
/// one, so [`show_dialog`](Self::show_dialog) always reports [`CANCEL`](Self::CANCEL) and no
/// checkout is ever attempted. Replace with the real port once a GUI layer exists.
pub struct CheckoutDialog {
    pub path_name: String,
    pub user: Option<User>,
}

impl CheckoutDialog {
    pub const CHECKOUT: i32 = 0;
    pub const CANCEL: i32 = 1;

    pub fn new(path_name: String, user: Option<User>) -> Self {
        Self { path_name, user }
    }

    pub fn show_dialog(&self) -> i32 {
        Self::CANCEL
    }

    pub fn exclusive_checkout(&self) -> bool {
        false
    }
}

/// Placeholder for `ghidra.features.base.memsearch.gui.SearchSettings`, referenced by
/// [`SearchFormat`](crate::feature::base::memsearch::format::search_format::SearchFormat) before
/// the real class is ported. `SearchFormat` only ever passes this type through as a parameter, so
/// no members are needed yet.
pub trait SearchSettings: Send + Sync {}

/// Placeholder for `ghidra.features.base.memsearch.matcher.SearchData`, the name/input/settings
/// triple every `UserInputByteMatcher` carries (`SearchData` is itself the `T` that
/// `UserInputByteMatcher implements ByteMatcher<SearchData>` matches produce). `SearchData` is a
/// concrete Java class (not an interface), so this stub is a struct rather than the placeholder
/// trait an auto-generated shape hint would suggest. Trimmed to the accessors
/// [`UserInputByteMatcherBase`] needs (`hashCode`/`equals` are omitted -- nothing compares two
/// `SearchData`s yet). Replace with the real port when `SearchData.java` is ported.
pub struct SearchData {
    name: String,
    input: String,
    settings: Option<Box<dyn SearchSettings>>,
}

impl SearchData {
    /// Java: `SearchData(String name, String input, SearchSettings settings)`.
    pub fn new(
        name: impl Into<String>,
        input: impl Into<String>,
        settings: Option<Box<dyn SearchSettings>>,
    ) -> Self {
        Self { name: name.into(), input: input.into(), settings }
    }

    /// Java: `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Java: `getInput()`.
    pub fn get_input(&self) -> &str {
        &self.input
    }

    /// Java: `getSettings()`.
    pub fn get_settings(&self) -> Option<&dyn SearchSettings> {
        self.settings.as_deref()
    }
}

/// Placeholder for the shared state of `ghidra.features.base.memsearch.matcher.UserInputByteMatcher`,
/// the abstract Java base that `InvalidByteMatcher`, `MaskedByteSequenceByteMatcher`, and
/// `RegExByteMatcher` all extend. Rust has no field inheritance, so this holds the one
/// `searchData` field the Java class carries; a concrete matcher embeds it and implements
/// [`UserInputByteMatcher`] for the abstract methods (the same [`SearchFormatBase`]/[`SearchFormat`]
/// split, for the same reason -- see
/// [`SearchFormatBase`](crate::feature::base::memsearch::format::search_format::SearchFormatBase)).
/// Replace with the real port when `UserInputByteMatcher.java` is ported.
pub struct UserInputByteMatcherBase {
    search_data: SearchData,
}

impl UserInputByteMatcherBase {
    /// Java: `UserInputByteMatcher(String name, String input, SearchSettings settings)`.
    pub fn new(
        name: impl Into<String>,
        input: impl Into<String>,
        settings: Option<Box<dyn SearchSettings>>,
    ) -> Self {
        Self { search_data: SearchData::new(name, input, settings) }
    }

    /// Java: `getName()`.
    pub fn get_name(&self) -> &str {
        self.search_data.get_name()
    }

    /// Java: `getInput()`.
    pub fn get_input(&self) -> &str {
        self.search_data.get_input()
    }

    /// Java: `getSettings()`.
    pub fn get_settings(&self) -> Option<&dyn SearchSettings> {
        self.search_data.get_settings()
    }

    /// Java: `getSearchData()`.
    pub fn get_search_data(&self) -> &SearchData {
        &self.search_data
    }
}

/// Placeholder for `ghidra.features.base.memsearch.matcher.UserInputByteMatcher`, referenced by
/// [`SearchFormat`](crate::feature::base::memsearch::format::search_format::SearchFormat) (whose
/// `parse` returns one, and whose `is_valid_text` default method calls
/// [`is_valid_search`](Self::is_valid_search) on the result) and implemented by
/// [`InvalidByteMatcher`](crate::feature::base::memsearch::matcher::invalid_byte_matcher::InvalidByteMatcher)
/// before the real class is ported. `UserInputByteMatcher implements ByteMatcher<SearchData>` in
/// Java, so the already-ported
/// [`ByteMatcher`](crate::feature::base::memsearch::matcher::ByteMatcher) trait is a supertrait
/// here rather than being re-declared. `getName`/`getInput`/`getSettings`/`getSearchData`/
/// `toString` are concrete methods every subclass inherits unchanged, so they are default methods
/// reading [`base`](Self::base) (mirroring `SearchFormat`'s `get_name`/`to_string`); `hashCode`/
/// `equals` are omitted, since nothing compares two matchers yet. See `UserInputByteMatcher.java`
/// for the type's full public surface. Replace with the real port when available.
pub trait UserInputByteMatcher:
    crate::feature::base::memsearch::matcher::ByteMatcher<SearchData> + Send + Sync
{
    /// The shared state (search data) every user-input matcher carries.
    fn base(&self) -> &UserInputByteMatcherBase;

    /// Java: `getToolTip()` (abstract). Additional info about this matcher (typically the mask
    /// bytes); Java's nullable return maps to `None`.
    fn get_tool_tip(&self) -> Option<String>;

    /// Java: `isValidSearch()`. Returns true if this matcher is valid and can be used to perform a
    /// search. Defaults to `true`, overridable.
    fn is_valid_search(&self) -> bool {
        true
    }

    /// Java: `isValidInput()`. Returns true if this matcher has valid (but possibly incomplete)
    /// input text. Defaults to `true`, overridable.
    fn is_valid_input(&self) -> bool {
        true
    }

    /// Java: `getName()`.
    fn get_name(&self) -> &str {
        self.base().get_name()
    }

    /// Java: `getInput()`.
    fn get_input(&self) -> &str {
        self.base().get_input()
    }

    /// Java: `getSettings()`.
    fn get_settings(&self) -> Option<&dyn SearchSettings> {
        self.base().get_settings()
    }

    /// Java: `getSearchData()`.
    fn get_search_data(&self) -> &SearchData {
        self.base().get_search_data()
    }

    /// Java: `toString()`, which returns `searchData.getInput()`.
    fn to_string(&self) -> String {
        self.base().get_input().to_string()
    }
}

/// Placeholder for the unported Java type `HexSearchFormat`, one of
/// [`SearchFormat`](crate::feature::base::memsearch::format::search_format::SearchFormat)'s six
/// concrete subclasses, referenced by `SearchFormat.HEX`/`SearchFormat.ALL`. `HexSearchFormat` is
/// a concrete Java class (not an interface), so this stub is a struct implementing the real
/// `SearchFormat` trait rather than a `dyn`-dispatched placeholder trait of its own. `parse` and
/// `convert_text` are the format's actual byte-parsing logic and are left `unimplemented!()`
/// pending that file's own port; `get_tool_tip`/`get_format_type` mirror the real
/// `HexSearchFormat.java` since they cost nothing to copy faithfully. Replace with the real port
/// when `HexSearchFormat.java` is ported.
pub struct HexSearchFormat {
    base: crate::feature::base::memsearch::format::search_format::SearchFormatBase,
}

impl HexSearchFormat {
    /// Java: `HexSearchFormat()`, which calls `super("Hex")`.
    pub fn new() -> Self {
        Self {
            base: crate::feature::base::memsearch::format::search_format::SearchFormatBase::new(
                "Hex",
            ),
        }
    }
}

impl Default for HexSearchFormat {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::feature::base::memsearch::format::search_format::SearchFormat for HexSearchFormat {
    fn base(&self) -> &crate::feature::base::memsearch::format::search_format::SearchFormatBase {
        &self.base
    }

    fn parse(&self, input: &str, settings: &dyn SearchSettings) -> Box<dyn UserInputByteMatcher> {
        let _ = (input, settings);
        unimplemented!("HexSearchFormat::parse is not ported yet")
    }

    fn get_tool_tip(&self) -> String {
        "Interpret value as a sequence of hex numbers, separated by spaces. Enter '.' or '?' for \
         a wildcard match"
            .to_string()
    }

    fn convert_text(
        &self,
        text: &str,
        old_settings: &dyn SearchSettings,
        new_settings: &dyn SearchSettings,
    ) -> String {
        let _ = (text, old_settings, new_settings);
        unimplemented!("HexSearchFormat::convert_text is not ported yet")
    }

    fn get_format_type(
        &self,
    ) -> crate::feature::base::memsearch::format::search_format::SearchFormatType {
        crate::feature::base::memsearch::format::search_format::SearchFormatType::Byte
    }
}

/// Placeholder for the unported Java type `BinarySearchFormat`. See [`HexSearchFormat`] for the
/// trimming rationale. Replace with the real port when `BinarySearchFormat.java` is ported.
pub struct BinarySearchFormat {
    base: crate::feature::base::memsearch::format::search_format::SearchFormatBase,
}

impl BinarySearchFormat {
    /// Java: `BinarySearchFormat()`, which calls `super("Binary")`.
    pub fn new() -> Self {
        Self {
            base: crate::feature::base::memsearch::format::search_format::SearchFormatBase::new(
                "Binary",
            ),
        }
    }
}

impl Default for BinarySearchFormat {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::feature::base::memsearch::format::search_format::SearchFormat for BinarySearchFormat {
    fn base(&self) -> &crate::feature::base::memsearch::format::search_format::SearchFormatBase {
        &self.base
    }

    fn parse(&self, input: &str, settings: &dyn SearchSettings) -> Box<dyn UserInputByteMatcher> {
        let _ = (input, settings);
        unimplemented!("BinarySearchFormat::parse is not ported yet")
    }

    fn get_tool_tip(&self) -> String {
        "Interpret value as a sequence of binary digits. Spaces will start the next byte. Bit \
         sequences less than 8 bits are padded with 0's to the left. Enter 'x', '.' or '?' for a \
         wildcard bit"
            .to_string()
    }

    fn convert_text(
        &self,
        text: &str,
        old_settings: &dyn SearchSettings,
        new_settings: &dyn SearchSettings,
    ) -> String {
        let _ = (text, old_settings, new_settings);
        unimplemented!("BinarySearchFormat::convert_text is not ported yet")
    }

    fn get_format_type(
        &self,
    ) -> crate::feature::base::memsearch::format::search_format::SearchFormatType {
        crate::feature::base::memsearch::format::search_format::SearchFormatType::Byte
    }
}

/// Placeholder for the unported Java type `DecimalSearchFormat`. See [`HexSearchFormat`] for the
/// trimming rationale. Replace with the real port when `DecimalSearchFormat.java` is ported.
pub struct DecimalSearchFormat {
    base: crate::feature::base::memsearch::format::search_format::SearchFormatBase,
}

impl DecimalSearchFormat {
    /// Java: `DecimalSearchFormat()`, which calls `super("Decimal")`.
    pub fn new() -> Self {
        Self {
            base: crate::feature::base::memsearch::format::search_format::SearchFormatBase::new(
                "Decimal",
            ),
        }
    }
}

impl Default for DecimalSearchFormat {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::feature::base::memsearch::format::search_format::SearchFormat for DecimalSearchFormat {
    fn base(&self) -> &crate::feature::base::memsearch::format::search_format::SearchFormatBase {
        &self.base
    }

    fn parse(&self, input: &str, settings: &dyn SearchSettings) -> Box<dyn UserInputByteMatcher> {
        let _ = (input, settings);
        unimplemented!("DecimalSearchFormat::parse is not ported yet")
    }

    fn get_tool_tip(&self) -> String {
        "Interpret values as a sequence of decimal numbers, separated by spaces".to_string()
    }

    fn convert_text(
        &self,
        text: &str,
        old_settings: &dyn SearchSettings,
        new_settings: &dyn SearchSettings,
    ) -> String {
        let _ = (text, old_settings, new_settings);
        unimplemented!("DecimalSearchFormat::convert_text is not ported yet")
    }

    fn get_format_type(
        &self,
    ) -> crate::feature::base::memsearch::format::search_format::SearchFormatType {
        crate::feature::base::memsearch::format::search_format::SearchFormatType::Integer
    }
}

/// Placeholder for the unported Java type `StringSearchFormat`. See [`HexSearchFormat`] for the
/// trimming rationale. Replace with the real port when `StringSearchFormat.java` is ported.
pub struct StringSearchFormat {
    base: crate::feature::base::memsearch::format::search_format::SearchFormatBase,
}

impl StringSearchFormat {
    /// Java: `StringSearchFormat()`, which calls `super("String")`.
    pub fn new() -> Self {
        Self {
            base: crate::feature::base::memsearch::format::search_format::SearchFormatBase::new(
                "String",
            ),
        }
    }
}

impl Default for StringSearchFormat {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::feature::base::memsearch::format::search_format::SearchFormat for StringSearchFormat {
    fn base(&self) -> &crate::feature::base::memsearch::format::search_format::SearchFormatBase {
        &self.base
    }

    fn parse(&self, input: &str, settings: &dyn SearchSettings) -> Box<dyn UserInputByteMatcher> {
        let _ = (input, settings);
        unimplemented!("StringSearchFormat::parse is not ported yet")
    }

    fn get_tool_tip(&self) -> String {
        "Interpret value as a sequence of characters.".to_string()
    }

    fn convert_text(
        &self,
        text: &str,
        old_settings: &dyn SearchSettings,
        new_settings: &dyn SearchSettings,
    ) -> String {
        let _ = (text, old_settings, new_settings);
        unimplemented!("StringSearchFormat::convert_text is not ported yet")
    }

    fn get_format_type(
        &self,
    ) -> crate::feature::base::memsearch::format::search_format::SearchFormatType {
        crate::feature::base::memsearch::format::search_format::SearchFormatType::StringType
    }
}

/// Placeholder for the unported Java type `RegExSearchFormat`. See [`HexSearchFormat`] for the
/// trimming rationale. Replace with the real port when `RegExSearchFormat.java` is ported.
pub struct RegExSearchFormat {
    base: crate::feature::base::memsearch::format::search_format::SearchFormatBase,
}

impl RegExSearchFormat {
    /// Java: `RegExSearchFormat()`, which calls `super("Reg Ex")`.
    pub fn new() -> Self {
        Self {
            base: crate::feature::base::memsearch::format::search_format::SearchFormatBase::new(
                "Reg Ex",
            ),
        }
    }
}

impl Default for RegExSearchFormat {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::feature::base::memsearch::format::search_format::SearchFormat for RegExSearchFormat {
    fn base(&self) -> &crate::feature::base::memsearch::format::search_format::SearchFormatBase {
        &self.base
    }

    fn parse(&self, input: &str, settings: &dyn SearchSettings) -> Box<dyn UserInputByteMatcher> {
        let _ = (input, settings);
        unimplemented!("RegExSearchFormat::parse is not ported yet")
    }

    fn get_tool_tip(&self) -> String {
        "Interpret value as a regular expression.".to_string()
    }

    fn convert_text(
        &self,
        text: &str,
        old_settings: &dyn SearchSettings,
        new_settings: &dyn SearchSettings,
    ) -> String {
        let _ = (text, old_settings, new_settings);
        unimplemented!("RegExSearchFormat::convert_text is not ported yet")
    }

    fn get_format_type(
        &self,
    ) -> crate::feature::base::memsearch::format::search_format::SearchFormatType {
        crate::feature::base::memsearch::format::search_format::SearchFormatType::StringType
    }
}

/// Placeholder for the unported Java type `FloatSearchFormat`. See [`HexSearchFormat`] for the
/// trimming rationale. Unlike the other five, Java's `FloatSearchFormat` is constructed twice with
/// different arguments (`SearchFormat.FLOAT = new FloatSearchFormat("Float", "Floating Point", 4)`
/// and `SearchFormat.DOUBLE = new FloatSearchFormat("Double", "Floating Point (8)", 8)`), so this
/// stub keeps the `longName`/`byteSize` fields Java stores for those two call sites even though
/// nothing here reads them yet (the real port's `getToolTip`/`getValue` do). Replace with the real
/// port when `FloatSearchFormat.java` is ported.
pub struct FloatSearchFormat {
    base: crate::feature::base::memsearch::format::search_format::SearchFormatBase,
    long_name: String,
    byte_size: i32,
}

impl FloatSearchFormat {
    /// Java: `FloatSearchFormat(String name, String longName, int size)`.
    pub fn new(name: impl Into<String>, long_name: impl Into<String>, byte_size: i32) -> Self {
        assert!(byte_size == 4 || byte_size == 8, "Only supports 4 or 8 byte floating point numbers");
        Self {
            base: crate::feature::base::memsearch::format::search_format::SearchFormatBase::new(
                name,
            ),
            long_name: long_name.into(),
            byte_size,
        }
    }

    /// Java: `SearchFormat.FLOAT = new FloatSearchFormat("Float", "Floating Point", 4)`.
    pub fn new_float() -> Self {
        Self::new("Float", "Floating Point", 4)
    }

    /// Java: `SearchFormat.DOUBLE = new FloatSearchFormat("Double", "Floating Point (8)", 8)`.
    pub fn new_double() -> Self {
        Self::new("Double", "Floating Point (8)", 8)
    }
}

impl crate::feature::base::memsearch::format::search_format::SearchFormat for FloatSearchFormat {
    fn base(&self) -> &crate::feature::base::memsearch::format::search_format::SearchFormatBase {
        &self.base
    }

    fn parse(&self, input: &str, settings: &dyn SearchSettings) -> Box<dyn UserInputByteMatcher> {
        let _ = (input, settings);
        unimplemented!("FloatSearchFormat::parse is not ported yet")
    }

    fn get_tool_tip(&self) -> String {
        format!("Interpret values as a sequence of {} numbers, separated by spaces", self.long_name)
    }

    fn convert_text(
        &self,
        text: &str,
        old_settings: &dyn SearchSettings,
        new_settings: &dyn SearchSettings,
    ) -> String {
        let _ = (text, old_settings, new_settings);
        unimplemented!("FloatSearchFormat::convert_text is not ported yet")
    }

    fn get_format_type(
        &self,
    ) -> crate::feature::base::memsearch::format::search_format::SearchFormatType {
        let _ = self.byte_size;
        crate::feature::base::memsearch::format::search_format::SearchFormatType::FloatingPoint
    }
}

// ---------------------------------------------------------------------------
// `ghidra.features.bsim.query.description` placeholders
//
// `FunctionDescription` sits on a dependency cycle with `CallgraphEntry` (each names the other
// in a field) and with `ExecutableRecord`/`SignatureRecord` (which the real
// `DescriptionManager` port interns and hands out). The placeholders below break that cycle;
// each is a concrete Java class, so each stub is a struct rather than a trait. See `STUBS.tsv`
// for provenance.
// ---------------------------------------------------------------------------

/// The state of an [`ExecutableRecord`] that the owning `DescriptionManager` mutates after the
/// record has been shared.
///
/// Java mutates these fields through whatever reference happens to be at hand -- the record in
/// the manager's set and the record every [`FunctionDescription`] points at are one object, so
/// `populateExecutableXref` followed by `saveXml` observes the indices it just assigned. The
/// Rust records are shared through [`Arc`], so that aliasing is modelled with a lock rather than
/// with `&mut`.
///
/// [`FunctionDescription`]: crate::feature::bsim::query::description::FunctionDescription
#[derive(Debug, Default, Clone)]
struct ExecutableState {
    /// Java `rowid`, reduced to its long (see the note on `FunctionDescription`'s id).
    row_id: Option<i64>,
    /// Java flag `ALREADY_STORED`.
    already_stored: bool,
    /// Java flag `CATEGORIES_SET`.
    categories_set: bool,
    /// Java `usercat`, kept sorted.
    usercat: Option<Vec<crate::feature::bsim::query::description::CategoryRecord>>,
    repository: Option<String>,
    path: Option<String>,
    xref_index: i32,
}

/// Placeholder for the unported Java type `ExecutableRecord`, referenced by
/// [`crate::feature::bsim::query::description::FunctionDescription`] and by
/// [`crate::feature::bsim::query::description::DescriptionManager`].
///
/// Only the members those two types need are present. Equality, ordering and hashing are by md5
/// alone, matching the Java original. The Java `Date` of ingest is held as milliseconds since
/// the epoch (what `Date.getTime()` returns), and the repository URL is stored verbatim rather
/// than being normalised through `GhidraURL`.
/// Replace with the real port when `ExecutableRecord.java` is ported.
#[derive(Debug, Default)]
pub struct ExecutableRecord {
    md5sum: String,
    executable_name: String,
    architecture: String,
    compiler_name: String,
    library: bool,
    /// Java `date`, as milliseconds since the epoch. `0` is Java's `EMPTY_DATE`.
    date: i64,
    state: std::sync::Mutex<ExecutableState>,
}

impl ExecutableRecord {
    /// Java: `ExecutableRecord.METADATA_NAME` and friends, the bits `compare_metadata` returns.
    pub const METADATA_NAME: i32 = 1;
    pub const METADATA_ARCH: i32 = 2;
    pub const METADATA_COMP: i32 = 4;
    pub const METADATA_DATE: i32 = 8;
    pub const METADATA_REPO: i32 = 16;
    pub const METADATA_PATH: i32 = 32;
    pub const METADATA_LIBR: i32 = 64;

    /// Java: `ExecutableRecord(String md5, String enm, String cnm, String arc, ...)`.
    ///
    /// Note the argument order, which follows the field order of the struct rather than the
    /// Java constructor's; [`new_full`](Self::new_full) follows Java.
    pub fn new(
        md5sum: impl Into<String>,
        executable_name: impl Into<String>,
        architecture: impl Into<String>,
        compiler_name: impl Into<String>,
    ) -> Self {
        Self {
            md5sum: md5sum.into(),
            executable_name: executable_name.into(),
            architecture: architecture.into(),
            compiler_name: compiler_name.into(),
            library: false,
            date: 0,
            state: std::sync::Mutex::new(ExecutableState::default()),
        }
    }

    /// Java: `ExecutableRecord(String md5, String execName, String compilerName,
    /// String architecture, Date date, RowKey id, String repo, String path)`.
    pub fn new_full(
        md5sum: impl Into<String>,
        executable_name: impl Into<String>,
        compiler_name: impl Into<String>,
        architecture: impl Into<String>,
        date: i64,
        row_id: Option<i64>,
        repository: Option<&str>,
        path: Option<&str>,
    ) -> Self {
        let res = Self {
            md5sum: md5sum.into(),
            executable_name: executable_name.into(),
            architecture: architecture.into(),
            compiler_name: compiler_name.into(),
            library: false,
            date,
            state: std::sync::Mutex::new(ExecutableState { row_id, ..Default::default() }),
        };
        res.set_repository(repository, path);
        res
    }

    /// Java: the library constructor `ExecutableRecord(String enm, String arc, RowKey id)`,
    /// which sets the `LIBRARY` flag and synthesizes a placeholder md5 via
    /// [`calc_library_md5_placeholder`](Self::calc_library_md5_placeholder).
    pub fn new_library_with_id(
        executable_name: impl Into<String>,
        architecture: impl Into<String>,
        row_id: Option<i64>,
    ) -> Self {
        let executable_name = executable_name.into();
        let architecture = architecture.into();
        Self {
            md5sum: Self::calc_library_md5_placeholder(&executable_name, &architecture),
            executable_name,
            architecture,
            compiler_name: String::new(),
            library: true,
            date: 0,
            state: std::sync::Mutex::new(ExecutableState { row_id, ..Default::default() }),
        }
    }

    /// The library constructor without a database id.
    pub fn new_library(executable_name: impl Into<String>, architecture: impl Into<String>) -> Self {
        Self::new_library_with_id(executable_name, architecture, None)
    }

    /// Java: `ExecutableRecord.calcLibraryMd5Placeholder(String enm, String arc)`, the stand-in
    /// hash a library record uses in place of a real md5.
    pub fn calc_library_md5_placeholder(enm: &str, arc: &str) -> String {
        use crate::generic::hash::simple_crc32::SimpleCRC32;

        fn word_to_ascii(val: u32, buf: &mut String) {
            for i in (0..=28).rev().step_by(4) {
                let nibble = (val >> i) & 0xf;
                buf.push(char::from_digit(nibble, 16).unwrap());
            }
        }

        let mut hi: u32 = 0x00b1_b110;
        let mut lo: u32 = 0xfaba_faba;
        // Java iterates over UTF-16 code units and masks each to a byte.
        for c in enm.encode_utf16() {
            let feed = lo >> 24;
            lo = SimpleCRC32::hash_one_byte(lo, u32::from(c) & 0xff);
            hi = SimpleCRC32::hash_one_byte(hi, feed);
        }
        lo ^= 0xf1b1_f1b1;
        for c in arc.encode_utf16() {
            let feed = lo >> 24;
            lo = SimpleCRC32::hash_one_byte(lo, u32::from(c) & 0xff);
            hi = SimpleCRC32::hash_one_byte(hi, feed);
        }
        let mut buf = String::from("bbbbbbbbaaaaaaaa");
        word_to_ascii(hi, &mut buf);
        word_to_ascii(lo, &mut buf);
        buf
    }

    pub fn get_md5(&self) -> &str {
        &self.md5sum
    }

    pub fn get_name_exec(&self) -> &str {
        &self.executable_name
    }

    pub fn get_architecture(&self) -> &str {
        &self.architecture
    }

    pub fn get_name_compiler(&self) -> &str {
        &self.compiler_name
    }

    pub fn is_library(&self) -> bool {
        self.library
    }

    /// Java: `getDate()`, as milliseconds since the epoch.
    pub fn get_date(&self) -> i64 {
        self.date
    }

    /// Java: `getRowId()`, reduced to the key's long.
    pub fn get_row_id(&self) -> Option<i64> {
        self.state.lock().unwrap().row_id
    }

    pub fn is_already_stored(&self) -> bool {
        self.state.lock().unwrap().already_stored
    }

    pub fn categories_are_set(&self) -> bool {
        self.state.lock().unwrap().categories_set
    }

    /// Java: `getAllCategories()`, which returns null when no category is set.
    pub fn get_all_categories(
        &self,
    ) -> Option<Vec<crate::feature::bsim::query::description::CategoryRecord>> {
        self.state.lock().unwrap().usercat.clone()
    }

    pub fn get_repository(&self) -> Option<String> {
        self.state.lock().unwrap().repository.clone()
    }

    pub fn get_path(&self) -> Option<String> {
        self.state.lock().unwrap().path.clone()
    }

    pub fn get_xref_index(&self) -> i32 {
        self.state.lock().unwrap().xref_index
    }

    /// Java: `setXrefIndex(int)`.
    pub fn set_xref_index(&self, val: i32) {
        self.state.lock().unwrap().xref_index = val;
    }

    /// Java: `setRowId(RowKey)`, reduced to the key's long.
    pub fn set_row_id(&self, id: i64) {
        self.state.lock().unwrap().row_id = Some(id);
    }

    /// Java: `setAlreadyStored()`.
    pub fn set_already_stored(&self) {
        self.state.lock().unwrap().already_stored = true;
    }

    /// Java: `setCategory(List<CategoryRecord>)`. Categories count as *set* even when the list
    /// is empty or absent, and are kept sorted.
    pub fn set_category(
        &self,
        cats: Option<Vec<crate::feature::bsim::query::description::CategoryRecord>>,
    ) {
        let mut state = self.state.lock().unwrap();
        state.categories_set = true;
        match cats {
            Some(mut cats) if !cats.is_empty() => {
                cats.sort();
                state.usercat = Some(cats);
            }
            _ => state.usercat = None,
        }
    }

    /// Java: `cloneCategories(ExecutableRecord op2)`.
    pub fn clone_categories(&self, op2: &ExecutableRecord) {
        let (set, cats) = {
            let other = op2.state.lock().unwrap();
            (other.categories_set, other.usercat.clone())
        };
        let mut state = self.state.lock().unwrap();
        state.categories_set = set;
        state.usercat = cats;
    }

    /// Java: `setRepository(String repo, String newpath)`, minus the `GhidraURL` normalisation
    /// of `repo`. A leading or trailing slash is stripped from the path, and a path of just
    /// `"/"` becomes absent, as in Java.
    pub fn set_repository(&self, repo: Option<&str>, newpath: Option<&str>) {
        let mut path = newpath.map(str::to_string);
        if let Some(p) = path.take() {
            let p = p.strip_suffix('/').unwrap_or(&p).to_string();
            let p = p.strip_prefix('/').unwrap_or(&p).to_string();
            path = if p.is_empty() { None } else { Some(p) };
        }
        let mut state = self.state.lock().unwrap();
        state.repository = repo.map(str::to_string);
        state.path = path;
    }

    /// Java: `compareMetadata(ExecutableRecord o)`, a bit-field of the `METADATA_*` fields that
    /// differ. Zero means the two records describe the same executable.
    pub fn compare_metadata(&self, o: &ExecutableRecord) -> i32 {
        let mut res = 0;
        if self.executable_name != o.executable_name {
            res |= Self::METADATA_NAME;
        }
        if self.architecture != o.architecture {
            res |= Self::METADATA_ARCH;
        }
        if self.library != o.library {
            res |= Self::METADATA_LIBR;
        }
        if self.library {
            return res; // Remaining fields aren't compared for libraries
        }
        if self.compiler_name != o.compiler_name {
            res |= Self::METADATA_COMP;
        }
        if self.date != o.date {
            res |= Self::METADATA_DATE;
        }
        let (mine, theirs) = (self.state.lock().unwrap(), o.state.lock().unwrap());
        if mine.repository != theirs.repository {
            res |= Self::METADATA_REPO;
        }
        if mine.path != theirs.path {
            res |= Self::METADATA_PATH;
        }
        res
    }

    /// Java: `ExecutableRecord.printRaw()`.
    pub fn print_raw(&self) -> String {
        format!(
            "{} {} {} {}",
            self.md5sum, self.executable_name, self.architecture, self.compiler_name
        )
    }

    /// Java: `ExecutableRecord.saveXml(Writer)`.
    pub fn save_xml<W: std::io::Write>(&self, fwrite: &mut W) -> std::io::Result<()> {
        use crate::util::xml::spec_xml_utils;

        write!(fwrite, "<exe")?;
        if self.library {
            write!(fwrite, " library=\"true\"")?;
        }
        write!(fwrite, ">\n  <md5>{}</md5>\n  <name>", self.md5sum)?;
        spec_xml_utils::xml_escape_writer(fwrite, &self.executable_name)?;
        write!(fwrite, "</name>\n  <arch>")?;
        spec_xml_utils::xml_escape_writer(fwrite, &self.architecture)?;
        write!(fwrite, "</arch>\n  <compiler>")?;
        spec_xml_utils::xml_escape_writer(fwrite, &self.compiler_name)?;
        write!(fwrite, "</compiler>\n")?;
        let millis = self.date % 1000;
        let seconds = self.date / 1000;
        write!(
            fwrite,
            "  <date millis=\"{}\">{}</date>\n",
            spec_xml_utils::encode_unsigned_integer(millis),
            spec_xml_utils::encode_unsigned_integer(seconds)
        )?;
        let (repository, path, usercat) = {
            let state = self.state.lock().unwrap();
            (state.repository.clone(), state.path.clone(), state.usercat.clone())
        };
        if let Some(repository) = repository {
            write!(fwrite, "  <repository>")?;
            spec_xml_utils::xml_escape_writer(fwrite, &repository)?;
            write!(fwrite, "</repository>\n")?;
        }
        if let Some(path) = path {
            write!(fwrite, "  <path>")?;
            spec_xml_utils::xml_escape_writer(fwrite, &path)?;
            write!(fwrite, "</path>\n")?;
        }
        for element in usercat.iter().flatten() {
            element.save_xml(fwrite)?;
        }
        write!(fwrite, "</exe>\n")
    }

    /// Java: `ExecutableRecord.restoreXml(XmlPullParser, DescriptionManager)`, which registers
    /// the parsed record with `man` and returns the interned instance.
    pub(crate) fn restore_xml<P: crate::util::xml::xml_pull_parser::XmlPullParser>(
        parser: &mut P,
        man: &mut crate::feature::bsim::query::description::DescriptionManager,
    ) -> Result<Arc<ExecutableRecord>, crate::feature::bsim::query::LshException> {
        use crate::feature::bsim::query::LshException;
        use crate::feature::bsim::query::description::CategoryRecord;
        use crate::util::xml::spec_xml_utils;
        use crate::util::xml::xml_element::XmlElement;

        let xml_err = |e: crate::util::xml::xml_exception::XmlException| {
            LshException::new(e.to_string())
        };

        let el = parser.start(&["exe"]).map_err(xml_err)?;
        let islib = el
            .get_attribute("library")
            .map(|v| spec_xml_utils::decode_boolean(&v))
            .unwrap_or(false);
        parser.start(&["md5"]).map_err(xml_err)?;
        let md5sum = parser.end().map_err(xml_err)?.get_text().to_string();
        parser.start(&["name"]).map_err(xml_err)?;
        let name_exec = parser.end().map_err(xml_err)?.get_text().to_string();
        let mut name_compiler = String::new();
        let mut architecture = String::new();
        let mut seconds: i64 = 0;
        let mut millis: i64 = 0;
        // Java never reads a row id back from the XML.
        let id: Option<i64> = None;
        let mut repo: Option<String> = None;
        let mut path: Option<String> = None;
        let mut cats: Option<Vec<CategoryRecord>> = None;
        while parser.peek().is_start() {
            if parser.peek().get_name() == "category" {
                cats.get_or_insert_with(Vec::new).push(CategoryRecord::restore_xml(parser)?);
                continue;
            }
            let subel = parser.start(&[]).map_err(xml_err)?;
            match subel.get_name() {
                "arch" => architecture = parser.end().map_err(xml_err)?.get_text().to_string(),
                "compiler" => name_compiler = parser.end().map_err(xml_err)?.get_text().to_string(),
                "date" => {
                    millis = spec_xml_utils::decode_long(subel.get_attribute("millis").as_deref());
                    if !(0..=1000).contains(&millis) {
                        millis = 0;
                    }
                    let text = parser.end().map_err(xml_err)?.get_text().to_string();
                    seconds = spec_xml_utils::decode_long(Some(&text));
                }
                "repository" => {
                    repo = Some(parser.end().map_err(xml_err)?.get_text().to_string())
                }
                "path" => path = Some(parser.end().map_err(xml_err)?.get_text().to_string()),
                _ => {
                    parser.end().map_err(xml_err)?;
                }
            }
        }
        parser.end().map_err(xml_err)?;

        let res = if islib {
            let res = man.new_executable_library(&name_exec, &architecture, id)?;
            if res.get_md5() != md5sum {
                return Err(LshException::new(
                    "Read bad library placeholder md5 for ExecutableRecord",
                ));
            }
            res
        } else {
            man.new_executable_record(
                &md5sum,
                &name_exec,
                &name_compiler,
                &architecture,
                seconds * 1000 + millis,
                repo.as_deref(),
                path.as_deref(),
                id,
            )?
        };
        res.set_category(cats);
        Ok(res)
    }
}

impl Clone for ExecutableRecord {
    fn clone(&self) -> Self {
        Self {
            md5sum: self.md5sum.clone(),
            executable_name: self.executable_name.clone(),
            architecture: self.architecture.clone(),
            compiler_name: self.compiler_name.clone(),
            library: self.library,
            date: self.date,
            state: std::sync::Mutex::new(self.state.lock().unwrap().clone()),
        }
    }
}

impl PartialEq for ExecutableRecord {
    fn eq(&self, other: &Self) -> bool {
        self.md5sum == other.md5sum
    }
}

impl Eq for ExecutableRecord {}

impl std::hash::Hash for ExecutableRecord {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.md5sum.hash(state);
    }
}

impl PartialOrd for ExecutableRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExecutableRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.md5sum.cmp(&other.md5sum)
    }
}

/// Placeholder for the unported Java type `SignatureRecord`, referenced by
/// [`crate::feature::bsim::query::description::FunctionDescription`].
///
/// The real record wraps an `LSHVector`; the placeholder carries only the duplicate count that
/// `FunctionDescription::save_xml` writes as the `sigdup` attribute, and the vector id that
/// `DescriptionManager::attach_signature` copies onto the function. Replace with the real port
/// when `SignatureRecord.java` is ported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureRecord {
    count: i32,
    vectorid: i64,
}

impl SignatureRecord {
    pub fn new(count: i32) -> Self {
        Self { count, vectorid: 0 }
    }

    /// Java: `SignatureRecord.getCount()`, the number of functions sharing this signature.
    pub fn get_count(&self) -> i32 {
        self.count
    }

    /// Java: package-private `setCount(int)`.
    pub(crate) fn set_count(&mut self, c: i32) {
        self.count = c;
    }

    /// Java: `SignatureRecord.getVectorId()`.
    pub fn get_vector_id(&self) -> i64 {
        self.vectorid
    }

    /// Java: package-private `setVectorId(long)`.
    pub(crate) fn set_vector_id(&mut self, i: i64) {
        self.vectorid = i;
    }

    /// Java: `SignatureRecord.saveXml(Writer)`, which delegates to the vector's `saveXml`.
    /// The placeholder holds no vector, so it writes nothing.
    pub fn save_xml<W: std::io::Write>(&self, _fwrite: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    /// Java: `SignatureRecord.restoreXml(...)`, which builds a record through the manager and
    /// attaches it to `fdesc`. The manager's factory discards the `<lshcosine>` subtree, since
    /// the placeholder record holds no vector, so the surrounding parse stays well formed.
    pub(crate) fn restore_xml<P: crate::util::xml::xml_pull_parser::XmlPullParser>(
        parser: &mut P,
        vector_factory: &crate::generic::seam_stubs::LSHVectorFactory,
        man: &mut crate::feature::bsim::query::description::DescriptionManager,
        fdesc: &mut crate::feature::bsim::query::description::FunctionDescription,
        count: i32,
    ) -> Result<(), crate::feature::bsim::query::LshException> {
        let srec = man.new_signature_from_xml(parser, vector_factory, count);
        man.attach_signature(fdesc, Arc::new(srec));
        Ok(())
    }
}

/// Placeholder for the unported Java type `CallgraphEntry`, referenced by
/// [`crate::feature::bsim::query::description::FunctionDescription`].
///
/// A single edge of the call graph: the called function plus a hash of the call site. The
/// callee is shared with whatever container owns it (Java holds a bare reference), so it is
/// held by [`Arc`] here -- `FunctionDescription::sort_callgraph` dedups by pointer identity
/// exactly as the Java does. Replace with the real port when `CallgraphEntry.java` is ported.
#[derive(Debug, Clone)]
pub struct CallgraphEntry {
    dest: Arc<crate::feature::bsim::query::description::FunctionDescription>,
    lochash: i32,
}

impl CallgraphEntry {
    /// Java: `CallgraphEntry(FunctionDescription d, int lhash)`.
    pub fn new(
        dest: Arc<crate::feature::bsim::query::description::FunctionDescription>,
        lochash: i32,
    ) -> Self {
        Self { dest, lochash }
    }

    /// The called function. Returned as the [`Arc`] itself so callers can compare identity.
    pub fn get_function_description(
        &self,
    ) -> &Arc<crate::feature::bsim::query::description::FunctionDescription> {
        &self.dest
    }

    pub fn get_local_hash(&self) -> i32 {
        self.lochash
    }

    /// Java: `CallgraphEntry.saveXml(FunctionDescription src, Writer fwrite)`.
    pub fn save_xml<W: std::io::Write>(
        &self,
        src: &crate::feature::bsim::query::description::FunctionDescription,
        fwrite: &mut W,
    ) -> std::io::Result<()> {
        use crate::util::xml::spec_xml_utils;

        let mut buf = String::new();
        buf.push_str("<call");
        spec_xml_utils::xml_escape_attribute(&mut buf, "dest", self.dest.get_function_name());
        if self.dest.get_address() != -1 {
            spec_xml_utils::encode_unsigned_integer_attribute(
                &mut buf,
                "addr",
                self.dest.get_address(),
            );
        }
        if self.lochash != 0 {
            spec_xml_utils::encode_unsigned_integer_attribute(
                &mut buf,
                "local",
                self.lochash as i64,
            );
        }
        let srcexe = src.get_executable_record();
        let destexe = self.dest.get_executable_record();
        if !Arc::ptr_eq(srcexe, destexe) {
            buf.push_str(">\n");
            if !destexe.is_library() {
                buf.push_str("  <md5>");
                buf.push_str(destexe.get_md5());
                buf.push_str("</md5>\n");
            }
            buf.push_str("  <name>");
            spec_xml_utils::xml_escape(&mut buf, destexe.get_name_exec());
            buf.push_str("</name>\n");
            if srcexe.get_architecture() != destexe.get_architecture() {
                buf.push_str("  <arch>");
                spec_xml_utils::xml_escape(&mut buf, destexe.get_architecture());
                buf.push_str("</arch>\n");
            }
            if srcexe.get_name_compiler() != destexe.get_name_compiler() {
                buf.push_str("  <compiler>");
                spec_xml_utils::xml_escape(&mut buf, destexe.get_name_compiler());
                buf.push_str("</compiler>\n");
            }
            buf.push_str("</call>\n");
        } else {
            buf.push_str("/>\n");
        }
        fwrite.write_all(buf.as_bytes())
    }

    /// Java: `CallgraphEntry.restoreXml(...)`, which resolves the callee through the manager and
    /// records the link. The placeholder discards the `<call>` subtree -- no link is created --
    /// so that the surrounding parse stays well formed and terminates.
    pub(crate) fn restore_xml<P: crate::util::xml::xml_pull_parser::XmlPullParser>(
        parser: &mut P,
        _man: &mut crate::feature::bsim::query::description::DescriptionManager,
        _src: &mut crate::feature::bsim::query::description::FunctionDescription,
    ) -> Result<(), crate::feature::bsim::query::LshException> {
        parser.discard_sub_tree();
        Ok(())
    }
}

impl PartialEq for CallgraphEntry {
    fn eq(&self, other: &Self) -> bool {
        *self.dest == *other.dest
    }
}

impl Eq for CallgraphEntry {}

impl PartialOrd for CallgraphEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CallgraphEntry {
    /// Java: `compareTo` defers entirely to the called function's ordering.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.dest.cmp(&other.dest)
    }
}

/// Placeholder for the unported Java type `BSimServerInfo`, referenced by `BSimJDBCDataSource`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait BSimServerInfo: Send + Sync {
    fn is_windows_file_path(&self) -> bool;
    fn to_url_string(&self) -> String;
    fn to_url(&self) -> std::io::Result<Box<dyn URL>>;
    fn get_db_type(&self) -> Box<dyn DBType>;
    fn set_user_info(&self, bds: &dyn BasicDataSource);
    fn has_password(&self) -> bool;
    fn has_default_login(&self) -> bool;
    fn get_user_name(&self) -> String;
    fn get_user_info(&self) -> String;
    fn get_server_name(&self) -> String;
    fn get_port(&self) -> i32;
    fn get_db_name(&self) -> String;
    fn get_short_db_name(&self) -> String;
    fn hash_code(&self) -> i32;
    fn equals(&self, obj: &dyn std::any::Any) -> bool;
    fn to_string(&self) -> String;
    fn get_function_database(&self, async_: bool) -> Box<dyn FunctionDatabase>;
    fn compare_to(&self, o: &dyn BSimServerInfo) -> i32;
}

/// Placeholder for the unported Java type `FunctionDatabase`, referenced by `BSimJDBCDataSource`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait FunctionDatabase: Send + Sync {
    fn to_string(&self) -> String;
    fn get_integer(&self) -> i32;
    fn is_password_change_allowed(&self) -> bool;
    fn change_password(&self, new_password: &[char]) -> String;
    fn get_status(&self) -> crate::feature::bsim::query::b_sim_jdbc_data_source::Status;
    fn get_connection_type(&self) -> crate::feature::bsim::query::b_sim_jdbc_data_source::ConnectionType;
    fn get_user_name(&self) -> String;
    fn get_lsh_vector_factory(&self) -> Box<dyn LSHVectorFactoryStub>;
    fn get_info(&self) -> Box<dyn DatabaseInformation>;
    fn compare_layout(&self) -> i32;
    fn get_server_info(&self) -> Box<dyn BSimServerInfo>;
    fn get_url_string(&self) -> String;
    fn initialize(&self) -> bool;
    fn close(&self);
    fn get_last_error(&self) -> Box<dyn BSimError>;
    fn query(&self, query: &dyn BSimQuery) -> Box<dyn QueryResponseRecord>;
    fn check_settings_for_query(&self, manage: &dyn DescriptionManager, info: &dyn DatabaseInformation) -> std::io::Result<()>;
    fn check_settings_for_insert(&self, manage: &dyn DescriptionManager, info: &dyn DatabaseInformation) -> std::io::Result<bool>;
    fn construct_fatal_error(&self, flags: i32, newrec: &ExecutableRecord, orig: &ExecutableRecord) -> String;
    fn construct_nonfatal_error(&self, flags: i32, newrec: &ExecutableRecord, orig: &ExecutableRecord) -> String;
    fn load_configuration_template(&self, configname: &str) -> std::io::Result<Box<dyn Configuration>>;
    fn generate_lsh_vector_factory(&self) -> Box<dyn WeightedLSHCosineVectorFactory>;
    fn get_queried_functions_per_stage(&self) -> i32;
    fn get_overview_functions_per_stage(&self) -> i32;
}

/// Placeholder for `URL` type.
pub trait URL: Send + Sync {}

/// Placeholder for `DBType` type.
pub trait DBType: Send + Sync {}

/// Placeholder for `BasicDataSource` type.
pub trait BasicDataSource: Send + Sync {}

/// Placeholder for `DatabaseInformation` type.
pub trait DatabaseInformation: Send + Sync {}

/// Placeholder for `BSimError` type.
pub trait BSimError: Send + Sync {}

/// Placeholder for `BSimQuery` type. Abstract base for all BSim queries.
pub trait BSimQuery: Send + Sync {
    fn build_response_template(&self);
    fn save_xml(&self, fwrite: &mut dyn std::io::Write) -> std::io::Result<()>;
    fn restore_xml(&self, parser: &dyn XmlPullParser, vector_factory: &dyn LSHVectorFactory) -> Result<(), crate::feature::bsim::query::LshException>;
}

/// Placeholder for `ResponseAdjustIndex` type. Response from vector index adjustment operations.
pub trait ResponseAdjustIndex: Send + Sync {
    fn save_xml(&self, fwrite: &mut dyn std::io::Write) -> std::io::Result<()>;
    fn restore_xml(&self, parser: &dyn XmlPullParser, vector_factory: &dyn LSHVectorFactory) -> Result<(), crate::feature::bsim::query::LshException>;
}

/// Placeholder for `LSHVectorFactory` type. Factory for creating and restoring LSH vectors.
pub trait LSHVectorFactory: Send + Sync {
    fn build_zero_vector(&self) -> Box<dyn LSHVector>;
    fn build_vector(&self, feature: &[i32]) -> Box<dyn LSHVector>;
    fn restore_vector_from_xml(&self, parser: &dyn XmlPullParser) -> Box<dyn LSHVector>;
    fn restore_vector_from_sql(&self, sql: &str) -> std::io::Result<Box<dyn LSHVector>>;
    fn set(&self, w_factory: &dyn WeightFactory, i_lookup: &dyn IDFLookup, settings: i32);
    fn is_loaded(&self) -> bool;
    fn get_significance_scale(&self) -> f64;
    fn get_significance_addend(&self) -> f64;
    fn get_settings(&self) -> i32;
    fn get_self_significance(&self, vector: &dyn LSHVector) -> f64;
    fn calculate_significance(&self, data: &dyn VectorCompare) -> f64;
    fn read_weights(&self, parser: &dyn XmlPullParser) -> std::io::Result<()>;
}


/// Placeholder for `DescriptionManager` type.
pub trait DescriptionManager: Send + Sync {}

/// Placeholder for `Configuration` type.
pub trait Configuration: Send + Sync {}

/// Placeholder for `WeightedLSHCosineVectorFactory` type.
pub trait WeightedLSHCosineVectorFactory: Send + Sync {}

/// Placeholder for `LSHVectorFactory` type.
pub trait LSHVectorFactoryStub: Send + Sync {}

/// Placeholder for `LSHVector` type.
pub trait LSHVector: Send + Sync {}

/// Placeholder for `WeightFactory` type.
pub trait WeightFactory: Send + Sync {}

/// Placeholder for `IDFLookup` type.
pub trait IDFLookup: Send + Sync {}

/// Placeholder for `VectorCompare` type.
pub trait VectorCompare: Send + Sync {}

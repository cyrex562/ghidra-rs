//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

pub use crate::program::model::address::Address as AddressType;
pub use crate::feature::vt::api::markuptype::vt_markup_type::{VtMarkupType, VtMarkupTypeBase};
pub use crate::feature::vt::api::main::vt_association::VtAssociation;
pub use crate::feature::vt::api::main::vt_markup_item::VtMarkupItem;
pub use crate::feature::vt::api::main::vt_match::VtMatch;

use crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage;
use crate::feature::vt::api::main::vt_association_markup_status::VtAssociationMarkupStatus;
use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
use crate::feature::vt::api::util::version_tracking_apply_exception::VersionTrackingApplyException;
use crate::framework::remote::User;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

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

/// Placeholder for `ghidra.features.base.memsearch.matcher.UserInputByteMatcher`, referenced by
/// [`SearchFormat`](crate::feature::base::memsearch::format::search_format::SearchFormat) (whose
/// `parse` returns one, and whose `is_valid_text` default method calls
/// [`is_valid_search`](Self::is_valid_search) on the result) before the real class is ported.
/// Trimmed to the one member `SearchFormat.isValidText` actually reads; see
/// `UserInputByteMatcher.java` for the type's full public surface. Replace with the real port
/// when available.
pub trait UserInputByteMatcher: Send + Sync {
    fn is_valid_search(&self) -> bool;
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

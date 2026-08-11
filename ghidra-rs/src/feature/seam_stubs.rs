//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

pub use crate::program::model::address::Address as AddressType;

use crate::feature::vt::api::implementation::markup_item_impl::MarkupItemImpl;
use crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage;
use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
use crate::feature::vt::api::main::vt_score::VtScore;
use crate::feature::vt::api::util::version_tracking_apply_exception::VersionTrackingApplyException;
use crate::framework::remote::User;

/// Placeholder for the unported Java type `VTAssociation`, referenced by `VTAssociationManager` and `AssociationHook`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait VtAssociation: Send + Sync {
    fn get_type(&self) -> Box<dyn VtAssociationType>;

    /// Java: `VTAssociationDB.getSession()`. Returns the real, already-ported `VTSession`
    /// (`crate::feature::vt::api::main::vt_session::VTSession`) rather than the minimal local
    /// [`VtSession`] stub below, which predates that port and is now stale for this purpose.
    fn get_session(&self) -> Box<dyn crate::feature::vt::api::main::vt_session::VTSession>;

    fn get_markup_items(&self, monitor: &dyn TaskMonitor) -> std::io::Result<Vec<Box<dyn VtMarkupItem>>>;
    fn has_applied_markup_items(&self) -> bool;
    fn get_source_address(&self) -> AddressType;
    fn get_destination_address(&self) -> AddressType;
    fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>>;
    fn set_markup_status(&self, markup_items_status: &dyn VtAssociationMarkupStatus);
    fn get_markup_status(&self) -> Box<dyn VtAssociationMarkupStatus>;
    fn get_status(&self) -> Box<dyn VtAssociationStatus>;
    fn set_accepted(&self) -> std::io::Result<()>;
    fn clear_status(&self) -> std::io::Result<()>;
    fn set_rejected(&self) -> std::io::Result<()>;
    fn get_vote_count(&self) -> i32;
    fn set_vote_count(&self, vote_count: i32);

    /// Java: `DBObject.getKey()`, inherited by the concrete `VTAssociationDB`. Defaulted (so
    /// existing/mock implementors keep compiling) since not every `VtAssociation` implementor
    /// backs a database row.
    ///
    /// Grown for
    /// [`VTMatchMarkupItemTableDBAdapterV0`](crate::feature::vt::api::main::db::vt_match_markup_item_table_db_adapter_v0::VTMatchMarkupItemTableDBAdapterV0)'s
    /// port of `VTMatchMarkupItemTableDBAdapterV0.createMarkupItemRecord`.
    fn get_key(&self) -> i64 {
        unimplemented!("VtAssociation::get_key not available on this implementor")
    }

    /// Java: the `(VTSessionDB) association.getSession()` cast that
    /// [`MarkupItemImpl`] performs before firing a markup event or reading a program's
    /// modification number. Defaulted to `None` -- the "not a database-backed session" case --
    /// since [`get_session`](Self::get_session) is not implementable by every implementor.
    ///
    /// Grown for the [`MarkupItemImpl`] port.
    fn get_session_db(&self) -> Option<std::sync::Arc<dyn VTSessionDB>> {
        None
    }

    /// Java: `VTAssociationDB.markupItemStatusChanged(VTMarkupItem)`, which forwards to the
    /// association manager so it can notify every registered `AssociationHook`. Defaulted to a
    /// no-op, mirroring the `if (!(association instanceof VTAssociationDB)) return;` guard in
    /// `MarkupItemImpl.fireMarkupItemStatusChanged`.
    ///
    /// Grown for the [`MarkupItemImpl`] port.
    fn markup_item_status_changed(&self, markup_item: &dyn VtMarkupItem) {
        let _ = markup_item;
    }
}

/// Placeholder for the unported Java type `VTMarkupItem`, referenced by `AssociationHook`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait VtMarkupItem: Send + Sync {
    fn can_apply(&self) -> bool;
    fn can_unapply(&self) -> bool;
    fn apply(&self, apply_action: &dyn VtMarkupItemApplyActionType, options: &dyn ToolOptions) -> std::io::Result<()>;
    fn unapply(&self) -> std::io::Result<()>;
    fn set_default_destination_address(&self, address: &AddressType, address_source: &str);
    fn set_destination_address(&self, address: &AddressType);
    fn get_destination_address_edit_status(&self) -> Box<dyn VtMarkupItemDestinationAddressEditStatus>;
    fn set_considered(&self, status: &dyn VtMarkupItemConsideredStatus);
    fn get_status(&self) -> Box<dyn VtMarkupItemStatus>;
    fn get_status_description(&self) -> String;
    fn get_association(&self) -> Box<dyn VtAssociation>;
    fn get_source_address(&self) -> AddressType;
    fn get_source_location(&self) -> Box<dyn ProgramLocation>;
    fn get_source_value(&self) -> Box<dyn Stringable>;
    fn get_destination_address(&self) -> AddressType;
    fn get_destination_location(&self) -> Box<dyn ProgramLocation>;
    fn get_destination_address_source(&self) -> String;
    fn get_current_destination_value(&self) -> Box<dyn Stringable>;
    fn get_original_destination_value(&self) -> Box<dyn Stringable>;
    fn supports_apply_action(&self, action_type: &dyn VtMarkupItemApplyActionType) -> bool;
    fn get_markup_type(&self) -> Box<dyn VtMarkupType>;
}

/// Placeholder for `VTAssociationType`.
pub trait VtAssociationType: Send + Sync {
    fn display_name(&self) -> &str;
}

/// Placeholder for `VTSession`.
pub trait VtSession: Send + Sync {
    fn get_name(&self) -> &str;
}

/// Placeholder for `TaskMonitor`.
pub trait TaskMonitor: Send + Sync {
    fn check_cancelled(&self) -> std::io::Result<()>;
}

/// Placeholder for `VTMarkupItemStatus`.
pub trait VtMarkupItemStatus: Send + Sync {
    fn is_applied(&self) -> bool;

    /// The real, already-ported enum behind this placeholder, for callers that need to switch on
    /// the status rather than just ask whether it is applied. Grown for the [`MarkupItemImpl`]
    /// port; see the bridging impl below.
    fn markup_item_status(
        &self,
    ) -> crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus {
        unimplemented!("this VtMarkupItemStatus placeholder has no ported enum behind it")
    }
}

/// Bridges the real, ported markup-item status enum onto the [`VtMarkupItemStatus`] placeholder
/// trait, so that [`MarkupItemImpl`] -- which speaks the real enum throughout -- can still be
/// handed to seams typed against the placeholder.
impl VtMarkupItemStatus for crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus {
    fn is_applied(&self) -> bool {
        self.is_unappliable()
    }

    fn markup_item_status(
        &self,
    ) -> crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus {
        *self
    }
}

/// Placeholder for `VTAssociationMarkupStatus`.
pub trait VtAssociationMarkupStatus: Send + Sync {
    fn get_status(&self) -> &str;
}

/// Placeholder for `VTAssociationStatus`.
pub trait VtAssociationStatus: Send + Sync {
    fn get_status(&self) -> &str;

    /// The real, already-ported enum behind this placeholder, for callers that need to ask it
    /// `canApply()` rather than just print it. Grown for the [`MarkupItemImpl`] port; see the
    /// bridging impl further down this file.
    fn association_status(
        &self,
    ) -> crate::feature::vt::api::main::vt_association_status::VtAssociationStatus {
        unimplemented!("this VtAssociationStatus placeholder has no ported enum behind it")
    }
}

/// Placeholder for `VTMarkupItemApplyActionType`.
pub trait VtMarkupItemApplyActionType: Send + Sync {
    fn get_name(&self) -> &str;

    /// The real, already-ported enum behind this placeholder. Grown for the [`MarkupItemImpl`]
    /// port; see the bridging impl below.
    fn apply_action_type(
        &self,
    ) -> crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType
    {
        unimplemented!("this VtMarkupItemApplyActionType placeholder has no ported enum behind it")
    }
}

/// Bridges the real, ported apply-action enum onto the [`VtMarkupItemApplyActionType`] placeholder
/// trait. The placeholder's `get_name` reports the Java enum constant's name.
impl VtMarkupItemApplyActionType
    for crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType
{
    fn get_name(&self) -> &str {
        use crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType as Action;
        match self {
            Action::Add => "ADD",
            Action::AddAsPrimary => "ADD_AS_PRIMARY",
            Action::ReplaceDefaultOnly => "REPLACE_DEFAULT_ONLY",
            Action::Replace => "REPLACE",
            Action::ReplaceFirstOnly => "REPLACE_FIRST_ONLY",
        }
    }

    fn apply_action_type(
        &self,
    ) -> crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType
    {
        *self
    }
}

/// Placeholder for `ToolOptions`.
pub trait ToolOptions: Send + Sync {
    fn get_option(&self, key: &str) -> Option<String>;
}

/// Placeholder for `VTMarkupItemDestinationAddressEditStatus`.
pub trait VtMarkupItemDestinationAddressEditStatus: Send + Sync {
    fn is_editable(&self) -> bool;
}

/// Bridges the real, ported edit-status enum onto the
/// [`VtMarkupItemDestinationAddressEditStatus`] placeholder trait, so that [`MarkupItemImpl`] can
/// answer the placeholder-typed `VtMarkupItem::get_destination_address_edit_status` with the enum
/// its own inherent accessor computes.
impl VtMarkupItemDestinationAddressEditStatus
    for crate::feature::vt::api::main::vt_markup_item_destination_address_edit_status::VtMarkupItemDestinationAddressEditStatus
{
    fn is_editable(&self) -> bool {
        use crate::feature::vt::api::main::vt_markup_item_destination_address_edit_status::VtMarkupItemDestinationAddressEditStatus as EditStatus;
        matches!(self, EditStatus::Editable)
    }
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

/// Placeholder for `VTMarkupType`.
///
/// Grown for the [`MarkupItemImpl`] port: everything below `get_name` is a `VTMarkupType` member
/// that `MarkupItemImpl` calls on its markup type. Each one carries the Java base class's own
/// default where it has one (`validateDestinationAddress` hands the suggested address back
/// unchanged; `conflictsWithOtherMarkup` answers `false`); the members that are `abstract` in Java
/// panic instead, so that the nine placeholder markup types further down this file keep compiling
/// until each is really ported.
pub trait VtMarkupType: Send + Sync {
    fn get_name(&self) -> &str;

    /// Java: the `type instanceof FunctionEntryPointBasedAbstractMarkupType` narrowing in
    /// `MarkupItemImpl.getDestinationAddressEditStatus()`. Rust has no `instanceof`, so the
    /// classification is asked of the markup type itself.
    fn is_function_entry_point_based(&self) -> bool {
        false
    }

    /// Java: the `type instanceof DataTypeMarkupType` narrowing in
    /// `MarkupItemImpl.getDestinationAddressEditStatus()`. See
    /// [`is_function_entry_point_based`](Self::is_function_entry_point_based).
    fn is_data_type_based(&self) -> bool {
        false
    }

    /// Java: `VTMarkupType.validateDestinationAddress`, whose base implementation accepts any
    /// address it is given.
    fn validate_destination_address(
        &self,
        association: &dyn VtAssociation,
        source_address: &AddressType,
        suggested_destination_address: &AddressType,
    ) -> AddressType {
        let _ = (association, source_address);
        suggested_destination_address.clone()
    }

    /// Java: `VTMarkupType.conflictsWithOtherMarkup`, whose base implementation reports no
    /// conflict.
    fn conflicts_with_other_markup(
        &self,
        markup_item: &MarkupItemImpl,
        markup_items: &[Box<dyn VtMarkupItem>],
    ) -> bool {
        let _ = (markup_item, markup_items);
        false
    }

    /// Java: `VTMarkupType.hasSameSourceAndDestinationValues` (abstract).
    fn has_same_source_and_destination_values(&self, markup_item: &MarkupItemImpl) -> bool {
        let _ = markup_item;
        unimplemented!("{}: hasSameSourceAndDestinationValues is not ported yet", self.get_name())
    }

    /// Java: `VTMarkupType.getSourceValue` (abstract).
    fn get_source_value(
        &self,
        association: &dyn VtAssociation,
        source_address: &AddressType,
    ) -> Box<dyn Stringable> {
        let _ = (association, source_address);
        unimplemented!("{}: getSourceValue is not ported yet", self.get_name())
    }

    /// Java: `VTMarkupType.getCurrentDestinationValue` (abstract).
    fn get_current_destination_value(
        &self,
        association: &dyn VtAssociation,
        destination_address: &AddressType,
    ) -> Box<dyn Stringable> {
        let _ = (association, destination_address);
        unimplemented!("{}: getCurrentDestinationValue is not ported yet", self.get_name())
    }

    /// Java: `VTMarkupType.getOriginalDestinationValue` (abstract).
    fn get_original_destination_value(
        &self,
        association: &dyn VtAssociation,
        destination_address: &AddressType,
    ) -> Box<dyn Stringable> {
        let _ = (association, destination_address);
        unimplemented!("{}: getOriginalDestinationValue is not ported yet", self.get_name())
    }

    /// Java: `VTMarkupType.getSourceLocation` (abstract).
    fn get_source_location(
        &self,
        association: &dyn VtAssociation,
        source_address: &AddressType,
    ) -> Box<dyn ProgramLocation> {
        let _ = (association, source_address);
        unimplemented!("{}: getSourceLocation is not ported yet", self.get_name())
    }

    /// Java: `VTMarkupType.getDestinationLocation` (abstract).
    fn get_destination_location(
        &self,
        association: &dyn VtAssociation,
        destination_address: &AddressType,
    ) -> Box<dyn ProgramLocation> {
        let _ = (association, destination_address);
        unimplemented!("{}: getDestinationLocation is not ported yet", self.get_name())
    }

    /// Java: `VTMarkupType.applyMarkup` (abstract). Returns whether the markup was applied.
    fn apply_markup(
        &self,
        markup_item: &MarkupItemImpl,
        markup_options: &dyn ToolOptions,
    ) -> Result<bool, VersionTrackingApplyException> {
        let _ = (markup_item, markup_options);
        unimplemented!("{}: applyMarkup is not ported yet", self.get_name())
    }

    /// Java: `VTMarkupType.unapplyMarkup` (abstract).
    fn unapply_markup(
        &self,
        markup_item: &MarkupItemImpl,
    ) -> Result<(), VersionTrackingApplyException> {
        let _ = markup_item;
        unimplemented!("{}: unapplyMarkup is not ported yet", self.get_name())
    }

    /// Java: `VTMarkupType.supportsApplyAction` (abstract).
    fn supports_apply_action(
        &self,
        apply_action: crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType,
    ) -> bool {
        let _ = apply_action;
        false
    }
}

/// Lets a shared markup type -- which is how
/// [`vt_markup_type_factory`](crate::feature::vt::api::markuptype::vt_markup_type_factory) hands
/// its singletons out -- be passed as the owned `Box<dyn VtMarkupType>` that
/// [`MarkupItemStorage`](crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage)
/// returns, without cloning the singleton and without a hand-written forwarding wrapper that would
/// silently fall back to the defaults above for every member it forgot to override.
impl VtMarkupType for std::sync::Arc<dyn VtMarkupType> {
    fn get_name(&self) -> &str {
        (**self).get_name()
    }

    fn is_function_entry_point_based(&self) -> bool {
        (**self).is_function_entry_point_based()
    }

    fn is_data_type_based(&self) -> bool {
        (**self).is_data_type_based()
    }

    fn validate_destination_address(
        &self,
        association: &dyn VtAssociation,
        source_address: &AddressType,
        suggested_destination_address: &AddressType,
    ) -> AddressType {
        (**self).validate_destination_address(
            association,
            source_address,
            suggested_destination_address,
        )
    }

    fn conflicts_with_other_markup(
        &self,
        markup_item: &MarkupItemImpl,
        markup_items: &[Box<dyn VtMarkupItem>],
    ) -> bool {
        (**self).conflicts_with_other_markup(markup_item, markup_items)
    }

    fn has_same_source_and_destination_values(&self, markup_item: &MarkupItemImpl) -> bool {
        (**self).has_same_source_and_destination_values(markup_item)
    }

    fn get_source_value(
        &self,
        association: &dyn VtAssociation,
        source_address: &AddressType,
    ) -> Box<dyn Stringable> {
        (**self).get_source_value(association, source_address)
    }

    fn get_current_destination_value(
        &self,
        association: &dyn VtAssociation,
        destination_address: &AddressType,
    ) -> Box<dyn Stringable> {
        (**self).get_current_destination_value(association, destination_address)
    }

    fn get_original_destination_value(
        &self,
        association: &dyn VtAssociation,
        destination_address: &AddressType,
    ) -> Box<dyn Stringable> {
        (**self).get_original_destination_value(association, destination_address)
    }

    fn get_source_location(
        &self,
        association: &dyn VtAssociation,
        source_address: &AddressType,
    ) -> Box<dyn ProgramLocation> {
        (**self).get_source_location(association, source_address)
    }

    fn get_destination_location(
        &self,
        association: &dyn VtAssociation,
        destination_address: &AddressType,
    ) -> Box<dyn ProgramLocation> {
        (**self).get_destination_location(association, destination_address)
    }

    fn apply_markup(
        &self,
        markup_item: &MarkupItemImpl,
        markup_options: &dyn ToolOptions,
    ) -> Result<bool, VersionTrackingApplyException> {
        (**self).apply_markup(markup_item, markup_options)
    }

    fn unapply_markup(
        &self,
        markup_item: &MarkupItemImpl,
    ) -> Result<(), VersionTrackingApplyException> {
        (**self).unapply_markup(markup_item)
    }

    fn supports_apply_action(
        &self,
        apply_action: crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType,
    ) -> bool {
        (**self).supports_apply_action(apply_action)
    }
}

/// Placeholder for the unported Java type `VTMatch`, referenced by `VTSession`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait VtMatch: Send + Sync {
    fn get_match_set(&self) -> Box<dyn VtMatchSet>;
    fn get_association(&self) -> Box<dyn VtAssociation>;
    fn get_tag(&self) -> VtMatchTag;
    fn set_tag(&self, tag: VtMatchTag);
    fn get_similarity_score(&self) -> VtScore;
    fn get_confidence_score(&self) -> VtScore;
    fn get_source_address(&self) -> AddressType;
    fn get_destination_address(&self) -> AddressType;
    fn get_source_length(&self) -> i32;
    fn get_destination_length(&self) -> i32;
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

/// Bridges the real, ported association-status enum onto the [`VtAssociationStatus`] placeholder
/// trait the `VtAssociation` seam speaks in, so no second status type has to be invented.
impl VtAssociationStatus
    for crate::feature::vt::api::main::vt_association_status::VtAssociationStatus
{
    fn get_status(&self) -> &str {
        self.display_name()
    }

    fn association_status(
        &self,
    ) -> crate::feature::vt::api::main::vt_association_status::VtAssociationStatus {
        *self
    }
}

/// Bridges the real, ported association-type enum onto the [`VtAssociationType`] placeholder
/// trait. See [`VtAssociationStatus`]'s impl above.
impl VtAssociationType for crate::feature::vt::api::main::vt_association_type::VtAssociationType {
    fn display_name(&self) -> &str {
        crate::feature::vt::api::main::vt_association_type::VtAssociationType::display_name(self)
    }
}

/// Bridges the real, ported markup-status struct onto the [`VtAssociationMarkupStatus`]
/// placeholder trait. See [`VtAssociationStatus`]'s impl above.
impl VtAssociationMarkupStatus
    for crate::feature::vt::api::main::vt_association_markup_status::VtAssociationMarkupStatus
{
    fn get_status(&self) -> &str {
        // The placeholder trait returns a borrowed string; the real `description()` builds an
        // owned one, so this reports the raw packed value's applied-ness instead, which is the
        // only thing the seam's callers look at.
        if self.has_applied_markup() {
            "Applied"
        }
        else if self.is_initialized() {
            "Unapplied"
        }
        else {
            "Uninitialized"
        }
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
    fn get_type(&self) -> Box<dyn VtAssociationType> {
        self.0.get_type()
    }

    fn get_session(&self) -> Box<dyn crate::feature::vt::api::main::vt_session::VTSession> {
        self.0.get_session()
    }

    fn get_markup_items(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> std::io::Result<Vec<Box<dyn VtMarkupItem>>> {
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

    fn set_markup_status(&self, markup_items_status: &dyn VtAssociationMarkupStatus) {
        self.0.set_markup_status(markup_items_status)
    }

    fn get_markup_status(&self) -> Box<dyn VtAssociationMarkupStatus> {
        self.0.get_markup_status()
    }

    fn get_status(&self) -> Box<dyn VtAssociationStatus> {
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
pub struct EolCommentMarkupType;

impl VtMarkupType for EolCommentMarkupType {
    fn get_name(&self) -> &str {
        "EOL Comment"
    }
}

/// Placeholder for the unported Java type `FunctionNameMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `FunctionNameMarkupType.java` is ported.
pub struct FunctionNameMarkupType;

impl VtMarkupType for FunctionNameMarkupType {
    fn get_name(&self) -> &str {
        "Function Name"
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
pub struct FunctionSignatureMarkupType;

impl VtMarkupType for FunctionSignatureMarkupType {
    fn get_name(&self) -> &str {
        "Function Signature"
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
pub struct LabelMarkupType;

impl VtMarkupType for LabelMarkupType {
    fn get_name(&self) -> &str {
        "Label"
    }
}

/// Placeholder for the unported Java type `PlateCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `PlateCommentMarkupType.java` is ported.
pub struct PlateCommentMarkupType;

impl VtMarkupType for PlateCommentMarkupType {
    fn get_name(&self) -> &str {
        "Plate Comment"
    }
}

/// Placeholder for the unported Java type `PostCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `PostCommentMarkupType.java` is ported.
pub struct PostCommentMarkupType;

impl VtMarkupType for PostCommentMarkupType {
    fn get_name(&self) -> &str {
        "Post Comment"
    }
}

/// Placeholder for the unported Java type `PreCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `PreCommentMarkupType.java` is ported.
pub struct PreCommentMarkupType;

impl VtMarkupType for PreCommentMarkupType {
    fn get_name(&self) -> &str {
        "Pre Comment"
    }
}

/// Placeholder for the unported Java type `RepeatableCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `RepeatableCommentMarkupType.java` is ported.
pub struct RepeatableCommentMarkupType;

impl VtMarkupType for RepeatableCommentMarkupType {
    fn get_name(&self) -> &str {
        "Repeatable Comment"
    }
}

/// Placeholder for the unported Java type `DataTypeMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `DataTypeMarkupType.java` is ported.
pub struct DataTypeMarkupType;

impl VtMarkupType for DataTypeMarkupType {
    fn get_name(&self) -> &str {
        "Data Type"
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

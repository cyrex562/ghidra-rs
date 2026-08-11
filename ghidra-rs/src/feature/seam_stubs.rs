//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

pub use crate::program::model::address::Address as AddressType;

use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
use crate::feature::vt::api::main::vt_score::VtScore;

/// Placeholder for the unported Java type `VTAssociation`, referenced by `VTAssociationManager` and `AssociationHook`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait VtAssociation: Send + Sync {
    fn get_type(&self) -> Box<dyn VtAssociationType>;
    fn get_session(&self) -> Box<dyn VtSession>;
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
}

/// Placeholder for `VTAssociationMarkupStatus`.
pub trait VtAssociationMarkupStatus: Send + Sync {
    fn get_status(&self) -> &str;
}

/// Placeholder for `VTAssociationStatus`.
pub trait VtAssociationStatus: Send + Sync {
    fn get_status(&self) -> &str;
}

/// Placeholder for `VTMarkupItemApplyActionType`.
pub trait VtMarkupItemApplyActionType: Send + Sync {
    fn get_name(&self) -> &str;
}

/// Placeholder for `ToolOptions`.
pub trait ToolOptions: Send + Sync {
    fn get_option(&self, key: &str) -> Option<String>;
}

/// Placeholder for `VTMarkupItemDestinationAddressEditStatus`.
pub trait VtMarkupItemDestinationAddressEditStatus: Send + Sync {
    fn is_editable(&self) -> bool;
}

/// Placeholder for `VTMarkupItemConsideredStatus`.
pub trait VtMarkupItemConsideredStatus: Send + Sync {
    fn is_considered(&self) -> bool;
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
pub trait VtMarkupType: Send + Sync {
    fn get_name(&self) -> &str;
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

/// Placeholder for the unported Java type `VTProgramCorrelator`, referenced by `VTSession`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait VtProgramCorrelator: Send + Sync {
    fn correlate(
        &self,
        session: &dyn VtSession,
        monitor: &dyn crate::util::task::TaskMonitor,
    ) -> std::io::Result<Box<dyn VtMatchSet>>;
    fn get_name(&self) -> String;
    fn get_options(&self) -> Box<dyn ToolOptions>;
    fn get_source_address_set(&self) -> Box<dyn crate::program::model::address::AddressSetView>;
    fn get_source_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::program::Program>;
    fn get_destination_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::program::Program>;
    fn get_destination_address_set(&self) -> Box<dyn crate::program::model::address::AddressSetView>;
}

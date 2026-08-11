//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::program::model::address::Address;

/// Placeholder for the unported Java type `VTAssociation`, referenced by `VTAssociationManager`.
/// Generated stub: only a shape hint. Replace with the real port when available.
pub trait VtAssociation: Send + Sync {
    /// Returns the type of this association.
    fn get_type(&self) -> Box<dyn VtAssociationType>;
    /// Returns the session this association belongs to.
    fn get_session(&self) -> Box<dyn VtSession>;
    /// Returns the markup items for this association.
    fn get_markup_items(&self, monitor: &dyn TaskMonitor) -> std::io::Result<Vec<Box<dyn VtMarkupItem>>>;
    /// Checks if this association has any applied markup items.
    fn has_applied_markup_items(&self) -> bool;
    /// Returns the source address of this association.
    fn get_source_address(&self) -> Address;
    /// Returns the destination address of this association.
    fn get_destination_address(&self) -> Address;
    /// Returns associations related to this one.
    fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>>;
    /// Sets the markup status for this association.
    fn set_markup_status(&self, markup_items_status: &dyn VtAssociationMarkupStatus);
    /// Returns the markup status of this association.
    fn get_markup_status(&self) -> Box<dyn VtAssociationMarkupStatus>;
    /// Returns the status of this association.
    fn get_status(&self) -> Box<dyn VtAssociationStatus>;
    /// Marks this association as accepted.
    fn set_accepted(&self) -> std::io::Result<()>;
    /// Clears the status of this association.
    fn clear_status(&self) -> std::io::Result<()>;
    /// Marks this association as rejected.
    fn set_rejected(&self) -> std::io::Result<()>;
    /// Returns the vote count for this association.
    fn get_vote_count(&self) -> i32;
    /// Sets the vote count for this association.
    fn set_vote_count(&self, vote_count: i32);
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

/// Placeholder for `VTMarkupItem`.
pub trait VtMarkupItem: Send + Sync {
    fn get_status(&self) -> Box<dyn VtMarkupItemStatus>;
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

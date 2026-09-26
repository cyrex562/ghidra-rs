//! Port of `ghidra.feature.vt.api.main.VTAssociation`.
//!
//! A `VTAssociation` is a possible equivalence between a function or data item in one program
//! and a function or data item in another program. Associations can be "Accepted", indicating
//! that the user has agreed that the association is correct.
//!
//! [`VTAssociationDB`](crate::feature::vt::api::db::vt_association_db::VTAssociationDB) is the
//! only in-repo implementor. `VTAssociation` sits on a dependency cycle with `VTMarkupItem` (an
//! association hands back the markup items that belong to it, and a markup item points back at
//! its association); `VTMarkupItem` is already ported, so this trait speaks it directly.
//! `VTAssociationStatusException` is not ported yet, so this trait speaks the placeholder struct
//! already declared in [`crate::feature::seam_stubs`] for it.

use crate::feature::seam_stubs::VTAssociationStatusException;
use crate::feature::vt::api::main::vt_association_markup_status::VtAssociationMarkupStatus;
use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
use crate::feature::vt::api::main::vt_markup_item::VtMarkupItem;
use crate::feature::vt::api::main::vt_session::VTSession;
use crate::program::model::address::Address;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Port of the `ghidra.feature.vt.api.main.VTAssociation` interface.
pub trait VtAssociation: Send + Sync {
    /// Java: `getType()`. The type of the association -- either Function or Data.
    fn get_type(&self) -> VtAssociationType;

    /// Java: `getSession()`. The session this association belongs to.
    fn get_session(&self) -> Box<dyn VTSession>;

    /// Java: `getMarkupItems(TaskMonitor)`. The markup items for this association.
    fn get_markup_items(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<Box<dyn VtMarkupItem>>, CancelledException>;

    /// Java: `hasAppliedMarkupItems()`. True if this association is accepted and has one or more
    /// markup items that have been applied.
    fn has_applied_markup_items(&self) -> bool;

    /// Java: `getSourceAddress()`.
    fn get_source_address(&self) -> Address;

    /// Java: `getDestinationAddress()`.
    fn get_destination_address(&self) -> Address;

    /// Java: `getRelatedAssociations()`. Associations that share either this association's source
    /// address or its destination address.
    fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>>;

    /// Java: `setMarkupStatus(VTAssociationMarkupStatus)`. Used by the association manager to
    /// update this association with the state of its markup items.
    fn set_markup_status(&self, markup_items_status: VtAssociationMarkupStatus);

    /// Java: `getMarkupStatus()`.
    fn get_markup_status(&self) -> VtAssociationMarkupStatus;

    /// Java: `getStatus()`. One of AVAILABLE, ACCEPTED, BLOCKED, or REJECTED.
    fn get_status(&self) -> VtAssociationStatus;

    /// Java: `setAccepted()`. Accepts this association without performing an apply.
    ///
    /// # Errors
    /// Returns [`VTAssociationStatusException`] if this association is
    /// [`VtAssociationStatus::Blocked`].
    fn set_accepted(&self) -> Result<(), VTAssociationStatusException>;

    /// Java: `clearStatus()`. Clears this association's status from ACCEPTED or REJECTED back to
    /// AVAILABLE.
    ///
    /// # Errors
    /// Returns [`VTAssociationStatusException`] if this association's status is not
    /// ACCEPTED/REJECTED, or if this association's markup items have been applied.
    fn clear_status(&self) -> Result<(), VTAssociationStatusException>;

    /// Java: `setRejected()`. Sets this association's status to REJECTED.
    ///
    /// # Errors
    /// Returns [`VTAssociationStatusException`] if this association is accepted.
    fn set_rejected(&self) -> Result<(), VTAssociationStatusException>;

    /// Java: `getVoteCount()`. The current number of facts that support this association.
    fn get_vote_count(&self) -> i32;

    /// Java: `setVoteCount(int)`.
    fn set_vote_count(&self, vote_count: i32);

    /// Java: `DBObject.getKey()`, inherited by the concrete `VTAssociationDB`. Defaulted (so
    /// existing/mock implementors keep compiling) since not every `VtAssociation` implementor
    /// backs a database row.
    fn get_key(&self) -> i64 {
        unimplemented!("VtAssociation::get_key not available on this implementor")
    }

    /// Java: the `(VTSessionDB) association.getSession()` cast that
    /// [`MarkupItemImpl`](crate::feature::vt::api::implementation::markup_item_impl::MarkupItemImpl)
    /// performs before firing a markup event or reading a program's modification number.
    /// Defaulted to `None` -- the "not a database-backed session" case -- since
    /// [`get_session`](Self::get_session) is not implementable by every implementor.
    fn get_session_db(&self) -> Option<std::sync::Arc<dyn crate::feature::seam_stubs::VTSessionDB>> {
        None
    }

    /// Java: `VTAssociationDB.markupItemStatusChanged(VTMarkupItem)`, which forwards to the
    /// association manager so it can notify every registered `AssociationHook`. Defaulted to a
    /// no-op, mirroring the `if (!(association instanceof VTAssociationDB)) return;` guard in
    /// `MarkupItemImpl.fireMarkupItemStatusChanged`.
    fn markup_item_status_changed(&self, markup_item: &dyn VtMarkupItem) {
        let _ = markup_item;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    fn address(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1), offset)
    }

    /// A minimal implementor exercising nothing but the default methods, standing in for a
    /// non-database-backed association.
    struct FixedAssociation {
        status: VtAssociationStatus,
        vote_count: std::sync::atomic::AtomicI32,
    }

    impl VtAssociation for FixedAssociation {
        fn get_type(&self) -> VtAssociationType {
            VtAssociationType::Function
        }

        fn get_session(&self) -> Box<dyn VTSession> {
            unimplemented!("not exercised by this test")
        }

        fn get_markup_items(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<Box<dyn VtMarkupItem>>, CancelledException> {
            Ok(Vec::new())
        }

        fn has_applied_markup_items(&self) -> bool {
            false
        }

        fn get_source_address(&self) -> Address {
            address(0x1000)
        }

        fn get_destination_address(&self) -> Address {
            address(0x2000)
        }

        fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }

        fn set_markup_status(&self, _markup_items_status: VtAssociationMarkupStatus) {}

        fn get_markup_status(&self) -> VtAssociationMarkupStatus {
            VtAssociationMarkupStatus::new()
        }

        fn get_status(&self) -> VtAssociationStatus {
            self.status
        }

        fn set_accepted(&self) -> Result<(), VTAssociationStatusException> {
            if self.status.is_blocked() {
                return Err(VTAssociationStatusException::new("blocked"));
            }
            Ok(())
        }

        fn clear_status(&self) -> Result<(), VTAssociationStatusException> {
            Ok(())
        }

        fn set_rejected(&self) -> Result<(), VTAssociationStatusException> {
            Ok(())
        }

        fn get_vote_count(&self) -> i32 {
            self.vote_count.load(std::sync::atomic::Ordering::Relaxed)
        }

        fn set_vote_count(&self, vote_count: i32) {
            self.vote_count.store(vote_count, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Java: `setAccepted()` throws `VTAssociationStatusException` when the association is
    /// BLOCKED.
    #[test]
    fn set_accepted_fails_when_blocked() {
        let association =
            FixedAssociation { status: VtAssociationStatus::Blocked, vote_count: 0.into() };
        assert!(association.set_accepted().is_err());
    }

    /// Java: `setAccepted()` succeeds for a non-blocked association.
    #[test]
    fn set_accepted_succeeds_when_available() {
        let association =
            FixedAssociation { status: VtAssociationStatus::Available, vote_count: 0.into() };
        assert!(association.set_accepted().is_ok());
    }

    #[test]
    fn get_markup_items_reports_none_by_default() {
        let association =
            FixedAssociation { status: VtAssociationStatus::Available, vote_count: 0.into() };
        let items = association.get_markup_items(&DummyMonitor).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn vote_count_round_trips_through_setter() {
        let association =
            FixedAssociation { status: VtAssociationStatus::Available, vote_count: 0.into() };
        association.set_vote_count(7);
        assert_eq!(association.get_vote_count(), 7);
    }

    #[test]
    fn usable_as_trait_object() {
        let association: Arc<dyn VtAssociation> =
            Arc::new(FixedAssociation { status: VtAssociationStatus::Rejected, vote_count: 0.into() });
        assert_eq!(association.get_type(), VtAssociationType::Function);
        assert_eq!(association.get_status(), VtAssociationStatus::Rejected);
        assert!(association.get_related_associations().is_empty());
    }
}

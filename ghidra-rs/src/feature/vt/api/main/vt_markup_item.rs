//! Port of `ghidra.feature.vt.api.main.VTMarkupItem`.
//!
//! The interface every version-tracking markup item satisfies: the pairing of a source-program
//! value with a destination-program address, together with the apply/unapply lifecycle and the
//! status bookkeeping that tracks whether the value has been copied across.
//! [`MarkupItemImpl`](crate::feature::vt::api::implementation::markup_item_impl::MarkupItemImpl)
//! is the only in-repo implementor.
//!
//! `VTMarkupItem` sits on a dependency cycle with `VTAssociation` (an association hands back the
//! markup items that belong to it, and a markup item points back at its association) and with
//! `VTMarkupItemConsideredStatus`/`Stringable`/`ToolOptions`; none of those are ported yet, so this
//! trait speaks the placeholder traits already declared in [`crate::feature::seam_stubs`] for them.
//! [`VtMarkupType`], the three status/action-type enums, and [`VersionTrackingApplyException`] are
//! already ported, so this trait speaks them directly -- which is also why `apply`/`unapply` return
//! `Result<(), VersionTrackingApplyException>` here rather than the `std::io::Result` the
//! pre-existing placeholder trait (now replaced by this port; see `crate::feature::seam_stubs`)
//! used as a stand-in before `VTMarkupItem` itself was ported.

use crate::feature::seam_stubs::{
    ProgramLocation, Stringable, ToolOptions, VtAssociation, VtMarkupItemConsideredStatus,
    VtMarkupType,
};
use crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType;
use crate::feature::vt::api::main::vt_markup_item_destination_address_edit_status::VtMarkupItemDestinationAddressEditStatus;
use crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus;
use crate::feature::vt::api::util::version_tracking_apply_exception::VersionTrackingApplyException;
use crate::program::model::address::Address;

/// Java: `VTMarkupItem.USER_DEFINED_ADDRESS_SOURCE`, the destination-address source recorded when
/// a user picks the address themselves rather than accepting a correlator's suggestion.
pub const USER_DEFINED_ADDRESS_SOURCE: &str = "User Defined";

/// Java: `VTMarkupItem.FUNCTION_ADDRESS_SOURCE`.
pub const FUNCTION_ADDRESS_SOURCE: &str = "Function";

/// Java: `VTMarkupItem.DATA_ADDRESS_SOURCE`.
pub const DATA_ADDRESS_SOURCE: &str = "Data";

/// Port of the `ghidra.feature.vt.api.main.VTMarkupItem` interface.
pub trait VtMarkupItem: Send + Sync {
    /// Java: `canApply()`. Returns true if this markup item can be applied.
    fn can_apply(&self) -> bool;

    /// Java: `canUnapply()`. Returns true if this markup item can be unapplied.
    fn can_unapply(&self) -> bool;

    /// Java: `apply(VTMarkupItemApplyActionType, ToolOptions)`. The destination address and its
    /// source must already be set before calling this.
    fn apply(
        &self,
        apply_action: VtMarkupItemApplyActionType,
        options: &dyn ToolOptions,
    ) -> Result<(), VersionTrackingApplyException>;

    /// Java: `unapply()`. Returns the destination value back to its original value.
    fn unapply(&self) -> Result<(), VersionTrackingApplyException>;

    /// Java: `setDefaultDestinationAddress(Address, String)`, the transient "best guess" address a
    /// correlator suggests. Not saved -- callers wanting a persisted choice should use
    /// [`set_destination_address`](Self::set_destination_address).
    fn set_default_destination_address(&self, address: &Address, address_source: &str);

    /// Java: `setDestinationAddress(Address)`, the persisted, user-chosen destination address.
    fn set_destination_address(&self, address: &Address);

    /// Java: `getDestinationAddressEditStatus()`.
    fn get_destination_address_edit_status(&self) -> VtMarkupItemDestinationAddressEditStatus;

    /// Java: `setConsidered(VTMarkupItemConsideredStatus)`, recording that the user looked at this
    /// item and chose not to apply it.
    fn set_considered(&self, status: &dyn VtMarkupItemConsideredStatus);

    /// Java: `getStatus()`.
    fn get_status(&self) -> VtMarkupItemStatus;

    /// Java: `getStatusDescription()`, an optional description of the current status (e.g. why an
    /// apply failed).
    fn get_status_description(&self) -> String;

    /// Java: `getAssociation()`, the association that generated this markup item.
    fn get_association(&self) -> Box<dyn VtAssociation>;

    /// Java: `getSourceAddress()`.
    fn get_source_address(&self) -> Address;

    /// Java: `getSourceLocation()`, the field-specific program location in the source program.
    fn get_source_location(&self) -> Box<dyn ProgramLocation>;

    /// Java: `getSourceValue()`.
    fn get_source_value(&self) -> Box<dyn Stringable>;

    /// Java: `getDestinationAddress()`.
    fn get_destination_address(&self) -> Address;

    /// Java: `getDestinationLocation()`, the field-specific program location in the destination
    /// program.
    fn get_destination_location(&self) -> Box<dyn ProgramLocation>;

    /// Java: `getDestinationAddressSource()`, indicating the origin of the destination address
    /// (an algorithm's name, or [`USER_DEFINED_ADDRESS_SOURCE`]).
    fn get_destination_address_source(&self) -> String;

    /// Java: `getCurrentDestinationValue()`, the value the destination currently holds.
    fn get_current_destination_value(&self) -> Box<dyn Stringable>;

    /// Java: `getOriginalDestinationValue()`, the value the destination held before this item was
    /// applied.
    fn get_original_destination_value(&self) -> Box<dyn Stringable>;

    /// Java: `supportsApplyAction(VTMarkupItemApplyActionType)`.
    fn supports_apply_action(&self, action_type: VtMarkupItemApplyActionType) -> bool;

    /// Java: `getMarkupType()`.
    fn get_markup_type(&self) -> Box<dyn VtMarkupType>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_source_constants_match_java() {
        assert_eq!(USER_DEFINED_ADDRESS_SOURCE, "User Defined");
        assert_eq!(FUNCTION_ADDRESS_SOURCE, "Function");
        assert_eq!(DATA_ADDRESS_SOURCE, "Data");
    }

    /// A minimal implementor -- standing in for `MarkupItemImpl` -- that only answers the methods
    /// this test exercises through `&dyn VtMarkupItem`, enough to prove the trait dispatches
    /// dynamically over a status the same way Java's interface does.
    struct FixedStatusItem(VtMarkupItemStatus);

    impl VtMarkupItem for FixedStatusItem {
        fn can_apply(&self) -> bool {
            unimplemented!("not exercised by this test")
        }

        fn can_unapply(&self) -> bool {
            // Java: `MarkupItemImpl.canUnapply()` is `markupItemStorage.getStatus().isUnappliable()`.
            self.0.is_unappliable()
        }

        fn apply(
            &self,
            _apply_action: VtMarkupItemApplyActionType,
            _options: &dyn ToolOptions,
        ) -> Result<(), VersionTrackingApplyException> {
            unimplemented!("not exercised by this test")
        }

        fn unapply(&self) -> Result<(), VersionTrackingApplyException> {
            unimplemented!("not exercised by this test")
        }

        fn set_default_destination_address(&self, _address: &Address, _address_source: &str) {}

        fn set_destination_address(&self, _address: &Address) {}

        fn get_destination_address_edit_status(&self) -> VtMarkupItemDestinationAddressEditStatus {
            unimplemented!("not exercised by this test")
        }

        fn set_considered(&self, _status: &dyn VtMarkupItemConsideredStatus) {}

        fn get_status(&self) -> VtMarkupItemStatus {
            self.0
        }

        fn get_status_description(&self) -> String {
            String::new()
        }

        fn get_association(&self) -> Box<dyn VtAssociation> {
            unimplemented!("not exercised by this test")
        }

        fn get_source_address(&self) -> Address {
            unimplemented!("not exercised by this test")
        }

        fn get_source_location(&self) -> Box<dyn ProgramLocation> {
            unimplemented!("not exercised by this test")
        }

        fn get_source_value(&self) -> Box<dyn Stringable> {
            unimplemented!("not exercised by this test")
        }

        fn get_destination_address(&self) -> Address {
            unimplemented!("not exercised by this test")
        }

        fn get_destination_location(&self) -> Box<dyn ProgramLocation> {
            unimplemented!("not exercised by this test")
        }

        fn get_destination_address_source(&self) -> String {
            unimplemented!("not exercised by this test")
        }

        fn get_current_destination_value(&self) -> Box<dyn Stringable> {
            unimplemented!("not exercised by this test")
        }

        fn get_original_destination_value(&self) -> Box<dyn Stringable> {
            unimplemented!("not exercised by this test")
        }

        fn supports_apply_action(&self, _action_type: VtMarkupItemApplyActionType) -> bool {
            unimplemented!("not exercised by this test")
        }

        fn get_markup_type(&self) -> Box<dyn VtMarkupType> {
            unimplemented!("not exercised by this test")
        }
    }

    #[test]
    fn trait_object_dispatches_can_unapply_from_status() {
        let applied = FixedStatusItem(VtMarkupItemStatus::Added);
        let item: &dyn VtMarkupItem = &applied;
        assert!(item.can_unapply());

        let unapplied = FixedStatusItem(VtMarkupItemStatus::Unapplied);
        let item: &dyn VtMarkupItem = &unapplied;
        assert!(!item.can_unapply());
    }
}

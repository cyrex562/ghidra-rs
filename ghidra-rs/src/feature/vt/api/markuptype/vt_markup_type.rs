//! Port of `ghidra.feature.vt.api.markuptype.VTMarkupType`.
//!
//! The base class every version-tracking markup type (EOL comment, label, function signature, ...)
//! extends. Java's `VTMarkupType` is an abstract class: it carries the one `name` field and the
//! `final`/concrete methods that read it or use it as a convenience (`getDisplayName`,
//! `getDestinationProgram`, `getSourceListing`, ...), alongside the abstract methods each concrete
//! subclass must supply (`createMarkupItems`, `applyMarkup`, `getSourceValue`, ...). Rust has no
//! field inheritance, so [`VtMarkupTypeBase`] holds the field and the concrete methods; a concrete
//! markup type embeds it and implements [`VtMarkupType`] for the abstract methods (and `base()`,
//! which lets the trait's default methods reach the embedded state). This is the same split
//! [`EmulateInstructionStateModifierBase`](crate::pcode::emulate::emulate_instruction_state_modifier::EmulateInstructionStateModifierBase)
//! uses for the same reason.
//!
//! `VTMarkupType` sits on a dependency cycle with `VTAssociation`/`VTMarkupItem` (a markup type
//! creates/compares markup items, which each point back at their markup type) and those two Java
//! interfaces are not ported yet, so this port speaks the placeholder traits already declared in
//! [`crate::feature::seam_stubs`] (`VtAssociation`, `VtMarkupItem`, `Stringable`, `ToolOptions`,
//! `ProgramLocation`) for them, and the concrete [`MarkupItemImpl`] -- the only ported
//! implementation of `VTMarkupItem` -- for the parameters Java types as `VTMarkupItem` but that
//! only that one concrete class actually flows through in this crate today.
//!
//! # Deviations from Java
//!
//! * **`getDestinationListing`/`getSourceListing`/`getSourceFunction`/`getDestinationFunction`
//!   panic.** Each reads `program.getListing()`/`program.getFunctionManager()`, but the ported
//!   [`Program`] trait can only hand out `&mut dyn Listing`/`&mut dyn FunctionManager` from
//!   `&mut self`, while [`VtAssociation`]'s session only ever hands back a shared `Arc<dyn
//!   Program>`. There is no way to get a mutable borrow out of that without risking silent,
//!   input-dependent failure (`Arc::get_mut` succeeding or not depending on who else is holding a
//!   clone), so these four convenience accessors are left unimplemented until `Program` grows a
//!   shared-access seam for its listing/function manager, matching how `VTAssociationDB` leaves its
//!   own manager-shaped methods (`getSession`, `getMarkupItems`, ...) unimplemented for the
//!   analogous reason.
//! * **`getOriginalDestinationValueForAppliedMarkupOfThisType`'s identity check becomes a name
//!   comparison.** Java tests `markupItem.getMarkupType() == this`; markup items hand back a freshly
//!   boxed `Box<dyn VtMarkupType>`, so no pointer test is available. Every well-known markup type
//!   has a unique display name (the same assumption [`MarkupItemImpl::unapply`] already relies on),
//!   so this compares by [`VtMarkupType::get_display_name`] instead.
//! * **No `Address.NO_ADDRESS` sentinel.** Java also treats `destinationAddress ==
//!   Address.NO_ADDRESS` as "no address"; the ported [`Address`] has no such constant, so only the
//!   `null` case (`None`) is handled.

use std::sync::Arc;

use crate::feature::seam_stubs::{ProgramLocation, Stringable, ToolOptions, VtAssociation, VtMarkupItem};
use crate::feature::vt::api::implementation::markup_item_impl::MarkupItemImpl;
use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
use crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType;
use crate::feature::vt::api::util::version_tracking_apply_exception::VersionTrackingApplyException;
use crate::framework::options::Options;
use crate::program::model::address::Address;
use crate::program::model::listing::{Function, Listing, Program};
use crate::util::task::TaskMonitor;

/// The shared state and concrete (non-abstract) behavior of a [`VtMarkupType`].
///
/// Port of the `name` field and the concrete methods of `ghidra.feature.vt.api.markuptype.VTMarkupType`.
pub struct VtMarkupTypeBase {
    name: String,
}

impl VtMarkupTypeBase {
    /// Java: `VTMarkupType(String name)`.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Java: `getDisplayName()`.
    pub fn get_display_name(&self) -> &str {
        &self.name
    }

    /// Java: `validateDestinationAddress(VTAssociation, Address, Address)`. The base implementation
    /// (used by "normal" markup types) accepts any address it is given.
    pub fn validate_destination_address(
        &self,
        _association: &dyn VtAssociation,
        _source_address: &Address,
        suggested_destination_address: &Address,
    ) -> Address {
        suggested_destination_address.clone()
    }

    /// Java: `getDestinationProgram(VTAssociation)`.
    pub fn get_destination_program(&self, association: &dyn VtAssociation) -> Arc<dyn Program> {
        association.get_session().get_destination_program()
    }

    /// Java: `getSourceProgram(VTAssociation)`.
    pub fn get_source_program(&self, association: &dyn VtAssociation) -> Arc<dyn Program> {
        association.get_session().get_source_program()
    }

    /// Java: `getDestinationListing(VTAssociation)`. See the module-level deviations doc: blocked
    /// on `Program` not yet exposing a way to reach its listing without exclusive `&mut` access.
    pub fn get_destination_listing(
        &self,
        association: &dyn VtAssociation,
    ) -> Option<Box<dyn Listing>> {
        let _ = association;
        unimplemented!(
            "VtMarkupTypeBase::get_destination_listing requires Program::get_listing(&mut self), \
             which the Arc<dyn Program> obtained from VtAssociation's session cannot provide yet"
        )
    }

    /// Java: `getSourceListing(VTAssociation)`. See [`get_destination_listing`](Self::get_destination_listing).
    pub fn get_source_listing(&self, association: &dyn VtAssociation) -> Option<Box<dyn Listing>> {
        let _ = association;
        unimplemented!(
            "VtMarkupTypeBase::get_source_listing requires Program::get_listing(&mut self), which \
             the Arc<dyn Program> obtained from VtAssociation's session cannot provide yet"
        )
    }

    /// Java: `getSourceFunction(VTAssociation)`. Blocked the same way as
    /// [`get_destination_listing`](Self::get_destination_listing), on `Program::get_function_manager`
    /// needing `&mut self`.
    pub fn get_source_function(&self, association: &dyn VtAssociation) -> Option<Arc<dyn Function>> {
        let _ = association;
        unimplemented!(
            "VtMarkupTypeBase::get_source_function requires Program::get_function_manager(&mut \
             self), which the Arc<dyn Program> obtained from VtAssociation's session cannot \
             provide yet"
        )
    }

    /// Java: `getDestinationFunction(VTAssociation)`. See
    /// [`get_source_function`](Self::get_source_function).
    pub fn get_destination_function(
        &self,
        association: &dyn VtAssociation,
    ) -> Option<Arc<dyn Function>> {
        let _ = association;
        unimplemented!(
            "VtMarkupTypeBase::get_destination_function requires Program::get_function_manager(&mut \
             self), which the Arc<dyn Program> obtained from VtAssociation's session cannot \
             provide yet"
        )
    }

    /// Java: `getAddress(ProgramLocation, Program)`.
    pub fn get_address(&self, loc: &dyn ProgramLocation, _program: &dyn Program) -> Address {
        loc.get_address()
    }

    /// Java: `conflictsWithOtherMarkup(MarkupItemImpl, Collection<VTMarkupItem>)`. The base
    /// implementation reports no conflict.
    pub fn conflicts_with_other_markup(
        &self,
        _markup_item: &MarkupItemImpl,
        _markup_items: &[Box<dyn VtMarkupItem>],
    ) -> bool {
        false
    }

    /// Java: `getOriginalDestinationValueForAppliedMarkupOfThisType(VTAssociation, Address,
    /// TaskMonitor)` (protected). `markup_type` stands in for the `this` Java compares
    /// `markupItem.getMarkupType()` against by identity -- see the module-level deviations doc.
    pub fn get_original_destination_value_for_applied_markup_of_this_type(
        &self,
        markup_type: &dyn VtMarkupType,
        association: &dyn VtAssociation,
        destination_address: Option<&Address>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn Stringable>>, crate::util::exception::CancelledException> {
        let Some(destination_address) = destination_address else {
            return Ok(None);
        };

        for markup_item in association.get_markup_items(monitor)? {
            if markup_item.get_markup_type().get_display_name() != markup_type.get_display_name() {
                continue;
            }
            if !markup_item.can_unapply() {
                continue;
            }
            let item_destination = markup_item.get_destination_address();
            if item_destination == *destination_address {
                // Return the original destination value for the first applied markup item we
                // find of this type at this address.
                return Ok(Some(markup_item.get_original_destination_value()));
            }
        }

        Ok(None)
    }
}

/// The abstract operations of a version-tracking markup type, plus the concrete convenience
/// methods every markup type shares (forwarded to its embedded [`VtMarkupTypeBase`]).
///
/// Port of `ghidra.feature.vt.api.markuptype.VTMarkupType`. See the module docs for the deviations
/// this port makes.
pub trait VtMarkupType: Send + Sync {
    /// The shared state (currently just the display name) every markup type carries.
    fn base(&self) -> &VtMarkupTypeBase;

    /// Java: `getDisplayName()`.
    fn get_display_name(&self) -> &str {
        self.base().get_display_name()
    }

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

    /// Java: `validateDestinationAddress(VTAssociation, Address, Address)`.
    fn validate_destination_address(
        &self,
        association: &dyn VtAssociation,
        source_address: &Address,
        suggested_destination_address: &Address,
    ) -> Address {
        self.base().validate_destination_address(association, source_address, suggested_destination_address)
    }

    /// Java: `getDestinationProgram(VTAssociation)`.
    fn get_destination_program(&self, association: &dyn VtAssociation) -> Arc<dyn Program> {
        self.base().get_destination_program(association)
    }

    /// Java: `getSourceProgram(VTAssociation)`.
    fn get_source_program(&self, association: &dyn VtAssociation) -> Arc<dyn Program> {
        self.base().get_source_program(association)
    }

    /// Java: `getDestinationListing(VTAssociation)`.
    fn get_destination_listing(&self, association: &dyn VtAssociation) -> Option<Box<dyn Listing>> {
        self.base().get_destination_listing(association)
    }

    /// Java: `getSourceListing(VTAssociation)`.
    fn get_source_listing(&self, association: &dyn VtAssociation) -> Option<Box<dyn Listing>> {
        self.base().get_source_listing(association)
    }

    /// Java: `getSourceFunction(VTAssociation)`.
    fn get_source_function(&self, association: &dyn VtAssociation) -> Option<Arc<dyn Function>> {
        self.base().get_source_function(association)
    }

    /// Java: `getDestinationFunction(VTAssociation)`.
    fn get_destination_function(&self, association: &dyn VtAssociation) -> Option<Arc<dyn Function>> {
        self.base().get_destination_function(association)
    }

    /// Java: `getAddress(ProgramLocation, Program)`.
    fn get_address(&self, loc: &dyn ProgramLocation, program: &dyn Program) -> Address {
        self.base().get_address(loc, program)
    }

    /// Java: `conflictsWithOtherMarkup(MarkupItemImpl, Collection<VTMarkupItem>)`.
    fn conflicts_with_other_markup(
        &self,
        markup_item: &MarkupItemImpl,
        markup_items: &[Box<dyn VtMarkupItem>],
    ) -> bool {
        self.base().conflicts_with_other_markup(markup_item, markup_items)
    }

    /// Java: `getOriginalDestinationValueForAppliedMarkupOfThisType(VTAssociation, Address,
    /// TaskMonitor)` (protected). `Self: Sized` because the implementation needs to unsize `self`
    /// into the `&dyn VtMarkupType` identity that [`VtMarkupTypeBase`]'s helper compares markup
    /// items against -- an operation that (unlike this trait's other default methods) is not
    /// object-safe, so this one is not reachable through a `&dyn VtMarkupType`. Every concrete
    /// markup type still gets it for free when called on its own concrete type.
    fn get_original_destination_value_for_applied_markup_of_this_type(
        &self,
        association: &dyn VtAssociation,
        destination_address: Option<&Address>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn Stringable>>, crate::util::exception::CancelledException>
    where
        Self: Sized,
    {
        self.base().get_original_destination_value_for_applied_markup_of_this_type(
            self,
            association,
            destination_address,
            monitor,
        )
    }

    // ---- Abstract in Java: every concrete markup type must answer these for itself. Defaulted
    // to panic (mirroring this trait's pre-port placeholder) so that markup types not yet ported
    // keep compiling; a real port overrides every one of these. ----

    /// Java: `supportsAssociationType(VTAssociationType)` (abstract).
    fn supports_association_type(&self, match_type: VtAssociationType) -> bool {
        let _ = match_type;
        unimplemented!("{}: supportsAssociationType is not ported yet", self.get_display_name())
    }

    /// Java: `createMarkupItems(VTAssociation)` (abstract).
    fn create_markup_items(&self, association_db: &dyn VtAssociation) -> Vec<Box<dyn VtMarkupItem>> {
        let _ = association_db;
        unimplemented!("{}: createMarkupItems is not ported yet", self.get_display_name())
    }

    /// Java: `applyMarkup(VTMarkupItem, ToolOptions)` (abstract). Returns whether the markup was
    /// applied.
    fn apply_markup(
        &self,
        markup_item: &MarkupItemImpl,
        markup_options: &dyn ToolOptions,
    ) -> Result<bool, VersionTrackingApplyException> {
        let _ = (markup_item, markup_options);
        unimplemented!("{}: applyMarkup is not ported yet", self.get_display_name())
    }

    /// Java: `unapplyMarkup(VTMarkupItem)` (abstract).
    fn unapply_markup(&self, markup_item: &MarkupItemImpl) -> Result<(), VersionTrackingApplyException> {
        let _ = markup_item;
        unimplemented!("{}: unapplyMarkup is not ported yet", self.get_display_name())
    }

    /// Java: `getApplyAction(ToolOptions)` (abstract).
    fn get_apply_action(&self, options: &dyn ToolOptions) -> VtMarkupItemApplyActionType {
        let _ = options;
        unimplemented!("{}: getApplyAction is not ported yet", self.get_display_name())
    }

    /// Java: `supportsApplyAction(VTMarkupItemApplyActionType)` (abstract). Defaulted to `false`
    /// (rather than a panic) since this is the one abstract member every not-yet-ported markup
    /// type placeholder in this crate already relies on answering conservatively.
    fn supports_apply_action(&self, apply_action: VtMarkupItemApplyActionType) -> bool {
        let _ = apply_action;
        false
    }

    /// Java: `getSourceLocation(VTAssociation, Address)` (abstract).
    fn get_source_location(
        &self,
        association: &dyn VtAssociation,
        source_address: &Address,
    ) -> Box<dyn ProgramLocation> {
        let _ = (association, source_address);
        unimplemented!("{}: getSourceLocation is not ported yet", self.get_display_name())
    }

    /// Java: `getSourceValue(VTAssociation, Address)` (abstract).
    fn get_source_value(&self, association: &dyn VtAssociation, source_address: &Address) -> Box<dyn Stringable> {
        let _ = (association, source_address);
        unimplemented!("{}: getSourceValue is not ported yet", self.get_display_name())
    }

    /// Java: `getDestinationLocation(VTAssociation, Address)` (abstract).
    fn get_destination_location(
        &self,
        association: &dyn VtAssociation,
        destination_address: &Address,
    ) -> Box<dyn ProgramLocation> {
        let _ = (association, destination_address);
        unimplemented!("{}: getDestinationLocation is not ported yet", self.get_display_name())
    }

    /// Java: `getCurrentDestinationValue(VTAssociation, Address)` (abstract).
    fn get_current_destination_value(
        &self,
        association: &dyn VtAssociation,
        destination_address: &Address,
    ) -> Box<dyn Stringable> {
        let _ = (association, destination_address);
        unimplemented!("{}: getCurrentDestinationValue is not ported yet", self.get_display_name())
    }

    /// Java: `getOriginalDestinationValue(VTAssociation, Address)` (abstract).
    fn get_original_destination_value(
        &self,
        association: &dyn VtAssociation,
        destination_address: &Address,
    ) -> Box<dyn Stringable> {
        let _ = (association, destination_address);
        unimplemented!("{}: getOriginalDestinationValue is not ported yet", self.get_display_name())
    }

    /// Java: `hasSameSourceAndDestinationValues(VTMarkupItem)` (abstract).
    fn has_same_source_and_destination_values(&self, markup_item: &MarkupItemImpl) -> bool {
        let _ = markup_item;
        unimplemented!("{}: hasSameSourceAndDestinationValues is not ported yet", self.get_display_name())
    }

    /// Java: `convertOptionsToForceApplyOfMarkupItem(VTMarkupItemApplyActionType, ToolOptions)`
    /// (abstract).
    fn convert_options_to_force_apply_of_markup_item(
        &self,
        apply_action: VtMarkupItemApplyActionType,
        apply_options: &dyn ToolOptions,
    ) -> Box<dyn Options> {
        let _ = (apply_action, apply_options);
        unimplemented!(
            "{}: convertOptionsToForceApplyOfMarkupItem is not ported yet",
            self.get_display_name()
        )
    }
}

/// Lets a shared markup type -- which is how
/// [`vt_markup_type_factory`](crate::feature::vt::api::markuptype::vt_markup_type_factory) hands
/// its singletons out -- be passed as the owned `Box<dyn VtMarkupType>` that
/// [`MarkupItemStorage`](crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage)
/// returns, without cloning the singleton and without a hand-written forwarding wrapper that would
/// silently fall back to the defaults above for every member it forgot to override.
impl VtMarkupType for Arc<dyn VtMarkupType> {
    fn base(&self) -> &VtMarkupTypeBase {
        (**self).base()
    }

    fn get_display_name(&self) -> &str {
        (**self).get_display_name()
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
        source_address: &Address,
        suggested_destination_address: &Address,
    ) -> Address {
        (**self).validate_destination_address(association, source_address, suggested_destination_address)
    }

    fn conflicts_with_other_markup(
        &self,
        markup_item: &MarkupItemImpl,
        markup_items: &[Box<dyn VtMarkupItem>],
    ) -> bool {
        (**self).conflicts_with_other_markup(markup_item, markup_items)
    }

    fn supports_association_type(&self, match_type: VtAssociationType) -> bool {
        (**self).supports_association_type(match_type)
    }

    fn create_markup_items(&self, association_db: &dyn VtAssociation) -> Vec<Box<dyn VtMarkupItem>> {
        (**self).create_markup_items(association_db)
    }

    fn has_same_source_and_destination_values(&self, markup_item: &MarkupItemImpl) -> bool {
        (**self).has_same_source_and_destination_values(markup_item)
    }

    fn get_source_value(&self, association: &dyn VtAssociation, source_address: &Address) -> Box<dyn Stringable> {
        (**self).get_source_value(association, source_address)
    }

    fn get_current_destination_value(
        &self,
        association: &dyn VtAssociation,
        destination_address: &Address,
    ) -> Box<dyn Stringable> {
        (**self).get_current_destination_value(association, destination_address)
    }

    fn get_original_destination_value(
        &self,
        association: &dyn VtAssociation,
        destination_address: &Address,
    ) -> Box<dyn Stringable> {
        (**self).get_original_destination_value(association, destination_address)
    }

    fn get_source_location(
        &self,
        association: &dyn VtAssociation,
        source_address: &Address,
    ) -> Box<dyn ProgramLocation> {
        (**self).get_source_location(association, source_address)
    }

    fn get_destination_location(
        &self,
        association: &dyn VtAssociation,
        destination_address: &Address,
    ) -> Box<dyn ProgramLocation> {
        (**self).get_destination_location(association, destination_address)
    }

    fn get_apply_action(&self, options: &dyn ToolOptions) -> VtMarkupItemApplyActionType {
        (**self).get_apply_action(options)
    }

    fn apply_markup(
        &self,
        markup_item: &MarkupItemImpl,
        markup_options: &dyn ToolOptions,
    ) -> Result<bool, VersionTrackingApplyException> {
        (**self).apply_markup(markup_item, markup_options)
    }

    fn unapply_markup(&self, markup_item: &MarkupItemImpl) -> Result<(), VersionTrackingApplyException> {
        (**self).unapply_markup(markup_item)
    }

    fn supports_apply_action(&self, apply_action: VtMarkupItemApplyActionType) -> bool {
        (**self).supports_apply_action(apply_action)
    }

    fn convert_options_to_force_apply_of_markup_item(
        &self,
        apply_action: VtMarkupItemApplyActionType,
        apply_options: &dyn ToolOptions,
    ) -> Box<dyn Options> {
        (**self).convert_options_to_force_apply_of_markup_item(apply_action, apply_options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::vt::api::main::vt_association_markup_status::VtAssociationMarkupStatus;
    use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;

    fn address(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1), offset)
    }

    struct StubMarkupType {
        base: VtMarkupTypeBase,
    }

    impl VtMarkupType for StubMarkupType {
        fn base(&self) -> &VtMarkupTypeBase {
            &self.base
        }
    }

    struct StubAssociation;

    impl VtAssociation for StubAssociation {
        fn get_type(&self) -> VtAssociationType {
            unimplemented!("not used by these tests")
        }

        fn get_session(&self) -> Box<dyn crate::feature::vt::api::main::vt_session::VTSession> {
            unimplemented!("not used by these tests")
        }

        fn get_markup_items(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<Box<dyn VtMarkupItem>>, crate::util::exception::CancelledException> {
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
            unimplemented!("not used by these tests")
        }

        fn get_status(&self) -> VtAssociationStatus {
            unimplemented!("not used by these tests")
        }

        fn set_accepted(&self) -> Result<(), crate::feature::seam_stubs::VTAssociationStatusException> {
            Ok(())
        }

        fn clear_status(&self) -> Result<(), crate::feature::seam_stubs::VTAssociationStatusException> {
            Ok(())
        }

        fn set_rejected(&self) -> Result<(), crate::feature::seam_stubs::VTAssociationStatusException> {
            Ok(())
        }

        fn get_vote_count(&self) -> i32 {
            0
        }

        fn set_vote_count(&self, _vote_count: i32) {}
    }

    /// Java: `getDisplayName()` just returns the constructor's `name` argument.
    #[test]
    fn get_display_name_returns_the_constructor_argument() {
        let markup_type = StubMarkupType { base: VtMarkupTypeBase::new("EOL Comment") };
        assert_eq!(markup_type.get_display_name(), "EOL Comment");
    }

    /// Java: `validateDestinationAddress` hands the suggested address back unchanged.
    #[test]
    fn validate_destination_address_accepts_any_address() {
        let markup_type = StubMarkupType { base: VtMarkupTypeBase::new("Label") };
        let suggested = address(0x4000);
        let validated =
            markup_type.validate_destination_address(&StubAssociation, &address(0x1000), &suggested);
        assert_eq!(validated, suggested);
    }

    /// Java: `conflictsWithOtherMarkup` reports no conflict by default.
    #[test]
    fn conflicts_with_other_markup_defaults_to_false() {
        let markup_type = StubMarkupType { base: VtMarkupTypeBase::new("Label") };
        let association: Arc<dyn VtAssociation> = Arc::new(StubAssociation);
        let markup_item = MarkupItemImpl::new(association, Arc::new(StubMarkupType { base: VtMarkupTypeBase::new("Label") }) as Arc<dyn VtMarkupType>, address(0x1000));
        assert!(!markup_type.conflicts_with_other_markup(&markup_item, &[]));
    }

    /// Java: `supportsApplyAction` has no universal default in Java (it's abstract), but every
    /// not-yet-ported markup type placeholder in this crate relies on this trait answering `false`
    /// until it overrides the method itself.
    #[test]
    fn supports_apply_action_defaults_to_false() {
        let markup_type = StubMarkupType { base: VtMarkupTypeBase::new("Label") };
        assert!(!markup_type.supports_apply_action(VtMarkupItemApplyActionType::Replace));
    }

    /// Java: a `null` destination address short-circuits to `null` without looking at any markup
    /// items.
    #[test]
    fn original_destination_value_for_applied_markup_is_none_without_a_destination() {
        let markup_type = StubMarkupType { base: VtMarkupTypeBase::new("Label") };
        let result = markup_type.get_original_destination_value_for_applied_markup_of_this_type(
            &StubAssociation,
            None,
            &DummyMonitor,
        );
        assert!(result.unwrap().is_none());
    }

    /// Java: with a destination address but no markup items at all, the search comes up empty.
    #[test]
    fn original_destination_value_for_applied_markup_is_none_with_no_markup_items() {
        let markup_type = StubMarkupType { base: VtMarkupTypeBase::new("Label") };
        let destination = address(0x2000);
        let result = markup_type.get_original_destination_value_for_applied_markup_of_this_type(
            &StubAssociation,
            Some(&destination),
            &DummyMonitor,
        );
        assert!(result.unwrap().is_none());
    }

    /// The `Arc<dyn VtMarkupType>` forwarding wrapper reports the same display name as the markup
    /// type it wraps, rather than silently falling back to a trait default.
    #[test]
    fn arc_wrapper_forwards_to_the_wrapped_markup_type() {
        let markup_type: Arc<dyn VtMarkupType> =
            Arc::new(StubMarkupType { base: VtMarkupTypeBase::new("Function Signature") });
        assert_eq!(VtMarkupType::get_display_name(&markup_type), "Function Signature");
        assert!(!VtMarkupType::supports_apply_action(&markup_type, VtMarkupItemApplyActionType::Add));
    }
}

//! Port of `ghidra.feature.vt.api.markuptype.FunctionEntryPointBasedAbstractMarkupType`.

use crate::feature::vt::api::main::vt_association::VtAssociation;
use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
use crate::feature::vt::api::markuptype::vt_markup_type::{VtMarkupType, VtMarkupTypeBase};
use crate::program::model::address::Address;

/// The shared state and concrete (non-abstract) behavior every function-entry-point-based markup
/// type shares (`FunctionNameMarkupType`, `FunctionSignatureMarkupType`, ...).
///
/// Port of `ghidra.feature.vt.api.markuptype.FunctionEntryPointBasedAbstractMarkupType`, an
/// abstract class extending `VTMarkupType` (already ported as [`VtMarkupType`]/
/// [`VtMarkupTypeBase`]). Per this crate's composition-over-inheritance convention -- the same
/// split [`VtMarkupTypeBase`]/[`VtMarkupType`] itself uses --
/// [`FunctionEntryPointBasedAbstractMarkupTypeBase`] embeds a [`VtMarkupTypeBase`] (standing in
/// for the Java `super(name)` call in the protected constructor) and carries the class's two
/// concrete method overrides ([`supports_association_type`](Self::supports_association_type),
/// [`validate_destination_address`](Self::validate_destination_address)); the
/// [`FunctionEntryPointBasedAbstractMarkupType`] trait is what a concrete markup type composes on
/// top of [`VtMarkupType`] to get them.
///
/// Rust's trait system does not forward same-named default methods across independent traits the
/// way Java's single-inheritance `extends` chain does: a concrete markup type that implements both
/// [`VtMarkupType`] and this trait must still explicitly forward `supports_association_type`/
/// `validate_destination_address` from its `VtMarkupType` impl into this trait's own default
/// methods (e.g. `fn supports_association_type(&self, t) -> bool { FunctionEntryPointBasedAbstractMarkupType::supports_association_type(self, t) }`)
/// to actually pick up the override when called through `&dyn VtMarkupType`. This is the same
/// shadowing pattern already used by
/// [`AssemblyParseNumericToken`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseNumericToken)
/// over [`AssemblyParseToken`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken). No
/// concrete subclass is wired up to this trait yet: `FunctionNameMarkupType` and
/// `FunctionSignatureMarkupType` (this class's only two real Java subclasses) remain unported
/// placeholders in [`crate::feature::seam_stubs`], each currently overriding
/// [`VtMarkupType::is_function_entry_point_based`] directly rather than through this class -- that
/// class-level rewiring is left for their own future ports, mirroring the precedent already
/// documented on [`AssemblyParseTreeNode`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseTreeNode)
/// for not retrofitting already-complete sibling ports onto a newly-ported superclass.
pub struct FunctionEntryPointBasedAbstractMarkupTypeBase {
    markup_type_base: VtMarkupTypeBase,
}

impl FunctionEntryPointBasedAbstractMarkupTypeBase {
    /// Mirrors the protected `FunctionEntryPointBasedAbstractMarkupType(String name)`, which
    /// forwards to `VTMarkupType(String name)`.
    pub fn new(name: impl Into<String>) -> Self {
        Self { markup_type_base: VtMarkupTypeBase::new(name) }
    }

    /// The embedded `VTMarkupType` state, for a concrete markup type to return from its own
    /// [`VtMarkupType::base`] implementation.
    pub fn markup_type_base(&self) -> &VtMarkupTypeBase {
        &self.markup_type_base
    }

    /// Mirrors `FunctionEntryPointBasedAbstractMarkupType.supportsAssociationType(VTAssociationType)`:
    /// only function associations are supported (unlike a plain data-oriented markup type).
    pub fn supports_association_type(&self, match_type: VtAssociationType) -> bool {
        match_type == VtAssociationType::Function
    }

    /// Mirrors `FunctionEntryPointBasedAbstractMarkupType.validateDestinationAddress(VTAssociation,
    /// Address, Address)`. Unlike `VTMarkupType`'s own base implementation (which accepts any
    /// suggested address unchanged, see [`VtMarkupTypeBase::validate_destination_address`]), a
    /// function-entry-point-based markup type is always anchored to the association's own
    /// destination address -- both the source address and the suggested destination address are
    /// ignored entirely, reproduced here even though it means those two parameters go unused.
    pub fn validate_destination_address(
        &self,
        association: &dyn VtAssociation,
        _source_address: &Address,
        _suggested_destination_address: &Address,
    ) -> Address {
        association.get_destination_address()
    }
}

/// Port of the abstract class `ghidra.feature.vt.api.markuptype.FunctionEntryPointBasedAbstractMarkupType`.
/// See [`FunctionEntryPointBasedAbstractMarkupTypeBase`]'s own docs for the composition split and
/// the shadowing caveat.
pub trait FunctionEntryPointBasedAbstractMarkupType: VtMarkupType {
    /// The shared state (the embedded `VTMarkupType` name) every function-entry-point-based markup
    /// type carries.
    fn base(&self) -> &FunctionEntryPointBasedAbstractMarkupTypeBase;

    /// Mirrors `FunctionEntryPointBasedAbstractMarkupType.supportsAssociationType(VTAssociationType)`.
    fn supports_association_type(&self, match_type: VtAssociationType) -> bool {
        FunctionEntryPointBasedAbstractMarkupType::base(self).supports_association_type(match_type)
    }

    /// Mirrors `FunctionEntryPointBasedAbstractMarkupType.validateDestinationAddress(VTAssociation,
    /// Address, Address)`.
    fn validate_destination_address(
        &self,
        association: &dyn VtAssociation,
        source_address: &Address,
        suggested_destination_address: &Address,
    ) -> Address {
        FunctionEntryPointBasedAbstractMarkupType::base(self).validate_destination_address(
            association,
            source_address,
            suggested_destination_address,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::vt::api::main::vt_association_markup_status::VtAssociationMarkupStatus;
    use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;
    use std::sync::Arc;

    fn address(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1), offset)
    }

    struct StubMarkupType {
        base: FunctionEntryPointBasedAbstractMarkupTypeBase,
    }

    impl VtMarkupType for StubMarkupType {
        fn base(&self) -> &VtMarkupTypeBase {
            self.base.markup_type_base()
        }

        fn is_function_entry_point_based(&self) -> bool {
            true
        }

        fn supports_association_type(&self, match_type: VtAssociationType) -> bool {
            FunctionEntryPointBasedAbstractMarkupType::supports_association_type(self, match_type)
        }

        fn validate_destination_address(
            &self,
            association: &dyn VtAssociation,
            source_address: &Address,
            suggested_destination_address: &Address,
        ) -> Address {
            FunctionEntryPointBasedAbstractMarkupType::validate_destination_address(
                self,
                association,
                source_address,
                suggested_destination_address,
            )
        }
    }

    impl FunctionEntryPointBasedAbstractMarkupType for StubMarkupType {
        fn base(&self) -> &FunctionEntryPointBasedAbstractMarkupTypeBase {
            &self.base
        }
    }

    struct StubAssociation {
        destination: Address,
    }

    impl VtAssociation for StubAssociation {
        fn get_type(&self) -> VtAssociationType {
            VtAssociationType::Function
        }

        fn get_session(&self) -> Box<dyn crate::feature::vt::api::main::vt_session::VTSession> {
            unimplemented!("not used by these tests")
        }

        fn get_markup_items(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<
            Vec<Box<dyn crate::feature::seam_stubs::VtMarkupItem>>,
            CancelledException,
        > {
            Ok(Vec::new())
        }

        fn has_applied_markup_items(&self) -> bool {
            false
        }

        fn get_source_address(&self) -> Address {
            address(0x1000)
        }

        fn get_destination_address(&self) -> Address {
            self.destination.clone()
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

    /// Java: `supportsAssociationType` accepts only `VTAssociationType.FUNCTION`.
    #[test]
    fn supports_association_type_accepts_only_function() {
        let markup_type = StubMarkupType {
            base: FunctionEntryPointBasedAbstractMarkupTypeBase::new("Function Name"),
        };
        assert!(VtMarkupType::supports_association_type(&markup_type, VtAssociationType::Function));
        assert!(!VtMarkupType::supports_association_type(&markup_type, VtAssociationType::Data));
    }

    /// Java: `validateDestinationAddress` ignores the suggested address entirely, always
    /// returning `association.getDestinationAddress()`.
    #[test]
    fn validate_destination_address_ignores_the_suggestion() {
        let markup_type = StubMarkupType {
            base: FunctionEntryPointBasedAbstractMarkupTypeBase::new("Function Signature"),
        };
        let association = StubAssociation { destination: address(0x2000) };
        let validated = VtMarkupType::validate_destination_address(
            &markup_type,
            &association,
            &address(0x1000),
            &address(0x4000),
        );
        assert_eq!(validated, address(0x2000));
    }

    /// Reached through `&dyn VtMarkupType`, proving the concrete type's explicit forwarding
    /// (rather than `VtMarkupType`'s own generic defaults) is what actually runs.
    #[test]
    fn dyn_vt_markup_type_dispatch_uses_the_overridden_behavior() {
        let markup_type: Box<dyn VtMarkupType> = Box::new(StubMarkupType {
            base: FunctionEntryPointBasedAbstractMarkupTypeBase::new("Function Name"),
        });
        assert!(markup_type.supports_association_type(VtAssociationType::Function));
        assert!(!markup_type.supports_association_type(VtAssociationType::Data));

        let association = StubAssociation { destination: address(0x3000) };
        let validated = markup_type.validate_destination_address(
            &association,
            &address(0x1000),
            &address(0x9999),
        );
        assert_eq!(validated, address(0x3000));
        assert!(markup_type.is_function_entry_point_based());
    }

    /// Java: `getDisplayName()`, inherited unchanged from `VTMarkupType`, still just returns the
    /// constructor's `name` argument.
    #[test]
    fn get_display_name_is_still_inherited_from_vt_markup_type() {
        let markup_type = StubMarkupType {
            base: FunctionEntryPointBasedAbstractMarkupTypeBase::new("Function Name"),
        };
        assert_eq!(markup_type.get_display_name(), "Function Name");
    }
}

use crate::program::model::address::Address;
use crate::program::model::lang::InjectPayload;
use crate::program::model::symbol::RefType;
use crate::program::seam_stubs::FlowOverride;

/// Reports and records p-code/flow overrides that apply to a single instruction, as consulted by
/// analyses that work with p-code (Decompiler, SymbolicPropagator).
///
/// All mutator methods take `&self` rather than `&mut self`: implementations are expected to
/// carry the "applied" flags via interior mutability, since callers throughout this crate (e.g.
/// [`InstructionPrototype`](crate::program::model::lang::instruction_prototype::InstructionPrototype))
/// hold and pass this type as `&dyn PcodeOverride`.
///
/// Port of `ghidra.program.model.pcode.PcodeOverride`.
pub trait PcodeOverride {
    /// Returns the address of the current instruction.
    fn get_instruction_start(&self) -> Address;

    /// Get the flow override which may have been applied to the current instruction.
    fn get_flow_override(&self) -> FlowOverride;

    /// Get the primary overriding reference address of `ref_type` from the current instruction.
    fn get_overriding_reference(&self, ref_type: RefType) -> Option<Address>;

    /// Get the fall-through override address which may have been applied to the current
    /// instruction.
    fn get_fall_through_override(&self) -> Option<Address>;

    /// Returns true if the call destination function at `call_dest_addr` has been tagged with a
    /// call-fixup.
    fn has_call_fixup(&self, call_dest_addr: Address) -> bool;

    /// Returns the call-fixup for a specified call destination. Returns `None` if the
    /// destination function has not been tagged, or was tagged with an unknown call-fixup name.
    fn get_call_fixup(&self, call_dest_addr: Address) -> Option<Box<dyn InjectPayload>>;

    /// Register that a call override has been applied at the current instruction.
    fn set_call_override_ref_applied(&self);

    /// Returns whether a call override has been applied at the current instruction.
    fn is_call_override_ref_applied(&self) -> bool;

    /// Register that a jump override has been applied at the current instruction.
    fn set_jump_override_ref_applied(&self);

    /// Returns whether a jump override has been applied at the current instruction.
    fn is_jump_override_ref_applied(&self) -> bool;

    /// Register that a callother call override has been applied at the current instruction.
    fn set_call_other_call_override_ref_applied(&self);

    /// Returns whether a callother call override has been applied at the current instruction.
    fn is_call_other_call_override_ref_applied(&self) -> bool;

    /// Register that a callother jump override has been applied at the current instruction.
    fn set_call_other_jump_override_ref_applied(&self);

    /// Returns whether a callother jump override has been applied at the current instruction.
    fn is_call_other_jump_override_applied(&self) -> bool;

    /// Returns whether there are any primary overriding references at the current instruction.
    fn has_potential_override(&self) -> bool;

    /// Get the primary call reference address from the current instruction.
    #[deprecated]
    fn get_primary_call_reference(&self) -> Option<Address>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::InjectPayloadError;
    use crate::program::model::listing::program::Program;
    use crate::program::model::pcode::{Encoder, PcodeOp};
    use std::cell::Cell;
    use std::sync::Arc;

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    struct MockInjectPayload;

    impl InjectPayload for MockInjectPayload {
        fn get_name(&self) -> String {
            "mockfixup".to_string()
        }
        fn get_type(&self) -> i32 {
            crate::program::model::lang::inject_payload::CALLFIXUP_TYPE
        }
        fn get_source(&self) -> String {
            String::new()
        }
        fn get_param_shift(&self) -> i32 {
            0
        }
        fn get_input(&self) -> Vec<crate::program::model::lang::inject_payload::InjectParameter> {
            Vec::new()
        }
        fn get_output(&self) -> Vec<crate::program::model::lang::inject_payload::InjectParameter> {
            Vec::new()
        }
        fn is_error_placeholder(&self) -> bool {
            false
        }
        fn inject(
            &self,
            _context: &dyn crate::program::seam_stubs::InjectContext,
            _emit: &mut dyn crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit,
        ) -> Result<(), InjectPayloadError> {
            Ok(())
        }
        fn get_pcode(
            &self,
            _program: &dyn Program,
            _context: &dyn crate::program::seam_stubs::InjectContext,
        ) -> Result<Vec<PcodeOp>, InjectPayloadError> {
            Ok(Vec::new())
        }
        fn is_fall_thru(&self) -> bool {
            true
        }
        fn is_incidental_copy(&self) -> bool {
            false
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn restore_xml<P: crate::util::xml::xml_pull_parser::XmlPullParser>(
            &mut self,
            _parser: &mut P,
            _language: &crate::program::model::lang::sleigh::SleighLanguage,
        ) -> Result<(), crate::util::xml::xml_parse_exception::XmlParseException>
        where
            Self: Sized,
        {
            Ok(())
        }
        fn is_equivalent(&self, other: &dyn InjectPayload) -> bool {
            other.get_name() == self.get_name()
        }
    }

    /// A minimal in-memory implementation, proving object-safety and exercising the
    /// applied-flag bookkeeping through `&self` interior mutability.
    struct MockOverride {
        instruction_start: Address,
        call_override_applied: Cell<bool>,
        jump_override_applied: Cell<bool>,
    }

    impl PcodeOverride for MockOverride {
        fn get_instruction_start(&self) -> Address {
            self.instruction_start.clone()
        }
        fn get_flow_override(&self) -> FlowOverride {
            FlowOverride::Call
        }
        fn get_overriding_reference(&self, ref_type: RefType) -> Option<Address> {
            if ref_type == RefType::CallOverrideUnconditional {
                Some(self.instruction_start.clone())
            } else {
                None
            }
        }
        fn get_fall_through_override(&self) -> Option<Address> {
            None
        }
        fn has_call_fixup(&self, _call_dest_addr: Address) -> bool {
            true
        }
        fn get_call_fixup(&self, _call_dest_addr: Address) -> Option<Box<dyn InjectPayload>> {
            Some(Box::new(MockInjectPayload))
        }
        fn set_call_override_ref_applied(&self) {
            self.call_override_applied.set(true);
        }
        fn is_call_override_ref_applied(&self) -> bool {
            self.call_override_applied.get()
        }
        fn set_jump_override_ref_applied(&self) {
            self.jump_override_applied.set(true);
        }
        fn is_jump_override_ref_applied(&self) -> bool {
            self.jump_override_applied.get()
        }
        fn set_call_other_call_override_ref_applied(&self) {}
        fn is_call_other_call_override_ref_applied(&self) -> bool {
            false
        }
        fn set_call_other_jump_override_ref_applied(&self) {}
        fn is_call_other_jump_override_applied(&self) -> bool {
            false
        }
        fn has_potential_override(&self) -> bool {
            self.get_overriding_reference(RefType::CallOverrideUnconditional).is_some()
        }
        #[allow(deprecated)]
        fn get_primary_call_reference(&self) -> Option<Address> {
            self.get_overriding_reference(RefType::CallOverrideUnconditional)
        }
    }

    #[test]
    fn tracks_applied_overrides_via_interior_mutability() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mock = MockOverride {
            instruction_start: addr(&space, 0x1000),
            call_override_applied: Cell::new(false),
            jump_override_applied: Cell::new(false),
        };
        let over: &dyn PcodeOverride = &mock;

        assert_eq!(over.get_instruction_start(), addr(&space, 0x1000));
        assert!(over.has_potential_override());
        assert_eq!(
            over.get_overriding_reference(RefType::CallOverrideUnconditional),
            Some(addr(&space, 0x1000))
        );
        assert_eq!(over.get_overriding_reference(RefType::Flow), None);

        assert!(!over.is_call_override_ref_applied());
        over.set_call_override_ref_applied();
        assert!(over.is_call_override_ref_applied());
        assert!(!over.is_jump_override_ref_applied());

        assert!(over.has_call_fixup(addr(&space, 0x2000)));
        let fixup = over.get_call_fixup(addr(&space, 0x2000)).expect("fixup");
        assert_eq!(fixup.get_name(), "mockfixup");
    }
}

use crate::program::model::address::Address;
use crate::program::model::listing::instruction::Instruction;
use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;

/// An [`Instruction`] in a [`Trace`](crate::trace::model::trace::Trace).
///
/// Port of `ghidra.trace.model.listing.TraceInstruction`.
///
/// The Java interface overrides several inherited `Instruction` members purely to narrow their
/// return types (or, for guest languages, remap their addresses into the trace's base address
/// space) to trace-specific behavior. Rust has no notion of covariantly re-overriding an
/// inherited trait method (the same issue documented on
/// [`TraceCodeUnit`](crate::trace::model::listing::trace_code_unit::TraceCodeUnit) and
/// [`TraceData`](crate::trace::model::listing::trace_data::TraceData)), so those overrides are
/// not re-declared here; implementations of the inherited [`Instruction`] methods must reproduce
/// them directly:
/// - `get_default_fall_through` must, for guest-language instructions, map the address into the
///   trace's base address space (see [`Self::get_guest_default_fall_through`] for the
///   unmapped/native-space variant).
/// - `get_default_flows` must likewise map guest-language addresses into the trace's base address
///   space (see [`Self::get_guest_default_flows`] for the unmapped/native-space variant).
/// - `get_next` and `get_previous` must each return a `TraceInstruction` (boxed as
///   `Arc<dyn Instruction>`). Note that instructions may be staggered vertically, so multiple
///   instructions may immediately follow/precede this one in terms of address; the rule to
///   resolve the ambiguity is that only instructions containing this instruction's start snap are
///   considered.
pub trait TraceInstruction: TraceCodeUnit + Instruction {
    /// Get the default fall-through as viewed in the instruction's native address space.
    ///
    /// For guest-language instructions, this is the unmapped counterpart to the inherited
    /// [`Instruction::get_default_fall_through`], which maps the address into the trace's base
    /// address space.
    fn get_guest_default_fall_through(&self) -> Option<Address>;

    /// Get the default flows as viewed in the instruction's native address space.
    ///
    /// For guest-language instructions, this is the unmapped counterpart to the inherited
    /// [`Instruction::get_default_flows`], which maps the addresses into the trace's base address
    /// space.
    fn get_guest_default_flows(&self) -> Option<Vec<Address>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::{Language, ProcessorContext, ProcessorContextView};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::instruction::OperandValue;
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::ContextChangeException;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::PcodeOp;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{
        CommentType, FlowOverride, InstructionContext, MemBuffer, RegisterValue,
    };
    use crate::program::util::CodeUnitInsertionException;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::{TracePlatform, TraceThread};
    use std::sync::Arc;

    struct MockReferenceIterator;
    impl ReferenceIterator for MockReferenceIterator {
        fn has_next(&self) -> bool {
            false
        }
        fn next_reference(&mut self) -> Option<Arc<dyn Reference>> {
            None
        }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    struct MockInstructionContext;
    impl InstructionContext for MockInstructionContext {}

    struct MockTraceInstruction {
        min_address: Address,
        length: i32,
        start_snap: i64,
        end_snap: i64,
        fall_through: Address,
        guest_fall_through: Address,
    }

    impl MemBuffer for MockTraceInstruction {
        fn get_address(&self) -> Address {
            self.min_address.clone()
        }
    }
    impl PropertySet for MockTraceInstruction {}

    impl ProcessorContextView for MockTraceInstruction {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }

        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }

        fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl ProcessorContext for MockTraceInstruction {
        fn set_value(
            &mut self,
            _register: &Register,
            _value: i128,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn set_register_value(
            &mut self,
            _value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    impl CodeUnit for MockTraceInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.min_address.offset())
        }

        fn get_label(&self) -> Option<String> {
            None
        }

        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }

        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }

        fn get_min_address(&self) -> Address {
            self.min_address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.min_address.clone()
        }

        fn get_mnemonic_string(&self) -> String {
            "MOV".to_string()
        }

        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }

        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}

        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}

        fn get_length(&self) -> i32 {
            self.length
        }

        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; self.length as usize])
        }

        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            buffer.fill(0x90);
            Ok(())
        }

        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.min_address.offset()
                && test_addr.offset() < self.min_address.offset() + self.length as i64
        }

        fn compare_to(&self, addr: &Address) -> i32 {
            self.min_address.offset().cmp(&addr.offset()) as i32
        }

        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(MockReferenceIterator)
        }

        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}

        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn get_num_operands(&self) -> i32 {
            1
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl Instruction for MockTraceInstruction {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register(&self, _operand_index: i32) -> Option<RegisterRef> {
            None
        }

        fn get_op_objects(&self, _operand_index: i32) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_input_objects(&self) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_result_objects(&self) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_default_operand_representation(&self, _operand_index: i32) -> String {
            String::new()
        }

        fn get_default_operand_representation_list(
            &self,
            _operand_index: i32,
        ) -> Option<Vec<OperandValue>> {
            None
        }

        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }

        fn get_operand_type(&self, _operand_index: i32) -> i32 {
            0
        }

        fn get_operand_ref_type(&self, _operand_index: i32) -> RefType {
            RefType::Data
        }

        fn get_default_fall_through_offset(&self) -> i32 {
            self.length
        }

        fn get_default_fall_through(&self) -> Option<Address> {
            Some(self.fall_through.clone())
        }

        fn get_fall_through(&self) -> Option<Address> {
            Some(self.fall_through.clone())
        }

        fn get_fall_from(&self) -> Option<Address> {
            None
        }

        fn get_flows(&self) -> Option<Vec<Address>> {
            None
        }

        fn get_default_flows(&self) -> Option<Vec<Address>> {
            None
        }

        fn get_flow_type(&self) -> RefType {
            RefType::FallThrough
        }

        fn is_fallthrough(&self) -> bool {
            true
        }

        fn has_fallthrough(&self) -> bool {
            true
        }

        fn get_flow_override(&self) -> FlowOverride {
            FlowOverride::None
        }

        fn set_flow_override(&mut self, _flow_override: FlowOverride) {}

        fn set_length_override(&mut self, _length: i32) -> Result<(), CodeUnitInsertionException> {
            Ok(())
        }

        fn is_length_overridden(&self) -> bool {
            false
        }

        fn get_parsed_length(&self) -> i32 {
            self.length
        }

        fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; self.length as usize])
        }

        fn get_pcode(&self) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_pcode_for_operand(&self, _operand_index: i32) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_delay_slot_depth(&self) -> i32 {
            0
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_next(&self) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn set_fall_through(&mut self, _addr: Option<Address>) {}

        fn clear_fall_through_override(&mut self) {}

        fn is_fall_through_overridden(&self) -> bool {
            false
        }

        fn get_instruction_context(&self) -> Arc<dyn InstructionContext> {
            Arc::new(MockInstructionContext)
        }
    }

    impl TraceCodeUnit for MockTraceInstruction {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread(&self) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_range(&self) -> AddressRange {
            AddressRange::new(
                self.min_address.clone(),
                addr(self.min_address.offset() + self.length as i64 - 1),
            )
        }

        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_start_snap(&self) -> i64 {
            self.start_snap
        }

        fn set_end_snap(&mut self, end_snap: i64) {
            self.end_snap = end_snap;
        }

        fn get_end_snap(&self) -> i64 {
            self.end_snap
        }

        fn delete(&mut self) {}
    }

    impl TraceInstruction for MockTraceInstruction {
        fn get_guest_default_fall_through(&self) -> Option<Address> {
            Some(self.guest_fall_through.clone())
        }

        fn get_guest_default_flows(&self) -> Option<Vec<Address>> {
            None
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_instruction() -> MockTraceInstruction {
        MockTraceInstruction {
            min_address: addr(0x400),
            length: 4,
            start_snap: 0,
            end_snap: 10,
            fall_through: addr(0x404),
            guest_fall_through: addr(0x1404),
        }
    }

    #[test]
    fn usable_as_trait_object_via_both_supertraits() {
        let insn: Box<dyn TraceInstruction> = Box::new(make_instruction());

        // TraceCodeUnit (supertrait) methods remain reachable through the trait object.
        assert_eq!(insn.get_start_snap(), 0);
        assert_eq!(insn.get_end_snap(), 10);

        // Instruction (supertrait) methods remain reachable through the trait object.
        assert_eq!(insn.get_default_fall_through(), Some(addr(0x404)));
        assert!(insn.is_fallthrough());

        // TraceInstruction's own methods.
        assert_eq!(
            insn.get_guest_default_fall_through(),
            Some(addr(0x1404))
        );
        assert_ne!(
            insn.get_guest_default_fall_through(),
            insn.get_default_fall_through()
        );
        assert_eq!(insn.get_guest_default_flows(), None);
    }
}

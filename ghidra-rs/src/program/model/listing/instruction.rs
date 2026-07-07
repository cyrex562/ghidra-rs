use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::ProcessorContext;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::pcode::PcodeOp;
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::RefType;
use crate::program::seam_stubs::{FlowOverride, InstructionContext, InstructionPrototype};
use crate::program::util::CodeUnitInsertionException;

/// Stands in for `InstructionPrototype.INVALID_DEPTH_CHANGE` (2^24), which is not yet ported.
pub const INVALID_DEPTH_CHANGE: i32 = 1 << 24;
/// Maximum value accepted by [`Instruction::set_length_override`].
pub const MAX_LENGTH_OVERRIDE: i32 = 7;

/// A single piece of operand data as returned by [`Instruction::get_op_objects`] and related
/// accessors. Stands in for Java's untyped `Object[]`/`List<Object>`, which is only ever
/// populated with `Register`, `Address`, `Scalar`, `Character`, or `String` instances.
#[derive(Debug, Clone)]
pub enum OperandValue {
    Register(RegisterRef),
    Address(Address),
    Scalar(Scalar),
    Character(char),
    Text(String),
}

/// Interface to define an instruction for a processor.
///
/// Port of `ghidra.program.model.listing.Instruction`.
pub trait Instruction: CodeUnit + ProcessorContext {
    /// The prototype for this instruction.
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype>;

    /// If a specific operand is a pure register, return it.
    ///
    /// # Arguments
    /// * `operand_index` - the 0-up index of the operand.
    fn get_register(&self, operand_index: i32) -> Option<RegisterRef>;

    /// Get objects used by this operand (Address, Scalar, Register, ...).
    fn get_op_objects(&self, operand_index: i32) -> Vec<OperandValue>;

    /// Get the input objects used by this instruction.
    /// These could be Scalars, Registers, Addresses.
    fn get_input_objects(&self) -> Vec<OperandValue>;

    /// Get the result objects produced/affected by this instruction. These would probably only
    /// be Register or Address.
    fn get_result_objects(&self) -> Vec<OperandValue>;

    /// Get the operand representation for the given operand index without markup.
    fn get_default_operand_representation(&self, operand_index: i32) -> String;

    /// Get the operand representation for the given operand index.
    ///
    /// A list of Register, Address, Scalar, Character, and String pieces is returned - without
    /// markup! Unsupported languages may return `None`.
    fn get_default_operand_representation_list(
        &self,
        operand_index: i32,
    ) -> Option<Vec<OperandValue>>;

    /// Get the separator string between an operand.
    ///
    /// The separator string for 0 are the characters before the first operand. The separator
    /// string for `num_operands + 1` are the characters after the last operand.
    ///
    /// # Arguments
    /// * `operand_index` - valid values are 0 thru `num_operands + 1`
    fn get_separator(&self, operand_index: i32) -> Option<String>;

    /// Get the type of a specific operand (zero based). See `OperandType`.
    fn get_operand_type(&self, operand_index: i32) -> i32;

    /// Get the operand reference type for the given operand index.
    fn get_operand_ref_type(&self, operand_index: i32) -> RefType;

    /// Get default fall-through offset in bytes from start of instruction to the fall-through
    /// instruction. This accounts for any instructions contained with delay slots.
    ///
    /// Returns zero if instruction has no fall through.
    fn get_default_fall_through_offset(&self) -> i32;

    /// Get the default fall through address for this instruction. This accounts for any
    /// instructions contained with delay slots.
    fn get_default_fall_through(&self) -> Option<Address>;

    /// Get the fall through for this instruction, factoring in any fall-through override and
    /// delay slotted instructions.
    fn get_fall_through(&self) -> Option<Address>;

    /// Get the address for the instruction that fell through to this instruction. This is useful
    /// for handling instructions that are found in a delay slot.
    fn get_fall_from(&self) -> Option<Address>;

    /// Get all addresses for flows other than a fall-through. This includes any flow references
    /// which have been added to the instruction. Returns `None` if there are no flows.
    fn get_flows(&self) -> Option<Vec<Address>>;

    /// Get all addresses for default flows established by the underlying instruction prototype.
    /// References are ignored. Returns `None` if there are no flows.
    fn get_default_flows(&self) -> Option<Vec<Address>>;

    /// The flow type of this instruction (how this instruction flows to the next instruction).
    fn get_flow_type(&self) -> RefType;

    /// True if this instruction has no execution flow other than fall-through.
    fn is_fallthrough(&self) -> bool;

    /// True if this instruction has a fall-through flow.
    fn has_fallthrough(&self) -> bool;

    /// The flow override which may have been set on this instruction.
    fn get_flow_override(&self) -> FlowOverride;

    /// Set the flow override for this instruction. Pass `FlowOverride::None` to clear.
    fn set_flow_override(&mut self, flow_override: FlowOverride);

    /// Set instruction length override.
    ///
    /// Specified length must be in the range `0..=MAX_LENGTH_OVERRIDE` where 0 clears the setting
    /// and adopts the default length. The specified length must be less than the actual number of
    /// bytes consumed by the prototype and be a multiple of the language specified instruction
    /// alignment.
    ///
    /// NOTE: Use of this feature with a delay slot instruction is discouraged.
    ///
    /// # Errors
    /// Returns `Err` if expanding the instruction length conflicts with another instruction or
    /// length is not a multiple of the language specified instruction alignment.
    fn set_length_override(&mut self, length: i32) -> Result<(), CodeUnitInsertionException>;

    /// True if an instruction length override has been set.
    fn is_length_overridden(&self) -> bool;

    /// Get the actual number of bytes parsed when forming this instruction.
    ///
    /// While this method will generally return the same value as `get_length`, its value will
    /// differ when [`Instruction::set_length_override`] has been used.
    fn get_parsed_length(&self) -> i32;

    /// Get the actual bytes parsed when forming this instruction.
    ///
    /// While this method will generally return the same value as `get_bytes`, it will return more
    /// bytes when [`Instruction::set_length_override`] has been used.
    ///
    /// # Errors
    /// Returns `Err` if the full number of bytes could not be read.
    fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException>;

    /// Get the p-code operations (micro code) that this instruction performs. Flow overrides are
    /// not factored in. Returns an empty vector if the language does not support p-code.
    fn get_pcode(&self) -> Vec<PcodeOp>;

    /// Get the p-code operations (micro code) that this instruction performs.
    ///
    /// NOTE: If `include_overrides` is true, unique temporary varnodes may be produced which vary
    /// in size to those produced for other instructions.
    fn get_pcode_with_overrides(&self, include_overrides: bool) -> Vec<PcodeOp>;

    /// Get the p-code operations (micro code) that a particular operand performs to compute its
    /// value.
    fn get_pcode_for_operand(&self, operand_index: i32) -> Vec<PcodeOp>;

    /// Get the number of delay slot instructions for this argument. This is 0 for instructions
    /// which don't have a delay slot.
    fn get_delay_slot_depth(&self) -> i32;

    /// True if this instruction was disassembled in a delay slot.
    fn is_in_delay_slot(&self) -> bool;

    /// The instruction following this one in address order, or `None` if none found.
    fn get_next(&self) -> Option<Arc<dyn Instruction>>;

    /// The instruction before this one in address order, or `None` if none found.
    fn get_previous(&self) -> Option<Arc<dyn Instruction>>;

    /// Override the instruction's default fall-through address to the given address. `None`
    /// indicates that the instruction has no fall through.
    fn set_fall_through(&mut self, addr: Option<Address>);

    /// Restores this instruction's fall-through address back to the default fall through for this
    /// instruction.
    fn clear_fall_through_override(&mut self);

    /// True if this instruction's fall through has been overridden.
    fn is_fall_through_overridden(&self) -> bool;

    /// The instruction context for this instruction.
    fn get_instruction_context(&self) -> Arc<dyn InstructionContext>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::register::Register;
    use crate::program::model::lang::ProcessorContextView;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::ContextChangeException;
    use crate::program::model::symbol::{Reference, ReferenceIterator, SourceType, Symbol};
    use crate::program::seam_stubs::{CommentType, ExternalReference, MemBuffer, PropertySet, RegisterValue};

    struct MockInstruction {
        address: Address,
        flow_override: FlowOverride,
        length_override: Option<i32>,
    }

    impl MemBuffer for MockInstruction {}
    impl PropertySet for MockInstruction {}

    impl ProcessorContextView for MockInstruction {
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

    impl ProcessorContext for MockInstruction {
        fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> {
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

    impl CodeUnit for MockInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.address.offset())
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
            self.address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.address.clone()
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
            self.length_override.unwrap_or(4)
        }

        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; self.get_length() as usize])
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
            test_addr.offset() == self.address.offset()
        }

        fn compare_to(&self, addr: &Address) -> i32 {
            self.address.offset().cmp(&addr.offset()) as i32
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
            unimplemented!("not needed for this smoke test")
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
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
            2
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl Instruction for MockInstruction {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_register(&self, _operand_index: i32) -> Option<RegisterRef> {
            None
        }

        fn get_op_objects(&self, _operand_index: i32) -> Vec<OperandValue> {
            vec![OperandValue::Scalar(Scalar::new(32, 1))]
        }

        fn get_input_objects(&self) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_result_objects(&self) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_default_operand_representation(&self, _operand_index: i32) -> String {
            "1".to_string()
        }

        fn get_default_operand_representation_list(
            &self,
            _operand_index: i32,
        ) -> Option<Vec<OperandValue>> {
            Some(vec![OperandValue::Text("1".to_string())])
        }

        fn get_separator(&self, operand_index: i32) -> Option<String> {
            if operand_index == 0 {
                Some(", ".to_string())
            } else {
                None
            }
        }

        fn get_operand_type(&self, _operand_index: i32) -> i32 {
            0
        }

        fn get_operand_ref_type(&self, _operand_index: i32) -> RefType {
            RefType::Data
        }

        fn get_default_fall_through_offset(&self) -> i32 {
            self.get_length()
        }

        fn get_default_fall_through(&self) -> Option<Address> {
            Some(self.address.clone())
        }

        fn get_fall_through(&self) -> Option<Address> {
            self.get_default_fall_through()
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
            self.flow_override
        }

        fn set_flow_override(&mut self, flow_override: FlowOverride) {
            self.flow_override = flow_override;
        }

        fn set_length_override(&mut self, length: i32) -> Result<(), CodeUnitInsertionException> {
            if length < 0 || length > MAX_LENGTH_OVERRIDE {
                return Err(CodeUnitInsertionException::new(
                    "length override out of range",
                ));
            }
            self.length_override = if length == 0 { None } else { Some(length) };
            Ok(())
        }

        fn is_length_overridden(&self) -> bool {
            self.length_override.is_some()
        }

        fn get_parsed_length(&self) -> i32 {
            4
        }

        fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; 4])
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
            unimplemented!("not needed for this smoke test")
        }
    }

    fn mock_address(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trait_object() {
        let mut instr: Box<dyn Instruction> = Box::new(MockInstruction {
            address: mock_address(0x400000),
            flow_override: FlowOverride::None,
            length_override: None,
        });

        assert_eq!(instr.get_length(), 4);
        assert!(instr.is_fallthrough());
        assert_eq!(instr.get_flow_override(), FlowOverride::None);

        instr.set_flow_override(FlowOverride::Branch);
        assert_eq!(instr.get_flow_override(), FlowOverride::Branch);

        instr.set_length_override(2).unwrap();
        assert!(instr.is_length_overridden());
        assert_eq!(instr.get_length(), 2);

        assert!(instr.set_length_override(100).is_err());

        assert!(matches!(
            instr.get_op_objects(0).as_slice(),
            [OperandValue::Scalar(_)]
        ));
    }
}

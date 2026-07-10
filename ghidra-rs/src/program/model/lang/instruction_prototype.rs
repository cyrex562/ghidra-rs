use std::io;
use std::sync::Arc;

use thiserror::Error;

use crate::program::model::address::Address;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::{
    InsufficientBytesException, InstructionContext, ProcessorContextView, UnknownContextException,
    UnknownInstructionException,
};
use crate::program::model::listing::instruction::OperandValue;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::pcode::PcodeOp;
use crate::program::model::scalar::Scalar;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::Mask;
use crate::program::model::symbol::RefType;
use crate::program::seam_stubs::{MemBuffer, ParserContext, PatchEncoder, PcodeOverride};

/// Sentinel value to indicate an invalid depth change.
///
/// Port of `InstructionPrototype.INVALID_DEPTH_CHANGE`.
pub const INVALID_DEPTH_CHANGE: i32 = 1 << 24;

/// Combines the checked exceptions declared on `InstructionPrototype.getPseudoParserContext`.
#[derive(Error, Debug)]
pub enum GetPseudoParserContextError {
    #[error(transparent)]
    InsufficientBytes(#[from] InsufficientBytesException),
    #[error(transparent)]
    UnknownInstruction(#[from] UnknownInstructionException),
    #[error(transparent)]
    UnknownContext(#[from] UnknownContextException),
    #[error(transparent)]
    MemoryAccess(#[from] MemoryAccessException),
}

/// Designed to describe one machine level instruction.
///
/// A language parser can return the same `InstructionPrototype` object for the same type node.
/// Prototypes for instructions will normally be fixed for a node.
///
/// Port of `ghidra.program.model.lang.InstructionPrototype`.
pub trait InstructionPrototype {
    /// A new instance of an instruction [`ParserContext`].
    ///
    /// # Arguments
    /// * `buf` - the memory from which this prototype was parsed, or an equivalent cache
    /// * `processor_context` - the (incoming) processor context during parse
    fn get_parser_context(
        &self,
        buf: &dyn MemBuffer,
        processor_context: &dyn ProcessorContextView,
    ) -> Result<Box<dyn ParserContext>, MemoryAccessException>;

    /// A [`ParserContext`] by parsing bytes outside of the normal disassembly process.
    ///
    /// # Arguments
    /// * `address` - where the `ParserContext` is needed, i.e. the first address of an
    ///   instruction to be parsed
    /// * `buffer` - of actual bytes
    /// * `processor_context` - the (incoming) processor context
    fn get_pseudo_parser_context(
        &self,
        address: &Address,
        buffer: &dyn MemBuffer,
        processor_context: &dyn ProcessorContextView,
    ) -> Result<Box<dyn ParserContext>, GetPseudoParserContextError>;

    /// True if instruction prototype expects one or more delay slotted instructions to exist.
    fn has_delay_slots(&self) -> bool;

    /// True if instruction semantics have a `crossbuild` instruction dependency which may
    /// require a robust [`InstructionContext`] with access to preceding instructions.
    fn has_cross_build_dependency(&self) -> bool;

    /// True if instruction semantics contain a reference to `inst_next2`.
    fn has_next2_dependency(&self) -> bool;

    /// The mnemonic for this prototype.
    ///
    /// Examples: "MOV" and "CALL".
    fn get_mnemonic(&self, context: &dyn InstructionContext) -> String;

    /// The length in bytes of this prototype.
    fn get_length(&self) -> i32;

    /// The [`Mask`] that describes which bits of this instruction determine the opcode, or
    /// `None` if unknown.
    fn get_instruction_mask(&self) -> Option<Box<dyn Mask>>;

    /// The [`Mask`] that describes which bits of this instruction determine a specific operand's
    /// value, or `None` if unknown.
    ///
    /// # Arguments
    /// * `operand_index` - the 0-up index of the operand
    fn get_operand_value_mask(&self, operand_index: i32) -> Option<Box<dyn Mask>>;

    /// The flow type of this instruction.
    ///
    /// This is used for analysis purposes, i.e. how this instruction flows to the next
    /// instruction.
    fn get_flow_type(&self, context: &dyn InstructionContext) -> RefType;

    /// The number of delay slot instructions following this instruction.
    ///
    /// This should be 0 for instructions which don't have a delay slot. This is used to support
    /// the delay slots found on some RISC processors such as SPARC and the PA-RISC. This returns
    /// an integer instead of a boolean in case some other processor executes more than one
    /// instruction from a delay slot.
    fn get_delay_slot_depth(&self, context: &dyn InstructionContext) -> i32;

    /// The number of delay-slot instruction bytes which correspond to this prototype.
    fn get_delay_slot_byte_count(&self) -> i32;

    /// True if this prototype was disassembled in a delay slot.
    fn is_in_delay_slot(&self) -> bool;

    /// The number of operands in this instruction.
    fn get_num_operands(&self) -> i32;

    /// The type of a specific operand.
    ///
    /// # Arguments
    /// * `operand_index` - the 0-up index of the operand
    /// * `context` - the instruction context
    fn get_op_type(&self, operand_index: i32, context: &dyn InstructionContext) -> i32;

    /// The [`Address`] for fall-through flow after this instruction, or `None` if flow cannot
    /// fall through this instruction.
    fn get_fall_through(&self, context: &dyn InstructionContext) -> Option<Address>;

    /// The byte offset to the fall-through flow after this instruction.
    ///
    /// Ordinarily, this is just the length (in bytes) of this instruction. However, if this
    /// instruction has delay-slotted instruction(s), their lengths are included. Even if flow
    /// cannot fall through this instruction, this method will still return the fall-through
    /// offset.
    fn get_fall_through_offset(&self, context: &dyn InstructionContext) -> i32;

    /// The [`Address`]es for all flows other than a fall-through, or `None` if no flows.
    ///
    /// A `None` return is equivalent to an empty array. Note the result may include an address
    /// that could not be evaluated, e.g. to `inst_next2` when the skipped instruction could not
    /// be parsed.
    fn get_flows(&self, context: &dyn InstructionContext) -> Option<Vec<Address>>;

    /// The separator string before a specific operand, or `None`.
    ///
    /// In particular, the separator string for operand 0 are the characters *before* the first
    /// operand. The separator string for `num_operands` are the characters *after* the last
    /// operand. A `None` return value is equivalent to an empty string.
    ///
    /// # Arguments
    /// * `operand_index` - valid values are 0 thru `num_operands`, inclusive
    fn get_separator(&self, operand_index: i32) -> Option<String>;

    /// The pieces for rendering an operand's representation, or `None` if the operation is not
    /// supported.
    ///
    /// # Arguments
    /// * `operand_index` - the 0-up index of the operand
    /// * `context` - the instruction context
    fn get_op_representation_list(
        &self,
        operand_index: i32,
        context: &dyn InstructionContext,
    ) -> Option<Vec<OperandValue>>;

    /// The [`Address`] value of a specific operand, or `None` if its value is not an `Address`.
    ///
    /// # Arguments
    /// * `operand_index` - the 0-up index of the operand
    /// * `context` - the instruction context
    fn get_address(&self, operand_index: i32, context: &dyn InstructionContext) -> Option<Address>;

    /// The register value of a specific operand, or `None` if its value is not a register.
    ///
    /// # Arguments
    /// * `operand_index` - the 0-up index of the operand
    /// * `context` - the instruction context
    fn get_register(
        &self,
        operand_index: i32,
        context: &dyn InstructionContext,
    ) -> Option<RegisterRef>;

    /// The [`Scalar`] value of a specific operand, or `None` if its value is not a `Scalar`.
    ///
    /// # Arguments
    /// * `operand_index` - the 0-up index of the operand
    /// * `context` - the instruction context
    fn get_scalar(&self, operand_index: i32, context: &dyn InstructionContext) -> Option<Scalar>;

    /// The objects used by a specific operand.
    ///
    /// # Arguments
    /// * `operand_index` - the 0-up index of the operand
    /// * `context` - the instruction context
    fn get_op_objects(
        &self,
        operand_index: i32,
        context: &dyn InstructionContext,
    ) -> Vec<OperandValue>;

    /// The suggested reference type for a specific operand.
    ///
    /// # Arguments
    /// * `operand_index` - the 0-up index of the operand
    /// * `context` - the instruction context
    /// * `override_` - if not `None`, steers local overrides of p-code generation
    fn get_operand_ref_type(
        &self,
        operand_index: i32,
        context: &dyn InstructionContext,
        override_: Option<&dyn PcodeOverride>,
    ) -> RefType;

    /// True if a specific operand ought to have a delimiter following it.
    ///
    /// # Arguments
    /// * `operand_index` - the 0-up index of the operand
    fn has_delimeter(&self, operand_index: i32) -> bool;

    /// The objects used as input by this instruction.
    ///
    /// Each element should probably only be one of `Address` or `Register`.
    fn get_input_objects(&self, context: &dyn InstructionContext) -> Vec<OperandValue>;

    /// The objects affected by this instruction.
    ///
    /// Each element should probably only be one of `Address` or `Register`.
    fn get_result_objects(&self, context: &dyn InstructionContext) -> Vec<OperandValue>;

    /// The p-code operations (micro code) that this instruction performs.
    ///
    /// This will return an empty vector if the language does not support p-code for this
    /// instruction.
    ///
    /// # Arguments
    /// * `context` - the instruction context
    /// * `override_` - if not `None`, may indicate that different elements of the pcode
    ///   generation are overridden
    fn get_pcode(
        &self,
        context: &dyn InstructionContext,
        override_: Option<&dyn PcodeOverride>,
    ) -> Vec<PcodeOp>;

    /// Does the same as [`InstructionPrototype::get_pcode`] but emits the operations directly to
    /// an encoder to optimize transfer to other processes.
    ///
    /// # Arguments
    /// * `encoder` - is the encoder receiving the operations
    /// * `context` - the instruction context
    /// * `override_` - if not `None`, may indicate that different elements of the pcode
    ///   generation are overridden
    ///
    /// # Errors
    /// Returns `Err` for problems writing to the stream underlying the encoder.
    fn get_pcode_packed(
        &self,
        encoder: &mut dyn PatchEncoder,
        context: &dyn InstructionContext,
        override_: Option<&dyn PcodeOverride>,
    ) -> io::Result<()>;

    /// The p-code operations (micro code) that perform the computation of a particular operand's
    /// value.
    ///
    /// # Arguments
    /// * `context` - the instruction context
    /// * `operand_index` - the 0-up index of the operand
    fn get_pcode_for_operand(
        &self,
        context: &dyn InstructionContext,
        operand_index: i32,
    ) -> Vec<PcodeOp>;

    /// The processor language module associated with this prototype.
    fn get_language(&self) -> Arc<dyn Language>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPrototype {
        length: i32,
    }

    impl InstructionPrototype for MockPrototype {
        fn get_parser_context(
            &self,
            _buf: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn ParserContext>, MemoryAccessException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_pseudo_parser_context(
            &self,
            _address: &Address,
            _buffer: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn ParserContext>, GetPseudoParserContextError> {
            unimplemented!("not needed for this smoke test")
        }

        fn has_delay_slots(&self) -> bool {
            false
        }

        fn has_cross_build_dependency(&self) -> bool {
            false
        }

        fn has_next2_dependency(&self) -> bool {
            false
        }

        fn get_mnemonic(&self, _context: &dyn InstructionContext) -> String {
            "MOV".to_string()
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn get_instruction_mask(&self) -> Option<Box<dyn Mask>> {
            None
        }

        fn get_operand_value_mask(&self, _operand_index: i32) -> Option<Box<dyn Mask>> {
            None
        }

        fn get_flow_type(&self, _context: &dyn InstructionContext) -> RefType {
            RefType::FallThrough
        }

        fn get_delay_slot_depth(&self, _context: &dyn InstructionContext) -> i32 {
            0
        }

        fn get_delay_slot_byte_count(&self) -> i32 {
            0
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_num_operands(&self) -> i32 {
            2
        }

        fn get_op_type(&self, _operand_index: i32, _context: &dyn InstructionContext) -> i32 {
            0
        }

        fn get_fall_through(&self, _context: &dyn InstructionContext) -> Option<Address> {
            None
        }

        fn get_fall_through_offset(&self, _context: &dyn InstructionContext) -> i32 {
            self.length
        }

        fn get_flows(&self, _context: &dyn InstructionContext) -> Option<Vec<Address>> {
            None
        }

        fn get_separator(&self, operand_index: i32) -> Option<String> {
            if operand_index == 0 {
                Some(", ".to_string())
            } else {
                None
            }
        }

        fn get_op_representation_list(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Vec<OperandValue>> {
            None
        }

        fn get_address(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Address> {
            None
        }

        fn get_register(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<RegisterRef> {
            None
        }

        fn get_scalar(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Scalar> {
            None
        }

        fn get_op_objects(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_operand_ref_type(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> RefType {
            RefType::Data
        }

        fn has_delimeter(&self, _operand_index: i32) -> bool {
            false
        }

        fn get_input_objects(&self, _context: &dyn InstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_result_objects(&self, _context: &dyn InstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_pcode(
            &self,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_pcode_packed(
            &self,
            _encoder: &mut dyn PatchEncoder,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> io::Result<()> {
            Ok(())
        }

        fn get_pcode_for_operand(
            &self,
            _context: &dyn InstructionContext,
            _operand_index: i32,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not needed for this smoke test")
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let proto: Box<dyn InstructionPrototype> = Box::new(MockPrototype { length: 4 });

        assert_eq!(proto.get_length(), 4);
        assert!(!proto.has_delay_slots());
        assert_eq!(proto.get_num_operands(), 2);
        assert_eq!(proto.get_separator(0), Some(", ".to_string()));
        assert_eq!(proto.get_separator(1), None);
        assert_eq!(proto.get_flow_type(&MockContext), RefType::FallThrough);
    }

    struct MockContext;
    impl InstructionContext for MockContext {
        fn get_address(&self) -> Address {
            unimplemented!("not needed for this smoke test")
        }

        fn get_processor_context(&self) -> &dyn ProcessorContextView {
            unimplemented!("not needed for this smoke test")
        }

        fn get_mem_buffer(&self) -> &dyn MemBuffer {
            unimplemented!("not needed for this smoke test")
        }

        fn get_parser_context(&self) -> Result<Box<dyn ParserContext>, MemoryAccessException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_parser_context_at(
            &self,
            _instruction_address: Address,
        ) -> Result<
            Box<dyn ParserContext>,
            crate::program::model::lang::instruction_context::InstructionContextError,
        > {
            unimplemented!("not needed for this smoke test")
        }
    }
}

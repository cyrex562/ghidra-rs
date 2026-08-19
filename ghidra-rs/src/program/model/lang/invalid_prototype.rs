//! Port of `ghidra.program.model.lang.InvalidPrototype`.
//!
//! Represents an invalid instruction prototype: what a language's parser uses when it cannot
//! consistently interpret bytes as any legal instruction. Every operand/flow query fails safe
//! (empty, zero, or `None`), and the mnemonic renders as `"BAD-Instruction"`.
//!
//! `InvalidPrototype` was itself selected as a dependency-cycle cut-point, so instead of porting
//! it as a single concrete struct its public API is split into the [`InvalidPrototype`] trait
//! (the one piece of state -- the [`Language`] passed to the Java constructor -- plus the one
//! method, `getOpRepresentation`, that isn't already part of [`InstructionPrototype`]).
//! [`DefaultInvalidPrototype`] is the directly-constructible implementation, mirroring the
//! concrete Java class: it implements both [`InstructionPrototype`] and `ParserContext`
//! (both the pre-existing stub used by [`InstructionPrototype::get_parser_context`] and the real
//! port at [`crate::program::model::lang::parser_context::ParserContext`]) over the same object,
//! with `getParserContext()`/`getPrototype()` each returning (a clone of) `this`, matching Java's
//! self-referential return.

use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::instruction_context::InstructionContext;
use crate::program::model::lang::instruction_prototype::{
    GetPseudoParserContextError, InstructionPrototype,
};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::mask::Mask;
use crate::program::model::lang::parser_context::ParserContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
use crate::program::model::listing::instruction::OperandValue;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::pcode::{OpCode, PatchEncoder, PcodeOp, PcodeOverride, SequenceNumber};
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::RefType;
use crate::program::seam_stubs::{ParserContext as ParserContextStub};
use crate::program::model::mem::MemBuffer;

/// The public behavior of `ghidra.program.model.lang.InvalidPrototype` that isn't already covered
/// by the (pre-existing) [`InstructionPrototype`] trait.
///
/// Port of `ghidra.program.model.lang.InvalidPrototype`.
pub trait InvalidPrototype {
    /// The language for which the invalid instruction was discovered.
    ///
    /// Port of the `InvalidPrototype.language` field (via `getLanguage()`).
    fn language(&self) -> Arc<dyn Language>;

    /// A placeholder representation for an operand, since the instruction could not be parsed.
    ///
    /// Port of
    /// `InvalidPrototype.getOpRepresentation(int, MemBuffer, ProcessorContextView, String)`.
    fn get_op_representation(
        &self,
        op_index: i32,
        buf: &dyn MemBuffer,
        context: &dyn ProcessorContextView,
        label: &str,
    ) -> String {
        let _ = (op_index, buf, context, label);
        "Please Re-Disassemble".to_string()
    }
}

/// Directly-constructible [`InvalidPrototype`], also implementing [`InstructionPrototype`] and
/// `ParserContext`.
///
/// Port of the concrete `ghidra.program.model.lang.InvalidPrototype` class.
#[derive(Clone)]
pub struct DefaultInvalidPrototype {
    language: Arc<dyn Language>,
}

impl DefaultInvalidPrototype {
    /// Construct a new invalid instruction prototype.
    ///
    /// # Arguments
    /// * `language` - is the [`Language`] for which the invalid instruction is discovered
    ///
    /// Port of `InvalidPrototype(Language)`.
    pub fn new(language: Arc<dyn Language>) -> Self {
        DefaultInvalidPrototype { language }
    }
}

impl InvalidPrototype for DefaultInvalidPrototype {
    fn language(&self) -> Arc<dyn Language> {
        self.language.clone()
    }
}

impl InstructionPrototype for DefaultInvalidPrototype {
    fn get_parser_context(
        &self,
        _buf: &dyn MemBuffer,
        _processor_context: &dyn ProcessorContextView,
    ) -> Result<Box<dyn ParserContextStub>, MemoryAccessException> {
        Ok(Box::new(self.clone()))
    }

    fn get_pseudo_parser_context(
        &self,
        _address: &Address,
        _buffer: &dyn MemBuffer,
        _processor_context: &dyn ProcessorContextView,
    ) -> Result<Box<dyn ParserContextStub>, GetPseudoParserContextError> {
        Err(GetPseudoParserContextError::UnknownInstruction(
            UnknownInstructionException::with_message(
                "InvalidPrototype has no pseudo parser context",
            ),
        ))
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
        "BAD-Instruction".to_string()
    }

    fn get_length(&self) -> i32 {
        1
    }

    fn get_instruction_mask(&self) -> Option<Box<dyn Mask>> {
        None
    }

    fn get_operand_value_mask(&self, _operand_index: i32) -> Option<Box<dyn Mask>> {
        None
    }

    fn get_flow_type(&self, _context: &dyn InstructionContext) -> RefType {
        RefType::Invalid
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
        1
    }

    fn get_op_type(&self, _operand_index: i32, _context: &dyn InstructionContext) -> i32 {
        0
    }

    fn get_fall_through(&self, _context: &dyn InstructionContext) -> Option<Address> {
        None
    }

    fn get_fall_through_offset(&self, _context: &dyn InstructionContext) -> i32 {
        0
    }

    fn get_flows(&self, _context: &dyn InstructionContext) -> Option<Vec<Address>> {
        Some(Vec::new())
    }

    fn get_separator(&self, _operand_index: i32) -> Option<String> {
        None
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

    fn get_scalar(&self, _operand_index: i32, _context: &dyn InstructionContext) -> Option<Scalar> {
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
        RefType::Invalid
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
        context: &dyn InstructionContext,
        _override_: Option<&dyn PcodeOverride>,
    ) -> Vec<PcodeOp> {
        vec![PcodeOp::new(
            OpCode::Unimplemented,
            SequenceNumber::new(context.get_address(), 0),
            Vec::new(),
            None,
        )]
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
        self.language.clone()
    }
}

impl ParserContextStub for DefaultInvalidPrototype {
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        Arc::new(self.clone())
    }
}

impl ParserContext for DefaultInvalidPrototype {
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        Arc::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockLanguage;
    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            crate::program::model::lang::language_id::LanguageID::new("x86:LE:32:default").unwrap()
        }

        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }

        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_data_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_instruction_alignment(&self) -> i32 {
            1
        }

        fn supports_pcode(&self) -> bool {
            true
        }

        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }

        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }

        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }

        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_register_in_space(
            &self,
            _addrspc: &Arc<crate::program::model::address::AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }

        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }

        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }

        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }

        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }

        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }

        fn get_segmented_space(&self) -> String {
            String::new()
        }

        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }

        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> io::Result<()> {
            Ok(())
        }

        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            Vec::new()
        }

        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }

        fn has_property(&self, _key: &str) -> bool {
            false
        }

        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }

        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }

        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }

        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }

        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }

        fn has_manual(&self) -> bool {
            false
        }

        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }

        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }

        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }

        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct MockContext {
        address: Address,
    }

    impl InstructionContext for MockContext {
        fn get_address(&self) -> Address {
            self.address.clone()
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

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn default_invalid_prototype_reports_failsafe_answers() {
        let language: Arc<dyn Language> = Arc::new(MockLanguage);
        let proto = DefaultInvalidPrototype::new(language);
        let context = MockContext {
            address: mock_address(0x4000),
        };

        assert!(!proto.has_delay_slots());
        assert!(!proto.has_cross_build_dependency());
        assert!(!proto.has_next2_dependency());
        assert_eq!(proto.get_mnemonic(&context), "BAD-Instruction");
        assert_eq!(proto.get_length(), 1);
        assert_eq!(proto.get_num_operands(), 1);
        assert_eq!(proto.get_flow_type(&context), RefType::Invalid);
        assert!(proto.get_instruction_mask().is_none());
        assert!(proto.get_fall_through(&context).is_none());
        assert_eq!(proto.get_flows(&context), Some(Vec::new()));
        assert_eq!(proto.get_op_representation(0, &StubBuf, &StubCtx, ""), "Please Re-Disassemble");

        let pcode = proto.get_pcode(&context, None);
        assert_eq!(pcode.len(), 1);
        assert_eq!(pcode[0].opcode, OpCode::Unimplemented);
        assert_eq!(pcode[0].seqnum.pc, mock_address(0x4000));

        assert!(proto.get_pcode_for_operand(&context, 0).is_empty());
        assert!(proto
            .get_pseudo_parser_context(&mock_address(0), &StubBuf, &StubCtx)
            .is_err());
    }

    #[test]
    fn get_parser_context_and_get_prototype_round_trip_through_this() {
        let language: Arc<dyn Language> = Arc::new(MockLanguage);
        let proto = DefaultInvalidPrototype::new(language);

        let parser_context: Box<dyn ParserContextStub> =
            InstructionPrototype::get_parser_context(&proto, &StubBuf, &StubCtx).unwrap();
        let round_tripped = parser_context.get_prototype();
        assert_eq!(round_tripped.get_mnemonic(&MockContext {
            address: mock_address(0),
        }), "BAD-Instruction");

        let real_parser_context: Arc<dyn InstructionPrototype> =
            <DefaultInvalidPrototype as ParserContext>::get_prototype(&proto);
        assert_eq!(real_parser_context.get_length(), 1);
    }

    #[test]
    fn usable_as_trait_object() {
        let language: Arc<dyn Language> = Arc::new(MockLanguage);
        let proto: Box<dyn InstructionPrototype> = Box::new(DefaultInvalidPrototype::new(language));
        assert_eq!(proto.get_length(), 1);
        assert!(!proto.has_delay_slots());
    }

    struct StubBuf;
    impl MemBuffer for StubBuf {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            mock_address(0)
        }
    }

    struct StubCtx;
    impl ProcessorContextView for StubCtx {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }

        fn get_value(&self, _register: &crate::program::model::lang::register::Register, _signed: bool) -> Option<i128> {
            None
        }

        fn get_register_value(
            &self,
            _register: &crate::program::model::lang::register::Register,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }

        fn has_value(&self, _register: &crate::program::model::lang::register::Register) -> bool {
            false
        }
    }
}

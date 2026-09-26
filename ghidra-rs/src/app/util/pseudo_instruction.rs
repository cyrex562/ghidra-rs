//! Port of `ghidra.app.util.PseudoInstruction`.
//!
//! A "fake" instruction produced by the pseudo-disassembler and the emulator's decoder: it acts
//! like an instruction from a program listing, but owns everything it is resolved against — a
//! private copy of its bytes ([`PseudoCodeUnit`]) and the processor context it was decoded under.
//! It is the pseudo *backing* of the one instruction concept described in `OWNERSHIP_MIGRATION.md`,
//! "Instruction/CodeUnit arena (2026-09-25)": its [`InstructionRecord`] is resolved against itself
//! as the [`InstructionSnapshot`], and the query logic shared with `InstructionDB` lives on
//! [`InstructionView`].
//!
//! # Shape
//!
//! Java's `PseudoInstruction` is a concrete class whose one subclass (`DecodeErrorInstruction`)
//! extends it for reuse, so it is a struct (`shape_rules.py`). It is generic over the owned
//! context `C`: Java's callers pass whatever `ProcessorContext` they hold (a disassembler
//! context, `DecodeErrorProcessorContext`, …), and the instruction keeps it as its snapshot.
//! `PseudoInstruction<C>` is `Send + Sync` exactly when `C` is — the prototype is a
//! [`SharedPrototype`] and the bytes are owned.
//!
//! # Not ported here
//!
//! - The `PseudoInstruction(Program, …)` constructor and everything that consults a program:
//!   labels, symbols, stored references, `getNext`/`getPrevious` through the listing. See
//!   [`PseudoCodeUnit`]'s module docs; this is the `program == null` path Java takes for every
//!   instruction the emulator and `Disassembler.pseudoDisassembleBlock` create.
//! - `setInstructionBlock` and the block lookups that use it (`getPrevious` within a block, the
//!   cross-build parser context of a sibling). `InstructionBlock` is still a mock-only trait here;
//!   a block back-reference becomes a call-time argument once it is a real container (decision
//!   2026-09-24: back-references become IDs or arguments). Without a block, Java parses the other
//!   instruction from this instruction's own bytes, which is what
//!   [`InstructionSnapshot::parser_context_at`] does below.
//! - The lazily cached parser context. Each query asks the prototype for a fresh one; that is a
//!   cost, not a behaviour difference.
//!
//! # Java behaviours with no Rust `null`
//!
//! The ported `CodeUnit`/`Instruction` traits have no way to return Java's `null` from
//! `getProgram()` and no error channel on the reference mutators. Where the Java class returns
//! `null` for a program-less instruction and the trait has an `Option`, this returns `None`; where
//! it throws `UnsupportedOperationException` (reference and property mutators, `getFallFrom`), or
//! returns `null` through a non-`Option` signature (`getProgram`), this panics with the Java
//! reason, which is what the unchecked exception (or the null dereference that follows) does.

use std::fmt;
use std::sync::Arc;

use crate::app::util::pseudo_code_unit::{PseudoCodeUnit, PseudoCodeUnitError};
use crate::program::model::address::{Address, AddressFactory};
use crate::program::model::lang::instruction_context::{
    InstructionContext, InstructionContextError,
};
use crate::program::model::lang::instruction_prototype::{
    GetPseudoParserContextError, InstructionPrototype,
};
use crate::program::model::lang::operand_type::OperandType;
use crate::program::model::lang::parser_context::ParserContext;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::unknown_context_exception::UnknownContextException;
use crate::program::model::lang::{ProcessorContext, ProcessorContextView};
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::instruction::{Instruction, OperandValue};
use crate::program::model::listing::instruction_pcode_override::InstructionPcodeOverrideImpl;
use crate::program::model::listing::instruction_record::{
    InstructionRecord, InstructionSnapshot, InstructionView, SharedPrototype,
};
use crate::program::model::listing::program::Program;
use crate::program::model::listing::{CommentType, ContextChangeException};
use crate::program::model::mem::{MemBuffer, MemoryAccessException};
use crate::program::model::pcode::PcodeOp;
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::{
    EmptyReferenceIterator, ExternalReference, MemReferenceImpl, RefType, Reference,
    ReferenceIterator, SourceType, Symbol,
};
use crate::program::model::util::PropertySet;
use crate::program::seam_stubs::{
    InstructionContext as SeamInstructionContext, RegisterValue,
};
use crate::program::model::listing::FlowOverride;
use crate::program::util::CodeUnitInsertionException;
use crate::util::exception::NoValueException;
use crate::util::saveable::Saveable;

/// Java's `UnsupportedOperationException` for an operation a program-less pseudo code unit
/// cannot perform.
fn unsupported(operation: &str) -> ! {
    panic!("UnsupportedOperationException: {operation} is not supported by a pseudo code unit without a program")
}

/// Port of the private `PseudoInstruction.getByteCacheSize(InstructionPrototype)`: the
/// instruction's length, plus its delay-slot bytes (a one-byte count is taken as a minimum and
/// replaced by another instruction of the same length), plus room for an `inst_next2`
/// instruction, plus 3 because sleigh reads patterns in 4-byte chunks.
pub fn byte_cache_size(prototype: &dyn InstructionPrototype) -> i32 {
    // NOTE: in certain cases this may not cache enough if slot size was specified as a minimum
    // and not actual
    let mut length = prototype.get_length();
    let mut delay_slot_byte_count = prototype.get_delay_slot_byte_count();
    if delay_slot_byte_count == 1 {
        // Assume this is a minimum delay slot size and cache enough for one more instruction of
        // the same size.
        delay_slot_byte_count = length;
    }
    length += delay_slot_byte_count;

    // Factor in optional inst_next2 use
    let mut next2_length = 0;
    if prototype.has_next2_dependency() {
        next2_length = match prototype.get_language().get_maximum_instruction_length() {
            // next instruction length based upon language specified property
            Some(max) => max,
            // next instruction length assumed to be the same as the current instruction
            None => length,
        };
    }
    length += next2_length;

    // Sleigh utilizes 4-byte (int) chunks when evaluating patterns; make sure we have enough
    // bytes to give out for any valid offset within the instruction
    length + 3
}

/// A pseudo (listing-less) instruction that owns its bytes and the context it was decoded
/// under. Port of `ghidra.app.util.PseudoInstruction`; see the module docs.
#[derive(Clone)]
pub struct PseudoInstruction<C> {
    unit: PseudoCodeUnit,
    record: InstructionRecord,
    context: C,
    addr_factory: Option<Arc<dyn AddressFactory>>,
}

impl<C> PseudoInstruction<C> {
    /// Port of `PseudoInstruction(Address, InstructionPrototype, MemBuffer, ProcessorContext)`:
    /// the instruction at `addr` decoded by `prototype` from `mem_buffer` (positioned at `addr`)
    /// under `context`. Caches [`byte_cache_size`] bytes of `mem_buffer`.
    ///
    /// # Errors
    /// [`PseudoCodeUnitError::AddressOverflow`] if the instruction would run off its address
    /// space; [`PseudoCodeUnitError::NonPositiveLength`] for a zero-length prototype.
    pub fn new(
        addr: Address,
        prototype: SharedPrototype,
        mem_buffer: &dyn MemBuffer,
        context: C,
    ) -> Result<Self, PseudoCodeUnitError> {
        let unit = PseudoCodeUnit::with_cache_length(
            addr.clone(),
            prototype.get_length(),
            byte_cache_size(prototype.as_ref()),
            mem_buffer,
        )?;
        Ok(Self {
            unit,
            record: InstructionRecord::new(addr, prototype),
            context,
            addr_factory: None,
        })
    }

    /// Port of `PseudoInstruction(AddressFactory, Address, InstructionPrototype, MemBuffer,
    /// ProcessorContext)`, the constructor `Disassembler.pseudoDisassembleBlock` uses. With an
    /// address factory, [`Instruction::get_pcode_with_overrides`] honours the instruction's
    /// overrides.
    ///
    /// # Errors
    /// As [`PseudoInstruction::new`].
    pub fn with_address_factory(
        addr_factory: Arc<dyn AddressFactory>,
        addr: Address,
        prototype: SharedPrototype,
        mem_buffer: &dyn MemBuffer,
        context: C,
    ) -> Result<Self, PseudoCodeUnitError> {
        let mut instruction = Self::new(addr, prototype, mem_buffer, context)?;
        instruction.addr_factory = Some(addr_factory);
        Ok(instruction)
    }

    /// The shared instruction state: address, prototype and overrides.
    pub fn record(&self) -> &InstructionRecord {
        &self.record
    }

    /// The code-unit state: address range, byte cache, comments.
    pub fn code_unit(&self) -> &PseudoCodeUnit {
        &self.unit
    }

    /// The context this instruction was decoded under.
    pub fn context(&self) -> &C {
        &self.context
    }

    /// The address factory given at construction, if any.
    pub fn address_factory(&self) -> Option<&Arc<dyn AddressFactory>> {
        self.addr_factory.as_ref()
    }

    /// Port of `getRepeatedByte()`: the byte every one of the instruction's bytes equals, or
    /// `None` if they differ.
    pub fn repeated_byte(&self) -> Option<u8> {
        let bytes = self.unit.cached_bytes();
        let b0 = bytes[0];
        let length = self.unit.length() as usize;
        if bytes[1..length].iter().all(|&b| b == b0) {
            Some(b0)
        } else {
            None
        }
    }

}

impl<C: ProcessorContextView> PseudoInstruction<C> {
    /// This instruction's record resolved against its own snapshot.
    pub fn view(&self) -> InstructionView<'_, Self> {
        InstructionView::new(&self.record, self)
    }

    /// Port of `getOperandRefType(int)`. Operands referring to data are `DATA` (or
    /// `INDIRECTION` for an indirect operand of a computed flow); operands referring to code take
    /// the prototype's flow type; everything else is `DATA`.
    fn operand_ref_type(&self, op_index: i32) -> RefType {
        let view = self.view();
        let op_type = view.operand_type(op_index) as u32;
        if OperandType::is_data_reference(op_type) {
            if view.flow_type().is_computed() && OperandType::is_indirect(op_type) {
                return RefType::Indirection;
            }
            return RefType::Data;
        }
        // code references get the flow type of the instruction
        if OperandType::is_code_reference(op_type) {
            return self.record.prototype().get_flow_type(&view);
        }
        RefType::Data
    }

    /// Port of `getOperandReferences(int)`: the operand's address, if it has one, as a single
    /// non-primary default-source memory reference (there is no reference manager to ask).
    fn operand_references(&self, op_index: i32) -> Vec<Arc<dyn Reference>> {
        let view = self.view();
        let Some(to_addr) = self.record.prototype().get_address(op_index, &view) else {
            return Vec::new();
        };
        vec![Arc::new(MemReferenceImpl::new(
            self.record.address().clone(),
            to_addr,
            self.operand_ref_type(op_index),
            SourceType::Default,
            op_index,
            false,
        ))]
    }
}

impl<C: ProcessorContextView> InstructionSnapshot for PseudoInstruction<C> {
    fn mem_buffer(&self) -> &dyn MemBuffer {
        &self.unit
    }

    fn processor_context(&self) -> &dyn ProcessorContextView {
        &self.context
    }

    /// Port of the block-less branch of `getParserContext(Address)`: parse the instruction at
    /// `address` out of this instruction's own bytes, under this instruction's context.
    fn parser_context_at(
        &self,
        record: &InstructionRecord,
        address: &Address,
    ) -> Result<Box<dyn ParserContext>, InstructionContextError> {
        match record
            .prototype()
            .get_pseudo_parser_context(address, &self.unit, &self.context)
        {
            Ok(context) => Ok(context),
            Err(GetPseudoParserContextError::InsufficientBytes(_)) => Err(UnknownContextException::with_message(
                format!(
                    "Insufficient bytes when generating pseudo-ParserContext for instruction at: {address}"
                ),
            )
            .into()),
            Err(GetPseudoParserContextError::UnknownInstruction(_)) => Err(UnknownContextException::with_message(
                format!(
                    "Could not generate pseudo-ParserContext because of unknown instruction at: {address}"
                ),
            )
            .into()),
            Err(GetPseudoParserContextError::UnknownContext(e)) => Err(e.into()),
            Err(GetPseudoParserContextError::MemoryAccess(e)) => Err(e.into()),
        }
    }
}

/// Port of `PseudoInstruction implements InstructionContext`: the instruction is the context its
/// prototype is queried with.
impl<C: ProcessorContextView> InstructionContext for PseudoInstruction<C> {
    fn get_address(&self) -> Address {
        self.record.address().clone()
    }

    fn get_processor_context(&self) -> &dyn ProcessorContextView {
        &self.context
    }

    fn get_mem_buffer(&self) -> &dyn MemBuffer {
        &self.unit
    }

    fn get_parser_context(&self) -> Result<Box<dyn ParserContext>, MemoryAccessException> {
        self.view().get_parser_context()
    }

    fn get_parser_context_at(
        &self,
        instruction_address: Address,
    ) -> Result<Box<dyn ParserContext>, InstructionContextError> {
        self.view().get_parser_context_at(instruction_address)
    }
}

impl<C: ProcessorContextView> fmt::Display for PseudoInstruction<C> {
    /// Port of `toString()`: mnemonic, then operands with their separators.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.view().display_string())
    }
}

impl<C> fmt::Debug for PseudoInstruction<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PseudoInstruction")
            .field("record", &self.record)
            .field("unit", &self.unit)
            .finish_non_exhaustive()
    }
}

impl<C> MemBuffer for PseudoInstruction<C> {
    fn get_address(&self) -> Address {
        self.unit.get_address()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.unit.byte(offset)
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        self.unit.read_bytes(buf, offset)
    }

    fn is_big_endian(&self) -> bool {
        self.unit.is_big_endian()
    }
}

/// Port of `PseudoCodeUnit`'s property methods: every accessor except `hasProperty` throws
/// `UnsupportedOperationException`.
impl<C> PropertySet for PseudoInstruction<C> {
    fn set_object_property(&mut self, _name: &str, _value: Box<dyn Saveable>) {
        unsupported("setProperty(String, Saveable)")
    }

    fn set_string_property(&mut self, _name: &str, _value: &str) {
        unsupported("setProperty(String, String)")
    }

    fn set_int_property(&mut self, _name: &str, _value: i32) {
        unsupported("setProperty(String, int)")
    }

    fn set_void_property(&mut self, _name: &str) {
        unsupported("setProperty(String)")
    }

    fn get_object_property(&self, _name: &str) -> Option<Box<dyn Saveable>> {
        unsupported("getObjectProperty")
    }

    fn get_string_property(&self, _name: &str) -> Option<String> {
        unsupported("getStringProperty")
    }

    fn get_int_property(&self, _name: &str) -> Result<i32, NoValueException> {
        unsupported("getIntProperty")
    }

    fn has_property(&self, _name: &str) -> bool {
        false
    }

    fn get_void_property(&self, _name: &str) -> bool {
        unsupported("getVoidProperty")
    }

    fn property_names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        unsupported("propertyNames")
    }

    fn remove_property(&mut self, _name: &str) {
        unsupported("removeProperty")
    }
}

/// Port of `PseudoInstruction`'s `ProcessorContextView` methods, which delegate to the context.
impl<C: ProcessorContextView> ProcessorContextView for PseudoInstruction<C> {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        self.context.get_base_context_register()
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.context.get_registers()
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.context.get_register(name)
    }

    fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        self.context.get_value(register, signed)
    }

    fn get_register_value(&self, register: &Register) -> Option<Box<dyn RegisterValue>> {
        self.context.get_register_value(register)
    }

    fn has_value(&self, register: &Register) -> bool {
        self.context.has_value(register)
    }
}

/// Port of `PseudoInstruction`'s `ProcessorContext` methods, which delegate to the context.
impl<C: ProcessorContext> ProcessorContext for PseudoInstruction<C> {
    fn set_value(&mut self, register: &Register, value: i128) -> Result<(), ContextChangeException> {
        self.context.set_value(register, value)
    }

    fn set_register_value(&mut self, value: Box<dyn RegisterValue>) -> Result<(), ContextChangeException> {
        self.context.set_register_value(value)
    }

    fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException> {
        self.context.clear_register(register)
    }
}

impl<C: ProcessorContext + Clone + 'static> CodeUnit for PseudoInstruction<C> {
    fn get_address_string(&self, show_block_name: bool, pad: bool) -> String {
        self.unit.address_string(show_block_name, pad)
    }

    /// No program, so no label (Java returns `null`).
    fn get_label(&self) -> Option<String> {
        None
    }

    /// No program, so no symbols (Java returns `null`).
    fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
        Vec::new()
    }

    fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
        None
    }

    fn get_min_address(&self) -> Address {
        self.unit.address().clone()
    }

    fn get_max_address(&self) -> Address {
        self.unit.max_address().clone()
    }

    /// Port of `getMnemonicString()`.
    fn get_mnemonic_string(&self) -> String {
        self.view().mnemonic()
    }

    fn get_comment(&self, comment_type: CommentType) -> Option<String> {
        self.unit.comment(comment_type)
    }

    fn get_comment_as_array(&self, comment_type: CommentType) -> Vec<String> {
        self.unit.comment_as_array(comment_type)
    }

    fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>) {
        self.unit.set_comment(comment_type, comment);
    }

    fn set_comment_as_array(&mut self, comment_type: CommentType, comment: &[String]) {
        self.unit.set_comment_as_array(comment_type, comment);
    }

    fn get_length(&self) -> i32 {
        self.unit.length()
    }

    fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        Ok(self.unit.bytes())
    }

    fn get_bytes_in_code_unit(&self, buffer: &mut [u8], buffer_offset: i32) -> Result<(), MemoryAccessException> {
        self.unit.bytes_in_code_unit(buffer, buffer_offset)
    }

    fn contains(&self, test_addr: &Address) -> bool {
        self.unit.contains(test_addr)
    }

    fn compare_to(&self, addr: &Address) -> i32 {
        self.unit.compare_to(addr)
    }

    fn add_mnemonic_reference(&mut self, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) {
        unsupported("addMnemonicReference")
    }

    fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {
        unsupported("removeMnemonicReference")
    }

    /// No reference manager: always empty, as in Java.
    fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
        Vec::new()
    }

    /// Port of `PseudoInstruction.getOperandReferences(int)`.
    fn get_operand_references(&self, index: i32) -> Vec<Arc<dyn Reference>> {
        self.operand_references(index)
    }

    /// No reference manager, so no primary reference (Java returns `null`).
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
        unsupported("addOperandReference")
    }

    fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {
        unsupported("removeOperandReference")
    }

    /// Port of `getReferencesFrom()` without a reference manager: every operand's references.
    fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
        (0..self.view().num_operands())
            .flat_map(|i| self.operand_references(i))
            .collect()
    }

    /// No reference manager, so nothing refers here (Java returns `null`).
    fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
        Box::new(EmptyReferenceIterator)
    }

    /// Java returns `null`; the ported trait cannot, so this panics. See the module docs.
    fn get_program(&self) -> Arc<dyn Program> {
        panic!("pseudo instruction at {} has no program", self.record.address())
    }

    fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
        None
    }

    fn remove_external_reference(&mut self, _op_index: i32) {
        unsupported("removeExternalReference")
    }

    fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {
        unsupported("setPrimaryMemoryReference")
    }

    fn set_stack_reference(&mut self, _op_index: i32, _offset: i32, _source_type: SourceType, _ref_type: RefType) {
        unsupported("setStackReference")
    }

    fn set_register_reference(
        &mut self,
        _op_index: i32,
        _reg: &Register,
        _source_type: SourceType,
        _ref_type: RefType,
    ) {
        unsupported("setRegisterReference")
    }

    fn get_num_operands(&self) -> i32 {
        self.view().num_operands()
    }

    fn get_address(&self, op_index: i32) -> Option<Address> {
        self.view().operand_address(op_index)
    }

    fn get_scalar(&self, op_index: i32) -> Option<Scalar> {
        self.view().scalar(op_index)
    }

    fn as_instruction(&self) -> Option<&dyn Instruction> {
        Some(self)
    }
}

/// The placeholder marker the ported `Instruction::get_instruction_context` returns; the real
/// contract is [`InstructionContext`], implemented above.
impl<C: 'static> SeamInstructionContext for PseudoInstruction<C> {}

impl<C: ProcessorContext + Clone + 'static> Instruction for PseudoInstruction<C> {
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        self.record.prototype().clone()
    }

    fn get_register(&self, operand_index: i32) -> Option<RegisterRef> {
        self.view().register(operand_index)
    }

    fn get_op_objects(&self, operand_index: i32) -> Vec<OperandValue> {
        self.view().op_objects(operand_index)
    }

    fn get_input_objects(&self) -> Vec<OperandValue> {
        self.view().input_objects()
    }

    fn get_result_objects(&self) -> Vec<OperandValue> {
        self.view().result_objects()
    }

    fn get_default_operand_representation(&self, operand_index: i32) -> String {
        self.view().default_operand_representation(operand_index)
    }

    fn get_default_operand_representation_list(&self, operand_index: i32) -> Option<Vec<OperandValue>> {
        self.view().default_operand_representation_list(operand_index)
    }

    fn get_separator(&self, operand_index: i32) -> Option<String> {
        self.view().separator(operand_index)
    }

    fn get_operand_type(&self, operand_index: i32) -> i32 {
        self.view().operand_type(operand_index)
    }

    fn get_operand_ref_type(&self, operand_index: i32) -> RefType {
        self.operand_ref_type(operand_index)
    }

    fn get_default_fall_through_offset(&self) -> i32 {
        self.view().default_fall_through_offset()
    }

    fn get_default_fall_through(&self) -> Option<Address> {
        self.view().default_fall_through()
    }

    fn get_fall_through(&self) -> Option<Address> {
        self.view().fall_through()
    }

    /// Java: `throw new UnsupportedOperationException("Not supported by pseduo instruction")`.
    fn get_fall_from(&self) -> Option<Address> {
        panic!("UnsupportedOperationException: Not supported by pseduo instruction")
    }

    /// Port of `getFlows()`: the default flows (there are no flow references).
    fn get_flows(&self) -> Option<Vec<Address>> {
        self.view().default_flows()
    }

    fn get_default_flows(&self) -> Option<Vec<Address>> {
        self.view().default_flows()
    }

    fn get_flow_type(&self) -> RefType {
        self.view().flow_type()
    }

    fn is_fallthrough(&self) -> bool {
        self.view().is_fallthrough()
    }

    fn has_fallthrough(&self) -> bool {
        self.view().has_fallthrough()
    }

    fn get_flow_override(&self) -> FlowOverride {
        self.record.flow_override()
    }

    fn set_flow_override(&mut self, flow_override: FlowOverride) {
        self.record.set_flow_override(flow_override);
    }

    /// Java throws `UnsupportedOperationException`: pseudo instructions have no length override.
    fn set_length_override(&mut self, _length: i32) -> Result<(), CodeUnitInsertionException> {
        Err(CodeUnitInsertionException::new(
            "length override is not supported by pseudo instructions",
        ))
    }

    fn is_length_overridden(&self) -> bool {
        false
    }

    /// Length override is not supported, so this is the length.
    fn get_parsed_length(&self) -> i32 {
        self.unit.length()
    }

    /// Length override is not supported, so these are the bytes.
    fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        Ok(self.unit.bytes())
    }

    fn get_pcode(&self) -> Vec<PcodeOp> {
        self.view().pcode(None)
    }

    /// Port of `getPcode(boolean)`: overrides apply only when asked for and when the instruction
    /// was built with an address factory.
    fn get_pcode_with_overrides(&self, include_overrides: bool) -> Vec<PcodeOp> {
        if !include_overrides || self.addr_factory.is_none() {
            return self.view().pcode(None);
        }
        let pcode_override = InstructionPcodeOverrideImpl::new(self);
        self.view().pcode(Some(&pcode_override))
    }

    fn get_pcode_for_operand(&self, operand_index: i32) -> Vec<PcodeOp> {
        self.view().pcode_for_operand(operand_index)
    }

    fn get_delay_slot_depth(&self) -> i32 {
        self.view().delay_slot_depth()
    }

    fn is_in_delay_slot(&self) -> bool {
        self.view().is_in_delay_slot()
    }

    /// No program listing to search (Java returns `null`).
    fn get_next(&self) -> Option<Arc<dyn Instruction>> {
        None
    }

    /// No block and no program listing to search (Java returns `null`).
    fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
        None
    }

    /// Port of `setFallThrough(Address)`.
    fn set_fall_through(&mut self, addr: Option<Address>) {
        let default = self.view().default_fall_through();
        self.record.set_fall_through(addr, default.as_ref());
    }

    fn clear_fall_through_override(&mut self) {
        self.record.set_fall_through_override(None);
    }

    fn is_fall_through_overridden(&self) -> bool {
        self.view().is_fall_through_overridden()
    }

    /// Java returns `this`. The ported trait wants a shared handle to the (member-less)
    /// placeholder context, so this hands out a copy of the instruction.
    fn get_instruction_context(&self) -> Arc<dyn SeamInstructionContext> {
        Arc::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::processor_context_impl::ProcessorContextImpl;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::mem::ByteMemBufferImpl;
    use crate::program::model::pcode::OpCode;

    /// Decodes `bytes` at `offset` with the real sleigh prototype of the toy language, and wraps
    /// it the way `Disassembler.pseudoDisassembleBlock` does.
    fn decode(lang: &Arc<SleighLanguage>, offset: i64, bytes: &[u8]) -> PseudoInstruction<ProcessorContextImpl> {
        let addr = Address::new(lang.get_default_space(), offset);
        let proto = lang
            .parse_prototype(
                Arc::new(ByteMemBufferImpl::new(addr.clone(), bytes.to_vec(), true)),
                Vec::new(),
                false,
            )
            .unwrap();
        let mem = ByteMemBufferImpl::new(addr.clone(), bytes.to_vec(), true);
        PseudoInstruction::new(addr, Arc::new(proto), &mem, ProcessorContextImpl::new(lang.clone())).unwrap()
    }

    fn name(value: &OperandValue) -> String {
        match value {
            OperandValue::Register(r) => r.name().to_string(),
            OperandValue::Scalar(s) => format!("#{:#x}", s.get_unsigned_value()),
            OperandValue::Address(a) => format!("{:#x}", a.offset()),
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn mov_is_a_fallthrough_instruction_with_register_and_scalar_operands() {
        let lang = decode_tests::language();
        let insn = decode(&lang, 0x1000, &[0x11, 0x2a]);

        assert_eq!(insn.get_mnemonic_string(), "mov");
        assert_eq!(insn.get_length(), 2);
        assert_eq!(insn.get_parsed_length(), 2);
        assert_eq!(CodeUnit::get_bytes(&insn).unwrap(), vec![0x11, 0x2a]);
        assert_eq!(insn.get_min_address().offset(), 0x1000);
        assert_eq!(insn.get_max_address().offset(), 0x1001);
        // length 2 + no delay slot + no inst_next2 + 3
        assert_eq!(insn.code_unit().cached_bytes().len(), 5);

        assert_eq!(insn.get_num_operands(), 2);
        assert_eq!(Instruction::get_register(&insn, 0).unwrap().name(), "r1");
        assert_eq!(insn.get_scalar(1).unwrap().get_unsigned_value(), 0x2a);
        assert_eq!(CodeUnit::get_address(&insn, 1), None);
        assert_eq!(insn.get_operand_type(0), OperandType::REGISTER as i32);
        assert_eq!(insn.get_default_operand_representation(0), "r1");
        assert_eq!(insn.get_separator(1).as_deref(), Some(","));
        assert_eq!(insn.to_string(), "mov r1,0x2a");
        assert_eq!(insn.get_result_objects().iter().map(name).collect::<Vec<_>>(), ["r1"]);
        assert_eq!(insn.get_input_objects().iter().map(name).collect::<Vec<_>>(), ["#0x2a"]);

        assert_eq!(insn.get_flow_type(), RefType::FallThrough);
        assert!(insn.is_fallthrough());
        assert!(insn.has_fallthrough());
        assert_eq!(insn.get_default_fall_through_offset(), 2);
        assert_eq!(insn.get_fall_through().unwrap().offset(), 0x1002);
        assert_eq!(insn.get_flows(), None);
        assert_eq!(insn.get_delay_slot_depth(), 0);
        assert!(!insn.is_in_delay_slot());
        // a scalar operand refers to nothing
        assert!(insn.get_references_from().is_empty());

        let pcode = insn.get_pcode();
        assert_eq!(pcode.len(), 1);
        assert_eq!(pcode[0].get_opcode(), OpCode::Copy);
        let out = pcode[0].get_output().unwrap();
        assert!(out.is_register());
        assert_eq!((out.get_offset(), out.get_size()), (4, 4));
        assert_eq!(pcode[0].get_inputs()[0].get_offset(), 0x2a);
        assert_eq!(pcode[0].seqnum.get_target().offset(), 0x1000);
        // no address factory: overrides are not consulted
        assert_eq!(insn.get_pcode_with_overrides(true).len(), 1);
    }

    #[test]
    fn jmp_flows_to_its_target_and_reports_an_operand_reference() {
        let lang = decode_tests::language();
        let insn = decode(&lang, 0x1000, &[0x20, 0x05]);

        assert_eq!(insn.to_string(), "jmp 0x1007");
        assert_eq!(insn.get_flow_type(), RefType::UnconditionalJump);
        assert_eq!(insn.get_flows().unwrap().iter().map(|a| a.offset()).collect::<Vec<_>>(), [0x1007]);
        assert_eq!(insn.get_default_flows(), insn.get_flows());
        assert_eq!(insn.get_fall_through(), None);
        assert!(!insn.has_fallthrough());
        assert!(!insn.is_fallthrough());
        assert_eq!(CodeUnit::get_address(&insn, 0).unwrap().offset(), 0x1007);
        assert_eq!(insn.get_operand_ref_type(0), RefType::UnconditionalJump);

        let refs = insn.get_operand_references(0);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from_address().offset(), 0x1000);
        assert_eq!(refs[0].to_address().offset(), 0x1007);
        assert_eq!(refs[0].reference_type(), RefType::UnconditionalJump);
        assert_eq!(refs[0].operand_index(), 0);
        assert!(!refs[0].is_primary());
        assert_eq!(insn.get_references_from().len(), 1);

        let pcode = insn.get_pcode();
        assert_eq!(pcode.len(), 1);
        assert_eq!(pcode[0].get_opcode(), OpCode::Branch);
        assert_eq!(pcode[0].get_inputs()[0].get_offset(), 0x1007);
    }

    #[test]
    fn overrides_change_the_flow_the_instruction_reports() {
        let lang = decode_tests::language();
        let mut insn = decode(&lang, 0x1000, &[0x20, 0x05]);
        insn.set_flow_override(FlowOverride::Call);
        assert_eq!(insn.get_flow_override(), FlowOverride::Call);
        assert_eq!(insn.get_flow_type(), RefType::UnconditionalCall);
        assert_eq!(insn.get_fall_through().unwrap().offset(), 0x1002);
        insn.set_flow_override(FlowOverride::Return);
        assert_eq!(insn.get_flows(), None);

        let mut mov = decode(&lang, 0x1000, &[0x11, 0x2a]);
        let target = Address::new(lang.get_default_space(), 0x2000);
        mov.set_fall_through(Some(target.clone()));
        assert!(mov.is_fall_through_overridden());
        assert_eq!(mov.get_fall_through(), Some(target));
        mov.set_fall_through(None);
        assert_eq!(mov.get_fall_through(), None);
        assert!(!mov.has_fallthrough());
        mov.clear_fall_through_override();
        assert_eq!(mov.get_fall_through().unwrap().offset(), 0x1002);
        // setting the default is the same as clearing
        mov.set_fall_through(mov.get_default_fall_through());
        assert!(!mov.is_fall_through_overridden());

        assert!(mov.set_length_override(1).is_err());
        assert!(!mov.is_length_overridden());
    }

    #[test]
    fn a_delay_slot_is_cached_and_parsed_from_the_instructions_own_bytes() {
        let lang = decode_tests::language();
        // jd 0x1012 ; delay slot: mov r1, #0x2a
        let insn = decode(&lang, 0x1000, &[0x40, 0x10, 0x11, 0x2a]);
        // length 2 + 2 delay-slot bytes + 3
        assert_eq!(insn.code_unit().cached_bytes(), &[0x40, 0x10, 0x11, 0x2a, 0, 0, 0]);
        assert_eq!(insn.get_length(), 2);
        assert_eq!(insn.get_delay_slot_depth(), 1);
        assert_eq!(insn.get_default_fall_through_offset(), 4);
        assert_eq!(insn.get_flows().unwrap()[0].offset(), 0x1012);

        let pcode = insn.get_pcode();
        assert_eq!(pcode.iter().map(|op| op.get_opcode()).collect::<Vec<_>>(), [OpCode::Copy, OpCode::Branch]);
        assert!(pcode.iter().all(|op| op.seqnum.get_target().offset() == 0x1000));

        // the delay-slot instruction's parser context comes from the cached bytes
        let slot = Address::new(lang.get_default_space(), 0x1002);
        assert!(insn.get_parser_context_at(slot).is_ok());
        // past the cache, nothing decodes
        let beyond = Address::new(lang.get_default_space(), 0x1005);
        match insn.get_parser_context_at(beyond) {
            Err(InstructionContextError::UnknownContext(e)) => assert!(
                e.to_string().contains("unknown instruction at"),
                "{e}"
            ),
            Err(other) => panic!("unexpected error {other}"),
            Ok(_) => panic!("decoded past the cache"),
        }
    }

    #[test]
    fn bytes_and_comments_come_from_the_owned_snapshot() {
        let lang = decode_tests::language();
        let mut insn = decode(&lang, 0x1000, &[0x31, 0x00]);
        assert_eq!(insn.get_mnemonic_string(), "ret");
        assert_eq!(insn.get_flow_type(), RefType::Terminator);
        assert_eq!(insn.repeated_byte(), None);
        assert_eq!(insn.get_byte(1).unwrap(), 0x00);
        assert!(insn.get_byte(64).is_err());
        assert_eq!(insn.get_parsed_bytes().unwrap(), vec![0x31, 0x00]);
        assert!(insn.contains(&Address::new(lang.get_default_space(), 0x1001)));
        assert_eq!(insn.get_address_string(false, false), "1000");
        insn.set_comment(CommentType::Eol, Some("done".into()));
        assert_eq!(insn.get_comment(CommentType::Eol).as_deref(), Some("done"));
        assert!(!insn.has_property("anything"));
        assert_eq!(insn.get_label(), None);
        assert!(insn.get_next().is_none() && insn.get_previous().is_none());
        assert!(insn.as_instruction().is_some());

        let dup = decode(&lang, 0x1000, &[0x10, 0x10]);
        assert_eq!(dup.repeated_byte(), Some(0x10));
    }

    fn decode_with_factory(lang: &Arc<SleighLanguage>, bytes: &[u8]) -> PseudoInstruction<ProcessorContextImpl> {
        let addr = Address::new(lang.get_default_space(), 0x1000);
        let proto = lang
            .parse_prototype(Arc::new(ByteMemBufferImpl::new(addr.clone(), bytes.to_vec(), true)), Vec::new(), false)
            .unwrap();
        let mem = ByteMemBufferImpl::new(addr.clone(), bytes.to_vec(), true);
        PseudoInstruction::with_address_factory(
            Arc::from(lang.get_address_factory()),
            addr,
            Arc::new(proto),
            &mem,
            ProcessorContextImpl::new(lang.clone()),
        )
        .unwrap()
    }

    #[test]
    fn with_an_address_factory_overrides_steer_the_pcode() {
        let lang = decode_tests::language();
        let mut insn = decode_with_factory(&lang, &[0x31, 0x00]);
        assert!(insn.address_factory().is_some());
        assert_eq!(insn.get_pcode_with_overrides(true)[0].get_opcode(), OpCode::Return);
        // a BRANCH flow override turns the RETURN into an indirect branch
        insn.set_flow_override(FlowOverride::Branch);
        assert_eq!(insn.get_flow_type(), RefType::ComputedJump);
        assert_eq!(insn.get_pcode_with_overrides(true)[0].get_opcode(), OpCode::BranchInd);
        // and is ignored when overrides are not asked for
        assert_eq!(insn.get_pcode_with_overrides(false)[0].get_opcode(), OpCode::Return);
        assert_eq!(insn.get_pcode()[0].get_opcode(), OpCode::Return);
    }

    /// Java's `InstructionPcodeOverride.hasCallFixup` dereferences `instr.getProgram()` for every
    /// emitted CALL, so a program-less pseudo instruction asked for overridden p-code of a call
    /// throws a `NullPointerException`. (The emulator asks with `includeOverrides == false`.)
    #[test]
    #[should_panic(expected = "has no program")]
    fn an_overridden_call_needs_a_program_for_its_call_fixup() {
        let lang = decode_tests::language();
        let mut insn = decode_with_factory(&lang, &[0x20, 0x05]);
        insn.set_flow_override(FlowOverride::Call);
        insn.get_pcode_with_overrides(true);
    }

    #[test]
    fn byte_cache_size_counts_delay_slots_and_the_chunk_margin() {
        let lang = decode_tests::language();
        let mov = decode(&lang, 0, &[0x11, 0x2a]);
        assert_eq!(byte_cache_size(mov.record().prototype().as_ref()), 5);
        let jd = decode(&lang, 0, &[0x40, 0x10, 0x11, 0x2a]);
        assert_eq!(byte_cache_size(jd.record().prototype().as_ref()), 7);
    }

    /// A context that is `Send + Sync` (unlike `ProcessorContextImpl`, which shares its language
    /// as a plain `Arc<dyn Language>`): the context-free toy language needs no values.
    #[derive(Clone)]
    struct NoContext(Arc<SleighLanguage>);

    impl ProcessorContextView for NoContext {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            self.0.get_context_base_register()
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.0.get_registers()
        }
        fn get_register(&self, name: &str) -> Option<RegisterRef> {
            self.0.get_register_by_name(name)
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

    impl ProcessorContext for NoContext {
        fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn set_register_value(&mut self, _value: Box<dyn RegisterValue>) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    #[test]
    fn a_pseudo_instruction_is_send_and_sync_when_its_context_is() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PseudoInstruction<NoContext>>();

        let lang = decode_tests::language();
        let addr = Address::new(lang.get_default_space(), 0x1000);
        let bytes = [0x20u8, 0x05];
        let proto = lang
            .parse_prototype(Arc::new(ByteMemBufferImpl::new(addr.clone(), bytes.to_vec(), true)), Vec::new(), false)
            .unwrap();
        let mem = ByteMemBufferImpl::new(addr.clone(), bytes.to_vec(), true);
        let insn = PseudoInstruction::new(addr, Arc::new(proto), &mem, NoContext(lang.clone())).unwrap();

        // decoded on one thread, queried on another
        let shared = Arc::new(insn);
        let remote = Arc::clone(&shared);
        let text = std::thread::spawn(move || remote.to_string()).join().unwrap();
        assert_eq!(text, "jmp 0x1007");

        // and usable as the emulator's decoded-instruction handle
        let handle: Box<dyn crate::pcode::seam_stubs::PseudoInstruction> = Box::new((*shared).clone());
        assert_eq!(handle.get_max_address().offset(), 0x1001);
        assert_eq!(handle.decode_error_message(), None);
    }
}

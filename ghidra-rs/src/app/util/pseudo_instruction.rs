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
//! # With a program
//!
//! [`PseudoInstruction::with_program`] is Java's `PseudoInstruction(Program, …)`: labels, symbols,
//! stored references, block names, out-of-cache bytes and `getNext`/`getPrevious` go through the
//! program (see [`PseudoCodeUnit`]'s module docs). The program-less constructors are the path Java
//! takes for every instruction the emulator and `Disassembler.pseudoDisassembleBlock` create.
//!
//! # The instruction block is a call-time argument
//!
//! Java's `setInstructionBlock` stores a back-reference to the `InstructionBlock` that owns the
//! instruction, consulted by `getPrevious` (a sibling within the block) and
//! `getParserContext(Address)` (a sibling's parser context for cross-builds). Here the block owns
//! its instructions (`OWNERSHIP_MIGRATION.md`, "Blocks, sets and the disassembler's context"), so
//! per the 2026-09-24 decision the back-reference becomes an argument:
//! [`get_previous_in`](PseudoInstruction::get_previous_in) and
//! [`get_parser_context_in`](PseudoInstruction::get_parser_context_in) take the block and behave
//! as Java does after `setInstructionBlock(block)`; the trait methods behave as Java does with no
//! block (the sibling is parsed from this instruction's own bytes, which is what
//! [`InstructionSnapshot::parser_context_at`] does below).
//!
//! Not ported: the lazily cached parser context (each query asks the prototype for a fresh one;
//! a cost, not a behaviour difference) and `invalidate`/`isValid`/`refreshIfNeeded` (the
//! staleness scaffolding convention 3 retires; see [`PseudoCodeUnit`]).
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

use crate::app::util::pseudo_code_unit::{
    unsupported_always, PseudoCodeUnit, PseudoCodeUnitError,
};
use crate::program::model::address::{Address, AddressFactory};
use crate::program::model::lang::instruction_context::{
    InstructionContext, InstructionContextError,
};
use crate::program::model::lang::instruction_block::InstructionBlock;
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
use crate::program::seam_stubs::InstructionContext as SeamInstructionContext;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::listing::FlowOverride;
use crate::program::util::CodeUnitInsertionException;
use crate::util::exception::NoValueException;
use crate::util::saveable::Saveable;

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

    /// Port of `PseudoInstruction(Program, Address, InstructionPrototype, MemBuffer,
    /// ProcessorContext)`: an instruction within `program`, which also supplies the address
    /// factory. Labels, symbols, stored references and neighbours come from the program.
    ///
    /// # Errors
    /// As [`PseudoInstruction::new`].
    pub fn with_program(
        program: Arc<dyn Program>,
        addr: Address,
        prototype: SharedPrototype,
        mem_buffer: &dyn MemBuffer,
        context: C,
    ) -> Result<Self, PseudoCodeUnitError> {
        let unit = PseudoCodeUnit::with_program(
            Some(program.clone()),
            addr.clone(),
            prototype.get_length(),
            byte_cache_size(prototype.as_ref()),
            mem_buffer,
        )?;
        Ok(Self {
            unit,
            record: InstructionRecord::new(addr, prototype),
            context,
            addr_factory: program.get_address_factory(),
        })
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

impl<C: ProcessorContext + Clone + 'static> PseudoInstruction<C> {
    /// Port of `getPrevious()` after `setInstructionBlock(block)`: when `block` is given and this
    /// instruction is not its first, the block's instruction covering the address before this one
    /// (Java: "there is no guarantee that getPrevious will work"; languages whose parallel
    /// instructions need this keep them within one block); otherwise the program listing's
    /// instruction before this one, or `None` without a program.
    pub fn get_previous_in(&self, block: Option<&InstructionBlock<Self>>) -> Option<Arc<dyn Instruction>> {
        let address = self.record.address();
        if let Some(block) = block {
            if &block.get_start_address() != address {
                if let Ok(addr) = address.previous() {
                    if let Some(instr) = block.find_first_intersecting_instruction(&addr, &addr) {
                        return Some(Arc::new(instr.clone()));
                    }
                }
            }
        }
        let program = self.unit.program()?;
        let previous = program.get_listing()?.get_instruction_before(address);
        previous
    }

    /// Port of `getParserContext(Address)` after `setInstructionBlock(block)`: this instruction's
    /// own parser context for its own address; otherwise the parser context of the block's
    /// instruction at `instruction_address`.
    ///
    /// # Errors
    /// [`UnknownContextException`] ("Block does not contain cross-build instruction") when the
    /// block has no instruction there; a [`MemoryAccessException`] from building the context.
    pub fn get_parser_context_in(
        &self,
        block: &InstructionBlock<Self>,
        instruction_address: &Address,
    ) -> Result<Box<dyn ParserContext>, InstructionContextError> {
        let address = self.record.address();
        if instruction_address == address {
            return Ok(InstructionContext::get_parser_context(self)?);
        }
        match block.get_instruction_at(instruction_address) {
            Some(instr) => Ok(InstructionContext::get_parser_context(instr)?),
            None => Err(UnknownContextException::with_message(format!(
                "Block does not contain cross-build instruction: {address} -> {instruction_address}"
            ))
            .into()),
        }
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
        unsupported_always("setProperty(String, Saveable)")
    }

    fn set_string_property(&mut self, _name: &str, _value: &str) {
        unsupported_always("setProperty(String, String)")
    }

    fn set_int_property(&mut self, _name: &str, _value: i32) {
        unsupported_always("setProperty(String, int)")
    }

    fn set_void_property(&mut self, _name: &str) {
        unsupported_always("setProperty(String)")
    }

    fn get_object_property(&self, _name: &str) -> Option<Box<dyn Saveable>> {
        unsupported_always("getObjectProperty")
    }

    fn get_string_property(&self, _name: &str) -> Option<String> {
        unsupported_always("getStringProperty")
    }

    fn get_int_property(&self, _name: &str) -> Result<i32, NoValueException> {
        unsupported_always("getIntProperty")
    }

    fn has_property(&self, _name: &str) -> bool {
        false
    }

    fn get_void_property(&self, _name: &str) -> bool {
        unsupported_always("getVoidProperty")
    }

    fn property_names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        unsupported_always("propertyNames")
    }

    fn remove_property(&mut self, _name: &str) {
        unsupported_always("removeProperty")
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

    fn get_register_value(&self, register: &Register) -> Option<RegisterValue> {
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

    fn set_register_value(&mut self, value: RegisterValue) -> Result<(), ContextChangeException> {
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

    /// The program's primary label here; `None` without a program (Java returns `null`).
    fn get_label(&self) -> Option<String> {
        self.unit.label()
    }

    /// The program's symbols here; empty without a program (Java returns `null`).
    fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
        self.unit.symbols()
    }

    fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
        self.unit.primary_symbol()
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

    /// Adds a mnemonic memory reference through the program's reference manager.
    ///
    /// # Panics
    /// Without a program (Java's `UnsupportedOperationException`).
    fn add_mnemonic_reference(&mut self, ref_addr: Address, ref_type: RefType, source_type: SourceType) {
        self.unit.add_mnemonic_reference(ref_addr, ref_type, source_type);
    }

    /// # Panics
    /// Without a program (Java's `UnsupportedOperationException`).
    fn remove_mnemonic_reference(&mut self, ref_addr: &Address) {
        self.unit.remove_mnemonic_reference(ref_addr);
    }

    /// The program's mnemonic references; empty without a program, as in Java.
    fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
        self.unit.mnemonic_references()
    }

    /// Port of `PseudoInstruction.getOperandReferences(int)`, which computes the reference from
    /// the prototype rather than asking a reference manager.
    fn get_operand_references(&self, index: i32) -> Vec<Arc<dyn Reference>> {
        self.operand_references(index)
    }

    /// The program's primary reference from the operand; `None` without a program.
    fn get_primary_reference(&self, index: i32) -> Option<Arc<dyn Reference>> {
        self.unit.primary_reference(index)
    }

    /// # Panics
    /// Without a program (Java's `UnsupportedOperationException`).
    fn add_operand_reference(
        &mut self,
        index: i32,
        ref_addr: Address,
        ref_type: RefType,
        source_type: SourceType,
    ) {
        self.unit.add_operand_reference(index, ref_addr, ref_type, source_type);
    }

    /// # Panics
    /// Without a program (Java's `UnsupportedOperationException`).
    fn remove_operand_reference(&mut self, index: i32, ref_addr: &Address) {
        self.unit.remove_operand_reference(index, ref_addr);
    }

    /// Port of `getReferencesFrom()`: the reference manager's references from this address, or,
    /// without a program, every operand's (prototype-computed) references.
    fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
        if let Some(references) = self.unit.references_from() {
            return references;
        }
        (0..self.view().num_operands())
            .flat_map(|i| self.operand_references(i))
            .collect()
    }

    /// The program's references to this address; empty without a program (Java returns `null`).
    fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
        self.unit
            .reference_iterator_to()
            .unwrap_or_else(|| Box::new(EmptyReferenceIterator))
    }

    /// The program given at construction. Without one Java returns `null`; the ported trait
    /// cannot, so this panics. See the module docs.
    fn get_program(&self) -> Arc<dyn Program> {
        match self.unit.program() {
            Some(program) => program.clone(),
            None => panic!("pseudo instruction at {} has no program", self.record.address()),
        }
    }

    fn get_external_reference(&self, op_index: i32) -> Option<Arc<dyn ExternalReference>> {
        self.unit.external_reference(op_index)
    }

    /// Java always throws `UnsupportedOperationException`.
    fn remove_external_reference(&mut self, op_index: i32) {
        self.unit.remove_external_reference(op_index)
    }

    /// # Panics
    /// Without a program (Java's `UnsupportedOperationException`).
    fn set_primary_memory_reference(&mut self, reference: Arc<dyn Reference>) {
        self.unit.set_primary_memory_reference(reference);
    }

    /// # Panics
    /// Without a program (`UnsupportedOperationException`) or for an operand index past the last
    /// operand (`IllegalArgumentException`).
    fn set_stack_reference(&mut self, op_index: i32, offset: i32, source_type: SourceType, ref_type: RefType) {
        let num_operands = self.view().num_operands();
        self.unit.set_stack_reference(op_index, offset, source_type, ref_type, num_operands);
    }

    /// # Panics
    /// As [`set_stack_reference`](CodeUnit::set_stack_reference).
    fn set_register_reference(
        &mut self,
        op_index: i32,
        reg: &Register,
        source_type: SourceType,
        ref_type: RefType,
    ) {
        let num_operands = self.view().num_operands();
        self.unit.set_register_reference(op_index, reg, source_type, ref_type, num_operands);
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

    /// Port of `getNext()`: the program listing's instruction after this one; `None` without a
    /// program.
    fn get_next(&self) -> Option<Arc<dyn Instruction>> {
        let program = self.unit.program()?;
        let next = program.get_listing()?.get_instruction_after(self.record.address());
        next
    }

    /// Port of `getPrevious()` with no instruction block: the program listing's instruction
    /// before this one, `None` without a program. See [`PseudoInstruction::get_previous_in`] for
    /// the block-aware form.
    fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
        self.get_previous_in(None)
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
        fn get_register_value(&self, _register: &Register) -> Option<RegisterValue> {
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
        fn set_register_value(&mut self, _value: RegisterValue) -> Result<(), ContextChangeException> {
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

    // ----- program-attached instructions -----

    use crate::program::database::code::test_support::{TestMemory, TestReferenceManager};
    use crate::program::database::symbol::symbol_db::SymbolDB;
    use crate::program::model::listing::{ManagerCell, ManagerGuard, StubListing};
    use crate::program::model::symbol::{SymbolTable, SymbolType};

    type Attached = PseudoInstruction<NoContext>;

    /// A symbol table with one label, `start`, at 0x1000.
    struct LabelTable {
        start: Arc<dyn Symbol>,
    }

    impl SymbolTable for LabelTable {
        fn create_label(&mut self, _addr: &Address, _name: &str, _source: SourceType) -> std::io::Result<Arc<dyn Symbol>> {
            unimplemented!("not exercised")
        }
        fn get_symbol(&self, _id: i64) -> std::io::Result<Option<Arc<dyn Symbol>>> {
            unimplemented!("not exercised")
        }
        fn get_symbols(&self, addr: &Address) -> std::io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(if addr == &self.start.get_address() { vec![self.start.clone()] } else { Vec::new() })
        }
        fn get_primary_symbol(&self, addr: &Address) -> std::io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.get_symbols(addr)?.into_iter().next())
        }
    }

    /// A listing whose only instructions are the ones either side of the instruction under test.
    #[derive(Default)]
    struct NeighbourListing {
        after: Option<Arc<Attached>>,
        before: Option<Arc<Attached>>,
    }

    impl StubListing for NeighbourListing {
        fn get_instruction_after(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            self.after.clone().map(|i| i as Arc<dyn Instruction>)
        }
        fn get_instruction_before(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            self.before.clone().map(|i| i as Arc<dyn Instruction>)
        }
    }

    struct AttachedProgram {
        factory: Arc<dyn AddressFactory>,
        memory: Arc<TestMemory>,
        references: ManagerCell<TestReferenceManager>,
        symbols: ManagerCell<LabelTable>,
        listing: ManagerCell<NeighbourListing>,
    }

    impl crate::framework::model::DomainObject for AttachedProgram {}

    impl Program for AttachedProgram {
        fn get_name(&self) -> String {
            "attached".to_string()
        }
        fn get_language_id(&self) -> String {
            "toy:BE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.factory.clone())
        }
        fn get_memory(&self) -> Option<Arc<dyn crate::program::model::mem::Memory>> {
            Some(self.memory.clone())
        }
        fn get_reference_manager(&self) -> Option<ManagerGuard<'_, dyn crate::program::model::symbol::ReferenceManager>> {
            Some(ManagerGuard::lock(&self.references))
        }
        fn get_symbol_table(&self) -> Option<ManagerGuard<'_, dyn SymbolTable>> {
            Some(ManagerGuard::lock(&self.symbols))
        }
        fn get_listing(&self) -> Option<ManagerGuard<'_, dyn crate::program::model::listing::Listing>> {
            Some(ManagerGuard::lock(&self.listing))
        }
    }

    /// Program memory: `mov r1,#0x2a ; mov r1,#0x2b ; ret` at 0x1000, then 0x99 bytes.
    const PROGRAM_BYTES: [u8; 12] = [0x11, 0x2a, 0x11, 0x2b, 0x31, 0x00, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99];

    fn attached_program(lang: &Arc<SleighLanguage>, listing: NeighbourListing) -> Arc<AttachedProgram> {
        let space = lang.get_default_space();
        Arc::new(AttachedProgram {
            factory: Arc::from(lang.get_address_factory()),
            memory: Arc::new(TestMemory::new(space.clone(), 0x1000, PROGRAM_BYTES.to_vec())),
            references: ManagerCell::new(TestReferenceManager::default()),
            symbols: ManagerCell::new(LabelTable {
                start: Arc::new(SymbolDB::new(
                    1,
                    "start".to_string(),
                    Address::new(space, 0x1000),
                    SymbolType::Label,
                    0,
                    true,
                    SourceType::UserDefined,
                )),
            }),
            listing: ManagerCell::new(listing),
        })
    }

    /// Decodes the instruction at `offset` of [`PROGRAM_BYTES`], within `program` if given.
    fn decode_in(lang: &Arc<SleighLanguage>, program: Option<Arc<dyn Program>>, offset: i64) -> Attached {
        let addr = Address::new(lang.get_default_space(), offset);
        let bytes = PROGRAM_BYTES[(offset - 0x1000) as usize..].to_vec();
        let proto = lang
            .parse_prototype(Arc::new(ByteMemBufferImpl::new(addr.clone(), bytes.clone(), true)), Vec::new(), false)
            .unwrap();
        let mem = ByteMemBufferImpl::new(addr.clone(), bytes, true);
        let context = NoContext(lang.clone());
        match program {
            Some(program) => PseudoInstruction::with_program(program, addr, Arc::new(proto), &mem, context),
            None => PseudoInstruction::new(addr, Arc::new(proto), &mem, context),
        }
        .unwrap()
    }

    #[test]
    fn the_program_constructor_keeps_the_program_and_its_address_factory() {
        let lang = decode_tests::language();
        let program = attached_program(&lang, NeighbourListing::default());
        let as_program: Arc<dyn Program> = program.clone();
        let insn = decode_in(&lang, Some(as_program.clone()), 0x1000);
        assert!(Arc::ptr_eq(&insn.get_program(), &as_program));
        assert!(insn.address_factory().is_some());
        assert_eq!(insn.to_string(), "mov r1,0x2a");
    }

    #[test]
    fn labels_symbols_and_block_names_come_from_the_program() {
        let lang = decode_tests::language();
        let program: Arc<dyn Program> = attached_program(&lang, NeighbourListing::default());
        let first = decode_in(&lang, Some(program.clone()), 0x1000);
        assert_eq!(first.get_label().as_deref(), Some("start"));
        assert_eq!(first.get_symbols().len(), 1);
        assert_eq!(first.get_primary_symbol().unwrap().get_name(), "start");
        assert_eq!(first.get_address_string(true, false), "text:1000");
        assert_eq!(first.get_address_string(false, false), "1000");

        let second = decode_in(&lang, Some(program), 0x1002);
        assert_eq!(second.get_label(), None);
        assert!(second.get_symbols().is_empty());

        let detached = decode_in(&lang, None, 0x1000);
        assert_eq!(detached.get_address_string(true, false), "1000");
    }

    #[test]
    fn reads_past_the_byte_cache_go_to_program_memory() {
        let lang = decode_tests::language();
        let program: Arc<dyn Program> = attached_program(&lang, NeighbourListing::default());
        let insn = decode_in(&lang, Some(program), 0x1000);
        // cache is 2 + 3 bytes; offset 6 is program memory
        assert_eq!(insn.code_unit().cached_bytes().len(), 5);
        assert_eq!(insn.get_byte(6).unwrap(), 0x99);
        assert!(insn.get_byte(64).is_err());
        // a request the cache cannot satisfy completely is a complete fill from memory
        let mut b = [0u8; 8];
        assert_eq!(MemBuffer::get_bytes(&insn, &mut b, 2), 8);
        assert_eq!(b, [0x11, 0x2b, 0x31, 0x00, 0x99, 0x99, 0x99, 0x99]);
        // one it can is served from the cache
        let mut two = [0u8; 2];
        assert_eq!(MemBuffer::get_bytes(&insn, &mut two, 0), 2);
        assert_eq!(two, [0x11, 0x2a]);

        let detached = decode_in(&lang, None, 0x1000);
        assert!(detached.get_byte(6).is_err());
        assert_eq!(MemBuffer::get_bytes(&detached, &mut b, 2), 3);
    }

    #[test]
    fn references_go_through_the_programs_reference_manager() {
        let lang = decode_tests::language();
        let program = attached_program(&lang, NeighbourListing::default());
        let mut insn = decode_in(&lang, Some(program.clone()), 0x1000);
        let target = Address::new(lang.get_default_space(), 0x2000);

        // mov has no address operand, so without stored references there are none
        assert!(insn.get_references_from().is_empty());
        insn.add_operand_reference(1, target.clone(), RefType::Data, SourceType::UserDefined);
        insn.add_mnemonic_reference(target.clone(), RefType::Read, SourceType::UserDefined);

        let from = insn.get_references_from();
        assert_eq!(from.len(), 2);
        assert_eq!(insn.get_mnemonic_references().len(), 1);
        assert_eq!(insn.get_mnemonic_references()[0].operand_index(), -1);
        let primary = insn.get_primary_reference(1).unwrap();
        assert_eq!(primary.to_address(), target);
        insn.set_primary_memory_reference(primary);
        assert!(insn.get_external_reference(1).is_none());
        assert_eq!(insn.get_reference_iterator_to().count(), 0);
        // the operand references a pseudo instruction reports are still the prototype's
        assert!(insn.get_operand_references(1).is_empty());

        insn.remove_mnemonic_reference(&target);
        assert!(insn.get_mnemonic_references().is_empty());
        insn.remove_operand_reference(1, &target);
        assert!(insn.get_references_from().is_empty());

        // the references live in the program: a second instruction at the address sees them
        insn.add_operand_reference(0, target.clone(), RefType::Data, SourceType::UserDefined);
        let again = decode_in(&lang, Some(program), 0x1000);
        assert_eq!(again.get_primary_reference(0).unwrap().to_address(), target);
    }

    #[test]
    #[should_panic(expected = "Invalid operand index [2] specified")]
    fn a_stack_reference_on_a_missing_operand_is_rejected() {
        let lang = decode_tests::language();
        let program: Arc<dyn Program> = attached_program(&lang, NeighbourListing::default());
        let mut insn = decode_in(&lang, Some(program), 0x1000);
        insn.set_stack_reference(2, 8, SourceType::UserDefined, RefType::Read);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException: addMnemonicReference")]
    fn a_detached_instruction_cannot_store_references() {
        let lang = decode_tests::language();
        let mut insn = decode_in(&lang, None, 0x1000);
        insn.add_mnemonic_reference(Address::new(lang.get_default_space(), 0x2000), RefType::Read, SourceType::UserDefined);
    }

    #[test]
    fn neighbours_come_from_the_program_listing() {
        let lang = decode_tests::language();
        let before = Arc::new(decode_in(&lang, None, 0x1000));
        let after = Arc::new(decode_in(&lang, None, 0x1004));
        let program: Arc<dyn Program> = attached_program(
            &lang,
            NeighbourListing { after: Some(after), before: Some(before) },
        );
        let insn = decode_in(&lang, Some(program), 0x1002);
        assert_eq!(insn.get_next().unwrap().get_min_address().offset(), 0x1004);
        assert_eq!(insn.get_previous().unwrap().get_min_address().offset(), 0x1000);
        assert_eq!(insn.get_previous_in(None).unwrap().get_min_address().offset(), 0x1000);
    }

    #[test]
    fn a_block_supplies_the_previous_instruction_and_cross_build_contexts() {
        let lang = decode_tests::language();
        let space = lang.get_default_space();
        let mut block: InstructionBlock<Attached> = InstructionBlock::new(Address::new(space.clone(), 0x1000));
        block.add_instruction(decode_in(&lang, None, 0x1000));
        block.add_instruction(decode_in(&lang, None, 0x1002));
        let second = block.get_instruction_at(&Address::new(space.clone(), 0x1002)).unwrap().clone();
        let first = block.get_instruction_at(&Address::new(space.clone(), 0x1000)).unwrap().clone();

        // within the block, the previous instruction is the block's
        let previous = second.get_previous_in(Some(&block)).unwrap();
        assert_eq!(previous.get_min_address().offset(), 0x1000);
        assert_eq!(previous.get_scalar(1).unwrap().get_unsigned_value(), 0x2a);
        // the block's first instruction falls back to the (absent) program
        assert!(first.get_previous_in(Some(&block)).is_none());

        // cross-build parser contexts come from the block's instructions
        assert!(second.get_parser_context_in(&block, &Address::new(space.clone(), 0x1002)).is_ok());
        assert!(second.get_parser_context_in(&block, &Address::new(space.clone(), 0x1000)).is_ok());
        let missing = Address::new(space.clone(), 0x1008);
        let expected = format!(
            "Block does not contain cross-build instruction: {} -> {missing}",
            Address::new(space, 0x1002)
        );
        match second.get_parser_context_in(&block, &missing) {
            Err(InstructionContextError::UnknownContext(e)) => assert!(e.to_string().contains(&expected), "{e}"),
            Err(other) => panic!("unexpected error {other}"),
            Ok(_) => panic!("found an instruction the block does not have"),
        }
    }
}

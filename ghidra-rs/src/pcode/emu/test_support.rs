//! Test fixtures shared by the emulator's tests: a language with a program counter, and an
//! instruction decoder that decodes real Sleigh instructions from a machine's memory.
//!
//! Both stand in for pieces not yet ported: a `.sla`-only
//! [`SleighLanguage`](crate::program::model::lang::sleigh::SleighLanguage) has no program counter
//! (only a `.pspec` declares one), and `SleighInstructionDecoder` waits on the `Instruction`
//! family's design.

use std::collections::HashSet;
use std::sync::Arc;

use crate::app::plugin::processors::generic::MemoryBlockDefinition;
use crate::pcode::emu::bytes_pcode_thread::BytesState;
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
use crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
use crate::pcode::seam_stubs::{PseudoInstruction, RegisterValue};
use crate::program::model::address::{Address, AddressFactory, AddressSetView, AddressSpace};
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
use crate::program::model::lang::instruction_context::{InstructionContext, InstructionContextError};
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::invalid_prototype::DefaultInvalidPrototype;
use crate::program::model::lang::language::{Language, ParseError};
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
use crate::program::model::lang::parser_context::ParserContext as LangParserContext;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_impl::ProcessorContextImpl;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::lang::unknown_context_exception::UnknownContextException;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::listing::instruction_stub::InstructionStub;
use crate::program::model::listing::Instruction;
use crate::program::model::mem::{ByteMemBufferImpl, MemBuffer, MemoryAccessException};
use crate::program::model::pcode::PcodeOp;
use crate::program::seam_stubs::{AddressLabelInfo, Processor};
use crate::util::task::TaskMonitor;

/// A language answering every query from `inner`, except that it declares `pc` as its program
/// counter, as the `.pspec` a real language ships with would.
pub(crate) struct PcLanguage {
    pub(crate) inner: Arc<dyn Language>,
    pub(crate) pc: RegisterRef,
}

impl Language for PcLanguage {
    fn get_language_id(&self) -> LanguageID {
        Language::get_language_id(self.inner.as_ref())
    }
    fn get_language_description(&self) -> Box<dyn LanguageDescription> {
        Language::get_language_description(self.inner.as_ref())
    }
    fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
        Language::get_parallel_instruction_helper(self.inner.as_ref())
    }
    fn get_processor(&self) -> Box<dyn Processor> {
        Language::get_processor(self.inner.as_ref())
    }
    fn get_version(&self) -> i32 {
        Language::get_version(self.inner.as_ref())
    }
    fn get_minor_version(&self) -> i32 {
        Language::get_minor_version(self.inner.as_ref())
    }
    fn get_address_factory(&self) -> Box<dyn AddressFactory> {
        Language::get_address_factory(self.inner.as_ref())
    }
    fn get_default_space(&self) -> Arc<AddressSpace> {
        Language::get_default_space(self.inner.as_ref())
    }
    fn get_default_data_space(&self) -> Arc<AddressSpace> {
        Language::get_default_data_space(self.inner.as_ref())
    }
    fn is_big_endian(&self) -> bool {
        Language::is_big_endian(self.inner.as_ref())
    }
    fn get_instruction_alignment(&self) -> i32 {
        Language::get_instruction_alignment(self.inner.as_ref())
    }
    fn supports_pcode(&self) -> bool {
        Language::supports_pcode(self.inner.as_ref())
    }
    fn is_volatile(&self, addr: &Address) -> bool {
        Language::is_volatile(self.inner.as_ref(), addr)
    }
    fn parse(
        &self,
        buf: &dyn MemBuffer,
        context: &mut dyn ProcessorContext,
        in_delay_slot: bool,
    ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
        Language::parse(self.inner.as_ref(), buf, context, in_delay_slot)
    }
    fn get_number_of_user_defined_op_names(&self) -> i32 {
        Language::get_number_of_user_defined_op_names(self.inner.as_ref())
    }
    fn get_user_defined_op_name(&self, index: i32) -> Option<String> {
        Language::get_user_defined_op_name(self.inner.as_ref(), index)
    }
    fn get_registers_at(&self, address: &Address) -> Vec<RegisterRef> {
        Language::get_registers_at(self.inner.as_ref(), address)
    }
    fn get_register_in_space(
        &self,
        addrspc: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
    ) -> Option<RegisterRef> {
        Language::get_register_in_space(self.inner.as_ref(), addrspc, offset, size)
    }
    fn get_registers(&self) -> Vec<RegisterRef> {
        Language::get_registers(self.inner.as_ref())
    }
    fn get_register_names(&self) -> Vec<String> {
        Language::get_register_names(self.inner.as_ref())
    }
    fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
        Language::get_register_by_name(self.inner.as_ref(), name)
    }
    fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
        Language::get_register_at(self.inner.as_ref(), addr, size)
    }
    fn get_program_counter(&self) -> Option<RegisterRef> {
        Some(self.pc.clone())
    }
    fn get_context_base_register(&self) -> Option<RegisterRef> {
        Language::get_context_base_register(self.inner.as_ref())
    }
    fn get_context_registers(&self) -> Vec<RegisterRef> {
        Language::get_context_registers(self.inner.as_ref())
    }
    fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
        Language::get_default_memory_blocks(self.inner.as_ref())
    }
    fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
        Language::get_default_symbols(self.inner.as_ref())
    }
    fn get_segmented_space(&self) -> String {
        Language::get_segmented_space(self.inner.as_ref())
    }
    fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
        Language::get_volatile_addresses(self.inner.as_ref())
    }
    fn apply_context_settings(&self, ctx: &mut dyn DefaultProgramContext) {
        Language::apply_context_settings(self.inner.as_ref(), ctx)
    }
    fn reload_language(&self, task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
        Language::reload_language(self.inner.as_ref(), task_monitor)
    }
    fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
        Language::get_compatible_compiler_spec_descriptions(self.inner.as_ref())
    }
    fn get_compiler_spec_by_id(
        &self,
        compiler_spec_id: &CompilerSpecID,
    ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
        Language::get_compiler_spec_by_id(self.inner.as_ref(), compiler_spec_id)
    }
    fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
        Language::get_default_compiler_spec(self.inner.as_ref())
    }
    fn has_property(&self, key: &str) -> bool {
        Language::has_property(self.inner.as_ref(), key)
    }
    fn get_property_as_int(&self, key: &str, default_int: i32) -> i32 {
        Language::get_property_as_int(self.inner.as_ref(), key, default_int)
    }
    fn get_property_as_boolean(&self, key: &str, default_boolean: bool) -> bool {
        Language::get_property_as_boolean(self.inner.as_ref(), key, default_boolean)
    }
    fn get_property_or(&self, key: &str, default_string: &str) -> String {
        Language::get_property_or(self.inner.as_ref(), key, default_string)
    }
    fn get_property(&self, key: &str) -> Option<String> {
        Language::get_property(self.inner.as_ref(), key)
    }
    fn get_property_keys(&self) -> HashSet<String> {
        Language::get_property_keys(self.inner.as_ref())
    }
    fn has_manual(&self) -> bool {
        Language::has_manual(self.inner.as_ref())
    }
    fn get_manual_entry(&self, instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
        Language::get_manual_entry(self.inner.as_ref(), instruction_mnemonic)
    }
    fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
        Language::get_manual_instruction_mnemonic_keys(self.inner.as_ref())
    }
    fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
        Language::get_manual_exception(self.inner.as_ref())
    }
    fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
        Language::get_sorted_vector_registers(self.inner.as_ref())
    }
    fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
        Language::get_register_addresses(self.inner.as_ref())
    }
    fn get_maximum_instruction_length(&self) -> Option<i32> {
        Language::get_maximum_instruction_length(self.inner.as_ref())
    }
}

/// Mirrors `InstructionDB`'s bridge from the prototype's parser context to the one an instruction
/// context hands out.
struct Bridge(Box<dyn crate::program::seam_stubs::ParserContext>);

impl LangParserContext for Bridge {
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        self.0.get_prototype()
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        self.0.as_any()
    }
}

/// An instruction parsed from bytes at an address, as the instruction context its prototype
/// builds p-code against.
struct Parsed {
    proto: Box<dyn InstructionPrototype>,
    mem: ByteMemBufferImpl,
    processor: ProcessorContextImpl,
}

impl InstructionContext for Parsed {
    fn get_address(&self) -> Address {
        self.mem.get_address()
    }
    fn get_processor_context(&self) -> &dyn ProcessorContextView {
        &self.processor
    }
    fn get_mem_buffer(&self) -> &dyn MemBuffer {
        &self.mem
    }
    fn get_parser_context(&self) -> Result<Box<dyn LangParserContext>, MemoryAccessException> {
        Ok(Box::new(Bridge(self.proto.get_parser_context(&self.mem, &self.processor)?)))
    }
    fn get_parser_context_at(
        &self,
        _instruction_address: Address,
    ) -> Result<Box<dyn LangParserContext>, InstructionContextError> {
        Err(UnknownContextException::with_message("no delay slots in these tests").into())
    }
}

/// A decoded instruction: its address, length, and p-code. The prototype answers only its
/// language, which is all [`PcodeProgram::from_instruction`](crate::pcode::exec::pcode_program::PcodeProgram::from_instruction)
/// asks of it.
struct DecodedInstruction {
    address: Address,
    length: i32,
    pcode: Vec<PcodeOp>,
    language: Arc<SleighLanguage>,
}

impl InstructionStub for DecodedInstruction {
    fn get_min_address(&self) -> Address {
        self.address.clone()
    }
    fn get_length(&self) -> i32 {
        self.length
    }
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        Arc::new(DefaultInvalidPrototype::new(Arc::clone(&self.language) as Arc<dyn Language>))
    }
    fn get_pcode(&self) -> Vec<PcodeOp> {
        self.pcode.clone()
    }
    fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<PcodeOp> {
        self.pcode.clone()
    }
}

struct NoPseudoInstruction;
impl PseudoInstruction for NoPseudoInstruction {}

/// Decodes real Sleigh instructions from a machine's shared memory, standing in for
/// `SleighInstructionDecoder`: read the bytes at the counter, parse them with the Sleigh language,
/// and build the instruction's p-code from its prototype.
pub(crate) struct SleighTestDecoder {
    pub(crate) language: Arc<SleighLanguage>,
    pub(crate) memory: SharedPcodeExecutorState<BytesState>,
    /// Every address this decoder was told the thread branched to.
    pub(crate) branched: Arc<std::sync::Mutex<Vec<i64>>>,
    last: Option<Arc<DecodedInstruction>>,
}

impl SleighTestDecoder {
    pub(crate) fn new(
        language: Arc<SleighLanguage>,
        memory: SharedPcodeExecutorState<BytesState>,
        branched: Arc<std::sync::Mutex<Vec<i64>>>,
    ) -> Self {
        Self { language, memory, branched, last: None }
    }
}

impl InstructionDecoder for SleighTestDecoder {
    fn get_language(&self) -> Arc<dyn Language> {
        Arc::clone(&self.language) as Arc<dyn Language>
    }

    fn decode_instruction(
        &mut self,
        address: &Address,
        _context: Option<&dyn RegisterValue>,
    ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
        // Java's decoder reads through the state's concrete buffer; the fixture's instructions
        // are at most two bytes long.
        let bytes = self.memory.lock().get_var(address.space(), address.offset(), 2, false, Reason::ExecuteDecode);
        let mem = ByteMemBufferImpl::new(address.clone(), bytes, self.language.is_big_endian());
        let mut processor = ProcessorContextImpl::new(self.language.clone());
        let proto = Language::parse(self.language.as_ref(), &mem, &mut processor, false)
            .map_err(|e| format!("cannot decode at {address}: {e:?}"))?;
        let parsed = Parsed { proto, mem, processor };
        let pcode = parsed.proto.get_pcode(&parsed, None);
        let length = parsed.proto.get_length();
        self.last = Some(Arc::new(DecodedInstruction {
            address: address.clone(),
            length,
            pcode,
            language: Arc::clone(&self.language),
        }));
        Ok(Box::new(NoPseudoInstruction))
    }

    fn branched(&mut self, address: &Address) {
        self.branched.lock().unwrap().push(address.offset());
    }

    fn get_last_instruction(&self) -> Option<Arc<dyn Instruction>> {
        self.last.clone().map(|i| i as Arc<dyn Instruction>)
    }

    fn get_last_length_with_delays(&self) -> i32 {
        self.last.as_ref().map_or(0, |i| i.length)
    }
}

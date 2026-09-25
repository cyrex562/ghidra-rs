//! Port of `ghidra.program.disassemble.Disassembler`: the pseudo-disassembly path.
//!
//! The disassembler follows instruction flows, parsing instructions with a language and tracking
//! processor context along the flow with a [`DisassemblerContextImpl`].
//!
//! # What is ported
//!
//! The language-only disassembler (`Disassembler(Language, AddressFactory, TaskMonitor,
//! DisassemblerMessageListener)` and `getDisassembler(Language, ...)`) and everything
//! [`Disassembler::pseudo_disassemble_block`] reaches: the block loop
//! (`disassembleInstructionBlock`), instruction parsing, delay slots, block termination on a
//! limit or a call, repeated-byte tracking, context flow through the disassembler's proxy program
//! context ([`DisassemblerProgramContext`]), and the immutable per-instruction context each pseudo
//! instruction owns ([`DisassemblerInstructionContext`]). This is the path the emulator's
//! `SleighInstructionDecoder` uses.
//!
//! # What is not (the program-mutating paths)
//!
//! Everything that needs a `Program`: the program constructors and `getDisassembler(Program,
//! ...)`, the `Program` options (`isMarkBadDisassemblyOptionEnabled`, ...), `disassemble(...)`
//! into a listing with its `InstructionSet` building (`disassembleNextInstructionSet`, the
//! `DisassemblerQueue`), flow following (`processInstructionFlows`, `checkForIndirectCallFlow`,
//! `isNoReturnCall`), the conflict checks against an `InstructionSet` and the listing inside the
//! block loop, memory-block restrictions (`initializedAddressSet`, `restrictedAddressSet`,
//! `setMemoryConstraintError`), bookmarks (`markInstructionError`, `markUnimplementedPcode`,
//! `clearUnimplementedPcodeWarnings`, `clearBadInstructionErrors`), and the proxy context's
//! delegation to a real program context. In the language-only disassembler those are all
//! unreachable (`program`, `instructionSet`, `initializedAddressSet` and `restrictedAddressSet`
//! are `null` and `followFlow` is `false`), so what is here behaves as Java's does for that
//! disassembler; the rest lands with the program arena, and `PORT_MANIFEST.tsv` keeps this class
//! `TODO` until then.
//!
//! # Deviations
//!
//! * The language is a [`SleighLanguage`]: parsing must yield a prototype that can be shared
//!   across threads (a [`SharedPrototype`]), which [`Language::parse`]'s boxed trait object is
//!   not. Every parsing Java language is a `SleighLanguage` (`OldLanguage` throws
//!   `UnsupportedOperationException` from `parse`).
//! * Java's language-specific subclass lookup (`customDisassemblerClass`) finds no subclass: none
//!   exists anywhere in Ghidra, so naming one fails as Java's `ClassNotFoundException` path does.
//! * `PseudoInstruction.setInstructionBlock` is not called: a pseudo instruction resolves a
//!   sibling's parser context from its own cached bytes (see
//!   [`PseudoInstruction`]'s docs), which cover its delay slots.
//! * Java's `SleighLanguage.parse` throws `NestedDelaySlotException`; the Rust parse reports it
//!   as an unknown instruction carrying that exception's message, which is how it is recognized
//!   here.
//! * `pseudoDisassembleBlock` catches any exception from the block loop and reports it. The
//!   checked ones never reach it (the loop records them in the block); the unchecked ones are
//!   programming errors, which panic here.

use std::rc::Rc;
use std::sync::Arc;

use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::SleighInstructionPrototype;
use crate::app::util::pseudo_code_unit::PseudoCodeUnitError;
use crate::app::util::pseudo_instruction::PseudoInstruction;
use crate::app::util::repeat_instruction_byte_tracker::RepeatInstructionByteTracker;
use crate::program::database::register::address_range_object_map::AddressRangeObjectMap;
use crate::program::disassemble::disassembler_context_impl::DisassemblerContextImpl;
use crate::program::disassemble::disassembler_message_listener::DisassemblerMessageListener;
use crate::program::model::address::{
    Address, AddressFactory, AddressRange, AddressRangeIterator, AddressSetView,
};
use crate::program::model::lang::ghidra_language_property_keys::CUSTOM_DISASSEMBLER_CLASS;
use crate::program::model::lang::instruction_block::InstructionBlock;
use crate::program::model::lang::instruction_block_flow::{InstructionBlockFlow, InstructionBlockFlowType};
use crate::program::model::lang::language::{Language, ParseError};
use crate::program::model::lang::nested_delay_slot_exception::NestedDelaySlotException;
use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::listing::instruction_record::SharedPrototype;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::model::mem::{MemBuffer, Memory, MemoryAccessException, WrappedMemBuffer};
use crate::program::seam_stubs::RegisterValue as RegisterValueTrait;
use crate::program::util::abstract_program_context::AbstractProgramContext;
use crate::program::util::program_context_impl::ProgramContextImpl;
use crate::util::task::TaskMonitor;

/// A pseudo instruction as the disassembler makes it: owning its bytes and the immutable context
/// it was decoded under.
pub type DisassembledInstruction = PseudoInstruction<DisassemblerInstructionContext>;

/// A block of [`DisassembledInstruction`]s.
pub type DisassembledBlock = InstructionBlock<DisassembledInstruction>;

/// Why an instruction could not be parsed or placed, as the checked exceptions Java's block loop
/// catches.
enum StepError {
    /// `AddressOutOfBoundsException` / `AddressOverflowException`.
    AddressOverflow,
    /// `InsufficientBytesException`, with its message.
    InsufficientBytes(String),
    /// `UnknownInstructionException`, with its message.
    UnknownInstruction(String),
    /// `NestedDelaySlotException`, which escapes the block loop.
    NestedDelaySlot(NestedDelaySlotException),
}

impl From<ParseError> for StepError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::InsufficientBytes(e) => StepError::InsufficientBytes(e.message().to_string()),
            ParseError::UnknownInstruction(e) => {
                if e.message() == NestedDelaySlotException::new().message() {
                    StepError::NestedDelaySlot(NestedDelaySlotException::new())
                } else {
                    StepError::UnknownInstruction(e.message().to_string())
                }
            }
        }
    }
}

impl From<PseudoCodeUnitError> for StepError {
    fn from(_: PseudoCodeUnitError) -> Self {
        // an instruction running off its space; a zero-length prototype is not parsed
        StepError::AddressOverflow
    }
}

/// Shares the block's memory buffer with the [`WrappedMemBuffer`]s the loop reads each
/// instruction through, which own the buffer they wrap.
struct SharedMemBuffer(Arc<dyn MemBuffer>);

impl MemBuffer for SharedMemBuffer {
    fn get_address(&self) -> Address {
        self.0.get_address()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.0.get_byte(offset)
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        self.0.get_bytes(buf, offset)
    }

    fn is_big_endian(&self) -> bool {
        self.0.is_big_endian()
    }

    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        self.0.get_memory()
    }
}

/// What the disassembler asks of a seed context: Java's `setSeedContext` takes any
/// `DisassemblerContextImpl`, whatever program context it reads.
trait SeedContext {
    fn base_context_register(&self) -> &RegisterRef;
    fn flow_context_value(&self, dest_addr: &Address) -> RegisterValue;
}

impl<P: ProgramContext> SeedContext for DisassemblerContextImpl<P> {
    fn base_context_register(&self) -> &RegisterRef {
        DisassemblerContextImpl::base_context_register(self)
    }

    fn flow_context_value(&self, dest_addr: &Address) -> RegisterValue {
        self.get_flow_context_value(dest_addr, false)
    }
}

/// Class to perform disassembly; see the module docs for what is ported.
///
/// Port of `ghidra.program.disassemble.Disassembler`.
pub struct Disassembler {
    language: Arc<SleighLanguage>,
    addr_factory: Arc<dyn AddressFactory>,
    /// `None` stands for Java's `Register.NO_CONTEXT`.
    base_context_register: Option<RegisterRef>,
    parallel_helper: Option<Box<dyn ParallelInstructionLanguageHelper>>,
    /// Provides seed context for new flows.
    seed_context: Option<Box<dyn SeedContext>>,
    listener: Option<Arc<dyn DisassemblerMessageListener>>,
    monitor: Arc<dyn TaskMonitor>,
    /// Java's `defaultLanguageContext`: the language's default context, since there is no
    /// program.
    default_language_context: Rc<ProgramContextImpl>,
    /// Proxy context, which contains in-progress disassembly context
    /// (`disassemblerProgramContext`), owned by the disassembler context.
    disassembler_context: DisassemblerContextImpl<DisassemblerProgramContext>,
    inst_alignment: i32,
    repeat_instruction_byte_tracker: RepeatInstructionByteTracker,
    do_mark_bad_instructions: bool,
    do_mark_unimpl_pcode: bool,
}

impl Disassembler {
    /// Program disassembler property enabling marking of instruction disassembly errors.
    pub const MARK_BAD_INSTRUCTION_PROPERTY: &'static str = super::MARK_BAD_INSTRUCTION_PROPERTY;
    /// Program disassembler property enabling marking of instructions which are missing their
    /// pcode implementation.
    pub const MARK_UNIMPL_PCODE_PROPERTY: &'static str = super::MARK_UNIMPL_PCODE_PROPERTY;
    /// Program disassembler property restricting disassembly to executable memory only.
    pub const RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY: &'static str =
        super::RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY;
    /// Bookmark category of instruction errors.
    pub const ERROR_BOOKMARK_CATEGORY: &'static str = "Bad Instruction";
    /// Bookmark category of instructions with unimplemented pcode.
    pub const UNIMPL_BOOKMARK_CATEGORY: &'static str = "Unimplemented Pcode";
    /// Default limit on a run of instructions made of one repeated byte.
    pub const MAX_REPEAT_PATTERN_LENGTH: i32 = 16;

    const DISASSEMBLE_MEMORY_CACHE_SIZE: usize = 8;

    /// Gets a suitable disassembler instance, intended for block pseudo-disassembly
    /// ([`Disassembler::pseudo_disassemble_block`]). Executable memory restriction is not
    /// provided. Port of `getDisassembler(Language, AddressFactory, TaskMonitor,
    /// DisassemblerMessageListener)`.
    ///
    /// # Panics
    /// If the language names a language-specific disassembler class
    /// (`customDisassemblerClass`): no such class exists, and Java fails the same way when the
    /// class cannot be found.
    pub fn get_disassembler(
        language: Arc<SleighLanguage>,
        addr_factory: Arc<dyn AddressFactory>,
        monitor: Arc<dyn TaskMonitor>,
        listener: Option<Arc<dyn DisassemblerMessageListener>>,
    ) -> Disassembler {
        if let Some(class_name) = language.get_property(CUSTOM_DISASSEMBLER_CLASS) {
            panic!(
                "Invalid Class specified for {CUSTOM_DISASSEMBLER_CLASS} ({class_name}): {}",
                language.get_language_id()
            );
        }
        Disassembler::new(language, addr_factory, monitor, listener)
    }

    /// Disassembler constructor intended for block pseudo-disassembly only. Executable memory
    /// restriction is not provided. Port of `Disassembler(Language, AddressFactory,
    /// TaskMonitor, DisassemblerMessageListener)`.
    pub fn new(
        language: Arc<SleighLanguage>,
        addr_factory: Arc<dyn AddressFactory>,
        monitor: Arc<dyn TaskMonitor>,
        listener: Option<Arc<dyn DisassemblerMessageListener>>,
    ) -> Disassembler {
        let dyn_language: Arc<dyn Language> = language.clone();
        let mut default_language_context = ProgramContextImpl::new(dyn_language.clone());
        language.apply_context_settings(&mut default_language_context);
        let default_language_context = Rc::new(default_language_context);
        let base_context_register = language.get_context_base_register();
        let disassembler_context = DisassemblerContextImpl::new(DisassemblerProgramContext::new(
            Arc::clone(&language),
            base_context_register.clone(),
            Rc::clone(&default_language_context),
        ));
        Disassembler {
            parallel_helper: language.get_parallel_instruction_helper(),
            inst_alignment: language.get_instruction_alignment(),
            base_context_register,
            language,
            addr_factory,
            seed_context: None,
            listener,
            monitor,
            default_language_context,
            disassembler_context,
            repeat_instruction_byte_tracker: RepeatInstructionByteTracker::new(
                Self::MAX_REPEAT_PATTERN_LENGTH,
                None,
            ),
            // Java's language constructor passes `false` for both.
            do_mark_bad_instructions: false,
            do_mark_unimpl_pcode: false,
        }
    }

    /// Sets the seed context used to establish initial context at starting points which are not
    /// arrived at via a natural disassembly flow; `None` disables it. Port of
    /// `setSeedContext(DisassemblerContextImpl)`; the disassembler keeps the seed.
    ///
    /// # Panics
    /// If the seed's context register differs from the disassembler's (Java's
    /// `IllegalArgumentException`).
    pub fn set_seed_context<P: ProgramContext + 'static>(
        &mut self,
        seed_context: Option<DisassemblerContextImpl<P>>,
    ) {
        if let Some(seed) = &seed_context {
            let seed_base = SeedContext::base_context_register(seed);
            let matches = match &self.base_context_register {
                Some(base) => base == seed_base,
                None => !seed_base.is_processor_context(),
            };
            if !matches {
                panic!(
                    "Seed context register does not match disassembler's context register: {}",
                    self.base_context_register.as_ref().map_or("NO_CONTEXT".to_string(), |r| r.name().to_string())
                );
            }
        }
        self.seed_context = seed_context.map(|s| Box::new(s) as Box<dyn SeedContext>);
    }

    /// Sets the maximum number of instructions in a single run which contain the same byte
    /// values; -1 disables the check. Port of `setRepeatPatternLimit(int)`.
    pub fn set_repeat_pattern_limit(&mut self, max_instructions: i32) {
        self.repeat_instruction_byte_tracker.set_repeat_pattern_limit(max_instructions);
    }

    /// Sets the region over which the repeat pattern limit is ignored. Port of
    /// `setRepeatPatternLimitIgnored(AddressSetView)`.
    pub fn set_repeat_pattern_limit_ignored(&mut self, set: Option<Box<dyn AddressSetView>>) {
        self.repeat_instruction_byte_tracker.set_repeat_pattern_limit_ignored(set);
    }

    /// The context accumulated by pseudo-disassembly.
    pub fn disassembler_context(&self) -> &DisassemblerContextImpl<DisassemblerProgramContext> {
        &self.disassembler_context
    }

    /// Clears any retained context state which may have been accumulated. Only needed when
    /// pseudo-disassembling over an extended code range, to avoid excessive in-memory state.
    /// Port of `resetDisassemblerContext()`.
    pub fn reset_disassembler_context(&mut self) {
        self.disassembler_context = DisassemblerContextImpl::new(DisassemblerProgramContext::new(
            Arc::clone(&self.language),
            self.base_context_register.clone(),
            Rc::clone(&self.default_language_context),
        ));
    }

    /// Pseudo-disassembles a single instruction block, only following fall-throughs. Should not
    /// be mixed with other disassembly on this instance. Port of
    /// `pseudoDisassembleBlock(MemBuffer, RegisterValue, int)`.
    ///
    /// # Arguments
    /// * `block_mem_buffer` - the memory to disassemble, positioned at the block start
    /// * `default_context_value` - starting context to use if no context has previously been
    ///   established for the block start
    /// * `limit` - maximum number of instructions to disassemble
    ///
    /// Returns the block of pseudo instructions, which may be empty and carry an error, or
    /// `None` if the block start is not properly aligned for instruction parsing.
    pub fn pseudo_disassemble_block(
        &mut self,
        block_mem_buffer: Box<dyn MemBuffer>,
        default_context_value: Option<&RegisterValue>,
        limit: i32,
    ) -> Option<DisassembledBlock> {
        let block_mem_buffer: Arc<dyn MemBuffer> = Arc::from(block_mem_buffer);
        let start_addr = block_mem_buffer.get_address();

        let addressable_unit_size = start_addr.space().unit_size();
        if self.inst_alignment % addressable_unit_size != 0
            || start_addr.offset() % self.inst_alignment as i64 != 0
        {
            self.report_message(&format!(
                "Disassembly address {start_addr} violates {}-byte instruction alignment",
                self.inst_alignment
            ));
            return None;
        }

        if let Some(seed) = &self.seed_context {
            let seed_value = seed.flow_context_value(&start_addr);
            self.disassembler_context.set_future_register_value_at(&start_addr, Some(seed_value));
        }

        if let (Some(base), Some(default_context_value)) = (&self.base_context_register, default_context_value) {
            let register_value = self
                .disassembler_context
                .get_register_value_at(base, &start_addr)
                .filter(RegisterValue::has_any_value);
            let default_value = ProgramContext::get_default_value(
                self.disassembler_context.program_context(),
                base,
                &start_addr,
            )
            .map(|v| RegisterValue::from_trait_object(v.as_ref()))
            .filter(RegisterValue::has_any_value);
            if register_value == default_value {
                // copy specified defaultContextValue to addr if context is language default
                self.disassembler_context
                    .set_future_register_value_at(&start_addr, Some(default_context_value.clone()));
            }
        }

        self.disassembler_context.flow_start(&start_addr);

        let mut block = InstructionBlock::new(start_addr.clone());

        // preserve and disable bookmark settings
        let old_mark_bad_instructions = self.do_mark_bad_instructions;
        let old_mark_unimplemented_pcode = self.do_mark_unimpl_pcode;
        self.do_mark_bad_instructions = false;
        self.do_mark_unimpl_pcode = false;

        // Java also catches any runtime exception here, reporting "Pseudo block disassembly
        // failure at ..."; the checked failures are recorded in the block, and the unchecked ones
        // (programming errors) are panics in this port.
        self.disassemble_instruction_block(&mut block, &block_mem_buffer, None, limit);

        // restore bookmark settings
        self.do_mark_bad_instructions = old_mark_bad_instructions;
        self.do_mark_unimpl_pcode = old_mark_unimplemented_pcode;

        if block.is_empty() {
            self.disassembler_context.flow_abort();
            return Some(block);
        }

        if self.base_context_register.is_some() {
            if let Some(fall_thru_addr) = block.get_fall_through() {
                // Merge fall-through context into program context for in-memory retention
                self.disassembler_context.copy_to_future_flow_state(&fall_thru_addr);
            }
        }

        self.disassembler_context.flow_end(Some(&block.get_max_address()));
        Some(block)
    }

    /// Port of `disassembleInstructionBlock` for the pseudo path: no instruction set, no listing
    /// to check against (see the module docs). Instructions are added to `block` until one
    /// without a fall-through, an error, or an early termination.
    fn disassemble_instruction_block(
        &mut self,
        block: &mut DisassembledBlock,
        block_mem_buffer: &Arc<dyn MemBuffer>,
        flow_from: Option<Address>,
        limit: i32,
    ) {
        let mut addr = Some(block_mem_buffer.get_address());
        let mut flow_from = flow_from;
        self.repeat_instruction_byte_tracker.reset();

        let result = self.disassemble_block_body(block, block_mem_buffer, &mut addr, &mut flow_from, limit);
        let Err(error) = result else {
            return;
        };
        let addr = addr.expect("the loop fails only while it has an address");
        match error {
            StepError::AddressOverflow => {
                block.set_instruction_memory_error(
                    addr,
                    flow_from,
                    "Instruction does not fit within address space constraint".to_string(),
                );
                self.block_terminated(block);
            }
            StepError::InsufficientBytes(message) => {
                block.set_instruction_memory_error(addr, flow_from, message);
                self.block_terminated(block);
            }
            // `NestedDelaySlotException` is an `UnknownInstructionException`, caught here
            StepError::UnknownInstruction(message) => {
                let context = self.current_base_context_value();
                block.set_parse_conflict(addr, context, flow_from, message);
                self.block_terminated(block);
            }
            StepError::NestedDelaySlot(e) => {
                let context = self.current_base_context_value();
                block.set_parse_conflict(addr, context, flow_from, e.message().to_string());
                self.block_terminated(block);
            }
        }
    }

    /// Java's `disassemblerContext.getRegisterValue(disassemblerContext.getBaseContextRegister())`.
    fn current_base_context_value(&self) -> Option<RegisterValue> {
        let base = self.disassembler_context.base_context_register().clone();
        self.disassembler_context.get_register_value(&base)
    }

    /// The `try` body of `disassembleInstructionBlock`; `addr` and `flow_from` are the loop's
    /// variables, left as they were when a step failed.
    fn disassemble_block_body(
        &mut self,
        block: &mut DisassembledBlock,
        block_mem_buffer: &Arc<dyn MemBuffer>,
        addr: &mut Option<Address>,
        flow_from: &mut Option<Address>,
        limit: i32,
    ) -> Result<(), StepError> {
        while !self.monitor.is_cancelled() {
            let Some(inst_addr) = addr.clone() else {
                break;
            };

            self.disassembler_context.flow_to_address(&inst_addr);

            let offset = inst_addr.subtract(&block_mem_buffer.get_address()) as i32;
            let instr_mem_buffer = WrappedMemBuffer::with_buffer_size(
                Box::new(SharedMemBuffer(Arc::clone(block_mem_buffer))),
                Self::DISASSEMBLE_MEMORY_CACHE_SIZE,
                offset,
            )
            .map_err(|_| StepError::AddressOverflow)?;

            let prototype = self.parse_instruction_prototype(&instr_mem_buffer, block)?;

            let context_value = self.base_context_value();

            let inst = self.get_pseudo_instruction(&instr_mem_buffer, prototype, context_value.clone())?;

            if self.repeat_instruction_byte_tracker.exceeds_repeat_byte_pattern(&inst) {
                block.set_parse_conflict(
                    inst_addr.clone(),
                    context_value,
                    flow_from.clone(),
                    "Maximum run of repeated byte instructions exceeded".to_string(),
                );
            }

            // process instruction flows and obtain fallthrough address
            *addr = self.process_instruction(inst, block_mem_buffer, block)?;

            let Some(fall_thru_addr) = addr.clone() else {
                self.block_terminated(block);
                return Ok(());
            };
            if block.has_instruction_error() {
                self.block_terminated(block);
                return Ok(());
            }
            let (termination_ok, is_call) = {
                let inst = block.get_instruction_at(&inst_addr).expect("the instruction was just added");
                (self.is_block_termination_ok(inst), inst.get_flow_type().is_call())
            };
            if self.end_block_early(&inst_addr, &fall_thru_addr, limit, termination_ok, block)
                || self.end_block_on_call(&inst_addr, &fall_thru_addr, is_call && termination_ok, block)
            {
                // Preserve fallthrough context for future disassembly continuation. No need to
                // set block fallthrough, since special block flows are added to facilitate future
                // prioritization of flows.
                self.disassembler_context.copy_to_future_flow_state(&fall_thru_addr);
                self.block_terminated(block);
                return Ok(());
            }

            *flow_from = Some(inst_addr);
        }
        Ok(())
    }

    /// The context register value at the current flow location, or `None` without a context
    /// register (Java asks for `NO_CONTEXT`, which yields `null` in the language-only
    /// disassembler).
    fn base_context_value(&self) -> Option<RegisterValue> {
        let base = self.base_context_register.as_ref()?;
        self.disassembler_context.get_register_value(base)
    }

    /// Signals that block disassembly has been terminated, an error perhaps recorded in the
    /// block. Port of `blockTerminated(InstructionBlock)`, which does nothing; Java intends it
    /// for extension cleanup.
    fn block_terminated(&mut self, _block: &mut DisassembledBlock) {}

    /// Parses instruction bytes and context into a prototype. Port of
    /// `parseInstructionPrototype(MemBuffer, InstructionBlock)`; `_block` is the fall-through
    /// sequence preceding the instruction, for crossbuilds.
    fn parse_instruction_prototype(
        &mut self,
        instr_mem_buffer: &dyn MemBuffer,
        _block: &DisassembledBlock,
    ) -> Result<SleighInstructionPrototype, StepError> {
        Ok(self.language.parse_sleigh(instr_mem_buffer, &mut self.disassembler_context, false)?)
    }

    /// Port of the private `endBlockEarly`: at the instruction limit (outside a parallel packet)
    /// the block ends with a priority flow to its fall-through.
    fn end_block_early(
        &mut self,
        inst_addr: &Address,
        fall_thru_addr: &Address,
        limit: i32,
        termination_ok: bool,
        block: &mut DisassembledBlock,
    ) -> bool {
        // (the uninitialized-memory condition needs a program; see the module docs)
        if block.get_instruction_count() as i64 >= limit as i64 && termination_ok {
            self.disassembler_context.copy_to_future_flow_state(fall_thru_addr);
            block.add_block_flow(InstructionBlockFlow::new(
                fall_thru_addr.clone(),
                Some(inst_addr.clone()),
                InstructionBlockFlowType::Priority,
            ));
            return true;
        }
        false
    }

    /// Port of the private `endBlockOnCall`: a call ends the block, deferring its fall-through
    /// in case the call does not return. `terminating_call` is `inst.getFlowType().isCall() &&
    /// isBlockTerminationOK(inst)`.
    fn end_block_on_call(
        &mut self,
        inst_addr: &Address,
        fall_thru_addr: &Address,
        terminating_call: bool,
        block: &mut DisassembledBlock,
    ) -> bool {
        if !terminating_call {
            return false;
        }
        self.disassembler_context.copy_to_future_flow_state(fall_thru_addr);
        let fall_through = InstructionBlockFlow::new(
            fall_thru_addr.clone(),
            Some(inst_addr.clone()),
            InstructionBlockFlowType::CallFallthrough,
        );
        // (queuing the flow needs the program path's DisassemblerQueue)
        block.add_block_flow(fall_through);
        block.add_branch_flow(fall_thru_addr.clone()); // treat fall-through like branch flow
        true
    }

    /// Port of the private `getPseudoInstruction` for the program-less disassembler.
    fn get_pseudo_instruction(
        &mut self,
        mem_buffer: &dyn MemBuffer,
        prototype: SleighInstructionPrototype,
        context_value: Option<RegisterValue>,
    ) -> Result<DisassembledInstruction, StepError> {
        let addr = mem_buffer.get_address();
        let processor_context = self.get_processor_context(&addr, prototype.get_length(), context_value)?;
        let prototype: SharedPrototype = Arc::new(prototype);
        Ok(PseudoInstruction::with_address_factory(
            Arc::clone(&self.addr_factory),
            addr,
            prototype,
            mem_buffer,
            processor_context,
        )?)
    }

    /// The processor context for the instruction being disassembled, for minting a
    /// [`PseudoInstruction`]. Port of `getProcessorContext(Address, int, RegisterValue)`.
    fn get_processor_context(
        &mut self,
        addr: &Address,
        instr_length: i32,
        context_value: Option<RegisterValue>,
    ) -> Result<DisassemblerInstructionContext, StepError> {
        self.disassembler_context
            .program_context_mut()
            .get_instruction_context(context_value, addr, instr_length)
    }

    /// Whether the block may end after `instr`; within a parallel instruction group it must
    /// continue. Port of `isBlockTerminationOK(Instruction)`.
    fn is_block_termination_ok(&self, instr: &DisassembledInstruction) -> bool {
        match &self.parallel_helper {
            None => true,
            Some(helper) => helper.is_end_of_parallel_instruction_group(instr),
        }
    }

    /// Adds a newly parsed instruction and its delay-slot instructions to the block, returning
    /// the instruction's fall-through address, if any. Port of
    /// `processInstruction(PseudoInstruction, MemBuffer, InstructionBlock, InstructionSet)` for
    /// the pseudo path (no flows are followed).
    fn process_instruction(
        &mut self,
        inst: DisassembledInstruction,
        block_mem_buffer: &Arc<dyn MemBuffer>,
        block: &mut DisassembledBlock,
    ) -> Result<Option<Address>, StepError> {
        let delay_slot_list = self
            .parse_delay_slots(&inst, block_mem_buffer, block)
            .map_err(StepError::NestedDelaySlot)?;

        // NOTE: Don't rely on the instruction for its fallthrough since this does not work on a
        // pseudo instruction with delay slots.
        let has_fallthrough = inst.has_fallthrough();
        block.add_instruction(inst);
        if let Some(delay_slot_list) = delay_slot_list {
            for ds_instr in delay_slot_list {
                block.add_instruction(ds_instr);
            }
        }

        if !has_fallthrough {
            return Ok(None);
        }
        Ok(block.get_max_address().next().ok())
    }

    /// Port of the private `parseDelaySlots`: the instructions filling `inst`'s delay slots, or
    /// `None` without delay slots or on an error (recorded in the block).
    fn parse_delay_slots(
        &mut self,
        inst: &DisassembledInstruction,
        block_mem_buffer: &Arc<dyn MemBuffer>,
        block: &mut DisassembledBlock,
    ) -> Result<Option<Vec<DisassembledInstruction>>, NestedDelaySlotException> {
        let mut min_delay_slot_bytes = inst.record().prototype().get_delay_slot_byte_count();
        if min_delay_slot_bytes == 0 {
            return Ok(None); // no delay slots
        }
        if inst.is_in_delay_slot() {
            return Err(NestedDelaySlotException::new());
        }

        let inst_addr = inst.get_min_address();
        let mut addr = inst_addr.clone();
        let mut length = inst.get_length();
        let mut instr_list = Vec::new();

        let result: Result<(), StepError> = loop {
            if min_delay_slot_bytes <= 0 {
                break Ok(());
            }
            addr = match addr.add_no_wrap(length as i64) {
                Ok(next) => next,
                Err(_) => {
                    block.set_instruction_memory_error(
                        addr.clone(),
                        Some(inst_addr.clone()),
                        "Failed to properly process delay slot at end of address space".to_string(),
                    );
                    break Ok(());
                }
            };

            self.disassembler_context.flow_to_address(&addr);

            let offset = addr.subtract(&block_mem_buffer.get_address()) as i32;
            let ds_instr_mem_buffer = match WrappedMemBuffer::new(
                Box::new(SharedMemBuffer(Arc::clone(block_mem_buffer))),
                offset,
            ) {
                Ok(buffer) => buffer,
                Err(_) => break Err(StepError::AddressOverflow),
            };

            // create one instruction
            let prototype =
                match self.language.parse_sleigh(&ds_instr_mem_buffer, &mut self.disassembler_context, true) {
                    Ok(prototype) => prototype,
                    Err(e) => break Err(e.into()),
                };
            let context_value = self.base_context_value();

            let ds_instr =
                match self.get_pseudo_instruction(&ds_instr_mem_buffer, prototype, context_value.clone()) {
                    Ok(ds_instr) => ds_instr,
                    Err(e) => break Err(e),
                };

            if self.repeat_instruction_byte_tracker.exceeds_repeat_byte_pattern(&ds_instr) {
                block.set_parse_conflict(
                    addr.clone(),
                    context_value,
                    Some(inst_addr.clone()),
                    "Maximum run of repeated byte instructions exceeded".to_string(),
                );
            }

            length = ds_instr.get_length();
            min_delay_slot_bytes -= length;
            instr_list.push(ds_instr);
        };

        match result {
            Ok(()) => return Ok(Some(instr_list)),
            Err(StepError::NestedDelaySlot(e)) => return Err(e),
            Err(StepError::AddressOverflow) => block.set_instruction_memory_error(
                addr,
                Some(inst_addr),
                "Instruction does not fit within address space constraint".to_string(),
            ),
            Err(StepError::InsufficientBytes(message)) => {
                block.set_instruction_memory_error(addr, Some(inst_addr), message)
            }
            Err(StepError::UnknownInstruction(message)) => {
                let context = self.current_base_context_value();
                block.set_parse_conflict(addr, context, Some(inst_addr), message);
            }
        }
        Ok(None) // error occurred
    }

    fn report_message(&self, msg: &str) {
        if let Some(listener) = &self.listener {
            listener.disassemble_message_reported(msg);
        }
    }
}

/// A proxy program context for the delayed nature of laying down instructions and their
/// context: it tracks context not yet committed, for use by the disassembler context in place of
/// the true program context.
///
/// Port of the inner class `Disassembler.DisassemblerProgramContext` for the program-less
/// disassembler: its reads fall back to the language's default context (Java's
/// `defaultLanguageContext`); the `realProgramContext` branches land with the program path. The
/// methods Java leaves unsupported ("not used during disassembly") panic as its
/// `UnsupportedOperationException` does.
pub struct DisassemblerProgramContext {
    base: AbstractProgramContext,
    language: Arc<SleighLanguage>,
    /// The disassembler's context register; `None` for `NO_CONTEXT`.
    base_context_register: Option<RegisterRef>,
    default_language_context: Rc<ProgramContextImpl>,
    temporary_context_map: AddressRangeObjectMap<RegisterValue>,
    /// An immutable context which may be shared by multiple instructions.
    instruction_context_cache: Option<DisassemblerInstructionContext>,
}

fn unsupported() -> ! {
    panic!("UnsupportedOperationException: not used during disassembly")
}

impl DisassemblerProgramContext {
    fn new(
        language: Arc<SleighLanguage>,
        base_context_register: Option<RegisterRef>,
        default_language_context: Rc<ProgramContextImpl>,
    ) -> Self {
        DisassemblerProgramContext {
            base: AbstractProgramContext::new(language.clone()),
            language,
            base_context_register,
            default_language_context,
            temporary_context_map: AddressRangeObjectMap::new(),
            instruction_context_cache: None,
        }
    }

    /// Following the parse of a new instruction prototype, gets an immutable processor context
    /// for minting a new instruction. With a value, the temporary context is expanded to hold it
    /// over the instruction. Port of `getInstructionContext(RegisterValue, Address, int)`.
    fn get_instruction_context(
        &mut self,
        value: Option<RegisterValue>,
        instr_addr: &Address,
        instr_length: i32,
    ) -> Result<DisassemblerInstructionContext, StepError> {
        let Some(value) = value else {
            // If none, implies no context register and should always be none
            let language = &self.language;
            return Ok(self
                .instruction_context_cache
                .get_or_insert_with(|| DisassemblerInstructionContext::new(Arc::clone(language), None))
                .clone());
        };

        let stale = self
            .instruction_context_cache
            .as_ref()
            .is_none_or(|cache| cache.context_value.as_ref() != Some(&value));
        if stale {
            self.instruction_context_cache =
                Some(DisassemblerInstructionContext::new(Arc::clone(&self.language), Some(value.clone())));
        }

        let max_addr = instr_addr.add(instr_length as i64 - 1).map_err(|_| StepError::AddressOverflow)?;
        self.temporary_context_map.set_object(instr_addr.clone(), max_addr, value);

        Ok(self.instruction_context_cache.clone().expect("just set"))
    }

    /// Port of `clearTemporaryContext()`.
    pub fn clear_temporary_context(&mut self) {
        self.temporary_context_map.clear_all();
    }

    /// The language default for `register`; none for a register the language does not have
    /// (Java's `NO_CONTEXT`), which has no default store.
    fn language_default(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        self.base.get_register(register.name())?;
        ProgramContext::get_default_value(self.default_language_context.as_ref(), register, address)
    }
}

impl ProgramContext for DisassemblerProgramContext {
    fn has_non_flowing_context(&self) -> bool {
        self.base.has_non_flowing_context()
    }

    fn get_flow_value(&self, value: Box<dyn RegisterValueTrait>) -> Box<dyn RegisterValueTrait> {
        self.base.get_flow_value(value)
    }

    fn get_non_flow_value(&self, value: Box<dyn RegisterValueTrait>) -> Option<Box<dyn RegisterValueTrait>> {
        self.base.get_non_flow_value(value)
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.base.get_register(name)
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.base.get_registers()
    }

    fn get_registers_with_values(&self) -> Vec<RegisterRef> {
        unsupported()
    }

    fn get_value(&self, _register: &Register, _address: &Address, _signed: bool) -> Option<i128> {
        unsupported()
    }

    /// The register is assumed to be the context register during disassembly.
    fn get_register_value(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        match self.temporary_context_map.get_object(address) {
            Some(value) => Some(Box::new(value)),
            None => self.language_default(register, address),
        }
    }

    fn set_register_value(
        &mut self,
        _start: &Address,
        _end: &Address,
        _value: Box<dyn RegisterValueTrait>,
    ) -> Result<(), ContextChangeException> {
        unsupported()
    }

    /// The register is assumed to be the context register during disassembly.
    fn get_non_default_value(&self, _register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        self.temporary_context_map
            .get_object(address)
            .map(|v| Box::new(v) as Box<dyn RegisterValueTrait>)
    }

    fn set_value(
        &mut self,
        _register: &Register,
        _start: &Address,
        _end: &Address,
        _value: Option<i128>,
    ) -> Result<(), ContextChangeException> {
        unsupported()
    }

    fn get_register_value_address_ranges(&self, _register: &Register) -> Box<dyn AddressRangeIterator> {
        unsupported()
    }

    fn get_register_value_address_ranges_in_range(
        &self,
        _register: &Register,
        _start: &Address,
        _end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        unsupported()
    }

    /// The register is assumed to be the context register during disassembly.
    fn get_register_value_range_containing(&self, _register: &Register, addr: &Address) -> AddressRange {
        self.temporary_context_map.get_address_range_containing(addr)
    }

    fn get_default_register_value_address_ranges(&self, _register: &Register) -> Box<dyn AddressRangeIterator> {
        unsupported()
    }

    fn get_default_register_value_address_ranges_in_range(
        &self,
        _register: &Register,
        _start: &Address,
        _end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        unsupported()
    }

    fn get_context_registers(&self) -> Vec<RegisterRef> {
        self.base.get_context_registers()
    }

    fn remove(&mut self, _start: &Address, _end: &Address, _register: &Register) -> Result<(), ContextChangeException> {
        unsupported()
    }

    fn get_register_names(&self) -> Vec<String> {
        self.base.get_register_names()
    }

    fn has_value_over_range(&self, _reg: &Register, _value: i128, _addr_set: &dyn AddressSetView) -> bool {
        unsupported()
    }

    /// The register is assumed to be the context register during disassembly.
    fn get_default_value(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        self.language_default(register, address)
    }

    fn get_base_context_register(&self) -> RegisterRef {
        self.base.get_base_context_register()
    }

    fn get_default_disassembly_context(&self) -> Box<dyn RegisterValueTrait> {
        self.base.get_default_disassembly_context()
    }

    fn set_default_disassembly_context(&mut self, value: Box<dyn RegisterValueTrait>) {
        self.base.set_default_disassembly_context(value);
    }

    /// Java returns `null` without a context register; the empty value of `NO_CONTEXT` stands in
    /// for it, which every caller treats the same (a value without any bits is no value).
    fn get_disassembly_context(&self, address: &Address) -> Box<dyn RegisterValueTrait> {
        if let Some(value) = self.temporary_context_map.get_object(address) {
            return Box::new(value);
        }
        self.base_context_register
            .as_ref()
            .and_then(|base| self.language_default(base, address))
            .unwrap_or_else(|| Box::new(RegisterValue::new(self.base.get_base_context_register())))
    }
}

/// An immutable context for minting pseudo instructions: the context register value an
/// instruction was decoded under. Cheap to clone, and `Send + Sync`, so the
/// [`PseudoInstruction`]s that own one can be shared.
///
/// Port of the private static nested class `Disassembler.InstructionContext` (renamed: the
/// unrelated `ghidra.program.model.lang.InstructionContext` interface is also in this crate).
#[derive(Clone)]
pub struct DisassemblerInstructionContext {
    language: Arc<SleighLanguage>,
    context_value: Option<RegisterValue>,
}

impl DisassemblerInstructionContext {
    fn new(language: Arc<SleighLanguage>, context_value: Option<RegisterValue>) -> Self {
        DisassemblerInstructionContext { language, context_value }
    }

    /// The context register value, if the language has a context register. Port of
    /// `getContextValue()`.
    pub fn context_value(&self) -> Option<&RegisterValue> {
        self.context_value.as_ref()
    }

    fn context_register_value(&self, register: &Register) -> Option<RegisterValue> {
        match &self.context_value {
            Some(value) if register.is_processor_context() => Some(value.get_register_value(register)),
            _ => None,
        }
    }
}

impl ProcessorContextView for DisassemblerInstructionContext {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        self.context_value.as_ref().map(|v| v.register().get_base_register())
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.language.get_registers()
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.language.get_register_by_name(name)
    }

    /// Java returns the unsigned value whatever `signed` asks.
    fn get_value(&self, register: &Register, _signed: bool) -> Option<i128> {
        self.context_register_value(register)?.unsigned_value().map(|v| v as i128)
    }

    fn get_register_value(&self, register: &Register) -> Option<Box<dyn RegisterValueTrait>> {
        self.context_register_value(register).map(|v| Box::new(v) as Box<dyn RegisterValueTrait>)
    }

    /// Java dereferences `getRegisterValue(register)`, which is `null` for anything but a context
    /// register when there is a context value; that `NullPointerException` is a panic here.
    fn has_value(&self, register: &Register) -> bool {
        self.context_register_value(register)
            .unwrap_or_else(|| {
                panic!("NullPointerException: no context value for register {}", register.name())
            })
            .has_value()
    }
}

impl ProcessorContext for DisassemblerInstructionContext {
    fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> {
        panic!("UnsupportedOperationException: an instruction's context is immutable")
    }

    fn set_register_value(&mut self, _value: Box<dyn RegisterValueTrait>) -> Result<(), ContextChangeException> {
        panic!("UnsupportedOperationException: an instruction's context is immutable")
    }

    fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
        panic!("UnsupportedOperationException: an instruction's context is immutable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::program::model::lang::instruction_error::InstructionErrorType;
    use crate::program::model::mem::ByteMemBufferImpl;
    use crate::program::model::pcode::OpCode;
    use crate::program::model::symbol::RefType;
    use crate::program::util::abstract_stored_program_context::test_support::{
        test_language, test_language_with_context,
    };
    use crate::util::task::DummyMonitor;
    use std::sync::Mutex;

    /// Records every message the disassembler reports.
    #[derive(Default)]
    struct Messages(Mutex<Vec<String>>);

    impl DisassemblerMessageListener for Messages {
        fn disassemble_message_reported(&self, msg: &str) {
            self.0.lock().unwrap().push(msg.to_string());
        }
    }

    struct Fixture {
        language: Arc<SleighLanguage>,
        disassembler: Disassembler,
        messages: Arc<Messages>,
    }

    impl Fixture {
        fn new() -> Self {
            let language = decode_tests::language();
            let messages = Arc::new(Messages::default());
            let factory: Arc<dyn AddressFactory> = SleighLanguage::get_address_factory(&language);
            let disassembler = Disassembler::get_disassembler(
                Arc::clone(&language),
                factory,
                Arc::new(DummyMonitor),
                Some(messages.clone() as Arc<dyn DisassemblerMessageListener>),
            );
            Fixture { language, disassembler, messages }
        }

        fn at(&self, offset: i64) -> Address {
            Address::new(self.language.get_default_space(), offset)
        }

        fn block(&mut self, offset: i64, bytes: &[u8], limit: i32) -> DisassembledBlock {
            let buffer = Box::new(ByteMemBufferImpl::new(self.at(offset), bytes.to_vec(), true));
            self.disassembler.pseudo_disassemble_block(buffer, None, limit).expect("aligned")
        }
    }

    fn offsets(addrs: &[Address]) -> Vec<i64> {
        addrs.iter().map(Address::offset).collect()
    }

    /// ```text
    /// 0x1000: 11 2a   mov r1, 0x2a
    /// 0x1002: 61 00   add r1, r0
    /// 0x1004: 70 04   bz r0, 0x100a
    /// 0x1006: 40 02   jd 0x100a
    /// 0x1008: 10 07     mov r0, 7      (delay slot)
    /// 0x100a: 31 00   ret
    /// ```
    const PROGRAM: [u8; 12] = [0x11, 0x2a, 0x61, 0x00, 0x70, 0x04, 0x40, 0x02, 0x10, 0x07, 0x31, 0x00];

    #[test]
    fn a_block_runs_through_fall_throughs_and_ends_after_a_branch_and_its_delay_slot() {
        let mut f = Fixture::new();
        let block = f.block(0x1000, &PROGRAM, i32::MAX);

        let insns: Vec<&DisassembledInstruction> = block.iter().collect();
        assert_eq!(
            insns.iter().map(|i| (i.get_min_address().offset(), i.to_string())).collect::<Vec<_>>(),
            vec![
                (0x1000, "mov r1,0x2a".to_string()),
                (0x1002, "add r1,r0".to_string()),
                (0x1004, "bz r0,0x100a".to_string()),
                (0x1006, "jd 0x100a".to_string()),
                // a delay-slot instruction's mnemonic is marked, as in Java
                (0x1008, "_mov r0,0x7".to_string()),
            ]
        );
        // The conditional branch falls through; the delayed jump does not, after its slot.
        assert_eq!(insns[2].get_flow_type(), RefType::ConditionalJump);
        assert_eq!(offsets(&insns[2].get_flows().unwrap()), vec![0x100a]);
        assert_eq!(insns[2].get_fall_through().unwrap().offset(), 0x1006);
        assert_eq!(insns[3].get_delay_slot_depth(), 1);
        assert!(!insns[3].has_fallthrough());
        assert!(insns[4].is_in_delay_slot());
        // The jump's p-code weaves in its delay slot, from the jump's own cached bytes.
        let pcode = insns[3].get_pcode();
        assert_eq!(pcode.iter().map(|op| op.get_opcode()).collect::<Vec<_>>(), vec![OpCode::Copy, OpCode::Branch]);
        assert_eq!(pcode[0].get_inputs()[0].get_offset(), 7);

        assert_eq!(block.get_instruction_count(), 5);
        assert_eq!(block.get_last_instruction_address(), Some(f.at(0x1006)), "delay slots excluded");
        assert_eq!(block.get_max_address(), f.at(0x1009));
        assert_eq!(block.to_string(), "[ ram:0x1000-ram:0x1009]");
        // Pseudo disassembly follows no flows and sets no fall-through.
        assert!(block.get_block_flows().is_none());
        assert!(block.get_branch_flows().is_empty());
        assert_eq!(block.get_fall_through(), None);
        assert!(!block.has_instruction_error());
        assert!(!f.disassembler.disassembler_context().is_flow_active());
        assert!(f.messages.0.lock().unwrap().is_empty());

        // No context register: each instruction's context holds no value.
        assert!(insns[0].context().context_value().is_none());
        assert!(ProcessorContextView::get_base_context_register(insns[0].context()).is_none());
    }

    #[test]
    fn the_limit_ends_a_block_with_a_priority_flow_to_its_fall_through() {
        let mut f = Fixture::new();
        let block = f.block(0x1000, &PROGRAM, 2);
        assert_eq!(block.iter().map(|i| i.get_min_address().offset()).collect::<Vec<_>>(), vec![0x1000, 0x1002]);
        let flows = block.get_block_flows().unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].get_type(), InstructionBlockFlowType::Priority);
        assert_eq!(flows[0].get_destination_address(), f.at(0x1004));
        assert_eq!(flows[0].get_flow_from_address(), Some(f.at(0x1002)));
        assert!(block.get_branch_flows().is_empty());
        assert_eq!(block.get_fall_through(), None);

        // A block may start in the middle of a flow: disassembling on from the limit.
        let rest = f.block(0x1004, &PROGRAM[4..], 1);
        assert_eq!(rest.iter().map(|i| i.get_mnemonic_string()).collect::<Vec<_>>(), vec!["bz"]);
        assert_eq!(rest.get_block_flows().unwrap()[0].get_destination_address(), f.at(0x1006));
    }

    #[test]
    fn a_return_ends_the_block() {
        let mut f = Fixture::new();
        let block = f.block(0x100a, &PROGRAM[10..], i32::MAX);
        assert_eq!(block.get_instruction_count(), 1);
        assert_eq!(block.get_instruction_at(&f.at(0x100a)).unwrap().get_mnemonic_string(), "ret");
        assert!(!block.has_instruction_error());
    }

    #[test]
    fn bytes_that_are_no_instruction_end_the_block_with_a_parse_conflict() {
        let mut f = Fixture::new();
        let block = f.block(0x1000, &[0x11, 0x2a, 0x00, 0x00], i32::MAX);
        assert_eq!(block.get_instruction_count(), 1);
        let conflict = block.get_instruction_conflict().unwrap();
        assert_eq!(conflict.get_instruction_error_type(), InstructionErrorType::Parse);
        assert_eq!(conflict.get_instruction_address(), f.at(0x1002));
        assert_eq!(conflict.get_flow_from_address(), Some(f.at(0x1000)));
        assert!(conflict.get_parse_context_value().is_none(), "no context register");
        assert!(!conflict.get_conflict_message().is_empty());

        // Nothing parses at all: an empty block carrying the error.
        let block = f.block(0x2000, &[0x00, 0x00], i32::MAX);
        assert!(block.is_empty());
        let conflict = block.get_instruction_conflict().unwrap();
        assert_eq!(conflict.get_instruction_address(), f.at(0x2000));
        assert_eq!(conflict.get_flow_from_address(), None);
        assert!(!f.disassembler.disassembler_context().is_flow_active(), "an empty block aborts its flow");
    }

    #[test]
    fn a_delay_slotted_instruction_in_a_delay_slot_is_a_parse_conflict() {
        let mut f = Fixture::new();
        // jd 0x1012, whose delay slot holds another jd
        let block = f.block(0x1000, &[0x40, 0x10, 0x40, 0x10], i32::MAX);
        assert!(block.is_empty());
        let conflict = block.get_instruction_conflict().unwrap();
        assert_eq!(conflict.get_instruction_error_type(), InstructionErrorType::Parse);
        assert_eq!(conflict.get_instruction_address(), f.at(0x1000));
        assert_eq!(conflict.get_conflict_message(), "Nested delay slotted instruction not permitted");
    }

    #[test]
    fn a_run_of_repeated_byte_instructions_is_flagged() {
        let mut f = Fixture::new();
        f.disassembler.set_repeat_pattern_limit(2);
        // mov r1, 0x11 four times
        let block = f.block(0x1000, &[0x11; 8], i32::MAX);
        assert_eq!(block.get_instruction_count(), 3, "the offending instruction is still added");
        let conflict = block.get_instruction_conflict().unwrap();
        assert_eq!(conflict.get_instruction_error_type(), InstructionErrorType::Parse);
        assert_eq!(conflict.get_instruction_address(), f.at(0x1004));
        assert_eq!(conflict.get_flow_from_address(), Some(f.at(0x1002)));
        assert_eq!(conflict.get_conflict_message(), "Maximum run of repeated byte instructions exceeded");

        // Disabled (Java's -1), the run is fine.
        f.disassembler.set_repeat_pattern_limit(-1);
        let block = f.block(0x1000, &[0x11; 8], 4);
        assert_eq!(block.get_instruction_count(), 4);
        assert!(!block.has_instruction_error());
    }

    #[test]
    fn a_seed_context_must_share_the_disassemblers_context_register() {
        let mut f = Fixture::new();
        f.disassembler.set_seed_context(Some(DisassemblerContextImpl::new(ProgramContextImpl::new(
            Arc::new(test_language()),
        ))));
        // Seeding a language without context changes nothing about the block.
        let block = f.block(0x1000, &PROGRAM, 1);
        assert_eq!(block.get_instruction_count(), 1);
        f.disassembler.set_seed_context::<ProgramContextImpl>(None);
        f.disassembler.reset_disassembler_context();
        assert!(!f.disassembler.disassembler_context().is_flow_active());
    }

    #[test]
    #[should_panic(expected = "Seed context register does not match disassembler's context register")]
    fn a_seed_context_with_another_context_register_is_rejected() {
        let mut f = Fixture::new();
        f.disassembler.set_seed_context(Some(DisassemblerContextImpl::new(ProgramContextImpl::new(
            Arc::new(test_language_with_context()),
        ))));
    }
}

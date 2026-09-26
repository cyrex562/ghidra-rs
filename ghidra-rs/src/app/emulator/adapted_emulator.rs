//! An implementation of [`Emulator`] that wraps the newer
//! [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator).
//!
//! Port of `ghidra.app.emulator.AdaptedEmulator`, a transitional utility: new use cases based on
//! p-code emulation should use `PcodeEmulator` directly.
//!
//! # Shape
//!
//! Java's class is a web of inner classes, each reaching back into the enclosing emulator:
//! `AdaptedPcodeEmulator extends PcodeEmulator` (its states and threads), `AdaptedPcodeThread
//! extends BytesPcodeThread` (last-executed address, missing-userop breaks, the "is decoding"
//! flag), `AdaptedBytesPcodeExecutorState` (running the memory access filters on every access),
//! `AdaptedBytesPcodeExecutorStatePiece`/`...StateSpace` (the fault handler), `AdaptedStateCallbacks`
//! (the load image) and `AdaptedFilteredMemoryState` (the filter chain's head). Here:
//!
//! * The machine is a [`PcodeEmulator`] over [`AdaptedBytesPcodeExecutorState`] whose threads carry
//!   [`AdaptedThreadHooks`], built by [`AdaptedPcodeEmulatorParts`] (Java's overridden
//!   `createSharedState`/`createLocalState`/`createThread`).
//! * The load image and fault handler are the state spaces' [`BytesSpaceHooks`] ([`AdaptedSpaceHooks`]).
//! * [`AdaptedEmulator`] owns every other part as a field: the break table, the filtered memory
//!   state (whose filter chain it registers filters in), the executing and decoding flags. The
//!   thread's hooks receive the break table at call time: [`execute_instruction`](Emulator::execute_instruction)
//!   lends it to them for the duration of the step and takes it back afterwards. Nothing holds a
//!   pointer back to the emulator.
//! * The two states (memory and registers) both run the filter chain on every access, so they
//!   share it, and the executing flag the chain consults, with the emulator (see
//!   [`FilteredMemoryState::shared_chain`]). Likewise the decoder shares the decoding flag.
//!
//! # Divergences
//!
//! * **Languages.** Java casts `config.getLanguage()` to `SleighLanguage`. Rust's [`Language`] has
//!   no downcast, so the Sleigh language is given alongside the configuration, whose language (one
//!   declaring the program counter) the threads bind to; see
//!   [`ThreadDecoding`](crate::pcode::emu::pcode_emulator::ThreadDecoding).
//! * **Address breakpoints.** Java's `AdaptedBreakTableCallback` (the emulator's break table)
//!   overrides `registerAddressCallback` to inject `__addr_cb(); emu_exec_decoded();` at the
//!   address, and its `AdaptedPcodeUseropLibrary` exports `__addr_cb`, which runs the break table's
//!   address callback and interrupts if the callback halted the emulator. Here the table is
//!   reached for registration through [`AdaptedEmulator::break_table_mut`], a handle
//!   ([`AdaptedBreakTableCallback`]) doing the same. The inject is the *thread's*, where Java's is
//!   the machine's: the emulator has exactly one thread, which consults its own injects first, so
//!   the effect is identical, and the thread's library -- which `__addr_cb` must be in to compile
//!   -- is the one that can reach the thread (see [`AdaptedPcodeUseropLibrary`]). Breakpoints are
//!   handed the thread as their [`BreakContext`]: halting one suspends the thread.
//! * **Exceptions.** Java catches the `RuntimeException` escaping a step into `lastError`. A thread
//!   step here panics with the exception's message (see
//!   [`default_pcode_thread`](crate::pcode::emu::default_pcode_thread)'s module docs), so the
//!   step runs under `catch_unwind` and the message is recorded; an interrupt is recognized by
//!   [`InterruptPcodeExecutionException::MESSAGE`], which every interrupt carries.

use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[allow(deprecated)]
use crate::app::emulator::adapted_memory_state::AdaptedMemoryState;
#[allow(deprecated)]
use crate::app::emulator::emulator::{Emulator, ExecuteInstructionError};
#[allow(deprecated)]
use crate::app::emulator::emulator_configuration::EmulatorConfiguration;
#[allow(deprecated)]
use crate::app::emulator::filtered_memory_state::FilteredMemoryState;
#[allow(deprecated)]
use crate::app::emulator::memory::MemoryLoadImage;
#[allow(deprecated)]
use crate::app::emulator::memory_access_filter::{
    MemoryAccessFilterCallbacks, MemoryAccessFilterChain, MemoryAccessFilterId,
};
use crate::pcode::emu::default_pcode_thread::{ThreadCore, ThreadHooks, ThreadRequest, ThreadRequests};
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
#[allow(deprecated)]
use crate::pcode::emu::modified_pcode_thread::ModifiedThreadHooks;
use crate::pcode::emu::pcode_emulation_callbacks::no_pcode_emulation_callbacks;
use crate::pcode::emu::pcode_emulator::{EmulatorThread, PcodeEmulator, PcodeEmulatorParts, ThreadDecoding};
use crate::pcode::emu::pcode_machine::{PcodeMachine, PcodeMachineThreads, SwiMode};
use crate::pcode::emu::pcode_thread::PcodeThread;
use crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState;
#[allow(deprecated)]
use crate::pcode::emulate::break_table::BreakTable;
#[allow(deprecated)]
use crate::pcode::emulate::break_callback::{BreakCallBack, BreakContext};
#[allow(deprecated)]
use crate::pcode::emulate::break_table_call_back::BreakTableCallBack;
use crate::pcode::emulate::emulate_execution_state::EmulateExecutionState;
use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::exec::bytes_pcode_executor_state::BytesPcodeExecutorState;
use crate::pcode::exec::bytes_pcode_executor_state_piece::BytesPcodeExecutorStatePiece;
use crate::pcode::exec::bytes_pcode_executor_state_space::{BytesPcodeExecutorStateSpace, BytesSpaceHooks};
use crate::pcode::exec::annotated_pcode_userop_library::{
    AnnotatedPcodeUseropDefinition, AnnotatedPcodeUseropLibrary, AnnotatedPcodeUseropLibraryBase, PcodeUserop,
    UseropInputs, UseropValueKind,
};
use crate::pcode::exec::interrupt_pcode_execution_exception::InterruptPcodeExecutionException;
use crate::pcode::exec::pcode_userop_library::{ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap};
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_state_callbacks::{NoPcodeStateCallbacks, NONE};
use crate::pcode::memstate::memory_fault_handler::MemoryFaultHandler;
use crate::pcode::memstate::memory_state::MemoryState;
use crate::pcode::pcoderaw::PcodeOpRaw;
use crate::pcode::seam_stubs::PseudoInstruction as DecodedInstruction;
use crate::pcode::utils::utils::bytes_to_long;
use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::Instruction;
use crate::program::model::mem::MemBuffer;
use crate::program::model::pcode::PcodeOp;
use crate::util::task::TaskMonitor;
use crate::util::Msg;

/// The plain bytes state an [`AdaptedBytesPcodeExecutorState`] wraps.
type InnerBytesState = BytesPcodeExecutorState<BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks>>;

/// The machine's threads.
pub type AdaptedPcodeThread = EmulatorThread<AdaptedBytesPcodeExecutorState, AdaptedThreadHooks>;

/// The machine: Java's `AdaptedEmulator.AdaptedPcodeEmulator`.
pub type AdaptedPcodeEmulator = PcodeEmulator<AdaptedBytesPcodeExecutorState, AdaptedThreadHooks>;

/// What the states share with the emulator to run the memory access filters: the chain its
/// [`FilteredMemoryState`] registers filters in, and whether the emulator is executing. See the
/// module docs.
#[allow(deprecated)]
#[derive(Clone)]
pub struct AdaptedFilters {
    chain: Arc<Mutex<MemoryAccessFilterChain>>,
    executing: Arc<AtomicBool>,
}

#[allow(deprecated)]
impl AdaptedFilters {
    /// Port of `AdaptedFilteredMemoryState.applyRead`: run the filter chain over bytes just read.
    fn apply_read(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, data: &mut [u8]) {
        let executing = self.executing.load(Ordering::SeqCst);
        self.chain.lock().expect("filter chain lock poisoned").filter_read(executing, space, offset, size, data);
    }

    /// Port of `AdaptedFilteredMemoryState.applyWrite`: run the filter chain over bytes about to
    /// be written.
    fn apply_write(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, data: &mut [u8]) {
        let executing = self.executing.load(Ordering::SeqCst);
        self.chain.lock().expect("filter chain lock poisoned").filter_write(executing, space, offset, size, data);
    }
}

/// The load image and fault handler of the emulator's state spaces.
///
/// Ports `AdaptedEmulator.AdaptedStateCallbacks` (as [`read_uninitialized`](BytesSpaceHooks::read_uninitialized))
/// and `AdaptedBytesPcodeExecutorStateSpace` (as [`warn_uninit`](BytesSpaceHooks::warn_uninit)),
/// which `AdaptedBytesPcodeExecutorStatePiece` joins in every space it creates.
#[allow(deprecated)]
pub struct AdaptedSpaceHooks {
    load_image: Option<Arc<dyn MemoryLoadImage>>,
    fault_handler: Arc<dyn MemoryFaultHandler>,
}

/// The contiguous bound of a non-empty set, and a buffer that long.
fn bound_of(set: &AddressSet) -> (Address, usize) {
    let min = set.min_address().expect("a non-empty set has a minimum");
    let max = set.max_address().expect("a non-empty set has a maximum");
    let length = max.subtract(&min) as usize + 1;
    (min, length)
}

/// Copy each range of `set` out of `data` (which starts at `min`) into `space`.
fn put_ranges(space: &BytesPcodeExecutorStateSpace, set: &AddressSet, min: &Address, data: &[u8]) {
    for range in set.address_ranges() {
        let offset = range.min_address().subtract(min) as usize;
        let portion = &data[offset..offset + range.length() as usize];
        space.put_data(range.min_address().offset(), portion);
    }
}

#[allow(deprecated)]
impl BytesSpaceHooks for AdaptedSpaceHooks {
    /// Port of `AdaptedStateCallbacks.readUninitialized`: fill the whole uninitialized bound from
    /// the load image, if there is one.
    ///
    /// # Panics
    ///
    /// On a read of uninitialized `unique` space without a load image (a thread's registers), as
    /// Java throws `AccessPcodeExecutionException`.
    fn read_uninitialized(
        &self,
        space: &BytesPcodeExecutorStateSpace,
        uninitialized: &AddressSet,
        _reason: Reason,
    ) -> AddressSet {
        if uninitialized.is_empty() {
            return uninitialized.clone();
        }
        let Some(load_image) = &self.load_image else {
            if space.get_address_space().space_type() == crate::program::model::address::AddressSpaceType::Unique {
                panic!("Attempted to read from uninitialized unique: {}", uninitialized.print_ranges());
            }
            return uninitialized.clone();
        };
        let (min, length) = bound_of(uninitialized);
        let mut data = vec![0u8; length];
        load_image.load_fill(&mut data, length as i32, &min, 0, false);
        put_ranges(space, uninitialized, &min, &data);
        AddressSet::new()
    }

    /// Port of `AdaptedBytesPcodeExecutorStateSpace.warnUninit`: ask the fault handler for the
    /// uninitialized bytes, and keep them if it supplied them.
    fn warn_uninit(&self, space: &BytesPcodeExecutorStateSpace, uninitialized: &AddressSet) {
        let (min, length) = bound_of(uninitialized);
        let mut data = vec![0u8; length];
        if self.fault_handler.uninitialized_read(&min, length as i32, &mut data, 0) {
            put_ranges(space, uninitialized, &min, &data);
        }
    }
}

/// A bytes state whose every access runs the emulator's memory access filters.
///
/// Port of `AdaptedEmulator.AdaptedBytesPcodeExecutorState extends BytesPcodeExecutorState`: it
/// wraps the plain bytes state (whose spaces carry [`AdaptedSpaceHooks`]) and overrides
/// `getVar`/`setVar`. Reads for [`Reason::Inspect`] are not filtered.
pub struct AdaptedBytesPcodeExecutorState {
    inner: InnerBytesState,
    filters: AdaptedFilters,
}

impl AdaptedBytesPcodeExecutorState {
    /// Port of `AdaptedBytesPcodeExecutorState(Language, MemoryFaultHandler, MemoryLoadImage)`.
    #[allow(deprecated)]
    pub fn new(
        language: Arc<dyn Language>,
        fault_handler: Arc<dyn MemoryFaultHandler>,
        load_image: Option<Arc<dyn MemoryLoadImage>>,
        filters: AdaptedFilters,
    ) -> Self {
        let hooks: Arc<dyn BytesSpaceHooks> = Arc::new(AdaptedSpaceHooks { load_image, fault_handler });
        let piece = BytesPcodeExecutorStatePiece::with_space_hooks(language, Arc::new(NONE), Some(hooks));
        Self { inner: BytesPcodeExecutorState::from_piece(piece), filters }
    }

    fn to_long(&self, offset: &Vec<u8>, purpose: Purpose) -> i64 {
        self.inner.get_arithmetic().to_long(offset, purpose).unwrap_or_else(|e| panic!("{e}"))
    }
}

impl ErasedPcodeExecutorStatePiece for AdaptedBytesPcodeExecutorState {}

impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for AdaptedBytesPcodeExecutorState {
    fn get_language(&self) -> Box<dyn Language> {
        self.inner.get_language()
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        self.inner.get_address_arithmetic()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        self.inner.get_arithmetic()
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        self.inner.stream_pieces()
    }

    /// Port of the overridden `setVar(AddressSpace, byte[], int, boolean, byte[])`.
    fn set_var_abstract(&mut self, space: &Arc<AddressSpace>, offset: &Vec<u8>, size: i32, quantize: bool, val: &Vec<u8>) {
        let mut val = val.clone();
        self.filters.apply_write(space, self.to_long(offset, Purpose::Store), size, &mut val);
        self.inner.set_var_abstract(space, offset, size, quantize, &val);
    }

    fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &Vec<u8>, size: i32, val: &Vec<u8>) {
        self.inner.set_var_internal_abstract(space, offset, size, val);
    }

    /// Port of the overridden `setVar(AddressSpace, long, int, boolean, byte[])`.
    fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &Vec<u8>) {
        let mut val = val.clone();
        self.filters.apply_write(space, offset, size, &mut val);
        self.inner.set_var(space, offset, size, quantize, &val);
    }

    fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &Vec<u8>) {
        self.inner.set_var_internal(space, offset, size, val);
    }

    /// Port of the overridden `getVar(AddressSpace, byte[], int, boolean, Reason)`.
    fn get_var_abstract(&self, space: &Arc<AddressSpace>, offset: &Vec<u8>, size: i32, quantize: bool, reason: Reason) -> Vec<u8> {
        let mut data = self.inner.get_var_abstract(space, offset, size, quantize, reason);
        if reason != Reason::Inspect {
            self.filters.apply_read(space, self.to_long(offset, Purpose::Load), size, &mut data);
        }
        data
    }

    fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &Vec<u8>, size: i32, reason: Reason) -> Vec<u8> {
        self.inner.get_var_internal_abstract(space, offset, size, reason)
    }

    /// Port of the overridden `getVar(AddressSpace, long, int, boolean, Reason)`.
    fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> Vec<u8> {
        let mut data = self.inner.get_var(space, offset, size, quantize, reason);
        if reason != Reason::Inspect {
            self.filters.apply_read(space, offset, size, &mut data);
        }
        data
    }

    fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> Vec<u8> {
        self.inner.get_var_internal(space, offset, size, reason)
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
        self.inner.get_register_values()
    }

    fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        self.inner.get_concrete_buffer(address, purpose)
    }

    fn clear(&mut self) {
        self.inner.clear();
    }

    fn get_next_entry_internal(&self, space: &Arc<AddressSpace>, offset: i64) -> Option<(i64, Vec<u8>)> {
        self.inner.get_next_entry_internal(space, offset)
    }
}

impl PcodeExecutorState<Vec<u8>> for AdaptedBytesPcodeExecutorState {}

/// A decoder raising the emulator's "is decoding" flag while it decodes.
///
/// Port of the anonymous `SleighInstructionDecoder` subclass of
/// `AdaptedPcodeThread.createInstructionDecoder`.
struct AdaptedDecoder {
    inner: Box<dyn InstructionDecoder>,
    is_decoding: Arc<AtomicBool>,
}

impl InstructionDecoder for AdaptedDecoder {
    fn get_language(&self) -> Arc<dyn Language> {
        self.inner.get_language()
    }

    fn decode_instruction(
        &mut self,
        address: &Address,
        context: Option<&RegisterValue>,
    ) -> Result<Box<dyn DecodedInstruction>, Box<dyn std::error::Error>> {
        self.is_decoding.store(true, Ordering::SeqCst);
        let result = self.inner.decode_instruction(address, context);
        self.is_decoding.store(false, Ordering::SeqCst);
        result
    }

    fn branched(&mut self, address: &Address) {
        self.inner.branched(address);
    }

    fn get_last_instruction(&self) -> Option<Arc<dyn Instruction>> {
        self.inner.get_last_instruction()
    }

    fn get_last_length_with_delays(&self) -> i32 {
        self.inner.get_last_length_with_delays()
    }
}

/// The core of the emulator's thread, as its hooks receive it.
type AdaptedThreadCore =
    ThreadCore<Vec<u8>, SharedPcodeExecutorState<AdaptedBytesPcodeExecutorState>, AdaptedBytesPcodeExecutorState>;

/// The name of the userop an address breakpoint's inject calls.
const ADDR_CB: &str = "__addr_cb";

/// The Sleigh injected at an address breakpoint: Java's text block
/// `__addr_cb();\nemu_exec_decoded();\n`.
const ADDR_CB_INJECT: &str = "__addr_cb();\nemu_exec_decoded();\n";

/// Port of `AdaptedEmulator.AdaptedPcodeUseropLibrary`: exports `__addr_cb`, the userop an
/// address breakpoint's inject calls.
///
/// Java's `__addr_cb()` runs `adaptedBreakTable.doAddressBreak(thread.getCounter())` and then
/// throws an `InterruptPcodeExecutionException` if the thread is suspended. It needs the break
/// table and the thread, neither of which a userop callback can reach, so it asks the thread's
/// hooks to run exactly that ([`ThreadRequest::Hooks`]); see
/// [`AdaptedThreadHooks`]' `on_thread_request`.
pub struct AdaptedPcodeUseropLibrary {
    base: AnnotatedPcodeUseropLibraryBase<Vec<u8>>,
    thread: Arc<ThreadRequests>,
}

impl AdaptedPcodeUseropLibrary {
    /// The library of the thread whose requests are `thread`.
    pub fn new(thread: Arc<ThreadRequests>) -> Self {
        let mut library = Self { base: AnnotatedPcodeUseropLibraryBase::new(), thread };
        library.init();
        library
    }
}

impl ErasedPcodeUseropLibrary for AdaptedPcodeUseropLibrary {}

impl PcodeUseropLibrary<Vec<u8>> for AdaptedPcodeUseropLibrary {
    fn get_userops(&self) -> &UseropMap<Vec<u8>> {
        self.base.get_userops()
    }
}

impl AnnotatedPcodeUseropLibrary<Vec<u8>> for AdaptedPcodeUseropLibrary {
    fn base_mut(&mut self) -> &mut AnnotatedPcodeUseropLibraryBase<Vec<u8>> {
        &mut self.base
    }

    fn collect_definitions(&self) -> Vec<AnnotatedPcodeUseropDefinition<Vec<u8>>> {
        let thread = Arc::clone(&self.thread);
        vec![AnnotatedPcodeUseropDefinition::new(
            ADDR_CB,
            PcodeUserop::default(),
            UseropInputs::Fixed(vec![]),
            UseropValueKind::Void,
            Box::new(move |_ctx, _args| {
                thread.post(ThreadRequest::Hooks(ADDR_CB.to_string()));
                None
            }),
        )]
    }
}

/// The thread, as a breakpoint sees the emulator: halting suspends it, as Java's
/// `AdaptedEmulator.setHalt` does.
struct ThreadHalt<'a>(&'a AdaptedThreadCore);

impl BreakContext for ThreadHalt<'_> {
    fn set_halt(&mut self, halt: bool) {
        self.0.set_suspended(halt);
    }

    fn get_halt(&self) -> bool {
        self.0.is_suspended()
    }
}

/// The overrides of `AdaptedEmulator.AdaptedPcodeThread extends BytesPcodeThread`.
///
/// It holds its parent's hooks ([`ModifiedThreadHooks`], `BytesPcodeThread`'s) and calls them
/// where Java calls `super`. The break table is the emulator's, lent to these hooks only while the
/// emulator steps the thread (see the module docs).
#[allow(deprecated)]
pub struct AdaptedThreadHooks {
    inner: ModifiedThreadHooks,
    last_execute_address: Option<Address>,
    break_table: Option<BreakTableCallBack>,
    is_decoding: Arc<AtomicBool>,
}

impl AdaptedThreadHooks {
    /// The address of the last instruction the thread began executing. Port of the
    /// `lastExecuteAddress` field; `None` until an instruction executes.
    pub fn last_execute_address(&self) -> Option<&Address> {
        self.last_execute_address.as_ref()
    }
}

#[allow(deprecated)]
impl ThreadHooks<Vec<u8>, SharedPcodeExecutorState<AdaptedBytesPcodeExecutorState>, AdaptedBytesPcodeExecutorState>
    for AdaptedThreadHooks
{
    /// Port of the overridden `createInstructionDecoder`: wrap the decoder so decoding raises the
    /// emulator's flag.
    fn create_instruction_decoder(&mut self, decoder: Box<dyn InstructionDecoder>) -> Box<dyn InstructionDecoder> {
        let decoder = <ModifiedThreadHooks as ThreadHooks<
            Vec<u8>,
            SharedPcodeExecutorState<AdaptedBytesPcodeExecutorState>,
            AdaptedBytesPcodeExecutorState,
        >>::create_instruction_decoder(&mut self.inner, decoder);
        Box::new(AdaptedDecoder { inner: decoder, is_decoding: Arc::clone(&self.is_decoding) })
    }

    fn create_userop_library(
        &mut self,
        thread: &ThreadCore<Vec<u8>, SharedPcodeExecutorState<AdaptedBytesPcodeExecutorState>, AdaptedBytesPcodeExecutorState>,
        library: Box<dyn PcodeUseropLibrary<Vec<u8>>>,
    ) -> Box<dyn PcodeUseropLibrary<Vec<u8>>> {
        let library = self.inner.create_userop_library(thread, library);
        // Java: `new AdaptedPcodeUseropLibrary().compose(super.createUseropLibrary())`.
        AdaptedPcodeUseropLibrary::new(Arc::clone(thread.thread_requests())).compose(library.as_ref())
    }

    /// Port of `AdaptedPcodeUseropLibrary.__addr_cb()`: run the address breakpoint at the counter,
    /// and interrupt if it halted the emulator.
    fn on_thread_request(&mut self, thread: &mut AdaptedThreadCore, request: &str) -> Result<(), LowlevelError> {
        if request != ADDR_CB {
            return self.inner.on_thread_request(thread, request);
        }
        if let Some(break_table) = &self.break_table {
            break_table.do_address_break(&thread.get_counter(), &mut ThreadHalt(thread));
        }
        if thread.is_suspended() {
            // The emulator must be halted in order to "break." Just halting the thread
            // (suspending) causes a SuspendedPcodeExecutionException, which the emulator treats
            // as an error; the interrupt is what it treats as a breakpoint.
            return Err(LowlevelError::with_message(InterruptPcodeExecutionException::MESSAGE));
        }
        Ok(())
    }

    /// Port of the overridden `preExecuteInstruction()`: record the instruction's address.
    fn pre_execute_instruction(
        &mut self,
        thread: &mut ThreadCore<Vec<u8>, SharedPcodeExecutorState<AdaptedBytesPcodeExecutorState>, AdaptedBytesPcodeExecutorState>,
    ) {
        self.inner.pre_execute_instruction(thread);
        self.last_execute_address = Some(thread.get_counter());
    }

    fn post_execute_instruction(
        &mut self,
        thread: &mut ThreadCore<Vec<u8>, SharedPcodeExecutorState<AdaptedBytesPcodeExecutorState>, AdaptedBytesPcodeExecutorState>,
    ) {
        self.inner.post_execute_instruction(thread);
    }

    /// Port of the overridden `onMissingUseropDef`: failing the parent, offer the op to the break
    /// table's p-code op breakpoints.
    fn on_missing_userop_def(
        &mut self,
        thread: &mut ThreadCore<Vec<u8>, SharedPcodeExecutorState<AdaptedBytesPcodeExecutorState>, AdaptedBytesPcodeExecutorState>,
        op: &PcodeOp,
        op_name: &str,
    ) -> bool {
        if self.inner.on_missing_userop_def(thread, op, op_name) {
            return true;
        }
        let Some(break_table) = &self.break_table else {
            return false;
        };
        break_table.do_pcode_op_break(&PcodeOpRaw::new(op), &mut ThreadHalt(thread))
    }

    fn override_counter(
        &mut self,
        thread: &mut ThreadCore<Vec<u8>, SharedPcodeExecutorState<AdaptedBytesPcodeExecutorState>, AdaptedBytesPcodeExecutorState>,
        counter: &Address,
    ) {
        self.inner.override_counter(thread, counter);
    }
}

/// Java's `AdaptedPcodeEmulator` overrides of `createSharedState`/`createLocalState`/`createThread`.
#[allow(deprecated)]
pub struct AdaptedPcodeEmulatorParts {
    load_image: Option<Arc<dyn MemoryLoadImage>>,
    fault_handler: Arc<dyn MemoryFaultHandler>,
    filters: AdaptedFilters,
    is_decoding: Arc<AtomicBool>,
}

// The load image and fault handler are only ever used from the thread stepping the emulator; the
// machine requires its parts be shareable, as the plain bytes state piece already asserts of the
// language it holds.
#[allow(deprecated)]
unsafe impl Send for AdaptedPcodeEmulatorParts {}
#[allow(deprecated)]
unsafe impl Sync for AdaptedPcodeEmulatorParts {}

#[allow(deprecated)]
impl PcodeEmulatorParts<AdaptedBytesPcodeExecutorState, AdaptedThreadHooks> for AdaptedPcodeEmulatorParts {
    /// `new AdaptedBytesPcodeExecutorState(language, faultHandler, loadImage)`.
    fn create_shared_state(&self, language: Arc<dyn Language>) -> AdaptedBytesPcodeExecutorState {
        AdaptedBytesPcodeExecutorState::new(
            language,
            Arc::clone(&self.fault_handler),
            self.load_image.clone(),
            self.filters.clone(),
        )
    }

    /// `new AdaptedBytesPcodeExecutorState(language, faultHandler, null)`.
    fn create_local_state(&self, language: Arc<dyn Language>) -> AdaptedBytesPcodeExecutorState {
        AdaptedBytesPcodeExecutorState::new(language, Arc::clone(&self.fault_handler), None, self.filters.clone())
    }

    /// `new AdaptedPcodeThread(name, this)`.
    fn create_thread_hooks(&self) -> AdaptedThreadHooks {
        AdaptedThreadHooks {
            inner: ModifiedThreadHooks::new(None),
            last_execute_address: None,
            break_table: None,
            is_decoding: Arc::clone(&self.is_decoding),
        }
    }
}

/// Why the last step failed, as Java's `lastError` records it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LastError {
    /// An `InterruptPcodeExecutionException`: a breakpoint.
    Interrupt,
    /// Any other `RuntimeException`, by its message.
    Fault(String),
}

/// An implementation of [`Emulator`] that wraps the newer `PcodeEmulator`.
///
/// Port of `ghidra.app.emulator.AdaptedEmulator`. Only a single thread is supported. See the
/// module docs for how the Java class's inner classes and back-references are arranged.
#[deprecated(since = "12.1", note = "use PcodeEmulator directly")]
#[allow(deprecated)]
pub struct AdaptedEmulator {
    language: Arc<dyn Language>,
    pc_reg: RegisterRef,
    emu: AdaptedPcodeEmulator,
    adapted_mem_state: AdaptedMemoryState<Vec<u8>>,
    /// Lent to the thread's hooks while stepping; see the module docs.
    break_table: Option<BreakTableCallBack>,
    filtered_mem_state: FilteredMemoryState,
    is_decoding: Arc<AtomicBool>,
    is_executing: Arc<AtomicBool>,
    last_error: Option<LastError>,
}

#[allow(deprecated)]
impl AdaptedEmulator {
    /// Construct the emulator.
    ///
    /// Port of `AdaptedEmulator(EmulatorConfiguration)`. `sleigh` is the Sleigh language Java
    /// casts `config.getLanguage()` to; the threads bind to `config.get_language()`, which must
    /// declare a program counter. See the module docs.
    ///
    /// # Panics
    ///
    /// If write-back is enabled ("write-back is not supported"), as Java throws
    /// `IllegalArgumentException`, or if the language has no program counter.
    pub fn new(config: &dyn EmulatorConfiguration, sleigh: Arc<SleighLanguage>) -> Self {
        let language = config.get_language();
        let filtered_mem_state = FilteredMemoryState::new(Box::new(Arc::clone(&language)));
        let pc_reg = language.get_program_counter().expect("Language has no program counter");
        assert!(!config.is_write_back_enabled(), "write-back is not supported");

        let is_decoding = Arc::new(AtomicBool::new(false));
        let is_executing = Arc::new(AtomicBool::new(false));
        let filters = AdaptedFilters {
            chain: filtered_mem_state.shared_chain(),
            executing: Arc::clone(&is_executing),
        };
        let load_data = config.get_load_data();
        let parts = AdaptedPcodeEmulatorParts {
            load_image: Some(Arc::from(load_data.get_memory_load_image())),
            fault_handler: Arc::from(config.get_memory_fault_handler()),
            filters,
            is_decoding: Arc::clone(&is_decoding),
        };
        let thread_decoding = ThreadDecoding::sleigh::<Vec<u8>>(Arc::clone(&sleigh), Arc::clone(&language));
        let mut emu = PcodeEmulator::with_parts(
            Arc::clone(&sleigh),
            no_pcode_emulation_callbacks(),
            thread_decoding,
            Arc::new(parts),
        );
        let thread = emu.new_thread();
        let state = SharedPcodeExecutorState::from_shared(thread.core().typed_state_handle());
        let adapted_mem_state = AdaptedMemoryState::new(Box::new(state), Reason::Inspect);

        let mut emulator = Self {
            language,
            pc_reg,
            emu,
            adapted_mem_state,
            break_table: Some(BreakTableCallBack::new(sleigh)),
            filtered_mem_state,
            is_decoding,
            is_executing,
            last_error: None,
        };
        emulator.initialize_registers(config);
        emulator
    }

    /// Port of `initializeRegisters(EmulatorConfiguration)`: write each initialized register of
    /// the load data's initial register state into the thread's state.
    fn initialize_registers(&mut self, config: &dyn EmulatorConfiguration) {
        let init_regs = config.get_load_data().get_initial_register_state();
        let mut keys: Vec<String> = init_regs.keys().into_iter().collect();
        keys.sort();
        for key in keys {
            if init_regs.is_initialized(&key) != Some(true) {
                continue;
            }
            let Some(register) = self.language.get_register_by_name(&key) else {
                Msg::warn(
                    "AdaptedEmulator",
                    &format!("No such register '{key}' in language {}", self.language.get_language_id()),
                );
                continue;
            };
            // Yes, allow memory-mapped registers to be initialized in this manner.
            let Some(val) = init_regs.vals(&key) else { continue };
            self.thread().get_state().set_var_register(&register, &val);
        }
    }

    /// The emulator's one thread.
    pub fn thread(&self) -> &AdaptedPcodeThread {
        self.emu.get_all_threads().into_iter().next().expect("the emulator has its thread")
    }

    fn thread_mut(&mut self) -> &mut AdaptedPcodeThread {
        let name = self.thread().get_name().to_string();
        self.emu.get_thread(&name, false).expect("the emulator has its thread")
    }

    /// The wrapped p-code emulator.
    pub fn pcode_emulator(&mut self) -> &mut AdaptedPcodeEmulator {
        &mut self.emu
    }

    /// The break table, for registering breakpoints: Java's `AdaptedBreakTableCallback`, which it
    /// hands out through `getBreakTable()`. See [`AdaptedBreakTableCallback`].
    pub fn break_table_mut(&mut self) -> AdaptedBreakTableCallback<'_> {
        AdaptedBreakTableCallback { emulator: self }
    }

    fn table_mut(&mut self) -> &mut BreakTableCallBack {
        self.break_table.as_mut().expect("the break table is only lent out while stepping")
    }

    /// Step (or finish) one instruction, recording anything that escapes as `lastError`.
    fn step(&mut self) {
        let break_table = self.break_table.take();
        self.thread_mut().hooks_mut().break_table = break_table;
        let thread = self.thread_mut();
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            if thread.get_frame().is_some() {
                thread.finish_instruction();
            } else {
                thread.step_instruction();
            }
        }));
        // Taking the message now, rather than carrying the payload around, keeps it intact.
        let error = result.err().map(|payload| panic_message(payload.as_ref()));
        self.break_table = self.thread_mut().hooks_mut().break_table.take();
        self.last_error = error.map(|message| {
            if message == InterruptPcodeExecutionException::MESSAGE {
                LastError::Interrupt
            } else {
                LastError::Fault(message)
            }
        });
    }
}

/// The emulator's break table, for registering breakpoints.
///
/// Port of `AdaptedEmulator.AdaptedBreakTableCallback extends BreakTableCallBack`: registering an
/// address breakpoint also injects `__addr_cb(); emu_exec_decoded();` at the address, and
/// unregistering one clears the inject. Java's subclass reaches the emulator through its enclosing
/// instance; this handle borrows it.
#[allow(deprecated)]
pub struct AdaptedBreakTableCallback<'a> {
    emulator: &'a mut AdaptedEmulator,
}

#[allow(deprecated)]
impl AdaptedBreakTableCallback<'_> {
    /// The table itself.
    pub fn table(&self) -> &BreakTableCallBack {
        self.emulator.get_break_table()
    }

    /// See [`BreakTableCallBack::register_pcode_callback`].
    ///
    /// # Errors
    /// If `name` is neither [`BreakTableCallBack::DEFAULT_NAME`] nor a userop of the language.
    pub fn register_pcode_callback(&mut self, name: &str, func: BreakCallBack) -> Result<(), LowlevelError> {
        self.emulator.table_mut().register_pcode_callback(name, func)
    }

    /// See [`BreakTableCallBack::unregister_pcode_callback`].
    ///
    /// # Errors
    /// If `name` is neither [`BreakTableCallBack::DEFAULT_NAME`] nor a userop of the language.
    pub fn unregister_pcode_callback(&mut self, name: &str) -> Result<(), LowlevelError> {
        self.emulator.table_mut().unregister_pcode_callback(name)
    }

    /// Port of the overridden `registerAddressCallback(Address, BreakCallBack)`: register the
    /// breakpoint, and inject its invocation ahead of the instruction at `addr`.
    pub fn register_address_callback(&mut self, addr: Address, func: BreakCallBack) {
        self.emulator.table_mut().register_address_callback(addr.clone(), func);
        self.emulator.thread_mut().inject(&addr, ADDR_CB_INJECT);
    }

    /// Port of the overridden `unregisterAddressCallback(Address)`.
    pub fn unregister_address_callback(&mut self, addr: &Address) {
        self.emulator.thread_mut().clear_inject(addr);
        self.emulator.table_mut().unregister_address_callback(addr);
    }
}

/// The message of a caught panic.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown error".to_string()
    }
}

#[allow(deprecated)]
impl Emulator for AdaptedEmulator {
    fn get_pc_register_name(&self) -> String {
        self.pc_reg.name().to_string()
    }

    /// Port of `setExecuteAddress(long)`: override the thread's counter.
    fn set_execute_address(&mut self, addressable_word_offset: i64) {
        let space = self.language.get_default_space();
        let address = space
            .address_from_word_offset(space.truncate_addressable_word_offset(addressable_word_offset))
            .unwrap_or_else(|e| panic!("{e:?}"));
        self.thread_mut().override_counter(&address);
    }

    fn get_execute_address(&self) -> Address {
        self.thread().get_counter()
    }

    fn get_last_execute_address(&self) -> Option<Address> {
        self.thread().hooks().last_execute_address().cloned()
    }

    fn get_pc(&self) -> i64 {
        let value = self.thread().get_state().get_var_register(&self.pc_reg, Reason::Inspect);
        bytes_to_long(&value, self.pc_reg.num_bytes() as usize, self.language.is_big_endian())
    }

    /// Port of `executeInstruction(boolean, TaskMonitor)`.
    ///
    /// # Errors
    ///
    /// The last step's failure, if it was not a breakpoint: Java rethrows `lastError`. It carries
    /// the failure's message as a [`LowlevelError`].
    fn execute_instruction(
        &mut self,
        stop_at_breakpoint: bool,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), ExecuteInstructionError> {
        if let Some(LastError::Fault(message)) = &self.last_error {
            return Err(LowlevelError::with_message(message.clone()).into());
        }
        self.emu.set_software_interrupt_mode(if stop_at_breakpoint { SwiMode::Active } else { SwiMode::IgnoreAll });
        self.is_executing.store(true, Ordering::SeqCst);
        self.step();
        self.emu.set_software_interrupt_mode(SwiMode::Active);
        self.is_executing.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_executing(&self) -> bool {
        self.is_executing.load(Ordering::SeqCst)
    }

    /// Port of `getEmulateExecutionState()`.
    fn get_emulate_execution_state(&self) -> EmulateExecutionState {
        match &self.last_error {
            Some(LastError::Interrupt) => EmulateExecutionState::Breakpoint,
            Some(LastError::Fault(_)) => EmulateExecutionState::Fault,
            None if self.is_decoding.load(Ordering::SeqCst) => EmulateExecutionState::InstructionDecode,
            None if self.is_executing() => EmulateExecutionState::Execute,
            None => EmulateExecutionState::Stopped,
        }
    }

    fn get_mem_state(&mut self) -> &mut dyn MemoryState {
        &mut self.adapted_mem_state
    }

    /// Port of `addMemoryAccessFilter(MemoryAccessFilter)`: `filter.addFilter(this)`, making it the
    /// head of the chain every state access runs.
    fn add_memory_access_filter(&mut self, filter: Box<dyn MemoryAccessFilterCallbacks>) -> MemoryAccessFilterId {
        self.filtered_mem_state.add_filter(filter)
    }

    fn get_filtered_mem_state(&mut self) -> &mut FilteredMemoryState {
        &mut self.filtered_mem_state
    }

    fn set_context_register_value(&mut self, reg_value: &RegisterValue) {
        self.thread_mut().override_context(reg_value);
    }

    /// Port of `getContextRegisterValue()`: the thread's context, `None` (Java's `null`) for a
    /// language without a context register.
    fn get_context_register_value(&self) -> Option<RegisterValue> {
        self.thread().get_context().cloned()
    }

    fn get_break_table(&self) -> &BreakTableCallBack {
        self.break_table.as_ref().expect("the break table is only lent out while stepping")
    }

    fn is_at_breakpoint(&self) -> bool {
        self.last_error == Some(LastError::Interrupt)
    }

    fn set_halt(&mut self, halt: bool) {
        self.thread_mut().set_suspended(halt);
    }

    fn get_halt(&self) -> bool {
        self.thread().is_suspended()
    }

    fn dispose(&mut self) {}
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use crate::app::emulator::memory::EmulatorLoadData;
    use crate::app::emulator::state::RegisterState;
    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::pcode::emu::test_support::PcLanguage;
    use crate::pcode::load_image::LoadImage;
    use crate::program::model::address::AddressFactory;
    use crate::program::model::lang::register::Register;
    use crate::util::task::DummyMonitor;

    /// A load image over a map of bytes; everything else reads as zero.
    #[derive(Clone, Default)]
    struct MapImage(HashMap<i64, u8>);

    impl LoadImage for MapImage {
        fn load_fill(&self, buf: &mut [u8], size: i32, addr: &Address, buf_offset: i32, _mask: bool) -> Option<Vec<u8>> {
            for i in 0..size as usize {
                buf[buf_offset as usize + i] = *self.0.get(&(addr.offset() + i as i64)).unwrap_or(&0);
            }
            None
        }
    }

    impl MemoryLoadImage for MapImage {
        fn write_back(&mut self, _bytes: &[u8], _size: i32, _addr: &Address, _offset: i32) {}
        fn dispose(&mut self) {}
    }

    #[derive(Clone, Default)]
    struct Regs(HashMap<String, (Vec<u8>, bool)>);

    impl RegisterState for Regs {
        fn keys(&self) -> HashSet<String> {
            self.0.keys().cloned().collect()
        }
        fn vals(&self, key: &str) -> Option<Vec<u8>> {
            self.0.get(key).map(|(v, _)| v.clone())
        }
        fn is_initialized(&self, key: &str) -> Option<bool> {
            self.0.get(key).map(|(_, i)| *i)
        }
        fn set_vals(&mut self, key: &str, vals: &[u8], set_initialized: bool) {
            self.0.insert(key.to_string(), (vals.to_vec(), set_initialized));
        }
        fn set_vals_long(&mut self, key: &str, val: i64, size: usize, set_initialized: bool) {
            let bytes = val.to_be_bytes()[8 - size..].to_vec();
            self.set_vals(key, &bytes, set_initialized);
        }
        fn dispose(&mut self) {}
    }

    struct LoadData {
        image: MapImage,
        regs: Regs,
    }

    impl EmulatorLoadData for LoadData {
        fn get_memory_load_image(&self) -> Box<dyn MemoryLoadImage> {
            Box::new(self.image.clone())
        }
        fn get_initial_register_state(&self) -> Box<dyn RegisterState> {
            Box::new(self.regs.clone())
        }
    }

    /// Records each uninitialized read, answering with `supply` for the whole range if set.
    #[derive(Clone)]
    struct FaultHandler {
        log: Arc<Mutex<Vec<(String, i64, i32)>>>,
        supply: Option<u8>,
    }

    impl MemoryFaultHandler for FaultHandler {
        fn uninitialized_read(&self, address: &Address, size: i32, buf: &mut [u8], buf_offset: i32) -> bool {
            self.log.lock().unwrap().push((address.space().name().to_string(), address.offset(), size));
            let Some(value) = self.supply else { return false };
            for b in &mut buf[buf_offset as usize..(buf_offset + size) as usize] {
                *b = 0;
            }
            buf[(buf_offset + size - 1) as usize] = value;
            true
        }
        fn unknown_address(&self, _address: &Address, _write: bool) -> bool {
            false
        }
    }

    struct Config {
        language: Arc<dyn Language>,
        image: MapImage,
        regs: Regs,
        faults: FaultHandler,
        write_back: bool,
    }

    impl EmulatorConfiguration for Config {
        fn get_language(&self) -> Arc<dyn Language> {
            Arc::clone(&self.language)
        }
        fn get_load_data(&self) -> Box<dyn EmulatorLoadData> {
            Box::new(LoadData { image: self.image.clone(), regs: self.regs.clone() })
        }
        fn get_memory_fault_handler(&self) -> Box<dyn MemoryFaultHandler> {
            Box::new(self.faults.clone())
        }
        fn is_write_back_enabled(&self) -> bool {
            self.write_back
        }
    }

    /// The Sleigh fixture's language as the threads bind to it: with a 4-byte `pc` at
    /// `register:0x100`, as a `.pspec` would declare.
    fn config(sleigh: &Arc<SleighLanguage>) -> Config {
        let register = sleigh.get_address_factory().get_address_space_by_name("register").unwrap();
        let pc = Register::new("pc", "program counter", register.address(0x100), 4, false, Register::TYPE_PC);
        Config {
            language: Arc::new(PcLanguage { inner: Arc::clone(sleigh) as Arc<dyn Language>, pc }),
            image: MapImage::default(),
            regs: Regs::default(),
            faults: FaultHandler { log: Arc::new(Mutex::new(Vec::new())), supply: None },
            write_back: false,
        }
    }

    fn ram(emu: &AdaptedEmulator) -> Arc<AddressSpace> {
        emu.language.get_default_space()
    }

    fn register_space(emu: &AdaptedEmulator) -> Arc<AddressSpace> {
        emu.language.get_address_factory().get_address_space_by_name("register").unwrap()
    }

    /// Write code through the emulator's memory state, as a client of the old API does.
    fn write(emu: &mut AdaptedEmulator, offset: i64, bytes: &[u8]) {
        let space = ram(emu);
        emu.get_mem_state().set_chunk(bytes, &space, offset, bytes.len() as i32).unwrap();
    }

    fn reg(emu: &AdaptedEmulator, offset: i64) -> Vec<u8> {
        let space = register_space(emu);
        emu.thread().get_state().get_var(&space, offset, 4, false, Reason::Inspect)
    }

    fn step(emu: &mut AdaptedEmulator) {
        emu.execute_instruction(true, &DummyMonitor).expect("no earlier fault");
    }

    #[test]
    fn steps_sleigh_instructions_tracking_counter_and_last_address() {
        let sleigh = decode_tests::language();
        let mut emu = AdaptedEmulator::new(&config(&sleigh), sleigh);
        // 0x1000: mov r1, 0x2a ; jmp 0x1009   0x1009: mov r0, 7
        write(&mut emu, 0x1000, &[0x11, 0x2a, 0x20, 0x05]);
        write(&mut emu, 0x1009, &[0x10, 0x07]);
        emu.set_execute_address(0x1000);
        assert_eq!(0x1000, emu.get_pc());
        assert_eq!(None, emu.get_last_execute_address());
        assert_eq!(EmulateExecutionState::Stopped, emu.get_emulate_execution_state());
        assert_eq!("pc", emu.get_pc_register_name());

        step(&mut emu);
        assert_eq!(vec![0, 0, 0, 0x2a], reg(&emu, 4));
        assert_eq!(0x1002, emu.get_execute_address().offset());
        assert_eq!(0x1000, emu.get_last_execute_address().unwrap().offset());

        step(&mut emu);
        assert_eq!(0x1009, emu.get_pc());
        assert_eq!(0x1002, emu.get_last_execute_address().unwrap().offset());

        step(&mut emu);
        assert_eq!(vec![0, 0, 0, 7], reg(&emu, 0));
        assert_eq!(0x100b, emu.get_execute_address().offset());
        assert!(!emu.is_executing());
        assert!(!emu.is_at_breakpoint());
        assert_eq!(EmulateExecutionState::Stopped, emu.get_emulate_execution_state());
        // The language has no context register: Java's getContextRegisterValue() is null.
        assert_eq!(None, emu.get_context_register_value());
    }

    #[test]
    fn initial_registers_and_the_load_image_feed_a_load() {
        let sleigh = decode_tests::language();
        let mut config = config(&sleigh);
        config.regs.set_vals("r1", &[0, 0, 0, 0x40], true);
        config.regs.set_vals("r0", &[0, 0, 0, 0x99], false); // not initialized: skipped
        config.regs.set_vals("nosuch", &[1], true); // no such register: warned and skipped
        config.image.0.extend([(0x40, 0xde), (0x41, 0xad), (0x42, 0xbe), (0x43, 0xef)]);
        let mut emu = AdaptedEmulator::new(&config, sleigh);
        assert_eq!(vec![0, 0, 0, 0x40], reg(&emu, 4));
        // 0x1000: ld r0, [r1]
        write(&mut emu, 0x1000, &[0x50, 0x01]);
        emu.set_execute_address(0x1000);
        step(&mut emu);
        assert_eq!(vec![0xde, 0xad, 0xbe, 0xef], reg(&emu, 0));
        assert!(config.faults.log.lock().unwrap().is_empty());
    }

    /// Records every filtered access, and adds one to the first byte of every read of RAM.
    struct RecordingFilter(Arc<Mutex<Vec<(&'static str, String, i64, i32)>>>);

    impl MemoryAccessFilterCallbacks for RecordingFilter {
        fn process_read(&mut self, spc: &Arc<AddressSpace>, off: i64, size: i32, values: &mut [u8]) {
            self.0.lock().unwrap().push(("read", spc.name().to_string(), off, size));
            if spc.name() == "ram" {
                values[0] = values[0].wrapping_add(1);
            }
        }
        fn process_write(&mut self, spc: &Arc<AddressSpace>, off: i64, size: i32, _values: &mut [u8]) {
            self.0.lock().unwrap().push(("write", spc.name().to_string(), off, size));
        }
    }

    #[test]
    fn memory_access_filters_see_and_may_change_executed_accesses() {
        let sleigh = decode_tests::language();
        let mut config = config(&sleigh);
        config.image.0.extend([(0x40, 0x10), (0x41, 0x20), (0x42, 0x30), (0x43, 0x40)]);
        let mut emu = AdaptedEmulator::new(&config, sleigh);
        // 0x1000: mov r1, 0x40 ; ld r0, [r1]
        write(&mut emu, 0x1000, &[0x11, 0x40, 0x50, 0x01]);
        emu.set_execute_address(0x1000);
        let log = Arc::new(Mutex::new(Vec::new()));
        emu.add_memory_access_filter(Box::new(RecordingFilter(Arc::clone(&log))));

        // Not executing: an execution-only filter sees nothing (the write of the counter).
        emu.set_execute_address(0x1000);
        assert!(log.lock().unwrap().is_empty());

        step(&mut emu);
        step(&mut emu);
        let log = log.lock().unwrap().clone();
        assert!(log.contains(&("write", "register".to_string(), 4, 4)), "{log:?}");
        assert!(log.contains(&("read", "register".to_string(), 4, 4)), "{log:?}");
        assert!(log.contains(&("read", "ram".to_string(), 0x40, 4)), "{log:?}");
        assert!(log.contains(&("write", "register".to_string(), 0, 4)), "{log:?}");
        // The filter's change to the read bytes is what the load delivered.
        assert_eq!(vec![0x11, 0x20, 0x30, 0x40], reg(&emu, 0));
    }

    #[test]
    fn uninitialized_register_read_asks_the_fault_handler() {
        let sleigh = decode_tests::language();
        let mut config = config(&sleigh);
        config.faults.supply = Some(3);
        let mut emu = AdaptedEmulator::new(&config, sleigh);
        // 0x1000: mov r0, 7 ; add r0, r1   (r1 never written)
        write(&mut emu, 0x1000, &[0x10, 0x07, 0x60, 0x01]);
        emu.set_execute_address(0x1000);
        step(&mut emu);
        assert!(config.faults.log.lock().unwrap().is_empty());
        step(&mut emu);
        assert_eq!(vec![("register".to_string(), 4, 4)], *config.faults.log.lock().unwrap());
        // The handler's bytes were kept: r0 = 7 + 3.
        assert_eq!(vec![0, 0, 0, 10], reg(&emu, 0));
        assert_eq!(vec![0, 0, 0, 3], reg(&emu, 4));
    }

    #[test]
    fn halting_stops_execution_as_a_fault_which_is_rethrown() {
        let sleigh = decode_tests::language();
        let mut emu = AdaptedEmulator::new(&config(&sleigh), sleigh);
        write(&mut emu, 0x1000, &[0x10, 0x07]);
        emu.set_execute_address(0x1000);
        emu.set_halt(true);
        assert!(emu.get_halt());
        // Java: the suspended thread throws SuspendedPcodeExecutionException, recorded as
        // lastError; it is not an interrupt, so the state is FAULT.
        emu.execute_instruction(true, &DummyMonitor).unwrap();
        assert_eq!(EmulateExecutionState::Fault, emu.get_emulate_execution_state());
        assert!(!emu.is_at_breakpoint());
        assert_eq!(vec![0, 0, 0, 0], reg(&emu, 0));
        assert_eq!(0x1000, emu.get_pc());
        // And every later attempt rethrows it.
        emu.set_halt(false);
        assert!(matches!(
            emu.execute_instruction(true, &DummyMonitor),
            Err(ExecuteInstructionError::Lowlevel(_))
        ));
    }

    #[test]
    fn undecodable_bytes_fault() {
        let sleigh = decode_tests::language();
        let mut emu = AdaptedEmulator::new(&config(&sleigh), sleigh);
        write(&mut emu, 0x1000, &[0x00, 0x00]);
        emu.set_execute_address(0x1000);
        emu.execute_instruction(false, &DummyMonitor).unwrap();
        assert_eq!(EmulateExecutionState::Fault, emu.get_emulate_execution_state());
    }

    #[test]
    #[should_panic(expected = "write-back is not supported")]
    fn write_back_is_rejected() {
        let sleigh = decode_tests::language();
        let mut config = config(&sleigh);
        config.write_back = true;
        AdaptedEmulator::new(&config, sleigh);
    }

    /// `setm` commits `TMode=1` (a non-flowing context bit) at its target, here the next
    /// instruction; the context then holds it for exactly that instruction.
    #[test]
    fn context_register_flows_across_a_globalset() {
        let sleigh = decode_tests::context_language();
        let mut emu = AdaptedEmulator::new(&config(&sleigh), sleigh);
        // 0x1000: setm 0x1002 ; 0x1002: mov r0, 7 ; 0x1004: mov r1, 8
        write(&mut emu, 0x1000, &[0x80, 0x00, 0x10, 0x07, 0x11, 0x08]);
        emu.set_execute_address(0x1000);
        let tmode = |emu: &AdaptedEmulator| {
            emu.get_context_register_value().expect("the language has a context register").unsigned_value_ignore_mask()
        };
        assert_eq!(0, tmode(&emu));

        step(&mut emu);
        assert_eq!(0x1002, emu.get_pc());
        assert_eq!(0x8000_0000, tmode(&emu));
        // The context is written to the thread's contextreg.
        assert_eq!(vec![0x80, 0, 0, 0], reg(&emu, 0x40));

        step(&mut emu);
        assert_eq!(vec![0, 0, 0, 7], reg(&emu, 0));
        // TMode does not flow past the instruction it was committed to.
        assert_eq!(0, tmode(&emu));
        assert_eq!(vec![0, 0, 0, 0], reg(&emu, 0x40));

        // Setting the context by hand, as a client establishing the initial context does.
        let contextreg = emu.language.get_context_base_register().unwrap();
        emu.set_context_register_value(&RegisterValue::with_value(contextreg, 0x8000_0000));
        assert_eq!(0x8000_0000, tmode(&emu));
        step(&mut emu);
        assert_eq!(vec![0, 0, 0, 8], reg(&emu, 4));
        assert_eq!(0, tmode(&emu));
    }

    /// ```text
    /// 0x1000: mov r1, 0x2a ; 0x1002: mov r0, 7 ; 0x1004: mov r1, 8
    /// ```
    fn breakpoint_program(emu: &mut AdaptedEmulator) {
        write(emu, 0x1000, &[0x11, 0x2a, 0x10, 0x07, 0x11, 0x08]);
        emu.set_execute_address(0x1000);
    }

    /// `EmulatorHelper`'s address breakpoint: halt the emulator, replacing the instruction.
    fn halting_breakpoint() -> BreakCallBack {
        BreakCallBack::new().with_address_callback(|_addr, emu| {
            emu.set_halt(true);
            true
        })
    }

    #[test]
    fn an_address_breakpoint_halts_before_its_instruction_and_resumes_into_it() {
        let sleigh = decode_tests::language();
        let mut emu = AdaptedEmulator::new(&config(&sleigh), sleigh);
        breakpoint_program(&mut emu);
        let at = ram(&emu).address(0x1002);
        emu.break_table_mut().register_address_callback(at.clone(), halting_breakpoint());

        step(&mut emu);
        assert_eq!(0x1002, emu.get_pc());
        assert!(!emu.is_at_breakpoint());

        // Stepping onto the breakpoint runs __addr_cb, which halts: a BREAKPOINT, not a fault, with
        // the instruction not yet executed and the PC at the break address.
        step(&mut emu);
        assert_eq!(EmulateExecutionState::Breakpoint, emu.get_emulate_execution_state());
        assert!(emu.is_at_breakpoint());
        assert!(emu.get_halt());
        assert_eq!(0x1002, emu.get_pc());
        assert_eq!(at, emu.get_execute_address());
        assert_eq!(vec![0, 0, 0, 0], reg(&emu, 0));

        // A client un-halts to continue (EmulatorHelper.run does); the step finishes the inject,
        // whose emu_exec_decoded() executes the instruction.
        emu.set_halt(false);
        step(&mut emu);
        assert_eq!(EmulateExecutionState::Stopped, emu.get_emulate_execution_state());
        assert!(!emu.is_at_breakpoint());
        assert_eq!(vec![0, 0, 0, 7], reg(&emu, 0));
        assert_eq!(0x1004, emu.get_pc());
        assert_eq!(0x1002, emu.get_last_execute_address().unwrap().offset());

        step(&mut emu);
        assert_eq!(vec![0, 0, 0, 8], reg(&emu, 4));
        assert_eq!(0x1006, emu.get_pc());
    }

    #[test]
    fn staying_halted_after_a_breakpoint_faults_the_next_step() {
        let sleigh = decode_tests::language();
        let mut emu = AdaptedEmulator::new(&config(&sleigh), sleigh);
        breakpoint_program(&mut emu);
        let at = ram(&emu).address(0x1000);
        emu.break_table_mut().register_address_callback(at, halting_breakpoint());
        step(&mut emu);
        assert!(emu.is_at_breakpoint());
        // Java: the thread is still suspended, so finishing the inject throws
        // SuspendedPcodeExecutionException, which is not an interrupt.
        step(&mut emu);
        assert_eq!(EmulateExecutionState::Fault, emu.get_emulate_execution_state());
        assert_eq!(vec![0, 0, 0, 0], reg(&emu, 4));
    }

    #[test]
    fn a_breakpoint_that_does_not_halt_lets_the_instruction_execute() {
        use std::sync::atomic::AtomicUsize;

        let sleigh = decode_tests::language();
        let mut emu = AdaptedEmulator::new(&config(&sleigh), sleigh);
        breakpoint_program(&mut emu);
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&hits);
        let at = ram(&emu).address(0x1000);
        emu.break_table_mut().register_address_callback(
            at.clone(),
            BreakCallBack::new().with_address_callback(move |addr, _emu| {
                assert_eq!(0x1000, addr.offset());
                seen.fetch_add(1, Ordering::SeqCst);
                false
            }),
        );
        step(&mut emu);
        assert_eq!(1, hits.load(Ordering::SeqCst));
        assert!(!emu.is_at_breakpoint());
        assert_eq!(vec![0, 0, 0, 0x2a], reg(&emu, 4));
        assert_eq!(0x1002, emu.get_pc());
    }

    #[test]
    fn an_unregistered_breakpoint_neither_calls_back_nor_injects() {
        let sleigh = decode_tests::language();
        let mut emu = AdaptedEmulator::new(&config(&sleigh), sleigh);
        breakpoint_program(&mut emu);
        let at = ram(&emu).address(0x1000);
        let mut table = emu.break_table_mut();
        table.register_address_callback(at.clone(), halting_breakpoint());
        table.unregister_address_callback(&at);
        assert!(!table.table().do_address_break(&at, &mut crate::pcode::emulate::HaltFlag::default()));
        assert!(emu.thread().get_inject(&at).is_none());
        step(&mut emu);
        assert!(!emu.is_at_breakpoint());
        assert_eq!(vec![0, 0, 0, 0x2a], reg(&emu, 4));
    }
}

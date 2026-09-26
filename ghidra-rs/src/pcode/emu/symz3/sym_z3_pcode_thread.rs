//! Port of `ghidra.pcode.emu.symz3.SymZ3PcodeThread`.
//!
//! # Shape
//!
//! Java's `SymZ3PcodeThread extends AuxPcodeThread<SymValueZ3> implements
//! InternalSymZ3RecordsPreconditions`. Following the emulator's thread convention (see
//! [`default_pcode_thread`](crate::pcode::emu::default_pcode_thread)'s module docs), its overrides
//! are [`SymZ3ThreadHooks`], which hold the [`AuxThreadHooks`] of its superclass, and the thread
//! is [`SymZ3PcodeThread`] = [`DefaultPcodeThread`] over those hooks, with the state delegates the
//! [`SymZ3PartsFactory`] makes: the emulator's paired memory behind its
//! [`SharedPcodeExecutorState`] handle, and the thread's own paired registers.
//!
//! * `createInstructionDecoder` wraps the base decoder in one that records each decoded
//!   instruction against the emulator's shared symbolic state (Java's anonymous
//!   `SleighInstructionDecoder` subclass).
//! * `createThreadState`/`getState()` narrow the thread's state to `SymZ3ThreadPcodeExecutorState`.
//!   The Rust thread state is already typed by its delegates, so that narrowing needs no type of
//!   its own.
//! * The state-touching members (`getSharedSymbolicState` and friends, `addInstruction`/`addOp`,
//!   `addPrecondition`/`getPreconditions`) are inherent methods on [`SymZ3PcodeThread`]. Java hands
//!   out the pieces themselves; the Rust thread's state sits behind locks, so the getters run a
//!   closure against the piece instead (see
//!   [`SharedPcodeExecutorState::with_symbolic`](crate::pcode::emu::symz3::sym_z3_paired_pcode_executor_state)).
//!
//! # Identity in records
//!
//! Java's `RecInstruction`/`RecOp` hold the thread object and read only its name. A Rust thread is
//! owned by its emulator, under that name (see
//! [`ThreadList`](crate::pcode::emu::abstract_pcode_machine::ThreadList)), so records hold a
//! [`SymZ3ThreadId`]: the thread's name, which is its key in the emulator.
//!
//! # Not ported
//!
//! The register/memory comparison debug tools (`printRegisterComparison`/`registerComparison`/
//! `printMemoryComparisonRegPlusOffset`/`memoryComparisonRegPlusOffset`) additionally need Z3
//! simplification, which the [`Z3Context`](crate::feature::seam_stubs::Z3Context) seam does not
//! expose; a caller can compose them from [`SymZ3PcodeThread::with_local_concrete_state`] and
//! [`SymZ3PcodeThread::with_local_symbolic_state`].

use std::sync::Arc;

use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::auxiliary::aux_pcode_thread::{AuxThreadHooks, AuxThreadParts};
use crate::pcode::emu::default_pcode_thread::{
    DefaultPcodeThread, PcodeThreadExecutor, ThreadCore, ThreadHooks,
};
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
use crate::pcode::emu::symz3::internal_sym_z3_records_execution::InternalSymZ3RecordsExecution;
use crate::pcode::emu::symz3::internal_sym_z3_records_preconditions::InternalSymZ3RecordsPreconditions;
use crate::pcode::emu::symz3::state::sym_z3_pcode_executor_state::SymZ3PcodeExecutorState;
use crate::pcode::emu::symz3::sym_z3_paired_pcode_executor_state::SymZ3PairedPcodeExecutorState;
use crate::pcode::emu::symz3::sym_z3_parts_factory::SymZ3PartsFactory;
use crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::SymZ3PcodeExecutorStatePiece;
use crate::pcode::emu::symz3::sym_z3_records_preconditions::SymZ3RecordsPreconditions;
use crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece;
use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::pcode::seam_stubs::PseudoInstruction;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::address::Address;
use crate::program::model::lang::language::Language;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::pcode::PcodeOp;

type Pair = (Vec<u8>, SymValueZ3);

/// The paired state of a SymZ3 emulator: its memory, and each thread's registers.
pub type SymZ3State = SymZ3PcodeExecutorState<NoPcodeStateCallbacks>;

/// The emulator's paired memory, as each of its threads holds it.
pub type SymZ3SharedState = SharedPcodeExecutorState<SymZ3State>;

/// A SymZ3 thread, as its emulator's records refer to it: by the name it is kept under in its
/// emulator. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SymZ3ThreadId(Arc<str>);

impl SymZ3ThreadId {
    /// The thread named `name`.
    pub fn new(name: impl AsRef<str>) -> Self {
        Self(Arc::from(name.as_ref()))
    }

    /// Java: `thread.getName()`.
    pub fn get_name(&self) -> &str {
        &self.0
    }
}

/// Java's anonymous `SleighInstructionDecoder` subclass: a decoder that records each instruction
/// it decodes against the emulator's shared symbolic state, as `addInstruction(instruction)`.
struct SymZ3InstructionDecoder {
    decoder: Box<dyn InstructionDecoder>,
    thread: SymZ3ThreadId,
    shared: SymZ3SharedState,
}

impl InstructionDecoder for SymZ3InstructionDecoder {
    fn get_language(&self) -> Arc<dyn Language> {
        self.decoder.get_language()
    }

    fn decode_instruction(
        &mut self,
        address: &Address,
        context: Option<&RegisterValue>,
    ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
        let instruction = self.decoder.decode_instruction(address, context)?;
        // The decoded `PseudoInstruction` is not (yet) an `Instruction`; the decoder keeps the one
        // it decoded, as `DefaultPcodeThread` itself reads it back.
        if let Some(decoded) = self.decoder.get_last_instruction() {
            let thread = &self.thread;
            self.shared.with_symbolic_mut(|symbolic| symbolic.add_instruction(thread, decoded));
        }
        Ok(instruction)
    }

    fn branched(&mut self, address: &Address) {
        self.decoder.branched(address);
    }

    fn get_last_instruction(&self) -> Option<Arc<dyn Instruction>> {
        self.decoder.get_last_instruction()
    }

    fn get_last_length_with_delays(&self) -> i32 {
        self.decoder.get_last_length_with_delays()
    }
}

/// The overrides of Java's `SymZ3PcodeThread`, over those of its superclass `AuxPcodeThread`.
pub struct SymZ3ThreadHooks {
    parent: AuxThreadHooks<SymValueZ3, SymZ3PartsFactory>,
    thread: SymZ3ThreadId,
    shared: SymZ3SharedState,
}

impl SymZ3ThreadHooks {
    /// The overrides for the thread named `thread` over the emulator's memory `shared`, whose
    /// parts come from `parts_factory`.
    pub fn new(parts_factory: Arc<SymZ3PartsFactory>, thread: SymZ3ThreadId, shared: SymZ3SharedState) -> Self {
        Self { parent: AuxThreadHooks::new(parts_factory, None), thread, shared }
    }

    /// The superclass's overrides.
    pub fn aux(&self) -> &AuxThreadHooks<SymValueZ3, SymZ3PartsFactory> {
        &self.parent
    }
}

impl ThreadHooks<Pair, SymZ3SharedState, SymZ3State> for SymZ3ThreadHooks {
    /// Port of the override: the base decoder, recording each decoded instruction.
    fn create_instruction_decoder(
        &mut self,
        decoder: Box<dyn InstructionDecoder>,
    ) -> Box<dyn InstructionDecoder> {
        let decoder = self.parent.create_instruction_decoder(decoder);
        Box::new(SymZ3InstructionDecoder {
            decoder,
            thread: self.thread.clone(),
            shared: self.shared.clone(),
        })
    }

    fn create_userop_library(
        &mut self,
        thread: &ThreadCore<Pair, SymZ3SharedState, SymZ3State>,
        library: Box<dyn PcodeUseropLibrary<Pair>>,
    ) -> Box<dyn PcodeUseropLibrary<Pair>> {
        self.parent.create_userop_library(thread, library)
    }

    fn create_executor(
        &mut self,
        thread: &ThreadCore<Pair, SymZ3SharedState, SymZ3State>,
    ) -> PcodeThreadExecutor<Pair> {
        self.parent.create_executor(thread)
    }

    fn pre_execute_instruction(&mut self, thread: &mut ThreadCore<Pair, SymZ3SharedState, SymZ3State>) {
        self.parent.pre_execute_instruction(thread);
    }

    fn post_execute_instruction(&mut self, thread: &mut ThreadCore<Pair, SymZ3SharedState, SymZ3State>) {
        self.parent.post_execute_instruction(thread);
    }

    fn on_missing_userop_def(
        &mut self,
        thread: &mut ThreadCore<Pair, SymZ3SharedState, SymZ3State>,
        op: &PcodeOp,
        op_name: &str,
    ) -> bool {
        self.parent.on_missing_userop_def(thread, op, op_name)
    }

    fn override_counter(&mut self, thread: &mut ThreadCore<Pair, SymZ3SharedState, SymZ3State>, counter: &Address) {
        self.parent.override_counter(thread, counter);
    }
}

/// A thread of SymZ3 (symbolic Z3) p-code emulation.
///
/// Port of `ghidra.pcode.emu.symz3.SymZ3PcodeThread`. See the module docs.
pub type SymZ3PcodeThread = DefaultPcodeThread<Pair, SymZ3SharedState, SymZ3State, SymZ3ThreadHooks>;

impl DefaultPcodeThread<Pair, SymZ3SharedState, SymZ3State, SymZ3ThreadHooks> {
    /// Construct a new thread with the given name belonging to the given emulator.
    ///
    /// Port of `SymZ3PcodeThread(String, AuxPcodeEmulator<SymValueZ3>)`; `parts` is what the
    /// constructor chain reads off the emulator (see [`AuxThreadParts`]), and `parts_factory` is
    /// the emulator's parts factory.
    ///
    /// # Panics
    ///
    /// If the language has no program counter, as [`DefaultPcodeThread::new`] requires.
    pub fn new_symz3(
        name: impl Into<String>,
        parts: AuxThreadParts<SymValueZ3, SymZ3State, SymZ3State>,
        parts_factory: Arc<SymZ3PartsFactory>,
    ) -> Self {
        let name = name.into();
        let AuxThreadParts { machine, exec_language, shared_state, local_state, decoder } = parts;
        let hooks = SymZ3ThreadHooks::new(parts_factory, SymZ3ThreadId::new(&name), shared_state.clone());
        DefaultPcodeThread::new(name, machine, exec_language, shared_state, local_state, decoder, hooks)
    }

    /// This thread, as the emulator's records refer to it.
    pub fn get_thread_id(&self) -> SymZ3ThreadId {
        self.hooks().thread.clone()
    }

    /// The emulator's paired memory, as this thread holds it.
    pub fn shared_state_handle(&self) -> SymZ3SharedState {
        self.hooks().shared.clone()
    }

    /// Run `f` against the shared (memory) concrete piece. Java: `getSharedConcreteState()`.
    pub fn with_shared_concrete_state<R>(
        &self,
        f: impl FnOnce(&dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>) -> R,
    ) -> R {
        self.hooks().shared.with_concrete(f)
    }

    /// Run `f` against the shared (memory) symbolic piece. Java: `getSharedSymbolicState()`.
    pub fn with_shared_symbolic_state<R>(
        &self,
        f: impl FnOnce(&SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> R,
    ) -> R {
        self.hooks().shared.with_symbolic(f)
    }

    /// Run `f` against the local (register) concrete piece. Java: `getLocalConcreteState()`.
    pub fn with_local_concrete_state<R>(
        &self,
        f: impl FnOnce(&dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>) -> R,
    ) -> R {
        f(self.core().get_state().get_local_state().get_left())
    }

    /// Run `f` against the local (register) symbolic piece. Java: `getLocalSymbolicState()`.
    pub fn with_local_symbolic_state<R>(
        &self,
        f: impl FnOnce(&SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> R,
    ) -> R {
        f(self.core().get_state().get_local_state().get_right())
    }

    /// Run `f` against the local (register) symbolic piece, for writing.
    pub fn with_local_symbolic_state_mut<R>(
        &self,
        f: impl FnOnce(&mut SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> R,
    ) -> R {
        f(self.core().get_state().get_local_state_mut().get_right_mut())
    }

    /// Java: `addInstruction(Instruction)`, which is
    /// `getSharedSymbolicState().addInstruction(this, inst)`.
    pub fn add_instruction(&self, inst: Arc<dyn Instruction>) {
        let thread = self.get_thread_id();
        self.hooks().shared.with_symbolic_mut(|symbolic| symbolic.add_instruction(&thread, inst));
    }

    /// Java: `addOp(PcodeOp)`, which is `getSharedSymbolicState().addOp(this, op)`.
    pub fn add_op(&self, op: PcodeOp) {
        let thread = self.get_thread_id();
        self.hooks().shared.with_symbolic_mut(|symbolic| symbolic.add_op(&thread, op));
    }
}

impl InternalSymZ3RecordsPreconditions for SymZ3PcodeThread {
    /// Java: `addPrecondition(String)`, delegating to `getLocalSymbolicState().addPrecondition`.
    fn add_precondition(&mut self, precondition: String) {
        self.with_local_symbolic_state_mut(|symbolic| symbolic.add_precondition(precondition));
    }
}

impl SymZ3RecordsPreconditions for SymZ3PcodeThread {
    /// Java: `getPreconditions()`, delegating to `getLocalSymbolicState().getPreconditions()`.
    fn get_preconditions(&self) -> Vec<String> {
        self.with_local_symbolic_state(|symbolic| symbolic.get_preconditions())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thread_id_is_its_name() {
        let id = SymZ3ThreadId::new("[Threads][7]");
        assert_eq!(id.get_name(), "[Threads][7]");
        assert_eq!(id, SymZ3ThreadId::new(String::from("[Threads][7]")));
    }
}

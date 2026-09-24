//! A p-code thread operating on concrete bytes.
//!
//! Port of `ghidra.pcode.emu.BytesPcodeThread`.
//!
//! This is the default thread for [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator).
//! Java's class is `BytesPcodeThread extends ModifiedPcodeThread<byte[]>` with only a constructor
//! delegating to `super(name, machine)`, so it adds no overrides: here it is
//! [`ModifiedPcodeThread`] over byte values, with its two state delegates fixed to the ones a
//! [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator) creates.

use std::sync::Arc;

use crate::pcode::emu::abstract_pcode_machine::PcodeMachineShared;
use crate::pcode::emu::default_pcode_thread::DefaultPcodeThread;
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
#[allow(deprecated)]
use crate::pcode::emu::modified_pcode_thread::{
    ModifiedPcodeThread, ModifiedThreadHooks, PcodeStateModifier,
};
use crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState;
use crate::pcode::exec::bytes_pcode_executor_state::BytesPcodeExecutorState;
use crate::pcode::exec::bytes_pcode_executor_state_piece::BytesPcodeExecutorStatePiece;
use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
use crate::program::model::lang::language::Language;

/// The concrete bytes state a [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator)
/// creates for its shared memory and for each thread's registers: Java's
/// `new BytesPcodeExecutorState(language, scb)`.
pub type BytesState = BytesPcodeExecutorState<BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks>>;

/// A simple p-code thread that operates on concrete bytes.
///
/// Port of `BytesPcodeThread`. Its shared delegate is the machine's shared memory, which every
/// thread of the machine refers to; its local delegate is its own registers.
pub type BytesPcodeThread =
    ModifiedPcodeThread<Vec<u8>, SharedPcodeExecutorState<BytesState>, BytesState>;

#[allow(deprecated)]
impl DefaultPcodeThread<Vec<u8>, SharedPcodeExecutorState<BytesState>, BytesState, ModifiedThreadHooks> {
    /// Construct a new thread.
    ///
    /// Port of `BytesPcodeThread(String, AbstractPcodeMachine<byte[]>)`, which is
    /// `super(name, machine)`: see [`ModifiedPcodeThread::new_modified`] for the parameters that
    /// stand in for what Java's constructor chain reads off the machine.
    ///
    /// # Panics
    ///
    /// If the language has no program counter, as Java's `Objects.requireNonNull` throws.
    pub fn new_bytes(
        name: impl Into<String>,
        machine: Arc<PcodeMachineShared<Vec<u8>>>,
        exec_language: Arc<dyn Language>,
        shared_state: SharedPcodeExecutorState<BytesState>,
        local_state: BytesState,
        decoder: Box<dyn InstructionDecoder>,
        modifier: Option<Arc<dyn PcodeStateModifier>>,
    ) -> Self {
        Self::new_modified(name, machine, exec_language, shared_state, local_state, decoder, modifier)
    }
}

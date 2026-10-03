//! The run-time executor state for the JIT-accelerated p-code emulator.
//!
//! Corresponds to `ghidra.pcode.emu.jit.JitBytesPcodeExecutorState`.
//!
//! This is an interface (trait in Rust) that extends `PcodeExecutorState<byte[]>` and adds a
//! method for fast access to address-space-specific state objects. This allows generated code to
//! bypass the space lookup and directly access pre-fetched state.

use std::sync::Arc;

use crate::pcode::emu::jit::jit_bytes_pcode_executor_state_piece::JitBytesPcodeExecutorStateSpace;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::AddressSpace;

/// The run-time executor state for the JIT-accelerated p-code emulator.
///
/// This trait extends [`PcodeExecutorState<Vec<u8>>`] and adds a method for direct access to
/// the state space for a given address space, allowing generated code to bypass the space lookup.
///
/// The associated type `Callbacks` represents the callback type used by this state's underlying
/// executor pieces. Each implementation of this trait fixes this type to a concrete callback type.
pub trait JitBytesPcodeExecutorState: PcodeExecutorState<Vec<u8>> {
    /// The callback type used by this state's executor pieces.
    type Callbacks: PcodeStateCallbacks;

    /// Get the state space for the given address space.
    ///
    /// Port of `getForSpace(AddressSpace)`. For generated code to side-step the space lookup.
    fn get_for_space(
        &self,
        space: &Arc<AddressSpace>,
    ) -> Option<JitBytesPcodeExecutorStateSpace<Self::Callbacks>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trait_definition() {
        // This is a compile-time check that the trait compiles correctly.
        // The actual instantiation and behavior testing happens in integration tests
        // with concrete implementations like JitDefaultBytesPcodeExecutorState.
    }
}

//! Port of `ghidra.pcode.emu.symz3.SymZ3PairedPcodeExecutorState`.

use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::SymZ3PcodeExecutorStatePiece;
use crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece;
use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;

/// Port of `ghidra.pcode.emu.symz3.SymZ3PairedPcodeExecutorState`.
///
/// A genuine open extension point (per `scripts/shape_rules.py`): the one in-repo implementor is
/// `state.SymZ3PcodeExecutorState` (distinct from the
/// `SymZ3PcodeExecutorStatePiece` referenced below -- two different Java classes despite the
/// similar name).
///
/// Java's `Pair<byte[], SymValueZ3>` is rendered as the tuple `(Vec<u8>, SymValueZ3)`, matching
/// this crate's established convention for `AuxPcodeEmulator`/`AuxEmulatorPartsFactory` and
/// friends.
pub trait SymZ3PairedPcodeExecutorState: PcodeExecutorState<(Vec<u8>, SymValueZ3)> {
    /// Java: `PcodeExecutorStatePiece<byte[], byte[]> getLeft()`. `PcodeExecutorStatePiece` is a
    /// genuine open extension point (per the dependency context for this class), so this returns
    /// `&dyn`.
    fn get_left(&self) -> &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>;

    /// Java: `SymZ3PcodeExecutorStatePiece getRight()`. `SymZ3PcodeExecutorStatePiece` is generic
    /// over its `PcodeStateCallbacks` type in this port (see that struct's module docs, since
    /// Java's `PcodeStateCallbacks` interface has no object-safe Rust equivalent); fixed here to
    /// [`NoPcodeStateCallbacks`], the only callback type any in-repo caller currently needs.
    fn get_right(&self) -> &SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>;

    /// Mutable counterpart to [`Self::get_right`], added for
    /// [`SymZ3PcodeThread`](crate::pcode::emu::symz3::sym_z3_pcode_thread::SymZ3PcodeThread)'s
    /// `addInstruction`/`addOp`/`addPrecondition`, none of which Java's `getRight()` alone can
    /// reach mutably in Rust (a Java reference is inherently mutable; `&SymZ3PcodeExecutorStatePiece`
    /// is not). Not itself a Java method -- see [`ThreadPcodeExecutorState::get_shared_state_mut`](crate::pcode::emu::thread_pcode_executor_state::ThreadPcodeExecutorState::get_shared_state_mut)'s
    /// docs for the same pattern one layer up.
    fn get_right_mut(&mut self) -> &mut SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>;
}

/// Java's `getLeft()`/`getRight()` on the emulator's shared state, which every thread holds
/// through a [`SharedPcodeExecutorState`] handle.
///
/// A handle cannot lend out a borrow of the state behind its lock the way Java hands out the piece
/// itself, so these run a closure against the piece while the state is locked. Do not reach the
/// same handle again from inside the closure: the lock is not reentrant.
impl<S: SymZ3PairedPcodeExecutorState> SharedPcodeExecutorState<S> {
    /// Run `f` against the concrete (left) piece. Java: `getLeft()`.
    pub fn with_concrete<R>(&self, f: impl FnOnce(&dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>) -> R) -> R {
        f(self.lock().get_left())
    }

    /// Run `f` against the symbolic (right) piece. Java: `getRight()`.
    pub fn with_symbolic<R>(&self, f: impl FnOnce(&SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> R) -> R {
        f(self.lock().get_right())
    }

    /// Run `f` against the symbolic (right) piece, for writing. Java: `getRight()`, whose result
    /// Java callers mutate.
    pub fn with_symbolic_mut<R>(
        &self,
        f: impl FnOnce(&mut SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> R,
    ) -> R {
        f(self.lock().get_right_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
    use crate::pcode::exec::pcode_executor_state_piece::{ErasedPcodeExecutorStatePiece, Reason};
    use crate::program::model::address::{Address, AddressSpace};
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::mem::MemBuffer;
    use std::sync::Arc;

    /// A minimal, unimplemented-bodied left piece: only enough of `PcodeExecutorStatePiece`'s
    /// required (non-default) methods to satisfy the trait, since this test proves
    /// `SymZ3PairedPcodeExecutorState`'s pairing contract, not `PcodeExecutorStatePiece`'s own
    /// (already independently tested) default-method plumbing.
    struct FakeLeft;

    impl ErasedPcodeExecutorStatePiece for FakeLeft {}

    impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for FakeLeft {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this test")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            unimplemented!("not exercised by this test")
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            unimplemented!("not exercised by this test")
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &Vec<u8>,
            _size: i32,
            _quantize: bool,
            _val: &Vec<u8>,
        ) {
        }
        fn set_var_internal_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &Vec<u8>,
            _size: i32,
            _val: &Vec<u8>,
        ) {
        }
        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &Vec<u8>,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> Vec<u8> {
            Vec::new()
        }
        fn get_var_internal_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &Vec<u8>,
            _size: i32,
            _reason: Reason,
        ) -> Vec<u8> {
            Vec::new()
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
            Vec::new()
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by this test")
        }
        fn clear(&mut self) {}
    }

    struct FakeState {
        left: FakeLeft,
        right: SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>,
    }

    impl ErasedPcodeExecutorStatePiece for FakeState {}

    impl PcodeExecutorStatePiece<(Vec<u8>, SymValueZ3), (Vec<u8>, SymValueZ3)> for FakeState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this test")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, SymValueZ3)>> {
            unimplemented!("not exercised by this test")
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, SymValueZ3)>> {
            unimplemented!("not exercised by this test")
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &(Vec<u8>, SymValueZ3),
            _size: i32,
            _quantize: bool,
            _val: &(Vec<u8>, SymValueZ3),
        ) {
        }
        fn set_var_internal_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &(Vec<u8>, SymValueZ3),
            _size: i32,
            _val: &(Vec<u8>, SymValueZ3),
        ) {
        }
        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &(Vec<u8>, SymValueZ3),
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> (Vec<u8>, SymValueZ3) {
            unimplemented!("not exercised by this test")
        }
        fn get_var_internal_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &(Vec<u8>, SymValueZ3),
            _size: i32,
            _reason: Reason,
        ) -> (Vec<u8>, SymValueZ3) {
            unimplemented!("not exercised by this test")
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, (Vec<u8>, SymValueZ3))> {
            Vec::new()
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by this test")
        }
        fn clear(&mut self) {}
    }

    impl PcodeExecutorState<(Vec<u8>, SymValueZ3)> for FakeState {}

    impl SymZ3PairedPcodeExecutorState for FakeState {
        fn get_left(&self) -> &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> {
            &self.left
        }
        fn get_right(&self) -> &SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks> {
            &self.right
        }
        fn get_right_mut(&mut self) -> &mut SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks> {
            &mut self.right
        }
    }

    #[test]
    fn pairs_a_concrete_left_with_a_symbolic_right() {
        use crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::testing::piece;
        use crate::pcode::emu::symz3::sym_z3_records_execution::SymZ3RecordsExecution;

        let state = FakeState { left: FakeLeft, right: piece() };
        assert!(SymZ3RecordsExecution::get_instructions(state.get_right()).is_empty());
        assert!(SymZ3RecordsExecution::get_ops(state.get_right()).is_empty());
        let _left: &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> = state.get_left();
    }
}

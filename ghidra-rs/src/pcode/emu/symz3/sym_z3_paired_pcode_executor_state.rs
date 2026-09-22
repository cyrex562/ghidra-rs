//! Port of `ghidra.pcode.emu.symz3.SymZ3PairedPcodeExecutorState`.

use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece;
use crate::pcode::seam_stubs::SymZ3PcodeExecutorStatePiece;

/// Port of `ghidra.pcode.emu.symz3.SymZ3PairedPcodeExecutorState`.
///
/// A genuine open extension point (per `scripts/shape_rules.py`): the one in-repo implementor is
/// the not-yet-ported `state.SymZ3PcodeExecutorState` (distinct from the also-unported
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

    /// Java: `SymZ3PcodeExecutorStatePiece getRight()`. `SymZ3PcodeExecutorStatePiece` is a
    /// concrete Java class (not yet ported; forward-referenced via the minimal placeholder in
    /// `crate::pcode::seam_stubs`), so this returns a concrete reference, not `&dyn`.
    fn get_right(&self) -> &SymZ3PcodeExecutorStatePiece;
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
        right: SymZ3PcodeExecutorStatePiece,
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
        fn get_right(&self) -> &SymZ3PcodeExecutorStatePiece {
            &self.right
        }
    }

    #[test]
    fn pairs_a_concrete_left_with_a_symbolic_right() {
        let state = FakeState { left: FakeLeft, right: SymZ3PcodeExecutorStatePiece::default() };
        assert!(state.get_right().get_instructions().is_empty());
        assert!(state.get_right().get_ops().is_empty());
        let _left: &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> = state.get_left();
    }
}

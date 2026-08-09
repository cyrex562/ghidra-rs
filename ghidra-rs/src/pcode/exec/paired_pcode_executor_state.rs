//! A paired executor state.
//!
//! Corresponds to `ghidra.pcode.exec.PairedPcodeExecutorState`.
//!
//! This composes a delegate state and piece "left" and "right", creating a single state which
//! instead stores pairs of values, where the left component has the value type of the left state,
//! and the right component has the value type of the right state. Note that both states are
//! addressed using only the left "control" component. Otherwise, every operation on this state is
//! decomposed into operations upon the delegate states, and the final result composed from the
//! results of those operations.
//!
//! Where a response cannot be composed of both states, the paired state defers to the left. In
//! this way, the left state controls the machine, while the right is computed in tandem. The
//! right never directly controls the machine.
//!
//! See [`PairedPcodeExecutorStatePiece`] regarding the composition of three or more pieces.
//!
//! Java's `org.apache.commons.lang3.tuple.Pair<L, R>` maps to a plain Rust tuple `(L, R)`
//! throughout this port.

use std::sync::Arc;

use crate::pcode::exec::paired_pcode_arithmetic::PairedPcodeArithmetic;
use crate::pcode::exec::paired_pcode_executor_state_piece::PairedPcodeExecutorStatePiece;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::pcode::seam_stubs::{ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::mem_buffer::MemBuffer;

/// A paired executor state.
///
/// `L` is the value type of the "left" (control) state, and `R` is the value type of the "right"
/// (auxiliary) state. `PL` is the concrete type of the left delegate state, and `PR` the concrete
/// type of the right delegate piece.
pub struct PairedPcodeExecutorState<L, R, PL, PR>
where
    PL: PcodeExecutorState<L>,
    PR: PcodeExecutorStatePiece<L, R>,
{
    piece: PairedPcodeExecutorStatePiece<L, L, R, PL, PR>,
    arithmetic: Arc<dyn PcodeArithmetic<(L, R)>>,
}

impl<L, R, PL, PR> PairedPcodeExecutorState<L, R, PL, PR>
where
    PL: PcodeExecutorState<L>,
    PR: PcodeExecutorStatePiece<L, R>,
{
    /// Port of `new PairedPcodeExecutorState(PairedPcodeExecutorStatePiece<L, L, R>)`.
    pub fn new(piece: PairedPcodeExecutorStatePiece<L, L, R, PL, PR>) -> Self {
        let arithmetic = piece.get_arithmetic();
        Self { piece, arithmetic }
    }

    /// Compose a paired state from the given left and right states.
    ///
    /// Port of `new PairedPcodeExecutorState(PcodeExecutorState<L>, PcodeExecutorStatePiece<L, R>,
    /// PcodeArithmetic<Pair<L, R>>)`.
    ///
    /// - `left` is the state backing the left side of paired values ("control").
    /// - `right` is the state backing the right side of paired values ("auxiliary").
    /// - `arithmetic` is the arithmetic for the paired values of the state.
    pub fn from_states(left: PL, right: PR, arithmetic: Arc<dyn PcodeArithmetic<(L, R)>>) -> Self {
        let address_arithmetic = left.get_arithmetic();
        let piece =
            PairedPcodeExecutorStatePiece::new(left, right, address_arithmetic, Arc::clone(&arithmetic));
        Self { piece, arithmetic }
    }

    /// Get the delegate backing the left side of paired values.
    ///
    /// Port of `PairedPcodeExecutorState.getLeft()`.
    pub fn get_left(&self) -> &PL {
        self.piece.get_left()
    }

    /// Get the delegate backing the right side of paired values.
    ///
    /// Port of `PairedPcodeExecutorState.getRight()`.
    pub fn get_right(&self) -> &PR {
        self.piece.get_right()
    }
}

impl<L, R, PL, PR> PairedPcodeExecutorState<L, R, PL, PR>
where
    L: 'static,
    R: 'static,
    PL: PcodeExecutorState<L>,
    PR: PcodeExecutorStatePiece<L, R>,
{
    /// Compose a paired state from the given left and right states, deriving the arithmetic by
    /// composing each delegate's own via [`PairedPcodeArithmetic`].
    ///
    /// Port of `new PairedPcodeExecutorState(PcodeExecutorState<L>, PcodeExecutorStatePiece<L,
    /// R>)`.
    pub fn from_pieces(left: PL, right: PR) -> Self {
        let arithmetic: Arc<dyn PcodeArithmetic<(L, R)>> =
            Arc::new(PairedPcodeArithmetic::new(left.get_arithmetic(), right.get_arithmetic()));
        Self::from_states(left, right, arithmetic)
    }
}

impl<L, R, PL, PR> PcodeExecutorStatePiece<(L, R), (L, R)> for PairedPcodeExecutorState<L, R, PL, PR>
where
    PL: PcodeExecutorState<L>,
    PR: PcodeExecutorStatePiece<L, R>,
{
    fn get_language(&self) -> Box<dyn Language> {
        self.piece.get_language()
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(L, R)>> {
        Arc::clone(&self.arithmetic)
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(L, R)>> {
        Arc::clone(&self.arithmetic)
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        self.piece.stream_pieces()
    }

    fn fork<CB: PcodeStateCallbacks>(&self, cb: &CB) -> Self
    where
        Self: Sized,
    {
        Self::new(self.piece.fork(cb))
    }

    fn set_var_abstract(&mut self, space: &Arc<AddressSpace>, offset: &(L, R), size: i32, quantize: bool, val: &(L, R)) {
        self.piece.set_var_abstract(space, &offset.0, size, quantize, val);
    }

    fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &(L, R), size: i32, val: &(L, R)) {
        self.piece.set_var_internal_abstract(space, &offset.0, size, val);
    }

    fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &(L, R)) {
        self.piece.set_var(space, offset, size, quantize, val);
    }

    fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &(L, R)) {
        self.piece.set_var_internal(space, offset, size, val);
    }

    fn get_var_abstract(&self, space: &Arc<AddressSpace>, offset: &(L, R), size: i32, quantize: bool, reason: Reason) -> (L, R) {
        self.piece.get_var_abstract(space, &offset.0, size, quantize, reason)
    }

    fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &(L, R), size: i32, reason: Reason) -> (L, R) {
        self.piece.get_var_internal_abstract(space, &offset.0, size, reason)
    }

    fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> (L, R) {
        self.piece.get_var(space, offset, size, quantize, reason)
    }

    fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> (L, R) {
        self.piece.get_var_internal(space, offset, size, reason)
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, (L, R))> {
        self.piece.get_register_values()
    }

    fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        self.piece.get_concrete_buffer(address, purpose)
    }

    fn clear(&mut self) {
        self.piece.clear();
    }
}

impl<L, R, PL, PR> PcodeExecutorState<(L, R)> for PairedPcodeExecutorState<L, R, PL, PR>
where
    PL: PcodeExecutorState<L>,
    PR: PcodeExecutorStatePiece<L, R>,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
    use crate::pcode::seam_stubs::ConcretionError;
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::Register;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::OpCode;

    /// Little-endian `i64` arithmetic, matching the one used in
    /// [`paired_pcode_executor_state_piece`](crate::pcode::exec::paired_pcode_executor_state_piece)'s
    /// tests.
    #[derive(Debug, Clone, Copy)]
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }

        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn binary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64, _sizein2: i32, _in2: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn mod_before_store(&self, _sizein_offset: i32, _space: &AddressSpace, _in_offset: &i64, _sizein_value: i32, in_value: &i64) -> i64 {
            *in_value
        }

        fn mod_after_load(&self, _sizein_offset: i32, _space: &AddressSpace, _in_offset: &i64, _sizein_value: i32, in_value: &i64) -> i64 {
            *in_value
        }

        fn from_const_bytes(&self, value: &[u8]) -> i64 {
            bytes_to_long(value, value.len(), false)
        }

        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(long_to_bytes(*value, 8, false))
        }

        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    /// A `MemBuffer` fixed at a single address, used to distinguish which delegate answered
    /// `get_concrete_buffer`.
    struct FixedMemBuffer {
        address: Address,
    }

    impl MemBuffer for FixedMemBuffer {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }

        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }

        fn is_big_endian(&self) -> bool {
            false
        }
    }

    /// A leaf state piece backed by an in-memory map, keyed by offset, mirroring
    /// [`paired_pcode_executor_state_piece`](crate::pcode::exec::paired_pcode_executor_state_piece)'s
    /// `MapPiece` test double. `buffer_address` lets `get_concrete_buffer` calls be traced back to
    /// whichever instance answered.
    struct MapPiece {
        cells: RefCell<HashMap<i64, i64>>,
        registers: RefCell<Vec<(RegisterRef, i64)>>,
        buffer_address: Address,
    }

    impl MapPiece {
        fn new(buffer_address: Address) -> Self {
            Self {
                cells: RefCell::new(HashMap::new()),
                registers: RefCell::new(Vec::new()),
                buffer_address,
            }
        }
    }

    impl ErasedPcodeExecutorStatePiece for MapPiece {}

    impl PcodeExecutorStatePiece<i64, i64> for MapPiece {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }

        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }

        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }

        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }

        fn fork<CB: PcodeStateCallbacks>(&self, _cb: &CB) -> Self
        where
            Self: Sized,
        {
            Self {
                cells: RefCell::new(self.cells.borrow().clone()),
                registers: RefCell::new(self.registers.borrow().clone()),
                buffer_address: self.buffer_address.clone(),
            }
        }

        fn set_var_abstract(&mut self, _space: &Arc<AddressSpace>, offset: &i64, _size: i32, _quantize: bool, val: &i64) {
            self.cells.borrow_mut().insert(*offset, *val);
        }

        fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &i64, size: i32, val: &i64) {
            self.set_var_abstract(space, offset, size, false, val);
        }

        fn get_var_abstract(&self, _space: &Arc<AddressSpace>, offset: &i64, _size: i32, _quantize: bool, _reason: Reason) -> i64 {
            *self.cells.borrow().get(offset).unwrap_or(&0)
        }

        fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &i64, size: i32, reason: Reason) -> i64 {
            self.get_var_abstract(space, offset, size, false, reason)
        }

        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            self.registers.borrow().clone()
        }

        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            Box::new(FixedMemBuffer { address: self.buffer_address.clone() })
        }

        fn clear(&mut self) {
            self.cells.borrow_mut().clear();
        }
    }

    impl PcodeExecutorState<i64> for MapPiece {}

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn paired_state(left: MapPiece, right: MapPiece) -> PairedPcodeExecutorState<i64, i64, MapPiece, MapPiece> {
        PairedPcodeExecutorState::from_pieces(left, right)
    }

    /// The state addresses both delegates using only the left ("control") component of the
    /// offset -- the right component of the offset is ignored, per the class javadoc.
    #[test]
    fn set_var_and_get_var_address_using_only_the_left_offset_component() {
        let ram = ram_space();
        let mut state = paired_state(MapPiece::new(ram.address(0x1000)), MapPiece::new(ram.address(0x2000)));

        state.set_var_abstract(&ram, &(0x1000, 0), 8, false, &(11, 22));

        assert_eq!(state.get_var_abstract(&ram, &(0x1000, 0), 8, false, Reason::ExecuteRead), (11, 22));
        // Same left offset, different right offset: still resolves to the same cell.
        assert_eq!(state.get_var_abstract(&ram, &(0x1000, 999), 8, false, Reason::ExecuteRead), (11, 22));
    }

    /// Concrete (`i64`) addressing passes straight through to the underlying piece, without any
    /// left/right decomposition of the offset itself.
    #[test]
    fn set_var_and_get_var_concrete_addressing_round_trips() {
        let ram = ram_space();
        let mut state = paired_state(MapPiece::new(ram.address(0x1000)), MapPiece::new(ram.address(0x2000)));

        state.set_var(&ram, 0x3000, 8, false, &(5, 6));

        assert_eq!(state.get_var(&ram, 0x3000, 8, false, Reason::ExecuteRead), (5, 6));
    }

    /// `getConcreteBuffer` defers entirely to the left ("control") delegate.
    #[test]
    fn get_concrete_buffer_defers_to_the_left_delegate() {
        let ram = ram_space();
        let state = paired_state(MapPiece::new(ram.address(0x1000)), MapPiece::new(ram.address(0x2000)));

        let buf = state.get_concrete_buffer(&ram.address(0x3000), Purpose::Other);

        assert_eq!(buf.get_address(), ram.address(0x1000));
    }

    /// `fork` produces a state whose delegates are independent of the original's.
    #[test]
    fn fork_produces_independent_delegates() {
        let ram = ram_space();
        let mut state = paired_state(MapPiece::new(ram.address(0x1000)), MapPiece::new(ram.address(0x2000)));
        state.set_var_abstract(&ram, &(0x100, 0), 8, false, &(1, 2));

        let mut forked = state.fork(&NoPcodeStateCallbacks);
        forked.set_var_abstract(&ram, &(0x100, 0), 8, false, &(9, 9));

        assert_eq!(state.get_var_abstract(&ram, &(0x100, 0), 8, false, Reason::ExecuteRead), (1, 2));
        assert_eq!(forked.get_var_abstract(&ram, &(0x100, 0), 8, false, Reason::ExecuteRead), (9, 9));
    }

    /// `clear` clears both delegates.
    #[test]
    fn clear_clears_both_delegates() {
        let ram = ram_space();
        let mut state = paired_state(MapPiece::new(ram.address(0x1000)), MapPiece::new(ram.address(0x2000)));
        state.set_var_abstract(&ram, &(0x100, 0), 8, false, &(1, 2));

        state.clear();

        assert_eq!(state.get_var_abstract(&ram, &(0x100, 0), 8, false, Reason::ExecuteRead), (0, 0));
    }

    /// `getRegisterValues` delegates straight through to the composed piece.
    #[test]
    fn get_register_values_delegates_to_the_piece() {
        let ram = ram_space();
        let left = MapPiece::new(ram.address(0x1000));
        let right = MapPiece::new(ram.address(0x2000));
        let shared = Register::new("R0", "", ram.address(0x10), 4, false, Register::TYPE_NONE);
        left.registers.borrow_mut().push((std::rc::Rc::clone(&shared), 1));
        right.registers.borrow_mut().push((std::rc::Rc::clone(&shared), 100));

        let state = paired_state(left, right);
        let values = state.get_register_values();

        assert_eq!(values, vec![(shared, (1, 100))]);
    }

    /// `getLeft`/`getRight` return the original delegates, addressable independently of the
    /// composed pair.
    #[test]
    fn get_left_and_get_right_return_the_original_delegates() {
        let ram = ram_space();
        let mut state = paired_state(MapPiece::new(ram.address(0x1000)), MapPiece::new(ram.address(0x2000)));
        state.set_var(&ram, 0x4000, 8, false, &(7, 8));

        assert_eq!(state.get_left().get_var_abstract(&ram, &0x4000, 8, false, Reason::ExecuteRead), 7);
        assert_eq!(state.get_right().get_var_abstract(&ram, &0x4000, 8, false, Reason::ExecuteRead), 8);
    }

    /// `from_states` (the explicit-arithmetic constructor) and `from_pieces` (the
    /// default-arithmetic constructor) both produce a working state.
    #[test]
    fn from_states_with_explicit_arithmetic_matches_from_pieces() {
        let ram = ram_space();
        let arithmetic: Arc<dyn PcodeArithmetic<(i64, i64)>> =
            Arc::new(PairedPcodeArithmetic::new(Arc::new(I64Arithmetic), Arc::new(I64Arithmetic)));
        let mut state = PairedPcodeExecutorState::from_states(
            MapPiece::new(ram.address(0x1000)),
            MapPiece::new(ram.address(0x2000)),
            arithmetic,
        );

        state.set_var(&ram, 0x5000, 8, false, &(3, 4));

        assert_eq!(state.get_var(&ram, 0x5000, 8, false, Reason::ExecuteRead), (3, 4));
    }
}

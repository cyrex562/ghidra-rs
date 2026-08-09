//! A state piece composed from two delegate pieces, storing pairs of values.
//!
//! Corresponds to `ghidra.pcode.exec.PairedPcodeExecutorStatePiece`.
//!
//! This composes two delegate pieces "left" and "right" creating a single piece which stores
//! pairs of values, where the left component has the value type of the left piece, and the right
//! component has the value type of the right piece. Both pieces must have the same address type.
//! Every operation on this piece is decomposed into operations upon the delegate pieces, and the
//! final result composed from the results of those operations.
//!
//! Java's `org.apache.commons.lang3.tuple.Pair<L, R>` maps to a plain Rust tuple `(L, R)`
//! throughout this port.

use std::sync::Arc;

use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::pcode::seam_stubs::{ErasedPcodeExecutorStatePiece, PairedPcodeArithmetic, PcodeExecutorStatePiece, Reason};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::mem_buffer::MemBuffer;

/// A paired executor state piece.
///
/// `A` is the type of offset (usually the type of a controlling state), `L` is the value type of
/// the "left" piece, and `R` is the value type of the "right" piece.
pub struct PairedPcodeExecutorStatePiece<A, L, R, PL, PR>
where
    PL: PcodeExecutorStatePiece<A, L>,
    PR: PcodeExecutorStatePiece<A, R>,
{
    left: PL,
    right: PR,
    address_arithmetic: Arc<dyn PcodeArithmetic<A>>,
    arithmetic: Arc<dyn PcodeArithmetic<(L, R)>>,
}

impl<A, L, R, PL, PR> PairedPcodeExecutorStatePiece<A, L, R, PL, PR>
where
    PL: PcodeExecutorStatePiece<A, L>,
    PR: PcodeExecutorStatePiece<A, R>,
{
    /// Port of `new PairedPcodeExecutorStatePiece(PcodeExecutorStatePiece<A, L>,
    /// PcodeExecutorStatePiece<A, R>, PcodeArithmetic<A>, PcodeArithmetic<Pair<L, R>>)`.
    pub fn new(
        left: PL,
        right: PR,
        address_arithmetic: Arc<dyn PcodeArithmetic<A>>,
        arithmetic: Arc<dyn PcodeArithmetic<(L, R)>>,
    ) -> Self {
        Self { left, right, address_arithmetic, arithmetic }
    }

    /// Get the delegate backing the left side of paired values.
    ///
    /// Port of `PairedPcodeExecutorStatePiece.getLeft()`.
    pub fn get_left(&self) -> &PL {
        &self.left
    }

    /// Get the delegate backing the right side of paired values.
    ///
    /// Port of `PairedPcodeExecutorStatePiece.getRight()`.
    pub fn get_right(&self) -> &PR {
        &self.right
    }
}

impl<A, L, R, PL, PR> PairedPcodeExecutorStatePiece<A, L, R, PL, PR>
where
    L: 'static,
    R: 'static,
    PL: PcodeExecutorStatePiece<A, L>,
    PR: PcodeExecutorStatePiece<A, R>,
{
    /// Port of `new PairedPcodeExecutorStatePiece(PcodeExecutorStatePiece<A, L>,
    /// PcodeExecutorStatePiece<A, R>)`, which derives the address arithmetic from `left` and
    /// composes a [`PairedPcodeArithmetic`] from each delegate's own arithmetic.
    pub fn from_pieces(left: PL, right: PR) -> Self {
        let address_arithmetic = left.get_address_arithmetic();
        let arithmetic: Arc<dyn PcodeArithmetic<(L, R)>> =
            Arc::new(PairedPcodeArithmetic::new(left.get_arithmetic(), right.get_arithmetic()));
        Self { left, right, address_arithmetic, arithmetic }
    }
}

impl<A, L, R, PL, PR> PcodeExecutorStatePiece<A, (L, R)> for PairedPcodeExecutorStatePiece<A, L, R, PL, PR>
where
    PL: PcodeExecutorStatePiece<A, L>,
    PR: PcodeExecutorStatePiece<A, R>,
{
    fn get_language(&self) -> Box<dyn Language> {
        self.left.get_language()
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<A>> {
        Arc::clone(&self.address_arithmetic)
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(L, R)>> {
        Arc::clone(&self.arithmetic)
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        let mut pieces = self.left.stream_pieces();
        pieces.extend(self.right.stream_pieces());
        pieces
    }

    fn fork<CB: PcodeStateCallbacks>(&self, cb: &CB) -> Self
    where
        Self: Sized,
    {
        Self {
            left: self.left.fork(cb),
            right: self.right.fork(cb),
            address_arithmetic: Arc::clone(&self.address_arithmetic),
            arithmetic: Arc::clone(&self.arithmetic),
        }
    }

    fn set_var_abstract(&mut self, space: &Arc<AddressSpace>, offset: &A, size: i32, quantize: bool, val: &(L, R)) {
        self.left.set_var_abstract(space, offset, size, quantize, &val.0);
        self.right.set_var_abstract(space, offset, size, quantize, &val.1);
    }

    fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &A, size: i32, val: &(L, R)) {
        self.left.set_var_internal_abstract(space, offset, size, &val.0);
        self.right.set_var_internal_abstract(space, offset, size, &val.1);
    }

    fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &(L, R)) {
        self.left.set_var(space, offset, size, quantize, &val.0);
        self.right.set_var(space, offset, size, quantize, &val.1);
    }

    fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &(L, R)) {
        self.left.set_var_internal(space, offset, size, &val.0);
        self.right.set_var_internal(space, offset, size, &val.1);
    }

    fn get_var_abstract(&self, space: &Arc<AddressSpace>, offset: &A, size: i32, quantize: bool, reason: Reason) -> (L, R) {
        (
            self.left.get_var_abstract(space, offset, size, quantize, reason),
            self.right.get_var_abstract(space, offset, size, quantize, reason),
        )
    }

    fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &A, size: i32, reason: Reason) -> (L, R) {
        (
            self.left.get_var_internal_abstract(space, offset, size, reason),
            self.right.get_var_internal_abstract(space, offset, size, reason),
        )
    }

    fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> (L, R) {
        (
            self.left.get_var(space, offset, size, quantize, reason),
            self.right.get_var(space, offset, size, quantize, reason),
        )
    }

    fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> (L, R) {
        (
            self.left.get_var_internal(space, offset, size, reason),
            self.right.get_var_internal(space, offset, size, reason),
        )
    }

    /// Port of `PairedPcodeExecutorStatePiece.getRegisterValues()`.
    ///
    /// Java pairs every register known to *either* delegate, filling the missing side with
    /// `null`. A Rust tuple `(L, R)` has no null-like member to fill in, so this only includes
    /// registers known to *both* delegates; in practice the two delegates track the same set of
    /// registers (they're driven by the same emulator), so this rarely differs from Java's union.
    fn get_register_values(&self) -> Vec<(RegisterRef, (L, R))> {
        let mut left_values = self.left.get_register_values();
        let right_values = self.right.get_register_values();
        let mut result = Vec::with_capacity(left_values.len().min(right_values.len()));
        for (right_register, right_value) in right_values {
            if let Some(pos) =
                left_values.iter().position(|(reg, _)| *reg.borrow() == *right_register.borrow())
            {
                let (_, left_value) = left_values.remove(pos);
                result.push((right_register, (left_value, right_value)));
            }
        }
        result
    }

    fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        self.left.get_concrete_buffer(address, purpose)
    }

    fn clear(&mut self) {
        self.left.clear();
        self.right.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
    use crate::pcode::seam_stubs::ConcretionError;
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::Register;
    use crate::program::model::pcode::OpCode;
    use std::cell::RefCell;

    /// Little-endian `i64` arithmetic, enough to exercise the address domain and both value
    /// domains in these tests.
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

    /// A leaf state piece backed by an in-memory map, keyed by offset. Enough of
    /// [`PcodeExecutorStatePiece`] is implemented faithfully (set/get, register values, fork,
    /// clear) to exercise [`PairedPcodeExecutorStatePiece`]'s decompose-then-recompose behavior;
    /// the rest (`get_language`, `get_concrete_buffer`) is never called by these tests.
    struct MapPiece {
        cells: RefCell<HashMap<i64, i64>>,
        registers: RefCell<Vec<(RegisterRef, i64)>>,
    }

    impl MapPiece {
        fn new() -> Self {
            Self { cells: RefCell::new(HashMap::new()), registers: RefCell::new(Vec::new()) }
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
            unimplemented!("not exercised by these tests")
        }

        fn clear(&mut self) {
            self.cells.borrow_mut().clear();
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn set_var_and_get_var_decompose_and_recompose_the_pair() {
        let ram = ram_space();
        let arithmetic: Arc<dyn PcodeArithmetic<(i64, i64)>> =
            Arc::new(PairedPcodeArithmetic::new(Arc::new(I64Arithmetic), Arc::new(I64Arithmetic)));
        let mut piece =
            PairedPcodeExecutorStatePiece::new(MapPiece::new(), MapPiece::new(), Arc::new(I64Arithmetic), arithmetic);

        piece.set_var_abstract(&ram, &0x1000, 8, false, &(11, 22));
        assert_eq!(piece.get_var_abstract(&ram, &0x1000, 8, false, Reason::ExecuteRead), (11, 22));

        // The two sides are genuinely independent: only the left value changed.
        piece.set_var(&ram, 0x2000, 8, false, &(33, 44));
        assert_eq!(piece.get_var(&ram, 0x2000, 8, false, Reason::ExecuteRead), (33, 44));
        assert_eq!(piece.get_left().get_var_abstract(&ram, &0x2000, 8, false, Reason::ExecuteRead), 33);
        assert_eq!(piece.get_right().get_var_abstract(&ram, &0x2000, 8, false, Reason::ExecuteRead), 44);
    }

    #[test]
    fn fork_produces_independent_delegates() {
        let ram = ram_space();
        let arithmetic: Arc<dyn PcodeArithmetic<(i64, i64)>> =
            Arc::new(PairedPcodeArithmetic::new(Arc::new(I64Arithmetic), Arc::new(I64Arithmetic)));
        let mut piece =
            PairedPcodeExecutorStatePiece::new(MapPiece::new(), MapPiece::new(), Arc::new(I64Arithmetic), arithmetic);
        piece.set_var_abstract(&ram, &0x100, 8, false, &(1, 2));

        let mut forked = piece.fork(&NoPcodeStateCallbacks);
        forked.set_var_abstract(&ram, &0x100, 8, false, &(9, 9));

        assert_eq!(piece.get_var_abstract(&ram, &0x100, 8, false, Reason::ExecuteRead), (1, 2));
        assert_eq!(forked.get_var_abstract(&ram, &0x100, 8, false, Reason::ExecuteRead), (9, 9));
    }

    #[test]
    fn clear_clears_both_delegates() {
        let ram = ram_space();
        let arithmetic: Arc<dyn PcodeArithmetic<(i64, i64)>> =
            Arc::new(PairedPcodeArithmetic::new(Arc::new(I64Arithmetic), Arc::new(I64Arithmetic)));
        let mut piece =
            PairedPcodeExecutorStatePiece::new(MapPiece::new(), MapPiece::new(), Arc::new(I64Arithmetic), arithmetic);
        piece.set_var_abstract(&ram, &0x100, 8, false, &(1, 2));

        piece.clear();

        assert_eq!(piece.get_var_abstract(&ram, &0x100, 8, false, Reason::ExecuteRead), (0, 0));
    }

    #[test]
    fn get_register_values_pairs_only_registers_known_to_both_sides() {
        let ram = ram_space();
        let arithmetic: Arc<dyn PcodeArithmetic<(i64, i64)>> =
            Arc::new(PairedPcodeArithmetic::new(Arc::new(I64Arithmetic), Arc::new(I64Arithmetic)));
        let left = MapPiece::new();
        let right = MapPiece::new();

        let shared = Register::new("R0", "", ram.address(0x10), 4, false, Register::TYPE_NONE);
        let left_only = Register::new("R1", "", ram.address(0x20), 4, false, Register::TYPE_NONE);
        left.registers.borrow_mut().push((std::rc::Rc::clone(&shared), 1));
        left.registers.borrow_mut().push((std::rc::Rc::clone(&left_only), 2));
        right.registers.borrow_mut().push((std::rc::Rc::clone(&shared), 100));

        let piece = PairedPcodeExecutorStatePiece::new(left, right, Arc::new(I64Arithmetic), arithmetic);
        let values = piece.get_register_values();

        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, shared);
        assert_eq!(values[0].1, (1, 100));
        assert!(!values.iter().any(|(reg, _)| *reg == left_only));
    }
}

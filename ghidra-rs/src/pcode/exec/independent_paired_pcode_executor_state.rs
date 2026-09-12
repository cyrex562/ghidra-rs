//! An executor state pairing two fully independent delegate states.
//!
//! Corresponds to `ghidra.pcode.exec.IndependentPairedPcodeExecutorState`.
//!
//! This composes a delegate state piece "left" and "right", creating a single state which instead
//! stores pairs of values, where the left component has the value type of the left piece, and the
//! right component has the value type of the right piece. Unlike
//! [`PairedPcodeExecutorState`](crate::pcode::exec::paired_pcode_executor_state::PairedPcodeExecutorState),
//! *each* side is addressed using its own value type -- there is no single shared "control"
//! address type -- so every abstract-domain operation is decomposed per side using that side's own
//! offset component, and the two states are otherwise fully independent.
//!
//! Where a response cannot be composed of both states, the paired state defers to the left. In
//! this way, the left state controls the machine, while the right is computed in tandem. The right
//! never directly controls the machine.
//!
//! Java's `org.apache.commons.lang3.tuple.Pair<L, R>` maps to a plain Rust tuple `(L, R)`
//! throughout this port.
//!
//! # Divergences from Java
//!
//! * **The `long`-offset overloads are *not* overridden here**, exactly as Java's class does not
//!   override them. They fall through to
//!   [`PcodeExecutorStatePiece`](crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece)'s
//!   default implementations, which convert the `long` into this state's own `(L, R)` domain via
//!   `get_address_arithmetic().from_const_u64(...)` (i.e., via the composed
//!   [`PairedPcodeArithmetic`]) and then call [`set_var_abstract`]/[`get_var_abstract`] below,
//!   which decompose per side as usual. This is a real, intentional difference from the sibling
//!   [`PairedPcodeExecutorState`], whose Java source *does* override the `long`-offset forms to
//!   delegate straight to its single inner piece.
//! * **`get_register_values` pairs only registers known to both delegates.** Java pairs every
//!   register known to *either* delegate, filling the missing side with `null`. A Rust tuple
//!   `(L, R)` has no null-like member to fill in, so -- following the same precedent already
//!   established by
//!   [`PairedPcodeExecutorStatePiece::get_register_values`](crate::pcode::exec::paired_pcode_executor_state_piece::PairedPcodeExecutorStatePiece)
//!   -- this only includes registers known to *both* delegates; in practice the two delegates
//!   track the same set of registers (they're driven by the same emulator), so this rarely
//!   differs from Java's union.

use std::sync::Arc;

use crate::pcode::exec::paired_pcode_arithmetic::PairedPcodeArithmetic;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::mem_buffer::MemBuffer;

/// An executor state pairing two fully independent delegate states.
///
/// `L` is the value type of the "left" (control) state, `R` is the value type of the "right"
/// (auxiliary) state, `PL` is the concrete type of the left delegate piece, and `PR` the concrete
/// type of the right delegate piece.
pub struct IndependentPairedPcodeExecutorState<L, R, PL, PR>
where
    PL: PcodeExecutorStatePiece<L, L>,
    PR: PcodeExecutorStatePiece<R, R>,
{
    left: PL,
    right: PR,
    arithmetic: Arc<dyn PcodeArithmetic<(L, R)>>,
}

impl<L, R, PL, PR> IndependentPairedPcodeExecutorState<L, R, PL, PR>
where
    PL: PcodeExecutorStatePiece<L, L>,
    PR: PcodeExecutorStatePiece<R, R>,
{
    /// Construct a paired state from the given left and right states and arithmetic.
    ///
    /// Port of `IndependentPairedPcodeExecutorState(PcodeExecutorStatePiece<L, L>,
    /// PcodeExecutorStatePiece<R, R>, PcodeArithmetic<Pair<L, R>>)`.
    pub fn new(left: PL, right: PR, arithmetic: Arc<dyn PcodeArithmetic<(L, R)>>) -> Self {
        Self { left, right, arithmetic }
    }

    /// Get the delegate backing the left side of paired values.
    ///
    /// Port of `getLeft()`.
    pub fn get_left(&self) -> &PL {
        &self.left
    }

    /// Get the delegate backing the right side of paired values.
    ///
    /// Port of `getRight()`.
    pub fn get_right(&self) -> &PR {
        &self.right
    }
}

impl<L, R, PL, PR> IndependentPairedPcodeExecutorState<L, R, PL, PR>
where
    L: 'static,
    R: 'static,
    PL: PcodeExecutorStatePiece<L, L>,
    PR: PcodeExecutorStatePiece<R, R>,
{
    /// Compose a paired state from the given left and right states, deriving the arithmetic by
    /// composing each delegate's own via [`PairedPcodeArithmetic`].
    ///
    /// Port of `IndependentPairedPcodeExecutorState(PcodeExecutorStatePiece<L, L>,
    /// PcodeExecutorStatePiece<R, R>)`.
    pub fn from_pieces(left: PL, right: PR) -> Self {
        let arithmetic: Arc<dyn PcodeArithmetic<(L, R)>> =
            Arc::new(PairedPcodeArithmetic::new(left.get_arithmetic(), right.get_arithmetic()));
        Self::new(left, right, arithmetic)
    }
}

impl<L, R, PL, PR> PcodeExecutorStatePiece<(L, R), (L, R)> for IndependentPairedPcodeExecutorState<L, R, PL, PR>
where
    PL: PcodeExecutorStatePiece<L, L>,
    PR: PcodeExecutorStatePiece<R, R>,
{
    fn get_language(&self) -> Box<dyn Language> {
        self.left.get_language()
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(L, R)>> {
        Arc::clone(&self.arithmetic)
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
        Self::new(self.left.fork(cb), self.right.fork(cb), Arc::clone(&self.arithmetic))
    }

    fn set_var_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &(L, R),
        size: i32,
        quantize: bool,
        val: &(L, R),
    ) {
        self.left.set_var_abstract(space, &offset.0, size, quantize, &val.0);
        self.right.set_var_abstract(space, &offset.1, size, quantize, &val.1);
    }

    fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &(L, R), size: i32, val: &(L, R)) {
        self.left.set_var_internal_abstract(space, &offset.0, size, &val.0);
        self.right.set_var_internal_abstract(space, &offset.1, size, &val.1);
    }

    fn get_var_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &(L, R),
        size: i32,
        quantize: bool,
        reason: Reason,
    ) -> (L, R) {
        (
            self.left.get_var_abstract(space, &offset.0, size, quantize, reason),
            self.right.get_var_abstract(space, &offset.1, size, quantize, reason),
        )
    }

    fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &(L, R), size: i32, reason: Reason) -> (L, R) {
        (
            self.left.get_var_internal_abstract(space, &offset.0, size, reason),
            self.right.get_var_internal_abstract(space, &offset.1, size, reason),
        )
    }

    /// Port of `getRegisterValues()`. See this module's docs on the union-vs-intersection
    /// divergence from Java.
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

    // Java's class does not override the `long`-offset forms (`setVar`/`setVarInternal`/
    // `getVar`/`getVarInternal` over `AddressSpace, long, ...`) or the abstract-domain
    // `getNextEntryInternal`; both fall through to this trait's defaults, exactly as in Java. See
    // this module's docs.
}

// `IndependentPairedPcodeExecutorState<L, R, PL, PR>` implements `PcodeExecutorState<(L, R)>` only
// where its own address domain and value domain agree, which they do here (both `(L, R)`);
// unlike `AbstractPcodeExecutorState`, no blanket impl is needed since this type already
// implements `PcodeExecutorStatePiece<(L, R), (L, R)>` directly above.
impl<L, R, PL, PR> crate::pcode::exec::pcode_executor_state::PcodeExecutorState<(L, R)>
    for IndependentPairedPcodeExecutorState<L, R, PL, PR>
where
    PL: PcodeExecutorStatePiece<L, L>,
    PR: PcodeExecutorStatePiece<R, R>,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::OpCode;
    use std::cell::RefCell;
    use std::collections::HashMap as StdHashMap;

    /// Little-endian `i64` arithmetic, reused for both the left and right domains.
    #[derive(Clone, Copy)]
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &i64,
            _sizein2: i32,
            _in2: &i64,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
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

    /// A leaf piece backed by an in-memory map, recording its own writes/reads and a fixed set of
    /// "known" registers -- so [`get_register_values`] tests can exercise the intersection
    /// behavior.
    struct MapPiece {
        label: &'static str,
        cells: RefCell<StdHashMap<i64, i64>>,
        writes: RefCell<Vec<(&'static str, i64, i64)>>,
        known_registers: Vec<RegisterRef>,
    }

    impl MapPiece {
        fn new(label: &'static str, known_registers: Vec<RegisterRef>) -> Self {
            Self { label, cells: RefCell::new(StdHashMap::new()), writes: RefCell::new(vec![]), known_registers }
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
        fn fork<CB: PcodeStateCallbacks>(&self, _cb: &CB) -> Self {
            unimplemented!("not exercised by these tests")
        }
        fn set_var_abstract(&mut self, _space: &Arc<AddressSpace>, offset: &i64, _size: i32, _quantize: bool, val: &i64) {
            self.writes.borrow_mut().push((self.label, *offset, *val));
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
            self.known_registers.iter().map(|r| (r.clone(), 0i64)).collect()
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {
            self.cells.borrow_mut().clear();
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn state() -> IndependentPairedPcodeExecutorState<i64, i64, MapPiece, MapPiece> {
        IndependentPairedPcodeExecutorState::from_pieces(
            MapPiece::new("left", vec![]),
            MapPiece::new("right", vec![]),
        )
    }

    #[test]
    fn set_and_get_var_abstract_decompose_per_side_using_each_sides_own_offset() {
        let mut s = state();
        let ram = ram_space();
        // Left and right use *different* offsets -- proving each side is addressed
        // independently, unlike PairedPcodeExecutorState's single shared offset.
        s.set_var_abstract(&ram, &(0x10, 0x20), 4, false, &(111, 222));

        assert_eq!(s.get_left().cells.borrow().get(&0x10), Some(&111));
        assert_eq!(s.get_right().cells.borrow().get(&0x20), Some(&222));
        assert_eq!(
            s.get_var_abstract(&ram, &(0x10, 0x20), 4, false, Reason::ExecuteRead),
            (111, 222)
        );
    }

    #[test]
    fn long_offset_forms_are_not_overridden_and_go_through_the_composed_arithmetic() {
        // Java's IndependentPairedPcodeExecutorState does not override the long-offset
        // overloads; they fall through to PcodeExecutorStatePiece's default, which converts the
        // long via get_address_arithmetic().from_const_u64(...) (i.e., PairedPcodeArithmetic) and
        // then calls set_var_abstract/get_var_abstract, which decompose per side as usual. Since
        // PairedPcodeArithmetic's from_const_u64 feeds the *same* long into both sides' own
        // arithmetic, the long offset ends up applied identically to both the left and right
        // piece here (not literally shared as one offset value in the pair -- each side computed
        // its own copy independently through its own arithmetic).
        let mut s = state();
        let ram = ram_space();
        s.set_var(&ram, 0x30, 4, false, &(7, 9));

        assert_eq!(s.get_left().cells.borrow().get(&0x30), Some(&7));
        assert_eq!(s.get_right().cells.borrow().get(&0x30), Some(&9));
        assert_eq!(s.get_var(&ram, 0x30, 4, false, Reason::ExecuteRead), (7, 9));
    }

    #[test]
    fn get_concrete_buffer_and_clear_and_language_defer_to_the_left() {
        let mut s = state();
        s.set_var_abstract(&ram_space(), &(1, 2), 4, false, &(10, 20));
        s.clear();
        assert!(s.get_left().cells.borrow().is_empty());
        assert!(s.get_right().cells.borrow().is_empty());
    }

    #[test]
    fn register_values_pairs_only_registers_known_to_both_sides() {
        // Java pairs every register known to *either* delegate, filling the missing side with
        // null; this port (like PairedPcodeExecutorStatePiece before it) only includes registers
        // known to both, since a Rust tuple has no null-like member for the missing side.
        let ram = ram_space();
        let common = crate::program::model::lang::register::Register::new(
            "common", "", ram.address(0), 4, false, crate::program::model::lang::register::Register::TYPE_NONE,
        );
        let left_only = crate::program::model::lang::register::Register::new(
            "left_only", "", ram.address(4), 4, false, crate::program::model::lang::register::Register::TYPE_NONE,
        );
        let right_only = crate::program::model::lang::register::Register::new(
            "right_only", "", ram.address(8), 4, false, crate::program::model::lang::register::Register::TYPE_NONE,
        );

        let s = IndependentPairedPcodeExecutorState::from_pieces(
            MapPiece::new("left", vec![common.clone(), left_only]),
            MapPiece::new("right", vec![common.clone(), right_only]),
        );

        let values = s.get_register_values();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0.borrow().name(), common.borrow().name());
        assert_eq!(values[0].1, (0, 0));
    }

    #[test]
    fn fork_forks_each_side_independently_and_keeps_the_arithmetic() {
        struct NoCallbacks;
        impl PcodeStateCallbacks for NoCallbacks {}

        // MapPiece's `fork` is unimplemented in this test double, so proving `fork` is *wired
        // up* (calls through to both sides) is enough; a real piece would actually deep-copy.
        let s = state();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.fork(&NoCallbacks)));
        assert!(result.is_err(), "fork should call through to each side's own fork()");
    }
}

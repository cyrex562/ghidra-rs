//! A paired concrete-plus-symz3 state.
//!
//! Port of `ghidra.pcode.emu.symz3.state.SymZ3PcodeExecutorState`.
//!
//! This contains the emulator's machine state along with symbolic expressions. Technically, one of
//! these will hold the machine's memory, while another (for each thread) will hold the machine's
//! registers. It's composed of two pieces. The concrete piece holds the actual concrete bytes, while
//! the [`SymValueZ3`] piece holds the symbolic values. A request to get a variable's value from this
//! state will return a pair where the left element comes from the concrete piece and the right
//! element comes from the symbolic piece.
//!
//! # Divergences from Java
//!
//! * Java's class *extends* `IndependentPairedPcodeExecutorState<byte[], SymValueZ3>`; this struct
//!   embeds one and forwards [`PcodeExecutorStatePiece`] to it, the composition convention used
//!   throughout `pcode::exec`.
//! * The symbolic piece is fixed to [`NoPcodeStateCallbacks`], as
//!   [`SymZ3PairedPcodeExecutorState::get_right`] requires; the concrete piece keeps its own
//!   callbacks type `CB`.
//! * The public constructor also takes the [`Z3Context`] the symbolic piece and its arithmetic
//!   build expressions with (see [`SymZ3PcodeArithmetic`]'s module docs).
//! * `fork` is not overridden in Java either; the inherited `IndependentPairedPcodeExecutorState`
//!   fork returns that superclass, not this type, so it has no `Self`-returning equivalent here
//!   and keeps the trait's default.

use std::sync::Arc;

use crate::feature::seam_stubs::Z3Context;
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::symz3::sym_z3_paired_pcode_executor_state::SymZ3PairedPcodeExecutorState;
use crate::pcode::emu::symz3::sym_z3_pcode_arithmetic::SymZ3PcodeArithmetic;
use crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::SymZ3PcodeExecutorStatePiece;
use crate::pcode::exec::bytes_pcode_executor_state_piece::BytesPcodeExecutorStatePiece;
use crate::pcode::exec::independent_paired_pcode_executor_state::IndependentPairedPcodeExecutorState;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_state_callbacks::{NoPcodeStateCallbacks, PcodeStateCallbacks};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::MemBuffer;

type Pair = (Vec<u8>, SymValueZ3);

/// A paired concrete-plus-symz3 state.
pub struct SymZ3PcodeExecutorState<CB: PcodeStateCallbacks> {
    inner: IndependentPairedPcodeExecutorState<
        Vec<u8>,
        SymValueZ3,
        BytesPcodeExecutorStatePiece<CB>,
        SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>,
    >,
}

impl<CB: PcodeStateCallbacks> SymZ3PcodeExecutorState<CB> {
    /// Create a state from the two given pieces.
    ///
    /// Port of the protected `SymZ3PcodeExecutorState(BytesPcodeExecutorStatePiece,
    /// SymZ3PcodeExecutorStatePiece)`; the paired arithmetic is composed from the two pieces'.
    pub fn from_pieces(
        concrete: BytesPcodeExecutorStatePiece<CB>,
        symz3: SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>,
    ) -> Self {
        Self { inner: IndependentPairedPcodeExecutorState::from_pieces(concrete, symz3) }
    }

    /// Create a state from the given concrete piece and a new symbolic piece.
    ///
    /// Port of `SymZ3PcodeExecutorState(Language, BytesPcodeExecutorStatePiece,
    /// PcodeStateCallbacks)`, which builds the symbolic piece as
    /// `new SymZ3PcodeExecutorStatePiece(language, SymZ3PcodeArithmetic.forLanguage(language), cb)`.
    pub fn new(
        language: Arc<dyn Language>,
        concrete: BytesPcodeExecutorStatePiece<CB>,
        cb: Arc<NoPcodeStateCallbacks>,
        ctx: Arc<dyn Z3Context>,
    ) -> Self {
        let address_arithmetic: Arc<dyn PcodeArithmetic<SymValueZ3>> =
            Arc::new(SymZ3PcodeArithmetic::for_language(language.as_ref(), Arc::clone(&ctx)));
        let symz3 = SymZ3PcodeExecutorStatePiece::new_for_language(language, address_arithmetic, cb, ctx);
        Self::from_pieces(concrete, symz3)
    }

    /// The concrete piece, as its own type.
    ///
    /// Java: `getLeft()`, which returns the piece typed as the general
    /// `PcodeExecutorStatePiece<byte[], byte[]>` (see [`SymZ3PairedPcodeExecutorState::get_left`]).
    pub fn concrete(&self) -> &BytesPcodeExecutorStatePiece<CB> {
        self.inner.get_left()
    }
}

impl<CB: PcodeStateCallbacks> ErasedPcodeExecutorStatePiece for SymZ3PcodeExecutorState<CB> {}

impl<CB: PcodeStateCallbacks> PcodeExecutorStatePiece<Pair, Pair> for SymZ3PcodeExecutorState<CB> {
    fn get_language(&self) -> Box<dyn Language> {
        self.inner.get_language()
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Pair>> {
        self.inner.get_address_arithmetic()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Pair>> {
        self.inner.get_arithmetic()
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        self.inner.stream_pieces()
    }

    fn set_var_abstract(&mut self, space: &Arc<AddressSpace>, offset: &Pair, size: i32, quantize: bool, val: &Pair) {
        self.inner.set_var_abstract(space, offset, size, quantize, val);
    }

    fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &Pair, size: i32, val: &Pair) {
        self.inner.set_var_internal_abstract(space, offset, size, val);
    }

    fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &Pair) {
        self.inner.set_var(space, offset, size, quantize, val);
    }

    fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &Pair) {
        self.inner.set_var_internal(space, offset, size, val);
    }

    fn get_var_abstract(&self, space: &Arc<AddressSpace>, offset: &Pair, size: i32, quantize: bool, reason: Reason) -> Pair {
        self.inner.get_var_abstract(space, offset, size, quantize, reason)
    }

    fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &Pair, size: i32, reason: Reason) -> Pair {
        self.inner.get_var_internal_abstract(space, offset, size, reason)
    }

    fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> Pair {
        self.inner.get_var(space, offset, size, quantize, reason)
    }

    fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> Pair {
        self.inner.get_var_internal(space, offset, size, reason)
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, Pair)> {
        self.inner.get_register_values()
    }

    fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        self.inner.get_concrete_buffer(address, purpose)
    }

    fn clear(&mut self) {
        self.inner.clear();
    }
}

impl<CB: PcodeStateCallbacks> PcodeExecutorState<Pair> for SymZ3PcodeExecutorState<CB> {}

impl<CB: PcodeStateCallbacks> SymZ3PairedPcodeExecutorState for SymZ3PcodeExecutorState<CB> {
    fn get_left(&self) -> &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> {
        self.inner.get_left()
    }

    /// Java's covariant override `getRight()`, typed as the symbolic piece.
    fn get_right(&self) -> &SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks> {
        self.inner.get_right()
    }

    fn get_right_mut(&mut self) -> &mut SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks> {
        self.inner.get_right_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::symz3::sym_z3_pcode_arithmetic::testing::EvalCtx;
    use crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::testing::test_language;
    use crate::pcode::exec::pcode_state_callbacks::NONE;
    use crate::program::model::lang::endian::Endian;

    fn state() -> SymZ3PcodeExecutorState<NoPcodeStateCallbacks> {
        let language = test_language();
        let concrete = BytesPcodeExecutorStatePiece::new(Arc::clone(&language), Arc::new(NONE));
        SymZ3PcodeExecutorState::new(language, concrete, Arc::new(NONE), Arc::new(EvalCtx))
    }

    fn space(s: &SymZ3PcodeExecutorState<NoPcodeStateCallbacks>, name: &str) -> Arc<AddressSpace> {
        s.get_language()
            .get_address_factory()
            .get_all_address_spaces()
            .into_iter()
            .find(|sp| sp.name() == name)
            .unwrap()
    }

    #[test]
    fn arithmetic_pairs_bytes_with_symz3_for_the_language() {
        let s = state();
        let arithmetic = s.get_arithmetic();
        assert_eq!(arithmetic.get_endian(), Some(Endian::Little));
        let (bytes, sym) = arithmetic.from_const_u64(0x1234, 2);
        assert_eq!(bytes, vec![0x34, 0x12]);
        assert_eq!(sym.to_long(&EvalCtx), Some(0x1234));
        // The right piece's arithmetic is the language's SymZ3 arithmetic.
        assert_eq!(s.get_right().get_arithmetic().get_endian(), Some(Endian::Little));
    }

    #[test]
    fn a_variable_is_stored_on_both_sides_independently() {
        let mut s = state();
        let unique = space(&s, "unique");
        let ctx = EvalCtx;
        let value = (vec![0xaa, 0xbb], SymValueZ3::from_bit_vec(&ctx, &*ctx.mk_bv_const("x", 16)));

        s.set_var(&unique, 0x10, 2, false, &value);
        let (bytes, sym) = s.get_var(&unique, 0x10, 2, false, Reason::ExecuteRead);

        assert_eq!(bytes, vec![0xaa, 0xbb]);
        assert_eq!(sym, value.1);
        // The left piece alone sees the concrete bytes.
        assert_eq!(s.get_left().get_var(&unique, 0x10, 2, false, Reason::Inspect), vec![0xaa, 0xbb]);
        assert_eq!(s.concrete().get_var(&unique, 0x10, 2, false, Reason::Inspect), vec![0xaa, 0xbb]);
    }

    #[test]
    fn clear_clears_both_sides() {
        // The unique space: the symbolic piece's register/memory spaces are still placeholders.
        let mut s = state();
        let unique = space(&s, "unique");
        let ctx = EvalCtx;
        let value = (vec![1, 2, 3, 4], SymValueZ3::from_bit_vec(&ctx, &*ctx.mk_bv(0x04030201, 32)));
        s.set_var(&unique, 0x40, 4, false, &value);
        s.clear();
        assert_eq!(s.get_left().get_var(&unique, 0x40, 4, false, Reason::Inspect), vec![0, 0, 0, 0]);
        // The symbolic piece dropped its unique space entirely, so (as in Java, where
        // `getUnique` then dereferences null) reading it back fails.
        let right = s.get_right();
        let read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            right.get_var(&unique, 0x40, 4, false, Reason::Inspect)
        }));
        assert!(read.is_err());
    }

    #[test]
    fn get_right_mut_reaches_the_symbolic_piece() {
        use crate::pcode::emu::symz3::internal_sym_z3_records_preconditions::InternalSymZ3RecordsPreconditions;
        use crate::pcode::emu::symz3::sym_z3_records_preconditions::SymZ3RecordsPreconditions;

        let mut s = state();
        assert!(s.get_right().get_preconditions().is_empty());
        s.get_right_mut().add_precondition("B:bool;s;(bvult x y)".to_string());
        assert_eq!(s.get_right().get_preconditions(), vec!["B:bool;s;(bvult x y)".to_string()]);
    }
}

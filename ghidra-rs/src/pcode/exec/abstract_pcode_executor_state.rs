//! A base for executor states composed from a single delegate state piece.
//!
//! Corresponds to `ghidra.pcode.exec.AbstractPcodeExecutorState`.
//!
//! Java's abstract class holds one field (`piece: PcodeExecutorStatePiece<A, T>`), delegates most
//! of [`PcodeExecutorState`] to it, and leaves one method abstract:
//! `protected abstract A extractAddress(T value)`, used to convert an offset expressed in the
//! state's own value domain `T` into the delegate piece's address domain `A` wherever Java
//! overloads on the abstract-addressed form. The `long`-addressed overloads bypass `extractAddress`
//! entirely, delegating straight to the piece's own `long`-addressed methods.
//!
//! Following the same split (and the same forwarding convention) already established by
//! [`AbstractBytesPcodeExecutorStatePiece`](crate::pcode::exec::abstract_bytes_pcode_executor_state_piece)
//! and
//! [`AbstractLongOffsetPcodeExecutorStatePiece`](crate::pcode::exec::abstract_long_offset_pcode_executor_state_piece):
//!
//! * [`AbstractPcodeExecutorStateBase`] holds the delegate piece, plus the concrete behavior Java
//!   implements, as associated functions taking the state itself (generic over
//!   [`AbstractPcodeExecutorState`]).
//! * [`AbstractPcodeExecutorState`] is the trait a concrete leaf implements, declaring
//!   `extract_address` (the one abstract operation) plus accessors for the embedded base.
//! * A concrete leaf embeds the base, implements this trait, and implements
//!   [`PcodeExecutorStatePiece<T, T>`] (and thus, trivially, [`PcodeExecutorState<T>`]) by
//!   forwarding each method to the matching associated function on the base -- exactly as
//!   [`AbstractLongOffsetPcodeExecutorStatePiece`]'s own concrete leaves do. (An earlier version of
//!   this module tried a blanket `impl<S: AbstractPcodeExecutorState<..>> PcodeExecutorStatePiece<T,
//!   T> for S`, which does not compile: `A` and `P` appear only in a `where` bound, not in the
//!   impl's self type, and a generic downstream type could implement both this trait and its own
//!   direct `PcodeExecutorStatePiece<T, T>`, which Rust's coherence checker cannot rule out. The
//!   per-leaf forwarding above sidesteps both problems, at the cost of writing out the forwarding
//!   once per leaf -- the same cost every sibling `Abstract*` module in this crate already pays.)
//!
//! No concrete subclass of this class is ported yet (Java's only one, `DefaultPcodeExecutorState`,
//! is not yet ported), so this module's tests build a throwaway leaf to exercise the forwarding.

use std::marker::PhantomData;
use std::sync::Arc;

use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::mem_buffer::MemBuffer;

/// The shared state of an executor state composed from a single delegate piece.
///
/// `A` is the delegate piece's address domain, `T` is the value domain (also the state's own
/// address domain, per [`PcodeExecutorState`](crate::pcode::exec::pcode_executor_state::PcodeExecutorState)),
/// and `P` is the concrete type of the delegate piece.
pub struct AbstractPcodeExecutorStateBase<A, T, P>
where
    P: PcodeExecutorStatePiece<A, T>,
{
    piece: P,
    _address: PhantomData<fn() -> A>,
    _value: PhantomData<fn() -> T>,
}

impl<A, T, P> AbstractPcodeExecutorStateBase<A, T, P>
where
    P: PcodeExecutorStatePiece<A, T>,
{
    /// Construct a state base wrapping the given delegate piece.
    ///
    /// Port of the constructor `AbstractPcodeExecutorState(PcodeExecutorStatePiece<A, T> piece)`.
    pub fn new(piece: P) -> Self {
        Self { piece, _address: PhantomData, _value: PhantomData }
    }

    /// The embedded delegate piece.
    pub fn piece(&self) -> &P {
        &self.piece
    }

    /// The embedded delegate piece, mutably.
    pub fn piece_mut(&mut self) -> &mut P {
        &mut self.piece
    }

    /// Port of `getLanguage()`.
    pub fn get_language<S>(state: &S) -> Box<dyn Language>
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        state.base().piece().get_language()
    }

    /// Port of `getArithmetic()`, and also of `PcodeExecutorState.getAddressArithmetic()`'s
    /// default (`return getArithmetic();`) -- the state's own address domain is `T`, the same as
    /// its value domain, so the two coincide.
    pub fn get_arithmetic<S>(state: &S) -> Arc<dyn PcodeArithmetic<T>>
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        state.base().piece().get_arithmetic()
    }

    /// Port of `streamPieces()`.
    pub fn stream_pieces<S>(state: &S) -> Vec<&dyn ErasedPcodeExecutorStatePiece>
    where
        S: AbstractPcodeExecutorState<A, T, P>,
        A: 'static,
        T: 'static,
        P: 'static,
    {
        state.base().piece().stream_pieces()
    }

    /// Port of `setVar(AddressSpace, T, int, boolean, T)`.
    pub fn set_var_abstract<S>(state: &mut S, space: &Arc<AddressSpace>, offset: &T, size: i32, quantize: bool, val: &T)
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        let a_offset = state.extract_address(offset);
        state.base_mut().piece_mut().set_var_abstract(space, &a_offset, size, quantize, val);
    }

    /// Port of `setVarInternal(AddressSpace, T, int, T)`.
    pub fn set_var_internal_abstract<S>(state: &mut S, space: &Arc<AddressSpace>, offset: &T, size: i32, val: &T)
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        let a_offset = state.extract_address(offset);
        state.base_mut().piece_mut().set_var_internal_abstract(space, &a_offset, size, val);
    }

    /// Port of `setVar(AddressSpace, long, int, boolean, T)`: delegates straight to the piece's
    /// own `long`-addressed method, bypassing `extractAddress` entirely (as Java does).
    pub fn set_var<S>(state: &mut S, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &T)
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        state.base_mut().piece_mut().set_var(space, offset, size, quantize, val);
    }

    /// Port of `setVarInternal(AddressSpace, long, int, T)`.
    pub fn set_var_internal<S>(state: &mut S, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &T)
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        state.base_mut().piece_mut().set_var_internal(space, offset, size, val);
    }

    /// Port of `getVar(AddressSpace, T, int, boolean, Reason)`.
    pub fn get_var_abstract<S>(state: &S, space: &Arc<AddressSpace>, offset: &T, size: i32, quantize: bool, reason: Reason) -> T
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        let a_offset = state.extract_address(offset);
        state.base().piece().get_var_abstract(space, &a_offset, size, quantize, reason)
    }

    /// Port of `getVarInternal(AddressSpace, T, int, Reason)`.
    pub fn get_var_internal_abstract<S>(state: &S, space: &Arc<AddressSpace>, offset: &T, size: i32, reason: Reason) -> T
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        let a_offset = state.extract_address(offset);
        state.base().piece().get_var_internal_abstract(space, &a_offset, size, reason)
    }

    /// Port of `getVar(AddressSpace, long, int, boolean, Reason)`: delegates straight to the
    /// piece's own `long`-addressed method, bypassing `extractAddress` entirely (as Java does).
    pub fn get_var<S>(state: &S, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> T
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        state.base().piece().get_var(space, offset, size, quantize, reason)
    }

    /// Port of `getVarInternal(AddressSpace, long, int, Reason)`.
    pub fn get_var_internal<S>(state: &S, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> T
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        state.base().piece().get_var_internal(space, offset, size, reason)
    }

    /// Port of `getRegisterValues()`.
    pub fn get_register_values<S>(state: &S) -> Vec<(RegisterRef, T)>
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        state.base().piece().get_register_values()
    }

    /// Port of `getConcreteBuffer(Address, PcodeArithmetic.Purpose)`.
    pub fn get_concrete_buffer<S>(state: &S, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer>
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        state.base().piece().get_concrete_buffer(address, purpose)
    }

    /// Port of `clear()`.
    pub fn clear<S>(state: &mut S)
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        state.base_mut().piece_mut().clear();
    }

    /// Port of `getNextEntryInternal(AddressSpace, long)`.
    pub fn get_next_entry_internal<S>(state: &S, space: &Arc<AddressSpace>, offset: i64) -> Option<(i64, T)>
    where
        S: AbstractPcodeExecutorState<A, T, P>,
    {
        state.base().piece().get_next_entry_internal(space, offset)
    }

    // Java's `AbstractPcodeExecutorState` does not override `fork` or the abstract-domain
    // `getNextEntryInternal(AddressSpace, T)`, so a concrete leaf's own `PcodeExecutorStatePiece`
    // impl should leave both to the trait's defaults (which panic, exactly as Java's own
    // unimplemented defaults do), rather than forwarding to an associated function here.
}

/// The one abstract operation `AbstractPcodeExecutorState` leaves for a concrete leaf, plus
/// accessors for the embedded [`AbstractPcodeExecutorStateBase`].
///
/// A concrete leaf implements this trait, then implements
/// [`PcodeExecutorStatePiece<T, T>`] by forwarding each method to the matching associated function
/// on [`AbstractPcodeExecutorStateBase`] (see the module docs).
pub trait AbstractPcodeExecutorState<A, T, P>
where
    P: PcodeExecutorStatePiece<A, T>,
{
    /// The embedded shared state of this class.
    fn base(&self) -> &AbstractPcodeExecutorStateBase<A, T, P>;

    /// The embedded shared state of this class, mutably.
    fn base_mut(&mut self) -> &mut AbstractPcodeExecutorStateBase<A, T, P>;

    /// Convert a value-domain offset into the delegate piece's address domain.
    ///
    /// Port of the abstract `protected abstract A extractAddress(T value)`.
    fn extract_address(&self, value: &T) -> A;
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
    use std::collections::HashMap;

    /// Little-endian `i64` arithmetic, used for both the piece's address domain and its (and the
    /// state's) value domain.
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

    /// A leaf piece backed by a map from (untagged) address to value. `A` and `T` are both `i64`
    /// as Rust types, but carry distinct *meanings*: this piece is addressed by the untagged
    /// address, while the composing state above it (see [`TaggedState`]) is addressed by a value
    /// that also carries a tag in its low nibble -- proving `extract_address` genuinely converts
    /// between two different domains, not just passing an offset through unchanged.
    #[derive(Default)]
    struct MapPiece {
        cells: HashMap<i64, i64>,
        /// Every offset a write landed at, so tests can confirm `extract_address` really ran.
        writes: RefCell<Vec<i64>>,
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
        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            offset: &i64,
            _size: i32,
            _quantize: bool,
            val: &i64,
        ) {
            self.writes.borrow_mut().push(*offset);
            self.cells.insert(*offset, *val);
        }
        fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &i64, size: i32, val: &i64) {
            self.set_var_abstract(space, offset, size, false, val);
        }
        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            offset: &i64,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> i64 {
            *self.cells.get(offset).unwrap_or(&0)
        }
        fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &i64, size: i32, reason: Reason) -> i64 {
            self.get_var_abstract(space, offset, size, false, reason)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            vec![]
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {
            self.cells.clear();
        }
    }

    /// A concrete leaf state whose value domain tags the low nibble of every offset with
    /// metadata, and whose `extract_address` strips that tag before delegating to the untagged
    /// [`MapPiece`] below it -- exactly the sort of thing Java's `extractAddress` exists for.
    struct TaggedState {
        base: AbstractPcodeExecutorStateBase<i64, i64, MapPiece>,
    }

    impl TaggedState {
        fn new() -> Self {
            Self { base: AbstractPcodeExecutorStateBase::new(MapPiece::default()) }
        }
    }

    impl AbstractPcodeExecutorState<i64, i64, MapPiece> for TaggedState {
        fn base(&self) -> &AbstractPcodeExecutorStateBase<i64, i64, MapPiece> {
            &self.base
        }
        fn base_mut(&mut self) -> &mut AbstractPcodeExecutorStateBase<i64, i64, MapPiece> {
            &mut self.base
        }
        fn extract_address(&self, value: &i64) -> i64 {
            value >> 4
        }
    }

    impl ErasedPcodeExecutorStatePiece for TaggedState {}

    impl PcodeExecutorStatePiece<i64, i64> for TaggedState {
        fn get_language(&self) -> Box<dyn Language> {
            AbstractPcodeExecutorStateBase::get_language(self)
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            AbstractPcodeExecutorStateBase::get_arithmetic(self)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            AbstractPcodeExecutorStateBase::get_arithmetic(self)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            AbstractPcodeExecutorStateBase::stream_pieces(self)
        }
        fn set_var_abstract(&mut self, space: &Arc<AddressSpace>, offset: &i64, size: i32, quantize: bool, val: &i64) {
            AbstractPcodeExecutorStateBase::set_var_abstract(self, space, offset, size, quantize, val);
        }
        fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &i64, size: i32, val: &i64) {
            AbstractPcodeExecutorStateBase::set_var_internal_abstract(self, space, offset, size, val);
        }
        fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &i64) {
            AbstractPcodeExecutorStateBase::set_var(self, space, offset, size, quantize, val);
        }
        fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &i64) {
            AbstractPcodeExecutorStateBase::set_var_internal(self, space, offset, size, val);
        }
        fn get_var_abstract(&self, space: &Arc<AddressSpace>, offset: &i64, size: i32, quantize: bool, reason: Reason) -> i64 {
            AbstractPcodeExecutorStateBase::get_var_abstract(self, space, offset, size, quantize, reason)
        }
        fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &i64, size: i32, reason: Reason) -> i64 {
            AbstractPcodeExecutorStateBase::get_var_internal_abstract(self, space, offset, size, reason)
        }
        fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> i64 {
            AbstractPcodeExecutorStateBase::get_var(self, space, offset, size, quantize, reason)
        }
        fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> i64 {
            AbstractPcodeExecutorStateBase::get_var_internal(self, space, offset, size, reason)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            AbstractPcodeExecutorStateBase::get_register_values(self)
        }
        fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
            AbstractPcodeExecutorStateBase::get_concrete_buffer(self, address, purpose)
        }
        fn clear(&mut self) {
            AbstractPcodeExecutorStateBase::clear(self);
        }
        fn get_next_entry_internal(&self, space: &Arc<AddressSpace>, offset: i64) -> Option<(i64, i64)> {
            AbstractPcodeExecutorStateBase::get_next_entry_internal(self, space, offset)
        }
    }

    impl PcodeExecutorState<i64> for TaggedState {}

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn abstract_domain_accessors_extract_the_address_before_delegating() {
        let mut state = TaggedState::new();
        let ram = ram_space();
        // Tagged offset 0x2001 (tag nibble = 1) should reach the delegate piece at address 0x200.
        state.set_var_abstract(&ram, &0x2001, 4, false, &0xAAAA);
        assert_eq!(state.base().piece().writes.borrow().as_slice(), &[0x200]);
        assert_eq!(state.get_var_abstract(&ram, &0x2001, 4, false, Reason::ExecuteRead), 0xAAAA);
        // A different tag over the same untagged address reaches the same underlying cell.
        assert_eq!(state.get_var_abstract(&ram, &0x2007, 4, false, Reason::ExecuteRead), 0xAAAA);
    }

    #[test]
    fn long_offset_accessors_bypass_extract_address_and_delegate_directly() {
        // Java: `getVar(AddressSpace, long, ...)` and friends delegate straight to
        // `piece.getVar(space, offset, ...)`, without ever calling `extractAddress`. So a
        // long-offset write lands at the given offset directly, not at `offset >> 4`.
        let mut state = TaggedState::new();
        let ram = ram_space();
        state.set_var(&ram, 0x50, 4, false, &7);
        assert_eq!(state.base().piece().writes.borrow().as_slice(), &[0x50]);
        assert_eq!(state.get_var(&ram, 0x50, 4, false, Reason::ExecuteRead), 7);
    }

    #[test]
    fn language_and_arithmetic_delegate_to_the_piece() {
        let state = TaggedState::new();
        // Java: getArithmetic() returns piece.getArithmetic(); getAddressArithmetic() (the
        // PcodeExecutorState default) returns the same thing, since A = T = i64 for the state's
        // own outward-facing (T, T) piece interface.
        assert_eq!(state.get_arithmetic().size_of(&0), 8);
        assert_eq!(state.get_address_arithmetic().size_of(&0), 8);
    }

    #[test]
    fn clear_delegates_to_the_piece() {
        let mut state = TaggedState::new();
        let ram = ram_space();
        state.set_var(&ram, 0x10, 4, false, &42);
        assert_eq!(state.get_var(&ram, 0x10, 4, false, Reason::Inspect), 42);
        state.clear();
        assert_eq!(state.get_var(&ram, 0x10, 4, false, Reason::Inspect), 0);
    }

    #[test]
    #[should_panic(expected = "no default implementation")]
    fn fork_is_unsupported_as_in_java() {
        // Java's `AbstractPcodeExecutorState` does not override `fork`, so it inherits the
        // interface's `UnsupportedOperationException` default; this port's leaf likewise leaves
        // `fork` to the trait's own default rather than forwarding it to the base.
        struct NoCallbacks;
        impl crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks for NoCallbacks {}
        let state = TaggedState::new();
        let _ = state.fork(&NoCallbacks);
    }
}

//! A p-code executor state formed from a piece whose address and value types are the same.
//!
//! Corresponds to `ghidra.pcode.exec.DefaultPcodeExecutorState`.
//!
//! Java's class is small: it `extends AbstractPcodeExecutorState<T, T>`, implements the one
//! abstract operation `extractAddress` as the identity (the piece's address domain already equals
//! the state's own value domain `T`), and overrides `fork` to wrap the delegate piece's own fork
//! in a fresh `DefaultPcodeExecutorState`.
//!
//! Following the composition-over-inheritance convention already established by
//! [`AbstractPcodeExecutorState`](crate::pcode::exec::abstract_pcode_executor_state)'s own module
//! docs (and exercised there by the test-only `TaggedState` leaf), this struct embeds an
//! [`AbstractPcodeExecutorStateBase`], implements [`AbstractPcodeExecutorState`] to supply
//! `extract_address`, and implements [`PcodeExecutorStatePiece<T, T>`] by forwarding each method
//! to the matching associated function on the base -- except `fork`, which this class alone among
//! the abstract base's leaves actually overrides.

use std::sync::Arc;

use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::abstract_pcode_executor_state::{
    AbstractPcodeExecutorState, AbstractPcodeExecutorStateBase,
};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::mem_buffer::MemBuffer;

/// A p-code executor state formed from a piece whose address and value types are the same.
///
/// Port of `ghidra.pcode.exec.DefaultPcodeExecutorState<T>`. `T` is the type of values and
/// addresses in the state; `P` is the concrete type of the delegate piece.
pub struct DefaultPcodeExecutorState<T, P>
where
    P: PcodeExecutorStatePiece<T, T>,
{
    base: AbstractPcodeExecutorStateBase<T, T, P>,
    /// The piece's arithmetic, cached at construction.
    ///
    /// Port of the field `protected final PcodeArithmetic<T> arithmetic`, assigned in the
    /// constructor from `piece.getArithmetic()`. Faithfully reproduced even though, exactly as in
    /// Java, nothing in this class ever reads it again afterward: [`Self::get_arithmetic`] (via
    /// [`AbstractPcodeExecutorStateBase::get_arithmetic`]) re-derives the same value straight from
    /// the embedded piece rather than returning this cached copy. Java's `DefaultPcodeExecutorState`
    /// does not override `getArithmetic()`, so the field is assigned once and never consulted -- a
    /// genuine (harmless) dead field in the real source, kept here rather than "fixed" by omission.
    #[allow(dead_code)]
    arithmetic: Arc<dyn PcodeArithmetic<T>>,
}

impl<T, P> DefaultPcodeExecutorState<T, P>
where
    P: PcodeExecutorStatePiece<T, T>,
{
    /// Construct a state wrapping the given delegate piece.
    ///
    /// Port of the constructor `DefaultPcodeExecutorState(PcodeExecutorStatePiece<T, T> piece)`.
    pub fn new(piece: P) -> Self {
        let arithmetic = piece.get_arithmetic();
        Self { base: AbstractPcodeExecutorStateBase::new(piece), arithmetic }
    }
}

impl<T, P> AbstractPcodeExecutorState<T, T, P> for DefaultPcodeExecutorState<T, P>
where
    T: Clone,
    P: PcodeExecutorStatePiece<T, T>,
{
    fn base(&self) -> &AbstractPcodeExecutorStateBase<T, T, P> {
        &self.base
    }

    fn base_mut(&mut self) -> &mut AbstractPcodeExecutorStateBase<T, T, P> {
        &mut self.base
    }

    /// Port of `protected T extractAddress(T value) { return value; }`: the delegate piece's
    /// address domain already equals this state's own value domain `T`, so the conversion is the
    /// identity. Java returns the same object reference; this clones it, since the trait's
    /// signature takes `&T` and must return an owned `T`.
    fn extract_address(&self, value: &T) -> T {
        value.clone()
    }
}

impl<T, P> PcodeExecutorStatePiece<T, T> for DefaultPcodeExecutorState<T, P>
where
    T: Clone,
    P: PcodeExecutorStatePiece<T, T>,
{
    fn get_language(&self) -> Box<dyn Language> {
        AbstractPcodeExecutorStateBase::get_language(self)
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        // Port of PcodeExecutorState's default `getAddressArithmetic() { return getArithmetic(); }`
        // -- the state's own address domain is T, the same as its value domain.
        AbstractPcodeExecutorStateBase::get_arithmetic(self)
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        AbstractPcodeExecutorStateBase::get_arithmetic(self)
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        // AbstractPcodeExecutorStateBase::stream_pieces requires `A: 'static, T: 'static, P:
        // 'static`, which this trait method's signature cannot assume; forward directly to the
        // piece instead, exactly as the base's own associated function does internally.
        self.base.piece().stream_pieces()
    }

    fn set_var_abstract(&mut self, space: &Arc<AddressSpace>, offset: &T, size: i32, quantize: bool, val: &T) {
        AbstractPcodeExecutorStateBase::set_var_abstract(self, space, offset, size, quantize, val);
    }

    fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &T, size: i32, val: &T) {
        AbstractPcodeExecutorStateBase::set_var_internal_abstract(self, space, offset, size, val);
    }

    fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &T) {
        AbstractPcodeExecutorStateBase::set_var(self, space, offset, size, quantize, val);
    }

    fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &T) {
        AbstractPcodeExecutorStateBase::set_var_internal(self, space, offset, size, val);
    }

    fn get_var_abstract(&self, space: &Arc<AddressSpace>, offset: &T, size: i32, quantize: bool, reason: Reason) -> T {
        AbstractPcodeExecutorStateBase::get_var_abstract(self, space, offset, size, quantize, reason)
    }

    fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &T, size: i32, reason: Reason) -> T {
        AbstractPcodeExecutorStateBase::get_var_internal_abstract(self, space, offset, size, reason)
    }

    fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> T {
        AbstractPcodeExecutorStateBase::get_var(self, space, offset, size, quantize, reason)
    }

    fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> T {
        AbstractPcodeExecutorStateBase::get_var_internal(self, space, offset, size, reason)
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, T)> {
        AbstractPcodeExecutorStateBase::get_register_values(self)
    }

    fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        AbstractPcodeExecutorStateBase::get_concrete_buffer(self, address, purpose)
    }

    fn clear(&mut self) {
        AbstractPcodeExecutorStateBase::clear(self);
    }

    fn get_next_entry_internal(&self, space: &Arc<AddressSpace>, offset: i64) -> Option<(i64, T)> {
        AbstractPcodeExecutorStateBase::get_next_entry_internal(self, space, offset)
    }

    // Java's `AbstractPcodeExecutorState` does not override the abstract-domain
    // `getNextEntryInternal(AddressSpace, T)`, and `DefaultPcodeExecutorState` does not either, so
    // `get_next_entry_internal_abstract` is left to the trait's own default (which panics, as in
    // Java).

    /// Port of the overridden `fork(PcodeStateCallbacks)`:
    /// ```java
    /// public PcodeExecutorState<T> fork(PcodeStateCallbacks cb) {
    ///     return new DefaultPcodeExecutorState<>(piece.fork(cb));
    /// }
    /// ```
    /// Unlike every other leaf built on [`AbstractPcodeExecutorStateBase`] so far (which leave
    /// `fork` to the trait's panicking default, since `AbstractPcodeExecutorState` itself does not
    /// override it), `DefaultPcodeExecutorState` is Java's one concrete subclass that *does*
    /// override `fork` -- so this is the first leaf in this port to do the same.
    fn fork<CB: PcodeStateCallbacks>(&self, cb: &CB) -> Self
    where
        Self: Sized,
    {
        let forked_piece = self.base.piece().fork(cb);
        DefaultPcodeExecutorState::new(forked_piece)
    }
}

impl<T, P> PcodeExecutorState<T> for DefaultPcodeExecutorState<T, P>
where
    T: Clone,
    P: PcodeExecutorStatePiece<T, T>,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::OpCode;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Little-endian `i64` arithmetic, used for both the address domain and the value domain.
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

    /// A leaf piece backed by a map from address (as `i64`) to value, whose address domain and
    /// value domain are both `i64` -- exactly the shape `DefaultPcodeExecutorState` is for.
    #[derive(Default, Clone)]
    struct MapPiece {
        cells: HashMap<i64, i64>,
        /// Every offset a write landed at, so tests can confirm `extract_address` really is the
        /// identity (values reach the piece unmodified).
        writes: RefCell<Vec<i64>>,
        forked: bool,
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
            let mut forked = self.clone();
            forked.forked = true;
            forked
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

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn extract_address_is_the_identity_so_writes_land_at_the_same_offset() {
        let mut state = DefaultPcodeExecutorState::new(MapPiece::default());
        let ram = ram_space();
        state.set_var_abstract(&ram, &0x2000, 4, false, &0xBEEF);
        // Unlike AbstractPcodeExecutorState's TaggedState test leaf (which strips a tag nibble),
        // DefaultPcodeExecutorState's extractAddress is a bare identity: the offset reaches the
        // piece completely unmodified.
        assert_eq!(state.base().piece().writes.borrow().as_slice(), &[0x2000]);
        assert_eq!(state.get_var_abstract(&ram, &0x2000, 4, false, Reason::ExecuteRead), 0xBEEF);
    }

    #[test]
    fn long_offset_accessors_delegate_directly_to_the_piece() {
        let mut state = DefaultPcodeExecutorState::new(MapPiece::default());
        let ram = ram_space();
        state.set_var(&ram, 0x50, 4, false, &7);
        assert_eq!(state.get_var(&ram, 0x50, 4, false, Reason::ExecuteRead), 7);
    }

    #[test]
    fn arithmetic_and_address_arithmetic_both_come_from_the_piece() {
        let state = DefaultPcodeExecutorState::new(MapPiece::default());
        // Java: getArithmetic() returns piece.getArithmetic(); getAddressArithmetic() (inherited
        // from PcodeExecutorState's default) returns the same thing.
        assert_eq!(state.get_arithmetic().size_of(&0), 8);
        assert_eq!(state.get_address_arithmetic().size_of(&0), 8);
    }

    #[test]
    fn clear_delegates_to_the_piece() {
        let mut state = DefaultPcodeExecutorState::new(MapPiece::default());
        let ram = ram_space();
        state.set_var(&ram, 0x10, 4, false, &42);
        assert_eq!(state.get_var(&ram, 0x10, 4, false, Reason::Inspect), 42);
        state.clear();
        assert_eq!(state.get_var(&ram, 0x10, 4, false, Reason::Inspect), 0);
    }

    #[test]
    fn fork_wraps_the_pieces_own_fork_in_a_new_state() {
        // Java: `new DefaultPcodeExecutorState<>(piece.fork(cb))`.
        let mut state = DefaultPcodeExecutorState::new(MapPiece::default());
        let ram = ram_space();
        state.set_var(&ram, 0x10, 4, false, &99);

        let forked = state.fork(&NoPcodeStateCallbacks);

        // The forked state carries over the piece's data (MapPiece::fork clones self)...
        assert_eq!(forked.get_var(&ram, 0x10, 4, false, Reason::Inspect), 99);
        // ...and is a genuinely new state wrapping the piece's own fork, not a panic as
        // AbstractPcodeExecutorState's own unoverridden default would produce.
        assert!(forked.base().piece().forked);
        assert!(!state.base().piece().forked);
    }

    #[test]
    fn constructor_caches_the_pieces_arithmetic_in_the_dead_field() {
        // Faithful reproduction of the Java quirk: `this.arithmetic = piece.getArithmetic();` is
        // assigned in the constructor but never read again by this class (getArithmetic() instead
        // re-derives it from the embedded piece each time). Exercise the constructor path to
        // confirm it does not panic and that the (otherwise unread) field is populated.
        let state = DefaultPcodeExecutorState::new(MapPiece::default());
        assert_eq!(state.arithmetic.size_of(&0), 8);
    }
}

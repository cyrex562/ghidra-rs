//! A p-code executor state composing a single [`BytesPcodeExecutorStatePiece`].
//!
//! Corresponds to `ghidra.pcode.exec.BytesPcodeExecutorState`.
//!
//! Java's class is small: `extends DefaultPcodeExecutorState<byte[]>`, adding only two
//! constructors (one public, building a fresh [`BytesPcodeExecutorStatePiece`]; one protected,
//! taking an already-built piece of the general `PcodeExecutorStatePiece<byte[], byte[]>` shape)
//! and an overridden `fork`.
//!
//! The protected constructor matters beyond mere faithfulness: Ghidra's
//! `ghidra.app.emulator.AdaptedEmulator` defines a `AdaptedBytesPcodeExecutorState extends
//! BytesPcodeExecutorState`, constructed via that protected constructor with a *different* piece
//! subtype (`AdaptedBytesPcodeExecutorStatePiece`, also extending `AbstractBytesPcodeExecutorStatePiece`
//! but not `BytesPcodeExecutorStatePiece` itself). Neither `AdaptedEmulator` nor its nested classes
//! are ported yet, but to leave the door open for that future port, this struct is generic over the
//! delegate piece type `P: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>` -- exactly mirroring how
//! [`DefaultPcodeExecutorState`] itself is generic over its own delegate piece type in this port,
//! and how Java's protected constructor accepts the general piece interface rather than the
//! concrete `BytesPcodeExecutorStatePiece` type.
//!
//! Following the composition-over-inheritance convention this crate already uses throughout
//! `pcode::exec` (see [`DefaultPcodeExecutorState`]'s own module docs), this struct embeds a
//! [`DefaultPcodeExecutorState<Vec<u8>, P>`] and implements [`PcodeExecutorStatePiece<Vec<u8>,
//! Vec<u8>>`] by forwarding every method to it.
//!
//! Deviation forced by the same generic-`P` shape: Java's override
//! ```java
//! public BytesPcodeExecutorState fork(PcodeStateCallbacks cb) {
//!     return new BytesPcodeExecutorState(piece.fork(cb));
//! }
//! ```
//! calls the piece's own (dynamically dispatched) `fork`, which for a real
//! `BytesPcodeExecutorStatePiece` resolves to that class's override. In this port,
//! [`PcodeExecutorStatePiece::fork`] is a trait method generic over the *caller's* callback type,
//! which [`BytesPcodeExecutorStatePiece`] deliberately leaves at the trait's panicking default (see
//! that module's own docs) in favor of a same-callback-type inherent `fork` method usable only when
//! the concrete piece type is statically known. This struct follows the identical pattern: its
//! [`PcodeExecutorStatePiece::fork`] trait implementation is left at the (panicking) default for
//! arbitrary generic `P`, while a real, working [`fork`](Self::fork) inherent method is provided in
//! a separate `impl` block specialized to `P = BytesPcodeExecutorStatePiece<CB>`, calling that
//! piece's own inherent `fork`.

use std::sync::Arc;

use crate::pcode::exec::abstract_pcode_executor_state::AbstractPcodeExecutorState;
use crate::pcode::exec::bytes_pcode_executor_state_piece::BytesPcodeExecutorStatePiece;
use crate::pcode::exec::default_pcode_executor_state::DefaultPcodeExecutorState;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::mem_buffer::MemBuffer;

/// A p-code executor state composing a single [`BytesPcodeExecutorStatePiece`] (or, for a future
/// subclass port, some other piece over the same `Vec<u8>` address/value domain).
///
/// Port of `ghidra.pcode.exec.BytesPcodeExecutorState`. `P` is the concrete type of the delegate
/// piece -- see the module docs for why it is generic rather than hardcoded to
/// [`BytesPcodeExecutorStatePiece`].
pub struct BytesPcodeExecutorState<P>
where
    P: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
{
    inner: DefaultPcodeExecutorState<Vec<u8>, P>,
}

impl<P> BytesPcodeExecutorState<P>
where
    P: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
{
    /// Construct a state wrapping an already-built delegate piece.
    ///
    /// Port of the protected constructor `BytesPcodeExecutorState(PcodeExecutorStatePiece<byte[],
    /// byte[]> piece)`. Exposed as `pub` (rather than `pub(crate)`) since Java's `protected` grants
    /// access to subclasses regardless of package, and a future port of `AdaptedEmulator`'s
    /// `AdaptedBytesPcodeExecutorState` (see the module docs) would live in a different module.
    pub fn from_piece(piece: P) -> Self {
        Self { inner: DefaultPcodeExecutorState::new(piece) }
    }

    /// The embedded delegate piece.
    pub fn piece(&self) -> &P {
        self.inner.base().piece()
    }
}

impl<CB> BytesPcodeExecutorState<BytesPcodeExecutorStatePiece<CB>>
where
    CB: PcodeStateCallbacks,
{
    /// Create the state for the given language.
    ///
    /// Port of `BytesPcodeExecutorState(Language, PcodeStateCallbacks)`, which is `super(new
    /// BytesPcodeExecutorStatePiece(language, cb))`.
    pub fn new(language: Arc<dyn Language>, cb: Arc<CB>) -> Self {
        Self::from_piece(BytesPcodeExecutorStatePiece::new(language, cb))
    }

    /// Fork the state, producing an independent copy that shares no mutable storage with this one.
    ///
    /// Port of the overridden `fork(PcodeStateCallbacks)`:
    /// ```java
    /// public BytesPcodeExecutorState fork(PcodeStateCallbacks cb) {
    ///     return new BytesPcodeExecutorState(piece.fork(cb));
    /// }
    /// ```
    /// See the module docs for why this is an inherent method (usable only when the delegate
    /// piece's concrete type -- and thus its callback type -- is statically known as
    /// `BytesPcodeExecutorStatePiece<CB>`) rather than an override of the
    /// [`PcodeExecutorStatePiece::fork`] trait method.
    pub fn fork(&self, cb: Arc<CB>) -> Self {
        Self::from_piece(self.piece().fork(cb))
    }
}

impl<P> PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for BytesPcodeExecutorState<P>
where
    P: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
{
    fn get_language(&self) -> Box<dyn Language> {
        self.inner.get_language()
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        self.inner.get_address_arithmetic()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        self.inner.get_arithmetic()
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        self.inner.stream_pieces()
    }

    fn set_var_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        quantize: bool,
        val: &Vec<u8>,
    ) {
        self.inner.set_var_abstract(space, offset, size, quantize, val);
    }

    fn set_var_internal_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        val: &Vec<u8>,
    ) {
        self.inner.set_var_internal_abstract(space, offset, size, val);
    }

    fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &Vec<u8>) {
        self.inner.set_var(space, offset, size, quantize, val);
    }

    fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &Vec<u8>) {
        self.inner.set_var_internal(space, offset, size, val);
    }

    fn get_var_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        quantize: bool,
        reason: Reason,
    ) -> Vec<u8> {
        self.inner.get_var_abstract(space, offset, size, quantize, reason)
    }

    fn get_var_internal_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        reason: Reason,
    ) -> Vec<u8> {
        self.inner.get_var_internal_abstract(space, offset, size, reason)
    }

    fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> Vec<u8> {
        self.inner.get_var(space, offset, size, quantize, reason)
    }

    fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> Vec<u8> {
        self.inner.get_var_internal(space, offset, size, reason)
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
        self.inner.get_register_values()
    }

    fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        self.inner.get_concrete_buffer(address, purpose)
    }

    fn clear(&mut self) {
        self.inner.clear();
    }

    fn get_next_entry_internal(&self, space: &Arc<AddressSpace>, offset: i64) -> Option<(i64, Vec<u8>)> {
        // Java's `AbstractPcodeExecutorState.getNextEntryInternal` forwards to the piece, and
        // neither `DefaultPcodeExecutorState` nor `BytesPcodeExecutorState` overrides it -- ported
        // faithfully by forwarding to `inner` here, exactly as `inner` itself forwards to its own
        // embedded piece.
        self.inner.get_next_entry_internal(space, offset)
    }

    // Java's `AbstractPcodeExecutorState` does not override the abstract-domain
    // `getNextEntryInternal(AddressSpace, T)`, so, as with `DefaultPcodeExecutorState`, this is left
    // to the trait's own default (which panics, as in Java).
}

impl<P> PcodeExecutorState<Vec<u8>> for BytesPcodeExecutorState<P> where P: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::utils::bytes_to_long;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::pcode::OpCode;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Little-endian `Vec<u8>` test arithmetic for the mock piece below (the real
    /// `BytesPcodeExecutorStatePiece` is exercised by the last test).
    struct BytesArithmetic;

    impl PcodeArithmetic<Vec<u8>> for BytesArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &Vec<u8>) -> Vec<u8> {
            unimplemented!("not exercised by these tests")
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &Vec<u8>,
            _sizein2: i32,
            _in2: &Vec<u8>,
        ) -> Vec<u8> {
            unimplemented!("not exercised by these tests")
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }
        fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
            value.to_vec()
        }
        fn to_concrete(&self, value: &Vec<u8>, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.clone())
        }
        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    /// A minimal mock piece over the `Vec<u8>`/`Vec<u8>` domain, used to exercise
    /// `BytesPcodeExecutorState<P>`'s forwarding for an arbitrary `P` -- standing in for
    /// `BytesPcodeExecutorStatePiece` itself, whose real construction path panics today because it
    /// depends on the not-yet-ported `BytesPcodeArithmetic` (see the dedicated test below).
    #[derive(Default, Clone)]
    struct MockBytesPiece {
        cells: RefCell<HashMap<i64, Vec<u8>>>,
        forked: bool,
    }

    impl ErasedPcodeExecutorStatePiece for MockBytesPiece {}

    impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for MockBytesPiece {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            Arc::new(BytesArithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            Arc::new(BytesArithmetic)
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
            offset: &Vec<u8>,
            _size: i32,
            _quantize: bool,
            val: &Vec<u8>,
        ) {
            // The abstract offset's length is `space.pointer_size()` bytes (4 for the 32-bit test
            // `ram_space()`), not necessarily 8 -- `bytes_to_long` (little-endian, matching
            // `BytesArithmetic`'s own endian) handles any length, unlike a fixed-width
            // `i64::from_le_bytes` conversion.
            let key = bytes_to_long(offset, offset.len(), false);
            self.cells.borrow_mut().insert(key, val.clone());
        }
        fn set_var_internal_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            val: &Vec<u8>,
        ) {
            self.set_var_abstract(space, offset, size, false, val);
        }
        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> Vec<u8> {
            // The abstract offset's length is `space.pointer_size()` bytes (4 for the 32-bit test
            // `ram_space()`), not necessarily 8 -- `bytes_to_long` (little-endian, matching
            // `BytesArithmetic`'s own endian) handles any length, unlike a fixed-width
            // `i64::from_le_bytes` conversion.
            let key = bytes_to_long(offset, offset.len(), false);
            self.cells.borrow().get(&key).cloned().unwrap_or_default()
        }
        fn get_var_internal_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            reason: Reason,
        ) -> Vec<u8> {
            self.get_var_abstract(space, offset, size, false, reason)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
            vec![]
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

    fn offset_bytes(offset: i64) -> Vec<u8> {
        offset.to_le_bytes().to_vec()
    }

    #[test]
    fn set_var_and_get_var_round_trip_through_the_embedded_piece() {
        let mut state = BytesPcodeExecutorState::from_piece(MockBytesPiece::default());
        let ram = ram_space();
        state.set_var(&ram, 0x100, 4, false, &vec![1, 2, 3, 4]);
        assert_eq!(state.get_var(&ram, 0x100, 4, false, Reason::ExecuteRead), vec![1, 2, 3, 4]);
    }

    #[test]
    fn set_var_abstract_and_get_var_abstract_round_trip_through_the_embedded_piece() {
        // Exercises DefaultPcodeExecutorState's identity extractAddress by way of
        // BytesPcodeExecutorState's own forwarding: the Vec<u8> "address" reaches the mock piece
        // unmodified.
        let mut state = BytesPcodeExecutorState::from_piece(MockBytesPiece::default());
        let ram = ram_space();
        let addr = offset_bytes(0x2000);
        state.set_var_abstract(&ram, &addr, 4, false, &vec![0xAA]);
        assert_eq!(state.get_var_abstract(&ram, &addr, 4, false, Reason::Inspect), vec![0xAA]);
    }

    #[test]
    fn clear_delegates_to_the_embedded_piece() {
        let mut state = BytesPcodeExecutorState::from_piece(MockBytesPiece::default());
        let ram = ram_space();
        state.set_var(&ram, 0x10, 4, false, &vec![42]);
        assert_eq!(state.get_var(&ram, 0x10, 4, false, Reason::Inspect), vec![42]);
        state.clear();
        assert_eq!(state.get_var(&ram, 0x10, 4, false, Reason::Inspect), Vec::<u8>::new());
    }

    #[test]
    fn arithmetic_and_address_arithmetic_both_come_from_the_piece() {
        let state = BytesPcodeExecutorState::from_piece(MockBytesPiece::default());
        assert_eq!(state.get_arithmetic().size_of(&vec![0u8; 3]), 3);
        assert_eq!(state.get_address_arithmetic().size_of(&vec![0u8; 3]), 3);
    }

    #[test]
    fn piece_accessor_exposes_the_embedded_delegate() {
        let mut state = BytesPcodeExecutorState::from_piece(MockBytesPiece::default());
        let ram = ram_space();
        state.set_var(&ram, 0x30, 1, false, &vec![9]);
        assert_eq!(state.piece().cells.borrow().get(&0x30), Some(&vec![9]));
    }

    /// Faithful reproduction of the "fork through the trait" gap documented in the module docs:
    /// for a generic (not statically-known-concrete) piece type, calling `fork` through the
    /// [`PcodeExecutorStatePiece`] trait method hits the trait's own panicking default, because
    /// `MockBytesPiece` (standing in for any piece that -- like `BytesPcodeExecutorStatePiece`
    /// itself -- only provides an inherent `fork`, not a trait override) never overrides that
    /// method either. Verified narrowly with `catch_unwind` around just the one call, per this
    /// project's test-verification convention.
    #[test]
    fn forking_a_generic_piece_through_the_trait_method_panics() {
        let state = BytesPcodeExecutorState::from_piece(MockBytesPiece::default());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            PcodeExecutorStatePiece::fork(&state, &crate::pcode::exec::pcode_state_callbacks::NONE)
        }));
        assert!(result.is_err(), "expected the trait's panicking default fork to be hit");
    }

    /// Exercises the real construction and fork path through the concrete
    /// [`BytesPcodeExecutorStatePiece`] (Java's public constructor
    /// `BytesPcodeExecutorState(Language, PcodeStateCallbacks)` and its `fork` override).
    #[test]
    fn real_piece_constructs_round_trips_and_forks_independently() {
        use crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::testing::test_language;
        use crate::pcode::exec::pcode_state_callbacks::NONE;

        let language = test_language();
        let ram = language
            .get_address_factory()
            .get_address_spaces()
            .into_iter()
            .find(|s| s.name() == "ram")
            .unwrap();
        let mut state = BytesPcodeExecutorState::new(language, Arc::new(NONE));
        assert_eq!(state.get_arithmetic().get_endian(), Some(Endian::Little));

        state.set_var(&ram, 0x20, 2, false, &vec![0xde, 0xad]);
        assert_eq!(state.get_var(&ram, 0x20, 2, false, Reason::Inspect), vec![0xde, 0xad]);

        let mut forked = state.fork(Arc::new(NONE));
        forked.set_var(&ram, 0x20, 1, false, &vec![0x00]);
        assert_eq!(forked.get_var(&ram, 0x20, 2, false, Reason::Inspect), vec![0x00, 0xad]);
        assert_eq!(state.get_var(&ram, 0x20, 2, false, Reason::Inspect), vec![0xde, 0xad]);
    }
}

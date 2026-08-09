//! A set of callbacks available for state changes during p-code execution.
//!
//! Corresponds to `ghidra.pcode.exec.PcodeStateCallbacks`.
//!
//! When dealing with emulation (as opposed to just p-code execution), consider
//! `PcodeEmulationCallbacks` (not yet ported) instead. These callbacks exist to avert the need to
//! extend `PcodeExecutorState`s/`PcodeExecutorStatePiece`s just to introduce integration-driven
//! behaviors, e.g., lazily loading state from an external machine-state snapshot via
//! [`PcodeStateCallbacks::read_uninitialized`].
//!
//! Java overloads `dataWritten`/`delegateDataWritten`/`readUninitialized`/
//! `delegateReadUninitialized` by parameter type (abstract addressing via `AddressSpace` + an
//! offset of domain `A`, vs. concrete addressing via `Address`). Rust has no overloading, so the
//! abstract-addressing methods carry an `_abstract` suffix here.

use std::sync::Arc;

use crate::pcode::exec::pcode_arithmetic::Purpose;
use crate::pcode::seam_stubs::{PcodeExecutorStatePiece, Reason};
use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpace};

/// A set of callbacks available for state changes during p-code execution.
pub trait PcodeStateCallbacks {
    /// Data was written into the given state piece (abstract addressing).
    fn data_written_abstract<A, T>(
        &self,
        _piece: &dyn PcodeExecutorStatePiece<A, T>,
        _space: &Arc<AddressSpace>,
        _offset: &A,
        _length: i32,
        _value: &T,
    ) {
    }

    /// Typically used from within [`PcodeStateCallbacks::data_written_abstract`] to forward the
    /// call to the callback for concrete addressing, [`PcodeStateCallbacks::data_written`].
    fn delegate_data_written_abstract<A, T>(
        &self,
        piece: &dyn PcodeExecutorStatePiece<A, T>,
        space: &Arc<AddressSpace>,
        offset: &A,
        length: i32,
        value: &T,
    ) {
        let address = piece
            .get_address_arithmetic()
            .to_address(offset, space, Purpose::Store)
            .expect("offset could not be made concrete to delegate dataWritten");
        self.data_written(piece, &address, length, value);
    }

    /// Data was written into the given state piece (concrete addressing).
    fn data_written<A, T>(
        &self,
        _piece: &dyn PcodeExecutorStatePiece<A, T>,
        _address: &Address,
        _length: i32,
        _value: &T,
    ) {
    }

    /// Typically used from within [`PcodeStateCallbacks::data_written`] to forward the call to
    /// the callback for abstract addressing, [`PcodeStateCallbacks::data_written_abstract`].
    fn delegate_data_written<A, T>(
        &self,
        piece: &dyn PcodeExecutorStatePiece<A, T>,
        address: &Address,
        length: i32,
        value: &T,
    ) {
        let offset = piece.get_address_arithmetic().from_const_address(address);
        self.data_written_abstract(piece, address.space(), &offset, length, value);
    }

    /// The executor is preparing to read from uninitialized portions of the given state piece
    /// (abstract addressing).
    ///
    /// This callback provides an opportunity for something to initialize the required portion
    /// lazily. In most cases, this should either return 0 indicating the requested portion
    /// remains uninitialized, or the full `length` indicating the full requested portion is now
    /// initialized. If, for some reason, the requested portion could only be partially
    /// initialized, this can return a smaller length. Partial initializations are only
    /// recognized from the starting offset.
    fn read_uninitialized_abstract<A, T>(
        &self,
        _piece: &dyn PcodeExecutorStatePiece<A, T>,
        _space: &Arc<AddressSpace>,
        _offset: &A,
        _length: i32,
        _reason: Reason,
    ) -> i32 {
        0
    }

    /// Typically used from within [`PcodeStateCallbacks::read_uninitialized_abstract`] to forward
    /// to the callback for concrete addressing, [`PcodeStateCallbacks::read_uninitialized`].
    fn delegate_read_uninitialized_abstract<A, T>(
        &self,
        piece: &dyn PcodeExecutorStatePiece<A, T>,
        space: &Arc<AddressSpace>,
        offset: &A,
        length: i32,
        reason: Reason,
    ) -> i32 {
        let l_offset = piece
            .get_address_arithmetic()
            .to_long(offset, Purpose::Load)
            .expect("offset could not be made concrete to delegate readUninitialized");
        let mut set = rng_set(space, l_offset, length);
        let remains = self.read_uninitialized(piece, &set, reason);
        if remains.has_same_addresses(&set) {
            return 0;
        }
        set.delete_set(&remains);
        match set.first_range() {
            Some(first) => first.length() as i32,
            None => 0,
        }
    }

    /// The executor is preparing to read from uninitialized portions of the given state piece
    /// (concrete addressing).
    ///
    /// This callback provides an opportunity for something to initialize the required portion
    /// lazily. This method must return the address set that remains uninitialized. If no part of
    /// the required portion was initialized, this should return a set with the same addresses as
    /// `set`. Otherwise, this should return a copy of `set` with the initialized parts removed.
    fn read_uninitialized<A, T>(
        &self,
        _piece: &dyn PcodeExecutorStatePiece<A, T>,
        set: &dyn AddressSetView,
        _reason: Reason,
    ) -> AddressSet {
        AddressSet::from_set(set)
    }

    /// Typically used from within [`PcodeStateCallbacks::read_uninitialized`] to forward to the
    /// callback for abstract addressing, [`PcodeStateCallbacks::read_uninitialized_abstract`].
    fn delegate_read_uninitialized<A, T>(
        &self,
        piece: &dyn PcodeExecutorStatePiece<A, T>,
        set: &dyn AddressSetView,
        reason: Reason,
    ) -> AddressSet {
        if set.is_empty() {
            return AddressSet::from_set(set);
        }
        let mut remains = AddressSet::from_set(set);
        for range in set.address_ranges() {
            let offset = piece.get_address_arithmetic().from_const_address(range.min_address());
            let l = self.read_uninitialized_abstract(
                piece,
                range.space(),
                &offset,
                range.length() as i32,
                reason,
            );
            if l == 0 {
                continue;
            }
            let end = range
                .min_address()
                .add(l as i64 - 1)
                .expect("initialized length overflowed the address range");
            remains.delete_range(range.min_address(), &end);
        }
        remains
    }
}

/// A convenience for constructing an address set from a varnode-like triple.
///
/// `length` is the size in bytes; a length of 0 yields an empty set.
pub fn rng_set(space: &Arc<AddressSpace>, offset: i64, length: i32) -> AddressSet {
    if length == 0 {
        return AddressSet::new();
    }
    let min = space.address(offset);
    let max = min
        .add(length as i64 - 1)
        .expect("range length overflowed the address space");
    AddressSet::from_start_end(min, max)
}

/// Check that the given piece has a required value domain.
///
/// Java's version exists to work around type erasure: a caller holding a piece with an unknown
/// (wildcard) value domain can check its runtime `Class` against a desired `T` and, if it
/// matches, treat the piece as `PcodeExecutorStatePiece<A, T>`. Rust generics are monomorphized
/// rather than erased, so a caller with `&dyn PcodeExecutorStatePiece<A, T>` already knows `T`
/// statically; this just re-checks the runtime domain name, for parity with the Java behavior of
/// rejecting a piece whose implementation reports a different value domain.
pub fn check_value_domain<'a, A, T>(
    piece: &'a dyn PcodeExecutorStatePiece<A, T>,
    domain: &str,
) -> Option<&'a dyn PcodeExecutorStatePiece<A, T>> {
    if piece.get_arithmetic().get_domain() == domain {
        Some(piece)
    } else {
        None
    }
}

/// Port of `PcodeStateCallbacks.NoPcodeStateCallbacks`: an implementation that does nothing, used
/// by [`NONE`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoPcodeStateCallbacks;

impl PcodeStateCallbacks for NoPcodeStateCallbacks {}

/// Port of `PcodeStateCallbacks.NONE`: callbacks that do nothing.
pub const NONE: NoPcodeStateCallbacks = NoPcodeStateCallbacks;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
    use crate::pcode::seam_stubs::ConcretionError;
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::OpCode;
    use std::cell::RefCell;

    /// Arithmetic over `i64`, used for both the address domain `A` and the value domain `T` in
    /// these tests. Only the members exercised by [`PcodeStateCallbacks`]'s default methods
    /// (`to_address`/`from_const_address`/`to_long`, all derived from `from_const_bytes`/
    /// `to_concrete`) need to behave correctly; the rest are never invoked.
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Big)
        }

        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64) -> i64 {
            unimplemented!("not exercised by PcodeStateCallbacks tests")
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
            unimplemented!("not exercised by PcodeStateCallbacks tests")
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
            bytes_to_long(value, value.len(), true)
        }

        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(long_to_bytes(*value, 8, true))
        }

        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    /// A minimal arithmetic-only piece. Only `get_address_arithmetic`/`get_arithmetic` are
    /// exercised by these tests (through `PcodeStateCallbacks`'s default delegation methods); the
    /// rest of [`PcodeExecutorStatePiece`]'s surface is irrelevant here.
    struct TestPiece;

    impl PcodeExecutorStatePiece<i64, i64> for TestPiece {
        fn get_language(&self) -> Box<dyn crate::program::model::lang::language::Language> {
            unimplemented!("not exercised by PcodeStateCallbacks tests")
        }

        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }

        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }

        fn stream_pieces(&self) -> Vec<&dyn crate::pcode::seam_stubs::ErasedPcodeExecutorStatePiece> {
            unimplemented!("not exercised by PcodeStateCallbacks tests")
        }

        fn set_var_abstract(&mut self, _space: &Arc<AddressSpace>, _offset: &i64, _size: i32, _quantize: bool, _val: &i64) {
            unimplemented!("not exercised by PcodeStateCallbacks tests")
        }

        fn set_var_internal_abstract(&mut self, _space: &Arc<AddressSpace>, _offset: &i64, _size: i32, _val: &i64) {
            unimplemented!("not exercised by PcodeStateCallbacks tests")
        }

        fn get_var_abstract(&self, _space: &Arc<AddressSpace>, _offset: &i64, _size: i32, _quantize: bool, _reason: Reason) -> i64 {
            unimplemented!("not exercised by PcodeStateCallbacks tests")
        }

        fn get_var_internal_abstract(&self, _space: &Arc<AddressSpace>, _offset: &i64, _size: i32, _reason: Reason) -> i64 {
            unimplemented!("not exercised by PcodeStateCallbacks tests")
        }

        fn get_register_values(&self) -> Vec<(crate::program::model::lang::register::RegisterRef, i64)> {
            unimplemented!("not exercised by PcodeStateCallbacks tests")
        }

        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn crate::program::model::mem::mem_buffer::MemBuffer> {
            unimplemented!("not exercised by PcodeStateCallbacks tests")
        }

        fn clear(&mut self) {
            unimplemented!("not exercised by PcodeStateCallbacks tests")
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn rng_set_matches_java_behavior() {
        let ram = ram_space();
        assert!(rng_set(&ram, 0x1000, 0).is_empty());

        let set = rng_set(&ram, 0x1000, 0x10);
        let range = set.first_range().expect("non-empty range");
        assert_eq!(range.min_address(), &ram.address(0x1000));
        assert_eq!(range.max_address(), &ram.address(0x100f));
        assert_eq!(range.length(), 0x10);
    }

    #[test]
    fn none_callbacks_are_all_no_ops() {
        let piece = TestPiece;
        let ram = ram_space();
        let addr = ram.address(0x2000);

        // Concrete dataWritten/readUninitialized on NONE do nothing observable; just confirm
        // they don't panic and readUninitialized reports the input as fully uninitialized.
        NONE.data_written(&piece, &addr, 4, &7i64);
        assert_eq!(NONE.read_uninitialized_abstract(&piece, &ram, &0x2000i64, 4, Reason::ExecuteRead), 0);

        let set = rng_set(&ram, 0x2000, 4);
        let remains = NONE.read_uninitialized(&piece, &set, Reason::ExecuteRead);
        assert!(remains.has_same_addresses(&set));
    }

    /// A spy that records `dataWritten` calls, mirroring how a real implementor overrides just
    /// one of the two addressing overloads and relies on `delegateDataWritten` to reach it from
    /// the other. Only the concretely-typed parameters (address/space/length) are recorded,
    /// since the trait's `A`/`T` domains are generic per call and can't be stored in a
    /// non-generic struct field.
    #[derive(Default)]
    struct RecordingCallbacks {
        concrete_writes: RefCell<Vec<(Address, i32)>>,
        abstract_writes: RefCell<Vec<(Arc<AddressSpace>, i32)>>,
    }

    impl PcodeStateCallbacks for RecordingCallbacks {
        fn data_written<A, T>(
            &self,
            _piece: &dyn PcodeExecutorStatePiece<A, T>,
            address: &Address,
            length: i32,
            _value: &T,
        ) {
            self.concrete_writes.borrow_mut().push((address.clone(), length));
        }

        fn data_written_abstract<A, T>(
            &self,
            _piece: &dyn PcodeExecutorStatePiece<A, T>,
            space: &Arc<AddressSpace>,
            _offset: &A,
            length: i32,
            _value: &T,
        ) {
            self.abstract_writes.borrow_mut().push((Arc::clone(space), length));
        }
    }

    #[test]
    fn delegate_data_written_abstract_forwards_to_concrete_address() {
        let piece = TestPiece;
        let ram = ram_space();
        let cb = RecordingCallbacks::default();

        cb.delegate_data_written_abstract(&piece, &ram, &0x2000i64, 4, &99i64);

        let writes = cb.concrete_writes.borrow();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0], (ram.address(0x2000), 4));
    }

    #[test]
    fn delegate_data_written_forwards_to_abstract_space() {
        let piece = TestPiece;
        let ram = ram_space();
        let addr = ram.address(0x3000);
        let cb = RecordingCallbacks::default();

        cb.delegate_data_written(&piece, &addr, 8, &42i64);

        let writes = cb.abstract_writes.borrow();
        assert_eq!(writes.len(), 1);
        assert!(Arc::ptr_eq(&writes[0].0, &ram));
        assert_eq!(writes[0].1, 8);
    }

    /// A spy whose `readUninitialized` (concrete addressing) simulates lazily initializing just
    /// the first 4 bytes of whatever range it's asked about.
    struct PartialInitCallbacks;

    impl PcodeStateCallbacks for PartialInitCallbacks {
        fn read_uninitialized<A, T>(
            &self,
            _piece: &dyn PcodeExecutorStatePiece<A, T>,
            set: &dyn AddressSetView,
            _reason: Reason,
        ) -> AddressSet {
            let mut remains = AddressSet::from_set(set);
            if let Some(first) = set.first_range() {
                let end = first.min_address().add(3).expect("test range in bounds");
                remains.delete_range(first.min_address(), &end);
            }
            remains
        }
    }

    #[test]
    fn delegate_read_uninitialized_abstract_reports_partial_initialization() {
        let piece = TestPiece;
        let ram = ram_space();
        let cb = PartialInitCallbacks;

        let initialized =
            cb.delegate_read_uninitialized_abstract(&piece, &ram, &0x4000i64, 16, Reason::ExecuteRead);
        assert_eq!(initialized, 4);
    }

    /// A spy whose `readUninitialized` (abstract addressing) always fully initializes whatever
    /// it's asked about.
    struct FullInitCallbacks;

    impl PcodeStateCallbacks for FullInitCallbacks {
        fn read_uninitialized_abstract<A, T>(
            &self,
            _piece: &dyn PcodeExecutorStatePiece<A, T>,
            _space: &Arc<AddressSpace>,
            _offset: &A,
            length: i32,
            _reason: Reason,
        ) -> i32 {
            length
        }
    }

    #[test]
    fn delegate_read_uninitialized_forwards_and_consumes_fully_initialized_range() {
        let piece = TestPiece;
        let ram = ram_space();
        let cb = FullInitCallbacks;
        let set = rng_set(&ram, 0x5000, 8);

        let remains = cb.delegate_read_uninitialized(&piece, &set, Reason::ExecuteRead);
        assert!(remains.is_empty());
    }

    #[test]
    fn check_value_domain_matches_by_domain_name() {
        let piece = TestPiece;
        let domain = piece.get_arithmetic().get_domain();

        assert!(check_value_domain(&piece, domain).is_some());
        assert!(check_value_domain(&piece, "not-a-real-domain").is_none());
    }
}

//! Storage for values of type `T`, addressed by offsets of type `A`.
//!
//! Corresponds to `ghidra.pcode.exec.PcodeExecutorStatePiece`.
//!
//! The typical pattern for implementing a state is to compose it from one or more state pieces.
//! Each piece must use the same address type and arithmetic. If more than one piece is needed,
//! they are composed using
//! [`PairedPcodeExecutorStatePiece`](crate::pcode::exec::paired_pcode_executor_state_piece::PairedPcodeExecutorStatePiece).
//! Once all the pieces are composed, the root piece can be wrapped to make a state using
//! `DefaultPcodeExecutorState` (not yet ported) or
//! [`PairedPcodeExecutorState`](crate::pcode::exec::paired_pcode_executor_state::PairedPcodeExecutorState).
//! The latter corrects the address type to be a pair so it matches the type of values.
//!
//! Java overloads `setVar`/`setVarInternal`/`getVar`/`getVarInternal`/`getNextEntryInternal` on
//! how the variable is described: abstract addressing via an `AddressSpace` plus an offset of
//! domain `A`, concrete addressing via an `AddressSpace` plus a `long`, or via an
//! [`Address`]/[`Varnode`]/[`Register`](RegisterRef). Rust has no overloading, so the
//! abstract-addressing methods carry an `_abstract` suffix and the others a suffix naming what
//! describes the variable; the plain names belong to the `AddressSpace` + `long` forms, matching
//! the convention in
//! [`PcodeStateCallbacks`](crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks).

use std::sync::Arc;

use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::range::AddressRange;
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::mem_buffer::MemBuffer;
use crate::program::model::pcode::Varnode;
use crate::program::seam_stubs::RegisterValue;

/// Reasons for reading state.
///
/// Port of the nested enum `PcodeExecutorStatePiece.Reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// The value is needed as the default program counter or disassembly context.
    ReInit,
    /// The value is being read by the emulator as data in the course of execution.
    ExecuteRead,
    /// The value is being decoded by the emulator as an instruction for execution.
    ExecuteDecode,
    /// The value is being inspected by something other than an emulator.
    Inspect,
}

/// A type-erased `PcodeExecutorStatePiece<?, ?>`, as produced by
/// [`PcodeExecutorStatePiece::stream_pieces`].
///
/// Java's wildcard existential type (a piece over *any* address/value domain) has no
/// generic-preserving Rust shape; since nothing downstream inspects an erased piece's members yet,
/// this is a bare, object-safe marker that concrete leaf pieces implement.
pub trait ErasedPcodeExecutorStatePiece {}

/// An interface that provides storage for values of type `T`, addressed by offsets of type `A`.
///
/// `get_address_arithmetic`/`get_arithmetic` return an owned `Arc<dyn PcodeArithmetic<_>>` rather
/// than a borrow, since a composing piece (like
/// [`PairedPcodeExecutorStatePiece`](crate::pcode::exec::paired_pcode_executor_state_piece::PairedPcodeExecutorStatePiece))
/// needs to cache the result in its own fields without borrowing from its delegates (which would
/// make it self-referential).
///
/// [`fork`](Self::fork) carries a `where Self: Sized` bound and a generic `CB` parameter (rather
/// than `&dyn PcodeStateCallbacks`) because
/// [`PcodeStateCallbacks`]'s methods are generic per call (mirroring Java's per-call type
/// parameters), which makes that trait itself not object-safe -- a `&dyn PcodeStateCallbacks`
/// parameter is simply not expressible. The `Self: Sized` bound excludes `fork` from this trait's
/// vtable without otherwise affecting its object safety, so `&dyn PcodeExecutorStatePiece<A, T>`
/// (as used by [`PcodeStateCallbacks`]'s own default methods) remains valid; `fork` is only ever
/// called on a statically-known concrete (or generic-but-`Sized`) piece type.
pub trait PcodeExecutorStatePiece<A, T> {
    /// Construct a range, if only to verify the range is valid.
    ///
    /// Port of `PcodeExecutorStatePiece.checkRange(AddressSpace, long, int)`. Panics where Java
    /// throws `IllegalArgumentException`.
    fn check_range(&self, space: &Arc<AddressSpace>, offset: i64, size: i32) {
        if space.space_type() == AddressSpaceType::Constant {
            return;
        }
        let valid = space
            .checked_address(offset)
            .ok()
            .and_then(|start| AddressRange::from_start_len(start, size as u64).ok())
            .is_some();
        if !valid {
            panic!("Given offset and length exceeds address space");
        }
    }

    /// Get the language defining the address spaces of this state piece.
    fn get_language(&self) -> Box<dyn Language>;

    /// Get the arithmetic used to manipulate addresses of the type used by this state.
    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<A>>;

    /// Get the arithmetic used to manipulate values of the type stored by this state.
    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>>;

    /// Stream over the pieces within.
    ///
    /// If this piece is not a composition of others, then simply yield this piece in a singleton.
    /// Otherwise, yield the component pieces. (Do not include the composition itself, just the
    /// component pieces.)
    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece>;

    /// Create a deep copy of this state.
    ///
    /// Java's default throws `UnsupportedOperationException`.
    fn fork<CB: PcodeStateCallbacks>(&self, _cb: &CB) -> Self
    where
        Self: Sized,
    {
        unimplemented!("PcodeExecutorStatePiece.fork has no default implementation")
    }

    /// Set the value of a variable, addressed by an offset in the abstract domain `A`.
    ///
    /// Port of `setVar(AddressSpace, A, int, boolean, T)`. `quantize` requests quantization to the
    /// language's "addressable unit".
    fn set_var_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &A,
        size: i32,
        quantize: bool,
        val: &T,
    );

    /// Set the value of a variable without issuing callbacks, addressed by an offset in the
    /// abstract domain `A`.
    ///
    /// Port of `setVarInternal(AddressSpace, A, int, T)`.
    fn set_var_internal_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &A,
        size: i32,
        val: &T,
    );

    /// Set the value of a variable.
    ///
    /// Port of `setVar(AddressSpace, long, int, boolean, T)`.
    fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &T) {
        self.check_range(space, offset, size);
        let a_offset = self.get_address_arithmetic().from_const_u64(offset as u64, space.pointer_size());
        self.set_var_abstract(space, &a_offset, size, quantize, val);
    }

    /// Set the value of a variable without issuing callbacks.
    ///
    /// Port of `setVarInternal(AddressSpace, long, int, T)`.
    fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &T) {
        let a_offset = self.get_address_arithmetic().from_const_u64(offset as u64, space.pointer_size());
        self.set_var_internal_abstract(space, &a_offset, size, val);
    }

    /// Get the value of a variable, addressed by an offset in the abstract domain `A`.
    ///
    /// Port of `getVar(AddressSpace, A, int, boolean, Reason)`.
    fn get_var_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &A,
        size: i32,
        quantize: bool,
        reason: Reason,
    ) -> T;

    /// Get the value of a variable without issuing callbacks, addressed by an offset in the
    /// abstract domain `A`.
    ///
    /// Port of `getVarInternal(AddressSpace, A, int, Reason)`.
    fn get_var_internal_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &A,
        size: i32,
        reason: Reason,
    ) -> T;

    /// Get the value of a variable.
    ///
    /// Port of `getVar(AddressSpace, long, int, boolean, Reason)`. This method is typically used
    /// for reading memory variables.
    fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> T {
        self.check_range(space, offset, size);
        let a_offset = self.get_address_arithmetic().from_const_u64(offset as u64, space.pointer_size());
        self.get_var_abstract(space, &a_offset, size, quantize, reason)
    }

    /// Get the value of a variable without issuing callbacks.
    ///
    /// Port of `getVarInternal(AddressSpace, long, int, Reason)`.
    fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> T {
        let a_offset = self.get_address_arithmetic().from_const_u64(offset as u64, space.pointer_size());
        self.get_var_internal_abstract(space, &a_offset, size, reason)
    }

    /// Get the entry at or after a given (abstract) offset, without issuing callbacks.
    ///
    /// Port of `getNextEntryInternal(AddressSpace, A)`. (Optional operation.) For pieces where
    /// each value is effective over a range, it is common to use an internal map (vice a byte
    /// array). When serializing the state, or otherwise seeking a complete examination, it is
    /// useful to retrieve those internal entries. Java's default throws
    /// `UnsupportedOperationException`; an implementor returns `None` where Java returns `null`.
    fn get_next_entry_internal_abstract(
        &self,
        _space: &Arc<AddressSpace>,
        _offset: &A,
    ) -> Option<(A, T)> {
        unimplemented!("PcodeExecutorStatePiece.getNextEntryInternal has no default implementation")
    }

    /// Get the entry at or after a given offset, without issuing callbacks.
    ///
    /// Port of `getNextEntryInternal(AddressSpace, long)`. See
    /// [`get_next_entry_internal_abstract`](Self::get_next_entry_internal_abstract). The returned
    /// entry *must* be for the given space; if no such entry exists, return `None`.
    fn get_next_entry_internal(&self, _space: &Arc<AddressSpace>, _offset: i64) -> Option<(i64, T)> {
        unimplemented!("PcodeExecutorStatePiece.getNextEntryInternal has no default implementation")
    }

    /// Set the value of a register variable.
    ///
    /// Port of `setVar(Register, T)`. Like Java's default, it quantizes.
    fn set_var_register(&mut self, reg: &RegisterRef, val: &T) {
        let (space, offset, size) = {
            let reg = reg.borrow();
            let address = reg.address();
            (Arc::clone(address.space()), address.offset(), reg.minimum_byte_size())
        };
        self.set_var(&space, offset, size, true, val);
    }

    /// Get the value of a register variable.
    ///
    /// Port of `getVar(Register, Reason)`.
    fn get_var_register(&self, reg: &RegisterRef, reason: Reason) -> T {
        let (space, offset, size) = {
            let reg = reg.borrow();
            let address = reg.address();
            (Arc::clone(address.space()), address.offset(), reg.minimum_byte_size())
        };
        self.get_var(&space, offset, size, true, reason)
    }

    /// Set the value of a variable described by a [`Varnode`].
    ///
    /// Port of `setVar(Varnode, T)`. Like Java's default, it quantizes.
    fn set_var_varnode(&mut self, var: &Varnode, val: &T) {
        self.set_var(var.get_address().space(), var.get_offset(), var.get_size(), true, val);
    }

    /// Get the value of a variable described by a [`Varnode`].
    ///
    /// Port of `getVar(Varnode, Reason)`.
    fn get_var_varnode(&self, var: &Varnode, reason: Reason) -> T {
        self.get_var(var.get_address().space(), var.get_offset(), var.get_size(), true, reason)
    }

    /// Set the value of a variable at the given address.
    ///
    /// Port of `setVar(Address, int, boolean, T)`.
    fn set_var_address(&mut self, address: &Address, size: i32, quantize: bool, val: &T) {
        let space = Arc::clone(address.space());
        self.set_var(&space, address.offset(), size, quantize, val);
    }

    /// Get the value of a variable at the given address.
    ///
    /// Port of `getVar(Address, int, boolean, Reason)`. This method is typically used for reading
    /// memory variables.
    fn get_var_address(&self, address: &Address, size: i32, quantize: bool, reason: Reason) -> T {
        self.get_var(address.space(), address.offset(), size, quantize, reason)
    }

    /// Get all register values known to this state.
    ///
    /// When the state acts as a cache, it should only return those cached.
    ///
    /// Returns a `Vec` of pairs rather than a `HashMap`, since [`Register`](RegisterRef)'s Rust
    /// port is `Rc<RefCell<Register>>`, and `RefCell` does not implement `Hash` (interior
    /// mutability would make cached hashes unsound), so `RegisterRef` cannot be a `HashMap` key.
    fn get_register_values(&self) -> Vec<(RegisterRef, T)>;

    /// Bind a buffer of concrete bytes at the given start address.
    fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer>;

    /// Quantize the given offset to the language's "addressable unit".
    fn quantize_offset(&self, space: &Arc<AddressSpace>, offset: i64) -> i64 {
        space.truncate_addressable_word_offset(offset) * space.unit_size() as i64
    }

    /// Erase the entire state or piece.
    ///
    /// This is generally only useful when the state is itself a cache to another object. This will
    /// ensure the state is reading from that object rather than a stale cache. If this is not a
    /// cache, this could in fact clear the whole state, and the machine using it will be left in
    /// the dark.
    fn clear(&mut self);

    /// Convenience to set a variable to a concrete value.
    fn set_concrete(&mut self, address: &Address, value: &[u8]) {
        let val = self.get_arithmetic().from_const_bytes(value);
        self.set_var_address(address, value.len() as i32, false, &val);
    }

    /// Convenience to inspect the concrete value of a variable.
    ///
    /// Java throws `ConcretionError` if the value cannot be made concrete; this returns it as an
    /// `Err`, matching [`PcodeArithmetic::to_concrete`].
    fn inspect_concrete(&self, address: &Address, size: i32) -> Result<Vec<u8>, ConcretionError> {
        let value = self.get_var_address(address, size, false, Reason::Inspect);
        self.get_arithmetic().to_concrete(&value, Purpose::Inspect)
    }

    /// Convenience to set a variable to a concrete value as a big integer.
    ///
    /// Java's `BigInteger` maps to `i128` throughout this port.
    fn set_big_integer(&mut self, address: &Address, size: i32, value: i128) {
        let val = self.get_arithmetic().from_const_big_int_default(value, size);
        self.set_var_address(address, size, false, &val);
    }

    /// Convenience to inspect the concrete value of a variable as a big integer.
    fn inspect_big_integer(&self, address: &Address, size: i32) -> Result<i128, ConcretionError> {
        let value = self.get_var_address(address, size, false, Reason::Inspect);
        self.get_arithmetic().to_big_integer(&value, Purpose::Inspect)
    }

    /// Convenience to set a variable to a concrete value as an `i64` (Java's `long`).
    fn set_long(&mut self, address: &Address, value: i64) {
        let val = self.get_arithmetic().from_const_u64(value as u64, 8);
        self.set_var_address(address, 8, false, &val);
    }

    /// Convenience to inspect the concrete value of a variable as an `i64` (Java's `long`).
    fn inspect_long(&self, address: &Address) -> Result<i64, ConcretionError> {
        let value = self.get_var_address(address, 8, false, Reason::Inspect);
        self.get_arithmetic().to_long(&value, Purpose::Inspect)
    }

    /// Convenience to set a variable to a concrete value as an `i32` (Java's `int`).
    fn set_int(&mut self, address: &Address, value: i32) {
        let val = self.get_arithmetic().from_const_u64(value as u32 as u64, 4);
        self.set_var_address(address, 4, false, &val);
    }

    /// Convenience to inspect the concrete value of a variable as an `i32` (Java's `int`).
    fn inspect_int(&self, address: &Address) -> Result<i32, ConcretionError> {
        let value = self.get_var_address(address, 4, false, Reason::Inspect);
        Ok(self.get_arithmetic().to_long(&value, Purpose::Inspect)? as i32)
    }

    /// Convenience to set a variable to a concrete value as an `i16` (Java's `short`).
    fn set_short(&mut self, address: &Address, value: i16) {
        let val = self.get_arithmetic().from_const_u64(value as u16 as u64, 2);
        self.set_var_address(address, 2, false, &val);
    }

    /// Convenience to inspect the concrete value of a variable as an `i16` (Java's `short`).
    fn inspect_short(&self, address: &Address) -> Result<i16, ConcretionError> {
        let value = self.get_var_address(address, 2, false, Reason::Inspect);
        Ok(self.get_arithmetic().to_long(&value, Purpose::Inspect)? as i16)
    }

    /// Convenience to set a variable to a concrete value as an `i8` (Java's `byte`).
    fn set_byte(&mut self, address: &Address, value: i8) {
        let val = self.get_arithmetic().from_const_u64(value as u8 as u64, 1);
        self.set_var_address(address, 1, false, &val);
    }

    /// Convenience to inspect the concrete value of a variable as an `i8` (Java's `byte`).
    fn inspect_byte(&self, address: &Address) -> Result<i8, ConcretionError> {
        let value = self.get_var_address(address, 1, false, Reason::Inspect);
        Ok(self.get_arithmetic().to_long(&value, Purpose::Inspect)? as i8)
    }

    /// Convenience to set a register variable to a concrete value as a [`RegisterValue`].
    ///
    /// **NOTE:** The register from the given value does not have to match the given register, but
    /// their *sizes* should at least match. This permits simpler moving of values from one
    /// register to another. If the sizes do not match, the behavior is undefined.
    fn set_register_value(&mut self, register: &RegisterRef, value: &dyn RegisterValue) {
        let val = self.get_arithmetic().from_const_register_value(value);
        self.set_var_register(register, &val);
    }

    /// Convenience to set a register variable to a concrete value as a [`RegisterValue`], using
    /// that value's own register.
    ///
    /// Port of `setRegisterValue(RegisterValue)`; Java overloads on arity, so this carries the
    /// `_of` suffix.
    fn set_register_value_of(&mut self, value: &dyn RegisterValue) {
        let register = value.get_register();
        self.set_register_value(&register, value);
    }

    /// Convenience to inspect the concrete value of a register variable as a [`RegisterValue`].
    ///
    /// Returns `(register, unsigned big-integer value)` rather than a `RegisterValue`, matching
    /// [`PcodeArithmetic::to_register_value`] pending a constructible `RegisterValue` port.
    fn inspect_register_value(
        &self,
        register: &RegisterRef,
    ) -> Result<(RegisterRef, i128), ConcretionError> {
        let value = self.get_var_register(register, Reason::Inspect);
        self.get_arithmetic().to_register_value(register, &value, Purpose::Inspect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::Register;
    use crate::program::model::pcode::OpCode;

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

    /// A leaf piece backed by a map from offset to value, recording every abstract-addressing
    /// call so the tests can check what the default methods routed down to.
    #[derive(Default)]
    struct MapPiece {
        cells: HashMap<i64, i64>,
        /// `(offset, size, quantize)` of each `set_var_abstract` call.
        writes: RefCell<Vec<(i64, i32, bool)>>,
        /// `(offset, size, quantize)` of each `get_var_abstract` call.
        reads: RefCell<Vec<(i64, i32, bool)>>,
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
            size: i32,
            quantize: bool,
            val: &i64,
        ) {
            self.writes.borrow_mut().push((*offset, size, quantize));
            self.cells.insert(*offset, *val);
        }

        fn set_var_internal_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            val: &i64,
        ) {
            self.set_var_abstract(space, offset, size, false, val);
        }

        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            quantize: bool,
            _reason: Reason,
        ) -> i64 {
            self.reads.borrow_mut().push((*offset, size, quantize));
            *self.cells.get(offset).unwrap_or(&0)
        }

        fn get_var_internal_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            reason: Reason,
        ) -> i64 {
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

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 1)
    }

    #[test]
    fn check_range_accepts_in_bounds_and_skips_the_constant_space() {
        let piece = MapPiece::default();
        let ram = ram_space();

        // Java: an in-bounds offset+length constructs an AddressRangeImpl without throwing.
        piece.check_range(&ram, 0x1000, 8);
        // Java: the last byte of the space is still a valid one-byte range.
        piece.check_range(&ram, 0xffff_ffff, 1);
        // Java: constant space returns immediately, without validating anything.
        piece.check_range(&const_space(), -1, 0x7fff_ffff);
    }

    #[test]
    #[should_panic(expected = "Given offset and length exceeds address space")]
    fn check_range_rejects_a_range_running_past_the_end_of_the_space() {
        // Java throws IllegalArgumentException: 0xfffffffe + 8 bytes overflows a 32-bit space.
        MapPiece::default().check_range(&ram_space(), 0xffff_fffe, 8);
    }

    #[test]
    fn set_var_and_get_var_by_address_route_to_the_abstract_form() {
        let mut piece = MapPiece::default();
        let ram = ram_space();
        let address = ram.address(0x2000);

        piece.set_var_address(&address, 4, false, &0x1234);

        assert_eq!(piece.get_var_address(&address, 4, false, Reason::ExecuteRead), 0x1234);
        assert_eq!(piece.writes.borrow().as_slice(), &[(0x2000, 4, false)]);
        assert_eq!(piece.reads.borrow().as_slice(), &[(0x2000, 4, false)]);
    }

    #[test]
    fn register_accessors_use_the_registers_address_and_minimum_byte_size_and_quantize() {
        let mut piece = MapPiece::default();
        let ram = ram_space();
        // Java: setVar(Register, T) uses reg.getAddress() and reg.getMinimumByteSize(), quantize=true.
        let r0 = Register::new("R0", "", ram.address(0x40), 4, false, Register::TYPE_NONE);

        piece.set_var_register(&r0, &0x5678);

        assert_eq!(piece.get_var_register(&r0, Reason::ExecuteRead), 0x5678);
        assert_eq!(piece.writes.borrow().as_slice(), &[(0x40, 4, true)]);
        assert_eq!(piece.reads.borrow().as_slice(), &[(0x40, 4, true)]);
    }

    #[test]
    fn concrete_convenience_accessors_round_trip() {
        let mut piece = MapPiece::default();
        let ram = ram_space();
        let address = ram.address(0x3000);

        piece.set_long(&address, -2);
        assert_eq!(piece.inspect_long(&address).unwrap(), -2);
        // Java's setLong writes Long.BYTES, unquantized.
        assert_eq!(piece.writes.borrow().last().copied(), Some((0x3000, 8, false)));

        // Java's inspectInt/Short/Byte truncate the concretized long by cast.
        piece.set_int(&address, -3);
        assert_eq!(piece.inspect_int(&address).unwrap(), -3);
        piece.set_short(&address, -4);
        assert_eq!(piece.inspect_short(&address).unwrap(), -4);
        piece.set_byte(&address, -5);
        assert_eq!(piece.inspect_byte(&address).unwrap(), -5);

        piece.set_big_integer(&address, 8, 0x0102_0304_0506_0708);
        assert_eq!(piece.inspect_big_integer(&address, 8).unwrap(), 0x0102_0304_0506_0708);

        // Little-endian, so the concrete bytes read back least-significant first.
        piece.set_concrete(&address, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(piece.inspect_concrete(&address, 8).unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn quantize_offset_scales_by_the_addressable_unit_size() {
        let piece = MapPiece::default();
        // Java: space.truncateAddressableWordOffset(offset) * space.getAddressableUnitSize().
        let byte_addressable = ram_space();
        assert_eq!(piece.quantize_offset(&byte_addressable, 0x1005), 0x1005);

        let word_addressable = AddressSpace::new("code", 32, 2, AddressSpaceType::Code, 2);
        assert_eq!(piece.quantize_offset(&word_addressable, 0x1005), 0x200a);
    }

    #[test]
    fn optional_next_entry_operations_are_unsupported_by_default() {
        let piece = MapPiece::default();
        let ram = ram_space();

        // Java's defaults throw UnsupportedOperationException.
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            piece.get_next_entry_internal(&ram, 0)
        }))
        .is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            piece.get_next_entry_internal_abstract(&ram, &0)
        }))
        .is_err());
    }
}

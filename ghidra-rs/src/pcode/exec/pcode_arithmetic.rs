//! Arithmetic p-code operations over an abstract value domain `T`.
//!
//! Corresponds to `ghidra.pcode.exec.PcodeArithmetic`.

use std::rc::Rc;
use std::sync::Arc;

use crate::pcode::seam_stubs::{ConcretionError, Reason};
use crate::pcode::utils::{big_integer_to_bytes, bytes_to_big_integer, bytes_to_long, long_to_bytes};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::pcode::{OpCode, PcodeOp};
use crate::program::seam_stubs::RegisterValue;

/// The number of bytes needed to encode the size (in bytes) of any value.
pub const SIZEOF_SIZEOF: i32 = 8;

/// Reasons for requiring a concrete value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// The value is needed to parse an instruction.
    Decode,
    /// The value is needed for disassembly context.
    Context,
    /// The value is needed to decide a conditional branch.
    Condition,
    /// The value will be used as the address of an indirect branch.
    Branch,
    /// The value will be used as the address of a value to load.
    Load,
    /// The value will be used as the address of a value to store.
    Store,
    /// The p-code specification defines the operand as a constant.
    ByDef,
    /// Some other reason, perhaps for userop library use.
    Other,
    /// The user or a tool is inspecting the value.
    Inspect,
}

impl Purpose {
    /// The [`Reason`] a `PcodeExecutorStatePiece` should give when reading a value for this
    /// purpose.
    pub fn reason(self) -> Reason {
        match self {
            Purpose::Decode => Reason::ExecuteDecode,
            Purpose::Context
            | Purpose::Condition
            | Purpose::Branch
            | Purpose::Load
            | Purpose::Store
            | Purpose::ByDef
            | Purpose::Other => Reason::ExecuteRead,
            Purpose::Inspect => Reason::Inspect,
        }
    }
}

/// An interface (trait) that defines arithmetic p-code operations on values of type `T`.
///
/// See `BytesPcodeArithmetic` (not yet ported) for the typical pattern when implementing an
/// arithmetic. There are generally two cases: 1) Where endianness matters, 2) Where endianness
/// does not matter. If endianness does not matter, [`PcodeArithmetic::get_endian`] should return
/// `None`, and [`PcodeArithmetic::from_const_bytes`]-based defaults that rely on it (namely
/// [`PcodeArithmetic::from_const_u64`] and [`PcodeArithmetic::from_const_big_int_signed`]) as well
/// as concretion defaults ([`PcodeArithmetic::to_big_integer`], [`PcodeArithmetic::to_long`])
/// must be overridden.
pub trait PcodeArithmetic<T> {
    /// Get a human-readable name for the type of values over which this arithmetic operates.
    ///
    /// Stands in for `getDomain()`, which returns `Class<T>` in Java; Rust has no equivalent
    /// reified generic, so this defaults to the compiler's type name for `T`.
    fn get_domain(&self) -> &'static str {
        std::any::type_name::<T>()
    }

    /// Get the endianness of this arithmetic, or `None` if the abstraction has no notion of
    /// endianness.
    fn get_endian(&self) -> Option<Endian>;

    /// Apply a unary operator to the given input.
    ///
    /// `sizeout` and `sizein1` are the sizes (in bytes) of the output and input variables,
    /// respectively.
    fn unary_op(&self, opcode: OpCode, sizeout: i32, sizein1: i32, in1: &T) -> T;

    /// Apply a unary operator to the given input, unpacking sizes from the full p-code op.
    fn unary_op_from_pcode_op(&self, op: &PcodeOp, in1: &T) -> T {
        let output = op.output.as_ref().expect("unary p-code op has no output");
        self.unary_op(op.opcode, output.get_size(), op.inputs[0].get_size(), in1)
    }

    /// Apply a binary operator to the given inputs.
    ///
    /// `sizeout`, `sizein1`, and `sizein2` are the sizes (in bytes) of the output and the first
    /// and second input variables, respectively.
    fn binary_op(&self, opcode: OpCode, sizeout: i32, sizein1: i32, in1: &T, sizein2: i32, in2: &T)
        -> T;

    /// Apply a binary operator to the given inputs, unpacking sizes from the full p-code op.
    fn binary_op_from_pcode_op(&self, op: &PcodeOp, in1: &T, in2: &T) -> T {
        let output = op.output.as_ref().expect("binary p-code op has no output");
        self.binary_op(
            op.opcode,
            output.get_size(),
            op.inputs[0].get_size(),
            in1,
            op.inputs[1].get_size(),
            in2,
        )
    }

    /// Apply the [`OpCode::PtrAdd`] operator to the given inputs.
    ///
    /// The "pointer add" op takes three operands: base, index, size; and is used as a more
    /// compact representation of array index address computation.
    fn ptr_add(
        &self,
        sizeout: i32,
        sizein_base: i32,
        in_base: &T,
        sizein_index: i32,
        in_index: &T,
        in_size: i32,
    ) -> T {
        let const_size = self.from_const_u64(in_size as u64, 4);
        let index_sized = self.binary_op(OpCode::IntMult, sizeout, sizein_index, in_index, 4, &const_size);
        self.binary_op(OpCode::IntAdd, sizeout, sizein_base, in_base, sizeout, &index_sized)
    }

    /// Apply the [`OpCode::PtrSub`] operator to the given inputs.
    ///
    /// The "pointer subfield" op takes two operands: base, offset; its behavior is exactly
    /// equivalent to [`OpCode::IntAdd`].
    fn ptr_sub(&self, sizeout: i32, sizein_base: i32, in_base: &T, sizein_offset: i32, in_offset: &T) -> T {
        self.binary_op(OpCode::IntAdd, sizeout, sizein_base, in_base, sizein_offset, in_offset)
    }

    /// Apply any modifications before a value is stored.
    ///
    /// Called on the offset and the value before the value is actually stored into the state.
    /// Note: STORE ops always quantize the offset.
    fn mod_before_store(
        &self,
        sizein_offset: i32,
        space: &AddressSpace,
        in_offset: &T,
        sizein_value: i32,
        in_value: &T,
    ) -> T;

    /// Apply any modifications before a value is stored, unpacking sizes from the full p-code op.
    fn mod_before_store_from_pcode_op(&self, op: &PcodeOp, space: &AddressSpace, in_offset: &T, in_value: &T) -> T {
        self.mod_before_store(
            op.inputs[1].get_size(),
            space,
            in_offset,
            op.inputs[2].get_size(),
            in_value,
        )
    }

    /// Apply any modifications after a value is loaded.
    ///
    /// Called on the address/offset and the value after the value is actually loaded from the
    /// state. Note: LOAD ops always quantize the offset.
    fn mod_after_load(
        &self,
        sizein_offset: i32,
        space: &AddressSpace,
        in_offset: &T,
        sizein_value: i32,
        in_value: &T,
    ) -> T;

    /// Apply any modifications after a value is loaded, unpacking sizes from the full p-code op.
    fn mod_after_load_from_pcode_op(&self, op: &PcodeOp, space: &AddressSpace, in_offset: &T, in_value: &T) -> T {
        let output = op.output.as_ref().expect("LOAD p-code op has no output");
        self.mod_after_load(op.inputs[1].get_size(), space, in_offset, output.get_size(), in_value)
    }

    /// Convert the given constant concrete byte value to type `T` having the same size.
    fn from_const_bytes(&self, value: &[u8]) -> T;

    /// Convert the given constant concrete value to type `T` having the given size (in bytes),
    /// with unsigned extension.
    ///
    /// This relies on [`PcodeArithmetic::get_endian`] returning `Some`; endian-agnostic
    /// arithmetics must override this.
    fn from_const_u64(&self, value: u64, size: i32) -> T {
        let big_endian = self
            .get_endian()
            .expect("endian-agnostic arithmetic must override from_const_u64")
            .is_big_endian();
        self.from_const_bytes(&long_to_bytes(value as i64, size as usize, big_endian))
    }

    /// Convert a `float` to `T`. If `size` is not 4 bytes, the raw bits are truncated or padded
    /// according to machine endianness.
    fn from_const_f32(&self, value: f32, size: i32) -> T {
        self.from_const_u64(value.to_bits() as u64, size)
    }

    /// Convert a `double` to `T`. If `size` is not 8 bytes, the raw bits are truncated or padded
    /// according to machine endianness.
    fn from_const_f64(&self, value: f64, size: i32) -> T {
        self.from_const_u64(value.to_bits(), size)
    }

    /// Convert a `bool` to `T`. `true` is represented as 1, and `false` as 0, padded to the given
    /// size.
    fn from_const_bool(&self, value: bool, size: i32) -> T {
        self.from_const_u64(if value { 1 } else { 0 }, size)
    }

    /// Convert the given constant concrete value to type `T` having the given size.
    ///
    /// `is_contextreg` indicates the value is from the disassembly context register: if so, the
    /// bytes are big endian, no matter the machine language's endianness.
    fn from_const_big_int(&self, value: i128, size: i32, is_contextreg: bool) -> T {
        let big_endian = is_contextreg
            || self
                .get_endian()
                .expect("endian-agnostic arithmetic must override from_const_big_int")
                .is_big_endian();
        self.from_const_bytes(&big_integer_to_bytes(value, size as usize, big_endian))
    }

    /// Convert the given constant concrete value (assumed not to be for the disassembly context
    /// register) to type `T` having the given size.
    fn from_const_big_int_default(&self, value: i128, size: i32) -> T {
        self.from_const_big_int(value, size, false)
    }

    /// Convert the given constant concrete register value to type `T`.
    fn from_const_register_value(&self, value: &dyn RegisterValue) -> T {
        let register = value.get_register();
        let reg = register.borrow();
        self.from_const_big_int(
            value.get_unsigned_value_ignore_mask() as i128,
            reg.num_bytes(),
            reg.is_processor_context(),
        )
    }

    /// Convert the given concrete address to type `T`.
    ///
    /// The value will have the pointer size of the address' space; other than deriving that
    /// size, the returned value has nothing to do with the address space.
    fn from_const_address(&self, address: &Address) -> T {
        let pointer_size = (address.space().size() + 7) / 8;
        self.from_const_u64(address.unsigned_offset(), pointer_size)
    }

    /// Convert, if possible, the given abstract value to a concrete byte array.
    fn to_concrete(&self, value: &T, purpose: Purpose) -> Result<Vec<u8>, ConcretionError>;

    /// Convert, if possible, the given abstract condition to a concrete boolean value.
    fn is_true(&self, cond: &T, purpose: Purpose) -> Result<bool, ConcretionError> {
        let concrete = self.to_concrete(cond, purpose)?;
        Ok(concrete.iter().any(|&b| b != 0))
    }

    /// Convert, if possible, the given abstract value to a concrete register value, returned as
    /// (register, unsigned big-integer value) pending a constructible `RegisterValue` port. See
    /// [`PcodeArithmetic::from_const_register_value`] for why this shape is used.
    fn to_register_value(
        &self,
        register: &RegisterRef,
        value: &T,
        purpose: Purpose,
    ) -> Result<(RegisterRef, i128), ConcretionError> {
        let effective_purpose = if register.borrow().is_processor_context() {
            Purpose::Context
        } else {
            purpose
        };
        let big_int = self.to_big_integer(value, effective_purpose)?;
        Ok((Rc::clone(register), big_int))
    }

    /// Convert, if possible, the given abstract value to a concrete big integer.
    fn to_big_integer(&self, value: &T, purpose: Purpose) -> Result<i128, ConcretionError> {
        let concrete = self.to_concrete(value, purpose)?;
        let big_endian = purpose == Purpose::Context
            || self.get_endian().map(Endian::is_big_endian).unwrap_or(false);
        Ok(bytes_to_big_integer(&concrete, concrete.len(), big_endian, false))
    }

    /// Convert, if possible, the given abstract value to a concrete long (64-bit integer).
    fn to_long(&self, value: &T, purpose: Purpose) -> Result<i64, ConcretionError> {
        let concrete = self.to_concrete(value, purpose)?;
        let big_endian = purpose == Purpose::Context
            || self.get_endian().map(Endian::is_big_endian).unwrap_or(false);
        Ok(bytes_to_long(&concrete, concrete.len(), big_endian))
    }

    /// Convert, if possible, the given abstract value to a concrete float.
    fn to_float(&self, value: &T, purpose: Purpose) -> Result<f32, ConcretionError> {
        Ok(f32::from_bits(self.to_long(value, purpose)? as u32))
    }

    /// Convert, if possible, the given abstract value to a concrete double.
    fn to_double(&self, value: &T, purpose: Purpose) -> Result<f64, ConcretionError> {
        Ok(f64::from_bits(self.to_long(value, purpose)? as u64))
    }

    /// Convert, if possible, the given abstract value to a concrete address in the given space.
    fn to_address(&self, value: &T, space: &Arc<AddressSpace>, purpose: Purpose) -> Result<Address, ConcretionError> {
        let offset = self.to_long(value, purpose)?;
        Ok(space.address(offset))
    }

    /// Get the size in bytes, if possible, of the given abstract value.
    fn size_of(&self, value: &T) -> i64;

    /// Get the size in bytes, if possible, of the given abstract value, as an abstract value.
    ///
    /// The returned size has a size of [`SIZEOF_SIZEOF`].
    fn size_of_abstract(&self, value: &T) -> T {
        self.from_const_u64(self.size_of(value) as u64, SIZEOF_SIZEOF)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::AddressSpaceType;

    /// Trivial little-endian byte-array arithmetic, enough to exercise the default methods and
    /// prove `PcodeArithmetic` is object-safe (usable as `Box<dyn PcodeArithmetic<Vec<u8>>>`).
    struct LittleEndianBytesArithmetic;

    impl PcodeArithmetic<Vec<u8>> for LittleEndianBytesArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }

        fn unary_op(&self, _opcode: OpCode, sizeout: i32, _sizein1: i32, in1: &Vec<u8>) -> Vec<u8> {
            let mut out = in1.clone();
            out.resize(sizeout as usize, 0);
            out
        }

        fn binary_op(
            &self,
            opcode: OpCode,
            sizeout: i32,
            _sizein1: i32,
            in1: &Vec<u8>,
            _sizein2: i32,
            in2: &Vec<u8>,
        ) -> Vec<u8> {
            let a = bytes_to_long(in1, in1.len(), false);
            let b = bytes_to_long(in2, in2.len(), false);
            let result = match opcode {
                OpCode::IntAdd => a.wrapping_add(b),
                OpCode::IntMult => a.wrapping_mul(b),
                _ => 0,
            };
            long_to_bytes(result, sizeout as usize, false)
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

    #[test]
    fn object_safe_and_smoke_test() {
        let arith: Box<dyn PcodeArithmetic<Vec<u8>>> = Box::new(LittleEndianBytesArithmetic);

        let two = arith.from_const_u64(2, 4);
        let three = arith.from_const_u64(3, 4);
        let sum = arith.binary_op(OpCode::IntAdd, 4, 4, &two, 4, &three);
        assert_eq!(arith.to_long(&sum, Purpose::Other).unwrap(), 5);

        let product = arith.binary_op(OpCode::IntMult, 4, 4, &two, 4, &three);
        assert_eq!(arith.to_long(&product, Purpose::Other).unwrap(), 6);

        assert!(arith.is_true(&arith.from_const_bool(true, 1), Purpose::Condition).unwrap());
        assert!(!arith.is_true(&arith.from_const_bool(false, 1), Purpose::Condition).unwrap());

        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let base = arith.from_const_u64(0x1000, 4);
        let index = arith.from_const_u64(3, 4);
        let added = arith.ptr_add(4, 4, &base, 4, &index, 4);
        assert_eq!(arith.to_long(&added, Purpose::Other).unwrap(), 0x100c);

        let addr = arith.to_address(&base, &ram, Purpose::Other).unwrap();
        assert_eq!(addr.offset(), 0x1000);

        assert_eq!(arith.size_of(&two), 4);
        assert_eq!(arith.size_of_abstract(&two).len(), SIZEOF_SIZEOF as usize);
    }
}

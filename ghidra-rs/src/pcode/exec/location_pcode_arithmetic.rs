//! An auxiliary arithmetic that reports the location of the control value.
//!
//! Corresponds to `ghidra.pcode.exec.LocationPcodeArithmetic`.
//!
//! This is intended for use as the right side of a `PairedPcodeArithmetic`. Note that constant
//! and unique spaces are never returned. Furthermore, any computation performed on a value,
//! producing a temporary value, philosophically does not exist at any location in the state.
//! Thus, most operations in this arithmetic result in `None`. The accompanying state piece
//! `LocationPcodeExecutorStatePiece` generates the actual locations.
//!
//! Java's `T` is `ValueLocation`, whose references may be `null`; the Rust port uses
//! `Option<ValueLocation>` for `T` to carry that nullability through the generic
//! [`PcodeArithmetic`] trait.

use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::seam_stubs::{ConcretionError, ValueLocation};
use crate::pcode::utils::bytes_to_long;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::endian::Endian;
use crate::program::model::pcode::OpCode;

/// An auxiliary arithmetic that reports the location the control value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocationPcodeArithmetic {
    BigEndian,
    LittleEndian,
}

impl LocationPcodeArithmetic {
    /// Port of `LocationPcodeArithmetic.forEndian(boolean)`.
    pub fn for_endian(big_endian: bool) -> Self {
        if big_endian { Self::BigEndian } else { Self::LittleEndian }
    }

    fn endian(&self) -> Endian {
        match self {
            Self::BigEndian => Endian::Big,
            Self::LittleEndian => Endian::Little,
        }
    }
}

impl PcodeArithmetic<Option<ValueLocation>> for LocationPcodeArithmetic {
    fn get_domain(&self) -> &'static str {
        "ValueLocation"
    }

    fn get_endian(&self) -> Option<Endian> {
        Some(self.endian())
    }

    fn unary_op(
        &self,
        opcode: OpCode,
        _sizeout: i32,
        _sizein1: i32,
        in1: &Option<ValueLocation>,
    ) -> Option<ValueLocation> {
        match opcode {
            OpCode::Copy | OpCode::IntZext | OpCode::IntSext => in1.clone(),
            _ => None,
        }
    }

    fn binary_op(
        &self,
        opcode: OpCode,
        _sizeout: i32,
        _sizein1: i32,
        in1: &Option<ValueLocation>,
        _sizein2: i32,
        in2: &Option<ValueLocation>,
    ) -> Option<ValueLocation> {
        match opcode {
            OpCode::IntLeft => {
                let in2 = in2.as_ref()?;
                let amount = in2.get_const().expect("INT_LEFT shift amount is not constant");
                in1.as_ref()
                    .expect("INT_LEFT base location is null")
                    .shift_left(amount as i32)
            }
            OpCode::IntOr => {
                let in1 = in1.as_ref()?;
                let in2 = in2.as_ref()?;
                in1.int_or(in2)
            }
            _ => None,
        }
    }

    fn mod_before_store(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &Option<ValueLocation>,
        _sizein_value: i32,
        in_value: &Option<ValueLocation>,
    ) -> Option<ValueLocation> {
        in_value.clone()
    }

    fn mod_after_load(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &Option<ValueLocation>,
        _sizein_value: i32,
        in_value: &Option<ValueLocation>,
    ) -> Option<ValueLocation> {
        in_value.clone()
    }

    fn from_const_bytes(&self, value: &[u8]) -> Option<ValueLocation> {
        Some(ValueLocation::from_const(
            bytes_to_long(value, value.len(), self.endian().is_big_endian()),
            value.len() as i32,
        ))
    }

    fn from_const_u64(&self, value: u64, size: i32) -> Option<ValueLocation> {
        Some(ValueLocation::from_const(value as i64, size))
    }

    fn from_const_big_int(&self, value: i128, size: i32, _is_contextreg: bool) -> Option<ValueLocation> {
        Some(ValueLocation::from_const(value as i64, size))
    }

    fn from_const_big_int_default(&self, value: i128, size: i32) -> Option<ValueLocation> {
        Some(ValueLocation::from_const(value as i64, size))
    }

    fn to_concrete(
        &self,
        _value: &Option<ValueLocation>,
        purpose: Purpose,
    ) -> Result<Vec<u8>, ConcretionError> {
        Err(ConcretionError::new("Cannot make 'location' concrete", purpose))
    }

    fn size_of(&self, value: &Option<ValueLocation>) -> i64 {
        value.as_ref().map(|v| v.size() as i64).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    #[test]
    fn for_endian_selects_variant() {
        assert_eq!(LocationPcodeArithmetic::for_endian(true), LocationPcodeArithmetic::BigEndian);
        assert_eq!(LocationPcodeArithmetic::for_endian(false), LocationPcodeArithmetic::LittleEndian);
    }

    #[test]
    fn get_endian_matches_variant() {
        assert_eq!(LocationPcodeArithmetic::BigEndian.get_endian(), Some(Endian::Big));
        assert_eq!(LocationPcodeArithmetic::LittleEndian.get_endian(), Some(Endian::Little));
    }

    #[test]
    fn unary_op_is_identity_for_copy_and_extensions_and_null_otherwise() {
        let arith = LocationPcodeArithmetic::LittleEndian;
        let loc = arith.from_const_u64(0x1234, 4);

        assert_eq!(arith.unary_op(OpCode::Copy, 4, 4, &loc), loc);
        assert_eq!(arith.unary_op(OpCode::IntZext, 8, 4, &loc), loc);
        assert_eq!(arith.unary_op(OpCode::IntSext, 8, 4, &loc), loc);
        assert_eq!(arith.unary_op(OpCode::IntAdd, 4, 4, &loc), None);
    }

    #[test]
    fn binary_op_int_left_shifts_by_whole_bytes() {
        let arith = LocationPcodeArithmetic::LittleEndian;
        let base = arith.from_const_u64(0xab, 1);
        let amount = arith.from_const_u64(16, 4);

        let shifted = arith.binary_op(OpCode::IntLeft, 4, 1, &base, 4, &amount);
        let shifted = shifted.expect("shift by whole bytes should succeed");
        assert_eq!(shifted.size(), 3);
    }

    #[test]
    fn binary_op_int_or_is_null_when_either_operand_is_null() {
        let arith = LocationPcodeArithmetic::LittleEndian;
        let loc = arith.from_const_u64(1, 4);

        assert_eq!(arith.binary_op(OpCode::IntOr, 4, 4, &None, 4, &loc), None);
        assert_eq!(arith.binary_op(OpCode::IntOr, 4, 4, &loc, 4, &None), None);
    }

    #[test]
    fn binary_op_default_case_is_null() {
        let arith = LocationPcodeArithmetic::LittleEndian;
        let a = arith.from_const_u64(1, 4);
        let b = arith.from_const_u64(2, 4);
        assert_eq!(arith.binary_op(OpCode::IntAdd, 4, 4, &a, 4, &b), None);
    }

    #[test]
    fn mod_before_store_and_after_load_return_value_unchanged() {
        let arith = LocationPcodeArithmetic::LittleEndian;
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let value = arith.from_const_u64(7, 4);

        assert_eq!(arith.mod_before_store(4, &ram, &None, 4, &value), value);
        assert_eq!(arith.mod_after_load(4, &ram, &None, 4, &value), value);
    }

    #[test]
    fn to_concrete_always_errs() {
        let arith = LocationPcodeArithmetic::LittleEndian;
        let value = arith.from_const_u64(1, 4);
        assert!(arith.to_concrete(&value, Purpose::Other).is_err());
    }

    #[test]
    fn size_of_null_is_zero() {
        let arith = LocationPcodeArithmetic::LittleEndian;
        assert_eq!(arith.size_of(&None), 0);
        assert_eq!(arith.size_of(&arith.from_const_u64(1, 4)), 4);
    }
}

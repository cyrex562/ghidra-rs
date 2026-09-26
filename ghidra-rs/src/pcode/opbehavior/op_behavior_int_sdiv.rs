//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntSdiv`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::error::LowlevelError;
use crate::pcode::utils::{convert_to_signed_value, zzz_sign_extend, zzz_zero_extend};
use crate::program::model::pcode::OpCode;

/// INT_SDIV p-code operation behavior: signed integer division.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntSdiv`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSdiv {
    base: OpBehavior,
}

impl OpBehaviorIntSdiv {
    /// Construct a new `OpBehaviorIntSdiv` for [`OpCode::IntSdiv`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntSdiv as i32) }
    }
}

impl Default for OpBehaviorIntSdiv {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntSdiv {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// # Panics
    /// Java throws `LowlevelError("Divide by 0")` if `in2 == 0`; ported here as a panic since
    /// this trait's methods are infallible.
    fn evaluate_binary_i64(&self, sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        if in2 == 0 {
            panic!("{}", LowlevelError::with_message("Divide by 0"));
        }
        let num = zzz_sign_extend(in1, 8 * sizein - 1);
        let denom = zzz_sign_extend(in2, 8 * sizein - 1);
        // `wrapping_div` matches Java's `long` division, which silently overflows (rather than
        // throwing) for the `i64::MIN / -1` edge case.
        let sres = num.wrapping_div(denom);
        zzz_zero_extend(sres, 8 * sizeout - 1)
    }

    /// # Panics
    /// Java throws `LowlevelError("Divide by 0")` if `in2 == 0`; ported here as a panic since
    /// this trait's methods are infallible.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        if in2 == 0 {
            panic!("{}", LowlevelError::with_message("Divide by 0"));
        }
        let in1 = convert_to_signed_value(in1, sizein);
        let in2 = convert_to_signed_value(in2, sizein);
        in1.wrapping_div(in2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntSdiv::new().opcode(), OpCode::IntSdiv as i32);
    }

    #[test]
    fn divides_positive_values() {
        let b = OpBehaviorIntSdiv::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 10, 3), 3);
    }

    #[test]
    fn divides_negative_by_positive() {
        let b = OpBehaviorIntSdiv::new();
        // -10 as a 1-byte value (0xf6) divided by 3 -> -3 (truncating toward zero), represented
        // as the 1-byte unsigned pattern 0xfd.
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xf6, 0x03), 0xfd);
    }

    #[test]
    #[should_panic(expected = "Divide by 0")]
    fn panics_on_zero_divisor() {
        let b = OpBehaviorIntSdiv::new();
        b.evaluate_binary_i64(4, 4, 10, 0);
    }

    #[test]
    fn i128_divides_positive_values() {
        let b = OpBehaviorIntSdiv::new();
        assert_eq!(b.evaluate_binary_i128(4, 4, 10, 3), 3);
    }

    #[test]
    fn i128_divides_negative_by_positive() {
        let b = OpBehaviorIntSdiv::new();
        // Same case as the i64 test, but the BigInteger overload returns the true signed value.
        assert_eq!(b.evaluate_binary_i128(1, 1, 0xf6, 0x03), -3);
    }

    #[test]
    #[should_panic(expected = "Divide by 0")]
    fn i128_panics_on_zero_divisor() {
        let b = OpBehaviorIntSdiv::new();
        b.evaluate_binary_i128(4, 4, 10, 0);
    }
}

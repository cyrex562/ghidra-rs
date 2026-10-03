//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntSrem`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::error::LowlevelError;
use crate::pcode::utils::{convert_to_signed_value, zzz_sign_extend, zzz_zero_extend};
use crate::program::model::pcode::OpCode;

/// INT_SREM p-code operation behavior: signed remainder.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntSrem`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSrem {
    base: OpBehavior,
}

impl OpBehaviorIntSrem {
    /// Construct a new `OpBehaviorIntSrem` for [`OpCode::IntSrem`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntSrem as i32) }
    }
}

impl Default for OpBehaviorIntSrem {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntSrem {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// # Panics
    /// Java throws `LowlevelError("Remainder by 0")` if `in2 == 0`; ported here as a panic since
    /// this trait's methods are infallible.
    fn evaluate_binary_i64(&self, sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        if in2 == 0 {
            panic!("{}", LowlevelError::with_message("Remainder by 0"));
        }
        let val = zzz_sign_extend(in1, 8 * sizein - 1);
        let modulus = zzz_sign_extend(in2, 8 * sizein - 1);
        // `wrapping_rem` matches Java's `long` remainder, which silently overflows to `0` (rather
        // than throwing) for the `i64::MIN % -1` edge case.
        let sres = val.wrapping_rem(modulus);
        zzz_zero_extend(sres, 8 * sizeout - 1)
    }

    /// # Panics
    /// Java throws `LowlevelError("Remainder by 0")` if `in2 == 0`; ported here as a panic since
    /// this trait's methods are infallible.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        if in2 == 0 {
            panic!("{}", LowlevelError::with_message("Remainder by 0"));
        }
        let in1 = convert_to_signed_value(in1, sizein);
        let in2 = convert_to_signed_value(in2, sizein);
        in1.wrapping_rem(in2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntSrem::new().opcode(), OpCode::IntSrem as i32);
    }

    #[test]
    fn computes_remainder_of_positive_values() {
        let b = OpBehaviorIntSrem::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 10, 3), 1);
    }

    #[test]
    fn computes_remainder_of_negative_dividend() {
        let b = OpBehaviorIntSrem::new();
        // -10 (0xf6 as a signed byte) % 3 == -1 (truncating remainder), as the 1-byte unsigned
        // pattern 0xff.
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xf6, 0x03), 0xff);
    }

    #[test]
    #[should_panic(expected = "Remainder by 0")]
    fn panics_on_zero_divisor() {
        let b = OpBehaviorIntSrem::new();
        b.evaluate_binary_i64(4, 4, 10, 0);
    }

    #[test]
    fn i128_computes_remainder_of_negative_dividend() {
        let b = OpBehaviorIntSrem::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 0xf6, 0x03), -1);
    }

    #[test]
    #[should_panic(expected = "Remainder by 0")]
    fn i128_panics_on_zero_divisor() {
        let b = OpBehaviorIntSrem::new();
        b.evaluate_binary_i128(4, 4, 10, 0);
    }
}

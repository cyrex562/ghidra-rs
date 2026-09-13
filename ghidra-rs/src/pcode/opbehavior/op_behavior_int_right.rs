//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntRight`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::calc_mask;
use crate::program::model::pcode::OpCode;
use crate::util::AssertException;

/// INT_RIGHT p-code operation behavior: logical (zero-fill) right shift.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntRight`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntRight {
    base: OpBehavior,
}

impl OpBehaviorIntRight {
    /// Construct a new `OpBehaviorIntRight` for [`OpCode::IntRight`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntRight as i32) }
    }
}

impl Default for OpBehaviorIntRight {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntRight {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        if in2 < 0 || in2 >= (8 * sizein) as i64 {
            return 0;
        }
        let shifted = ((in1 as u64).checked_shr(in2 as u32).unwrap_or(0)) as i64;
        shifted & calc_mask(sizeout)
    }

    /// # Panics
    /// Java throws `AssertException("Expected unsigned in values")` if either input is negative;
    /// ported here as a panic since this trait's methods are infallible.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        if in1 < 0 || in2 < 0 {
            panic!("{}", AssertException::with_message("Expected unsigned in values"));
        }
        let max_shift = (sizein as i128) * 8;
        if in2 >= max_shift {
            return 0;
        }
        ((in1 as u128).checked_shr(in2 as u32).unwrap_or(0)) as i128
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntRight::new().opcode(), OpCode::IntRight as i32);
    }

    #[test]
    fn shifts_right_logically() {
        let b = OpBehaviorIntRight::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 16, 4), 1);
    }

    #[test]
    fn shift_beyond_width_yields_zero() {
        let b = OpBehaviorIntRight::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xff, 8), 0);
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xff, 100), 0);
    }

    #[test]
    fn negative_shift_yields_zero() {
        let b = OpBehaviorIntRight::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xff, -1), 0);
    }

    #[test]
    fn logical_shift_does_not_sign_extend() {
        let b = OpBehaviorIntRight::new();
        // Even though 0xff looks negative as a signed byte, INT_RIGHT is a zero-fill shift.
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xff, 4), 0x0f);
    }

    #[test]
    fn i128_shifts_right() {
        let b = OpBehaviorIntRight::new();
        assert_eq!(b.evaluate_binary_i128(4, 4, 16, 4), 1);
        assert_eq!(b.evaluate_binary_i128(1, 1, 0xff, 8), 0);
    }

    #[test]
    #[should_panic(expected = "Expected unsigned in values")]
    fn i128_panics_on_negative_input() {
        let b = OpBehaviorIntRight::new();
        b.evaluate_binary_i128(1, 1, -1, 1);
    }
}

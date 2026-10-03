//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntCarry`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::{calc_bigmask, calc_mask};
use crate::program::model::pcode::OpCode;
use crate::util::AssertException;

/// INT_CARRY p-code operation behavior: `1` if adding the two operands overflows (carries) within
/// `sizein` bytes.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntCarry`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntCarry {
    base: OpBehavior,
}

impl OpBehaviorIntCarry {
    /// Construct a new `OpBehaviorIntCarry` for [`OpCode::IntCarry`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntCarry as i32) }
    }
}

impl Default for OpBehaviorIntCarry {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntCarry {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        let masked_sum = in1.wrapping_add(in2) & calc_mask(sizein);
        if (in1 as u64) > (masked_sum as u64) { 1 } else { 0 }
    }

    /// # Panics
    /// Java throws `AssertException("Expected unsigned in values")` if either input is negative;
    /// ported here as a panic since this trait's methods are infallible.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        if in1 < 0 || in2 < 0 {
            panic!("{}", AssertException::with_message("Expected unsigned in values"));
        }
        let masked_sum = in1.wrapping_add(in2) & calc_bigmask(sizein);
        if in1 > masked_sum { 1 } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntCarry::new().opcode(), OpCode::IntCarry as i32);
    }

    #[test]
    fn no_carry_for_small_sum() {
        let b = OpBehaviorIntCarry::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x01, 0x02), 0);
    }

    #[test]
    fn carry_when_sum_overflows_size() {
        let b = OpBehaviorIntCarry::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xff, 0x01), 1);
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x80, 0x80), 1);
    }

    #[test]
    fn i128_no_carry_for_small_sum() {
        let b = OpBehaviorIntCarry::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 0x01, 0x02), 0);
    }

    #[test]
    fn i128_carry_when_sum_overflows_size() {
        let b = OpBehaviorIntCarry::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 0xff, 0x01), 1);
    }

    #[test]
    #[should_panic(expected = "Expected unsigned in values")]
    fn i128_panics_on_negative_input() {
        let b = OpBehaviorIntCarry::new();
        b.evaluate_binary_i128(1, 1, -1, 1);
    }
}

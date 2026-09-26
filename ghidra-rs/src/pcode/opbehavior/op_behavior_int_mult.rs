//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntMult`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::calc_mask;
use crate::program::model::pcode::OpCode;

/// INT_MULT p-code operation behavior: integer multiplication.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntMult`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntMult {
    base: OpBehavior,
}

impl OpBehaviorIntMult {
    /// Construct a new `OpBehaviorIntMult` for [`OpCode::IntMult`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntMult as i32) }
    }
}

impl Default for OpBehaviorIntMult {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntMult {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
        in1.wrapping_mul(in2) & calc_mask(sizeout)
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
        in1.wrapping_mul(in2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntMult::new().opcode(), OpCode::IntMult as i32);
    }

    #[test]
    fn multiplies_small_values() {
        let b = OpBehaviorIntMult::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 6, 7), 42);
    }

    #[test]
    fn wraps_on_overflow_for_size() {
        let b = OpBehaviorIntMult::new();
        // 1-byte mult: 0x10 * 0x10 = 0x100, masked to 1 byte -> 0x00.
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x10, 0x10), 0x00);
    }

    #[test]
    fn i128_multiplies_values() {
        let b = OpBehaviorIntMult::new();
        assert_eq!(b.evaluate_binary_i128(8, 8, 6, 7), 42);
    }
}

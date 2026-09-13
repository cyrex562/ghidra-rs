//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntSub`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::calc_mask;
use crate::program::model::pcode::OpCode;

/// INT_SUB p-code operation behavior: unsigned subtraction of same-size operands.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntSub`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSub {
    base: OpBehavior,
}

impl OpBehaviorIntSub {
    /// Construct a new `OpBehaviorIntSub` for [`OpCode::IntSub`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntSub as i32) }
    }
}

impl Default for OpBehaviorIntSub {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntSub {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
        in1.wrapping_sub(in2) & calc_mask(sizeout)
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
        in1.wrapping_sub(in2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntSub::new().opcode(), OpCode::IntSub as i32);
    }

    #[test]
    fn subtracts_small_values() {
        let b = OpBehaviorIntSub::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 5, 3), 2);
    }

    #[test]
    fn wraps_on_underflow_for_size() {
        let b = OpBehaviorIntSub::new();
        // 1-byte sub: 0x00 - 0x01 wraps to 0xff once masked to 1 byte.
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x00, 0x01), 0xff);
    }

    #[test]
    fn i128_subtracts_values() {
        let b = OpBehaviorIntSub::new();
        assert_eq!(b.evaluate_binary_i128(8, 8, 300, 200), 100);
    }
}

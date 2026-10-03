//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntAdd`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::calc_mask;
use crate::program::model::pcode::OpCode;

/// INT_ADD p-code operation behavior: unsigned addition of same-size operands.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntAdd`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntAdd {
    base: OpBehavior,
}

impl OpBehaviorIntAdd {
    /// Construct a new `OpBehaviorIntAdd` for [`OpCode::IntAdd`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntAdd as i32) }
    }
}

impl Default for OpBehaviorIntAdd {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntAdd {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
        in1.wrapping_add(in2) & calc_mask(sizeout)
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
        in1.wrapping_add(in2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntAdd::new().opcode(), OpCode::IntAdd as i32);
    }

    #[test]
    fn adds_small_values() {
        let b = OpBehaviorIntAdd::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 2, 3), 5);
    }

    #[test]
    fn wraps_on_overflow_for_size() {
        let b = OpBehaviorIntAdd::new();
        // 1-byte add: 0xff + 0x01 wraps to 0x00 once masked to 1 byte.
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xff, 0x01), 0x00);
    }

    #[test]
    fn i128_adds_values() {
        let b = OpBehaviorIntAdd::new();
        assert_eq!(b.evaluate_binary_i128(8, 8, 100, 200), 300);
    }
}

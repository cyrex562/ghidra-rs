//! Port of `ghidra.pcode.opbehavior.OpBehaviorBoolAnd`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// Boolean AND (`&&`) p-code operation behavior.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorBoolAnd`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorBoolAnd {
    base: OpBehavior,
}

impl OpBehaviorBoolAnd {
    /// Construct a new `OpBehaviorBoolAnd` for [`OpCode::BoolAnd`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::BoolAnd as i32) }
    }
}

impl Default for OpBehaviorBoolAnd {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorBoolAnd {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
        in1 & in2
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
        in1 & in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorBoolAnd::new().opcode(), OpCode::BoolAnd as i32);
    }

    #[test]
    fn true_and_true_is_true() {
        let b = OpBehaviorBoolAnd::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 1, 1), 1);
    }

    #[test]
    fn true_and_false_is_false() {
        let b = OpBehaviorBoolAnd::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 1, 0), 0);
    }

    #[test]
    fn false_and_false_is_false() {
        let b = OpBehaviorBoolAnd::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0, 0), 0);
    }

    #[test]
    fn i128_and_operation() {
        let b = OpBehaviorBoolAnd::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 1, 1), 1);
        assert_eq!(b.evaluate_binary_i128(1, 1, 1, 0), 0);
    }
}

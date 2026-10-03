//! Port of `ghidra.pcode.opbehavior.OpBehaviorBoolNegate`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use crate::program::model::pcode::OpCode;

/// Boolean negate (`!`) p-code operation behavior.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorBoolNegate`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorBoolNegate {
    base: OpBehavior,
}

impl OpBehaviorBoolNegate {
    /// Construct a new `OpBehaviorBoolNegate` for [`OpCode::BoolNegate`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::BoolNegate as i32) }
    }
}

impl Default for OpBehaviorBoolNegate {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorBoolNegate {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_unary_i64(&self, _sizeout: i32, _sizein: i32, in1: i64) -> i64 {
        in1 ^ 1
    }

    fn evaluate_unary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128) -> i128 {
        in1 ^ 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorBoolNegate::new().opcode(), OpCode::BoolNegate as i32);
    }

    #[test]
    fn negates_true_to_false() {
        let b = OpBehaviorBoolNegate::new();
        assert_eq!(b.evaluate_unary_i64(1, 1, 1), 0);
    }

    #[test]
    fn negates_false_to_true() {
        let b = OpBehaviorBoolNegate::new();
        assert_eq!(b.evaluate_unary_i64(1, 1, 0), 1);
    }

    #[test]
    fn i128_negation() {
        let b = OpBehaviorBoolNegate::new();
        assert_eq!(b.evaluate_unary_i128(1, 1, 1), 0);
        assert_eq!(b.evaluate_unary_i128(1, 1, 0), 1);
    }
}

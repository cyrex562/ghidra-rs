//! Port of `ghidra.pcode.opbehavior.OpBehaviorBoolOr`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// Boolean OR (`||`) p-code operation behavior.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorBoolOr`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorBoolOr {
    base: OpBehavior,
}

impl OpBehaviorBoolOr {
    /// Construct a new `OpBehaviorBoolOr` for [`OpCode::BoolOr`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::BoolOr as i32) }
    }
}

impl Default for OpBehaviorBoolOr {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorBoolOr {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
        in1 | in2
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
        in1 | in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorBoolOr::new().opcode(), OpCode::BoolOr as i32);
    }

    #[test]
    fn false_or_false_is_false() {
        let b = OpBehaviorBoolOr::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0, 0), 0);
    }

    #[test]
    fn true_or_false_is_true() {
        let b = OpBehaviorBoolOr::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 1, 0), 1);
    }

    #[test]
    fn true_or_true_is_true() {
        let b = OpBehaviorBoolOr::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 1, 1), 1);
    }

    #[test]
    fn i128_or_operation() {
        let b = OpBehaviorBoolOr::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 0, 1), 1);
    }
}

//! Port of `ghidra.pcode.opbehavior.OpBehaviorBoolXor`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// Boolean XOR p-code operation behavior.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorBoolXor`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorBoolXor {
    base: OpBehavior,
}

impl OpBehaviorBoolXor {
    /// Construct a new `OpBehaviorBoolXor` for [`OpCode::BoolXor`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::BoolXor as i32) }
    }
}

impl Default for OpBehaviorBoolXor {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorBoolXor {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
        in1 ^ in2
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
        in1 ^ in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorBoolXor::new().opcode(), OpCode::BoolXor as i32);
    }

    #[test]
    fn same_values_yield_false() {
        let b = OpBehaviorBoolXor::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 1, 1), 0);
        assert_eq!(b.evaluate_binary_i64(1, 1, 0, 0), 0);
    }

    #[test]
    fn different_values_yield_true() {
        let b = OpBehaviorBoolXor::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 1, 0), 1);
        assert_eq!(b.evaluate_binary_i64(1, 1, 0, 1), 1);
    }

    #[test]
    fn i128_xor_operation() {
        let b = OpBehaviorBoolXor::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 1, 1), 0);
    }
}

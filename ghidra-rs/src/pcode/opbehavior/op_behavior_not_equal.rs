//! Port of `ghidra.pcode.opbehavior.OpBehaviorNotEqual`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// INT_NOTEQUAL p-code operation behavior: `1` if the operands differ, `0` otherwise.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorNotEqual`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorNotEqual {
    base: OpBehavior,
}

impl OpBehaviorNotEqual {
    /// Construct a new `OpBehaviorNotEqual` for [`OpCode::IntNotEqual`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntNotEqual as i32) }
    }
}

impl Default for OpBehaviorNotEqual {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorNotEqual {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
        if in1 != in2 { 1 } else { 0 }
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
        if in1 == in2 { 0 } else { 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorNotEqual::new().opcode(), OpCode::IntNotEqual as i32);
    }

    #[test]
    fn unequal_values_yield_one() {
        let b = OpBehaviorNotEqual::new();
        assert_eq!(b.evaluate_binary_i64(1, 4, 42, 43), 1);
    }

    #[test]
    fn equal_values_yield_zero() {
        let b = OpBehaviorNotEqual::new();
        assert_eq!(b.evaluate_binary_i64(1, 4, 42, 42), 0);
    }

    #[test]
    fn i128_inequality() {
        let b = OpBehaviorNotEqual::new();
        assert_eq!(b.evaluate_binary_i128(1, 8, 100, 101), 1);
        assert_eq!(b.evaluate_binary_i128(1, 8, 100, 100), 0);
    }
}

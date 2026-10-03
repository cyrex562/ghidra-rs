//! Port of `ghidra.pcode.opbehavior.OpBehaviorEqual`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// INT_EQUAL p-code operation behavior: `1` if the operands are equal, `0` otherwise.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorEqual`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorEqual {
    base: OpBehavior,
}

impl OpBehaviorEqual {
    /// Construct a new `OpBehaviorEqual` for [`OpCode::IntEqual`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntEqual as i32) }
    }
}

impl Default for OpBehaviorEqual {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorEqual {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
        if in1 == in2 { 1 } else { 0 }
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
        if in1 == in2 { 1 } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorEqual::new().opcode(), OpCode::IntEqual as i32);
    }

    #[test]
    fn equal_values_yield_one() {
        let b = OpBehaviorEqual::new();
        assert_eq!(b.evaluate_binary_i64(1, 4, 42, 42), 1);
    }

    #[test]
    fn unequal_values_yield_zero() {
        let b = OpBehaviorEqual::new();
        assert_eq!(b.evaluate_binary_i64(1, 4, 42, 43), 0);
    }

    #[test]
    fn i128_equality() {
        let b = OpBehaviorEqual::new();
        assert_eq!(b.evaluate_binary_i128(1, 8, 100, 100), 1);
        assert_eq!(b.evaluate_binary_i128(1, 8, 100, 101), 0);
    }
}

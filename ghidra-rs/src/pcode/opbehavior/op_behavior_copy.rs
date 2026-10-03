//! Port of `ghidra.pcode.opbehavior.OpBehaviorCopy`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use crate::program::model::pcode::OpCode;

/// COPY p-code operation behavior: returns the input unchanged.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorCopy`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorCopy {
    base: OpBehavior,
}

impl OpBehaviorCopy {
    /// Construct a new `OpBehaviorCopy` for [`OpCode::Copy`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::Copy as i32) }
    }
}

impl Default for OpBehaviorCopy {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorCopy {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_unary_i64(&self, _sizeout: i32, _sizein: i32, in1: i64) -> i64 {
        in1
    }

    fn evaluate_unary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128) -> i128 {
        in1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorCopy::new().opcode(), OpCode::Copy as i32);
    }

    #[test]
    fn returns_input_unchanged_i64() {
        let b = OpBehaviorCopy::new();
        assert_eq!(b.evaluate_unary_i64(8, 8, 0x1234_5678_9abc_def0), 0x1234_5678_9abc_def0);
        assert_eq!(b.evaluate_unary_i64(4, 4, 0), 0);
        assert_eq!(b.evaluate_unary_i64(1, 1, -1), -1);
    }

    #[test]
    fn returns_input_unchanged_i128() {
        let b = OpBehaviorCopy::new();
        assert_eq!(b.evaluate_unary_i128(16, 16, 12345), 12345);
    }
}

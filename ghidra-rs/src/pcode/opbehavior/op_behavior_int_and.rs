//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntAnd`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// INT_AND p-code operation behavior: bitwise AND.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntAnd`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntAnd {
    base: OpBehavior,
}

impl OpBehaviorIntAnd {
    /// Construct a new `OpBehaviorIntAnd` for [`OpCode::IntAnd`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntAnd as i32) }
    }
}

impl Default for OpBehaviorIntAnd {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntAnd {
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
        assert_eq!(OpBehaviorIntAnd::new().opcode(), OpCode::IntAnd as i32);
    }

    #[test]
    fn ands_bytes() {
        let b = OpBehaviorIntAnd::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xff, 0x0f), 0x0f);
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xf0, 0x0f), 0x00);
    }

    #[test]
    fn i128_ands_values() {
        let b = OpBehaviorIntAnd::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 0xff, 0x0f), 0x0f);
    }
}

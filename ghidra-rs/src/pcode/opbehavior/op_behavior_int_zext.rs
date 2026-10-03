//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntZext`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use crate::program::model::pcode::OpCode;

/// INT_ZEXT p-code operation behavior: zero-extends `in1` (a no-op on the raw value, since
/// callers are expected to already treat it as zero-extended/unsigned and truncate to `sizeout`
/// themselves).
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntZext`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntZext {
    base: OpBehavior,
}

impl OpBehaviorIntZext {
    /// Construct a new `OpBehaviorIntZext` for [`OpCode::IntZext`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntZext as i32) }
    }
}

impl Default for OpBehaviorIntZext {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorIntZext {
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
        assert_eq!(OpBehaviorIntZext::new().opcode(), OpCode::IntZext as i32);
    }

    #[test]
    fn returns_input_unchanged_i64() {
        let b = OpBehaviorIntZext::new();
        assert_eq!(b.evaluate_unary_i64(4, 1, 0xff), 0xff);
        assert_eq!(b.evaluate_unary_i64(4, 1, 0), 0);
    }

    #[test]
    fn returns_input_unchanged_i128() {
        let b = OpBehaviorIntZext::new();
        assert_eq!(b.evaluate_unary_i128(4, 1, 0xff), 0xff);
    }
}

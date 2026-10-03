//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntOr`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// INT_OR p-code operation behavior: bitwise OR.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntOr`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntOr {
    base: OpBehavior,
}

impl OpBehaviorIntOr {
    /// Construct a new `OpBehaviorIntOr` for [`OpCode::IntOr`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntOr as i32) }
    }
}

impl Default for OpBehaviorIntOr {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntOr {
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
        assert_eq!(OpBehaviorIntOr::new().opcode(), OpCode::IntOr as i32);
    }

    #[test]
    fn ors_bytes() {
        let b = OpBehaviorIntOr::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xf0, 0x0f), 0xff);
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x00, 0x00), 0x00);
    }

    #[test]
    fn i128_ors_values() {
        let b = OpBehaviorIntOr::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 0xf0, 0x0f), 0xff);
    }
}

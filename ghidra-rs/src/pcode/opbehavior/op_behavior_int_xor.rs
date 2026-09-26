//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntXor`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// INT_XOR p-code operation behavior: bitwise exclusive OR.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntXor`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntXor {
    base: OpBehavior,
}

impl OpBehaviorIntXor {
    /// Construct a new `OpBehaviorIntXor` for [`OpCode::IntXor`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntXor as i32) }
    }
}

impl Default for OpBehaviorIntXor {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntXor {
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
        assert_eq!(OpBehaviorIntXor::new().opcode(), OpCode::IntXor as i32);
    }

    #[test]
    fn xors_bytes() {
        let b = OpBehaviorIntXor::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xff, 0x0f), 0xf0);
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xaa, 0xaa), 0x00);
    }

    #[test]
    fn i128_xors_values() {
        let b = OpBehaviorIntXor::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 0xff, 0x0f), 0xf0);
    }
}

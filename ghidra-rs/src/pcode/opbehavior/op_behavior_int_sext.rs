//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntSext`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use crate::pcode::utils::{convert_to_signed_value, sign_extend};
use crate::program::model::pcode::OpCode;

/// INT_SEXT p-code operation behavior: sign-extends `in1` from `sizein` to `sizeout` bytes.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntSext`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSext {
    base: OpBehavior,
}

impl OpBehaviorIntSext {
    /// Construct a new `OpBehaviorIntSext` for [`OpCode::IntSext`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntSext as i32) }
    }
}

impl Default for OpBehaviorIntSext {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorIntSext {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_unary_i64(&self, sizeout: i32, sizein: i32, in1: i64) -> i64 {
        sign_extend(in1, sizein, sizeout)
    }

    fn evaluate_unary_i128(&self, _sizeout: i32, sizein: i32, in1: i128) -> i128 {
        convert_to_signed_value(in1, sizein)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntSext::new().opcode(), OpCode::IntSext as i32);
    }

    #[test]
    fn sign_extends_negative_byte_to_word() {
        let b = OpBehaviorIntSext::new();
        assert_eq!(b.evaluate_unary_i64(4, 1, 0xff), 0xffff_ffffu32 as i64);
    }

    #[test]
    fn sign_extends_positive_byte_to_word() {
        let b = OpBehaviorIntSext::new();
        assert_eq!(b.evaluate_unary_i64(4, 1, 0x7f), 0x7f);
    }

    #[test]
    fn same_size_is_noop() {
        let b = OpBehaviorIntSext::new();
        assert_eq!(b.evaluate_unary_i64(1, 1, 0x12), 0x12);
    }

    #[test]
    fn i128_sign_extends_negative_byte() {
        let b = OpBehaviorIntSext::new();
        assert_eq!(b.evaluate_unary_i128(4, 1, 0xff), -1);
    }
}

//! Port of `ghidra.pcode.opbehavior.OpBehaviorInt2Comp`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use crate::pcode::utils::uintb_negate;
use crate::program::model::pcode::OpCode;
use crate::util::AssertException;

/// INT_2COMP p-code operation behavior: two's-complement negation.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorInt2Comp`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorInt2Comp {
    base: OpBehavior,
}

impl OpBehaviorInt2Comp {
    /// Construct a new `OpBehaviorInt2Comp` for [`OpCode::Int2Comp`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::Int2Comp as i32) }
    }
}

impl Default for OpBehaviorInt2Comp {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorInt2Comp {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`: `Utils.uintb_negate(in1 - 1, sizein)`.
    fn evaluate_unary_i64(&self, _sizeout: i32, sizein: i32, in1: i64) -> i64 {
        uintb_negate(in1.wrapping_sub(1), sizein)
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`.
    ///
    /// # Panics
    /// Java throws `AssertException("Expected unsigned in value")` if `in1` is negative; ported
    /// here as a panic since this trait's methods are infallible.
    fn evaluate_unary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128) -> i128 {
        if in1 < 0 {
            panic!("{}", AssertException::with_message("Expected unsigned in value"));
        }
        -in1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorInt2Comp::new().opcode(), OpCode::Int2Comp as i32);
    }

    #[test]
    fn negates_positive_one_byte_value() {
        let b = OpBehaviorInt2Comp::new();
        assert_eq!(b.evaluate_unary_i64(1, 1, 1), 0xff);
    }

    #[test]
    fn negates_zero() {
        let b = OpBehaviorInt2Comp::new();
        assert_eq!(b.evaluate_unary_i64(1, 1, 0), 0);
    }

    #[test]
    fn i128_negates_positive_value() {
        let b = OpBehaviorInt2Comp::new();
        assert_eq!(b.evaluate_unary_i128(4, 4, 5), -5);
    }

    #[test]
    #[should_panic(expected = "Expected unsigned in value")]
    fn i128_panics_on_negative_input() {
        let b = OpBehaviorInt2Comp::new();
        b.evaluate_unary_i128(4, 4, -1);
    }
}

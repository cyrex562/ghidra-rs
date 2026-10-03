//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntNegate`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use crate::pcode::utils::uintb_negate;
use crate::program::model::pcode::OpCode;
use crate::util::AssertException;

/// INT_NEGATE p-code operation behavior: bitwise complement (`~in1`).
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntNegate`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntNegate {
    base: OpBehavior,
}

impl OpBehaviorIntNegate {
    /// Construct a new `OpBehaviorIntNegate` for [`OpCode::IntNegate`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntNegate as i32) }
    }
}

impl Default for OpBehaviorIntNegate {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorIntNegate {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`: `Utils.uintb_negate(in1, sizein)`, a bitwise
    /// complement masked to the low `sizein` bytes.
    fn evaluate_unary_i64(&self, _sizeout: i32, sizein: i32, in1: i64) -> i64 {
        uintb_negate(in1, sizein)
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`: `in1.not()`.
    ///
    /// # Quirk: not masked to `sizein`, unlike the `long` overload
    /// Java's `BigInteger.not()` returns the *arbitrary-precision* two's-complement complement,
    /// mathematically `-(in1 + 1)` -- it does **not** mask the result to `sizein` bytes the way
    /// `Utils.uintb_negate` does for the `long` overload above. This is a genuine inconsistency
    /// between the two overloads in the original Java source (faithfully preserved here rather
    /// than "fixed" to match `evaluate_unary_i64`): callers of the `BigInteger` overload get a
    /// negative, unbounded-looking result instead of a `sizein`-byte masked positive one.
    ///
    /// # Panics
    /// Java throws `AssertException("Expected unsigned in value")` if `in1` is negative; ported
    /// here as a panic since this trait's methods are infallible.
    fn evaluate_unary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128) -> i128 {
        if in1 < 0 {
            panic!("{}", AssertException::with_message("Expected unsigned in value"));
        }
        // BigInteger.not(): -(in1 + 1).
        -(in1.wrapping_add(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntNegate::new().opcode(), OpCode::IntNegate as i32);
    }

    #[test]
    fn complements_one_byte_value() {
        let b = OpBehaviorIntNegate::new();
        assert_eq!(b.evaluate_unary_i64(1, 1, 0x0f), 0xf0);
    }

    #[test]
    fn complements_zero() {
        let b = OpBehaviorIntNegate::new();
        assert_eq!(b.evaluate_unary_i64(1, 1, 0), 0xff);
    }

    /// Java quirk: the `BigInteger` overload returns `-(in1 + 1)`, not a `sizein`-masked bitwise
    /// complement -- it diverges from the `long` overload's result for the same logical input.
    #[test]
    fn i128_not_matches_java_biginteger_semantics_not_masked() {
        let b = OpBehaviorIntNegate::new();
        // long overload of 0x0f (1 byte) gives 0xf0 (a small positive masked value).
        // BigInteger overload instead gives -(0x0f + 1) == -16.
        assert_eq!(b.evaluate_unary_i128(1, 1, 0x0f), -16);
    }

    #[test]
    #[should_panic(expected = "Expected unsigned in value")]
    fn i128_panics_on_negative_input() {
        let b = OpBehaviorIntNegate::new();
        b.evaluate_unary_i128(1, 1, -1);
    }
}

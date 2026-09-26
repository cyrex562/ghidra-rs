//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntSright`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::{calc_mask, convert_to_signed_value, signbit_negative};
use crate::program::model::pcode::OpCode;
use crate::util::AssertException;

/// INT_SRIGHT p-code operation behavior: signed (arithmetic, sign-filled) right shift.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntSright`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSright {
    base: OpBehavior,
}

impl OpBehaviorIntSright {
    /// Construct a new `OpBehaviorIntSright` for [`OpCode::IntSright`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntSright as i32) }
    }
}

impl Default for OpBehaviorIntSright {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntSright {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        let max_shift = (sizein * 8 - 1) as i64;
        if in2 < 0 || in2 > max_shift {
            if signbit_negative(in1, sizein) {
                return calc_mask(sizein);
            }
            return 0;
        }
        if signbit_negative(in1, sizein) {
            let mut res = in1 >> in2;
            let mut mask = calc_mask(sizein);
            mask = ((mask as u64).checked_shr(in2 as u32).unwrap_or(0) as i64) ^ mask;
            res |= mask;
            res
        }
        else {
            (in1 as u64).checked_shr(in2 as u32).unwrap_or(0) as i64
        }
    }

    /// # Quirk: returns a true signed value, not an "unsigned-looking" masked bit pattern
    /// The `i64` overload above encodes sign-extension by OR-ing extra high bits into an
    /// otherwise-unsigned result (e.g. a 1-byte `-8` comes back as `0xf8`). This overload instead
    /// returns the shift's actual signed value directly (`-8`), matching Java's
    /// `BigInteger.shiftRight`, which has no fixed width to encode a sign into. Faithfully
    /// reproduced (not "fixed" to match the other overload's shape).
    ///
    /// # Panics
    /// Java throws `AssertException("Expected unsigned in values")` if either input is negative;
    /// ported here as a panic since this trait's methods are infallible.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        if in1 < 0 || in2 < 0 {
            panic!("{}", AssertException::with_message("Expected unsigned in values"));
        }
        let signbit = sizein * 8 - 1;
        let max_shift = signbit as i128;
        let in2 = if in2 > max_shift { max_shift } else { in2 };
        let in1 = if signbit >= 0 && signbit < 128 && ((in1 >> signbit) & 1) != 0 {
            convert_to_signed_value(in1, sizein)
        }
        else {
            in1
        };
        if in2 >= 128 { if in1 < 0 { -1 } else { 0 } } else { in1 >> in2 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntSright::new().opcode(), OpCode::IntSright as i32);
    }

    #[test]
    fn positive_value_shifts_like_logical_shift() {
        let b = OpBehaviorIntSright::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x40, 2), 0x10);
    }

    #[test]
    fn negative_byte_sign_extends() {
        let b = OpBehaviorIntSright::new();
        // 0x80 is -128 as a signed byte; >> 4 should give 0xf8 (-8 as a signed byte).
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x80, 4), 0xf8);
    }

    #[test]
    fn shift_beyond_width_saturates_to_sign() {
        let b = OpBehaviorIntSright::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x80, 100), 0xff);
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x40, 100), 0x00);
    }

    #[test]
    fn negative_shift_saturates_to_sign() {
        let b = OpBehaviorIntSright::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x80, -1), 0xff);
    }

    /// Unlike the `i64` overload (which bakes sign-extension into extra high bits of an
    /// "unsigned-looking" result, e.g. `0xf8` for a 1-byte `-8`), the `i128`/`BigInteger` overload
    /// returns the shift's *true signed* value directly (`-8`), since `BigInteger` has no need for
    /// width-scoped bit-pattern tricks the way a fixed-width `long` does. This is a genuine,
    /// intentional difference between the two overloads' output *shapes* for the same logical
    /// result -- not a bug -- faithfully reproduced from `BigInteger.shiftRight`'s semantics.
    #[test]
    fn i128_returns_true_signed_value_not_a_masked_bit_pattern() {
        let b = OpBehaviorIntSright::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 0x80, 4), -8);
        assert_eq!(b.evaluate_binary_i128(1, 1, 0x40, 2), 0x10);
    }

    #[test]
    #[should_panic(expected = "Expected unsigned in values")]
    fn i128_panics_on_negative_input() {
        let b = OpBehaviorIntSright::new();
        b.evaluate_binary_i128(1, 1, -1, 1);
    }
}

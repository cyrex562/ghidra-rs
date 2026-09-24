//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatEqual`.

use super::op_behavior::OpBehavior;
use super::binary_op_behavior::BinaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_EQUAL p-code operation behavior: floating-point equality (a one-byte boolean).
///
/// Each evaluation looks up the [`FloatFormat`](crate::pcode::floatformat::FloatFormat) for the
/// operand size and delegates to it, exactly as the Java class does. The `BigInteger` path
/// widens this crate's `i128` stand-in to a [`BigInt`] and narrows the result back to its low 128
/// bits. The widening is two's-complement, which reads a 16-byte operand with its top bit set the
/// same way the float decoding does (sign bit set), and passes a negative value such as a signed
/// `INT2FLOAT` input through as Java's negative `BigInteger` would.
///
/// # Panics
/// If a size has no float format (Java: `UnsupportedFloatFormatException`).
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatEqual`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatEqual {
    base: OpBehavior,
}

impl OpBehaviorFloatEqual {
    /// Construct a new `OpBehaviorFloatEqual` for [`OpCode::FloatEqual`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatEqual as i32) }
    }
}

impl Default for OpBehaviorFloatEqual {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorFloatEqual {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateBinary(int, int, long, long)`.
    fn evaluate_binary_i64(&self, _sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        let format = format_for(sizein);
        format.op_equal(in1, in2)
    }

    /// Port of `evaluateBinary(int, int, BigInteger, BigInteger)`.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        let format = format_for(sizein);
        big_int_to_i128(&format.op_equal_big(&BigInt::from(in1), &BigInt::from(in2)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::floatformat::{get_float_format, FloatFormat};

    fn ff(size: i32) -> &'static FloatFormat {
        get_float_format(size).unwrap()
    }

    /// `ff.getEncoding(ff.getBigFloat(d))` as this crate's `i128` BigInteger stand-in.
    fn big_enc(ff: &FloatFormat, d: f64) -> i128 {
        big_int_to_i128(&ff.get_encoding_big(&ff.get_big_float_f64(d)))
    }

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorFloatEqual::new().opcode(), OpCode::FloatEqual as i32);
    }

    #[test]
    fn evaluate_binary_long() {
        let op = OpBehaviorFloatEqual::new();
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding(d);
        for (a, b, expect) in [(1.234, 1.234, 1), (-1.234, -1.234, 1), (-1.234, 1.234, 0), (f64::INFINITY, f64::INFINITY, 1), (f64::INFINITY, f64::NEG_INFINITY, 0), (f64::NEG_INFINITY, f64::NEG_INFINITY, 1), (f64::INFINITY, f64::NAN, 0), (f64::NAN, f64::NAN, 0), (0.0, -0.0, 1)] {
            assert_eq!(expect, op.evaluate_binary_i64(1, 8, e(a), e(b)), "{} == {}", a, b);
        }
    }

    #[test]
    fn evaluate_binary_big() {
        let op = OpBehaviorFloatEqual::new();
        let ff = ff(8);
        let e = |d: f64| big_enc(ff, d);
        let inf = big_int_to_i128(&ff.get_big_infinity_encoding(false));
        let ninf = big_int_to_i128(&ff.get_big_infinity_encoding(true));
        let nan = big_int_to_i128(&ff.get_big_nan_encoding(false));
        let zero = big_int_to_i128(&ff.get_big_zero_encoding(false));
        assert_eq!(1, op.evaluate_binary_i128(1, 8, e(1.234), e(1.234)));
        assert_eq!(1, op.evaluate_binary_i128(1, 8, e(-1.234), e(-1.234)));
        assert_eq!(0, op.evaluate_binary_i128(1, 8, e(-1.234), e(1.234)));
        assert_eq!(1, op.evaluate_binary_i128(1, 8, inf, inf));
        assert_eq!(0, op.evaluate_binary_i128(1, 8, inf, ninf));
        assert_eq!(1, op.evaluate_binary_i128(1, 8, ninf, ninf));
        assert_eq!(0, op.evaluate_binary_i128(1, 8, inf, nan));
        assert_eq!(1, op.evaluate_binary_i128(1, 8, zero, zero));
    }
}

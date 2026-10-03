//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatFloat2Float`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_FLOAT2FLOAT p-code operation behavior: floating-point conversion between float precisions (`sizein` bytes to `sizeout` bytes).
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
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatFloat2Float`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatFloat2Float {
    base: OpBehavior,
}

impl OpBehaviorFloatFloat2Float {
    /// Construct a new `OpBehaviorFloatFloat2Float` for [`OpCode::FloatFloat2Float`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatFloat2Float as i32) }
    }
}

impl Default for OpBehaviorFloatFloat2Float {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorFloatFloat2Float {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`.
    fn evaluate_unary_i64(&self, sizeout: i32, sizein: i32, in1: i64) -> i64 {
        let formatout = format_for(sizeout);
        let formatin = format_for(sizein);
        formatin.op_float2float(in1, formatout)
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`.
    fn evaluate_unary_i128(&self, sizeout: i32, sizein: i32, in1: i128) -> i128 {
        let formatout = format_for(sizeout);
        let formatin = format_for(sizein);
        big_int_to_i128(&formatin.op_float2float_big(&BigInt::from(in1), formatout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::floatformat::{get_float_format, BigFloat, FloatFormat};

    fn ff(size: i32) -> &'static FloatFormat {
        get_float_format(size).unwrap()
    }

    fn big_dec(ff: &FloatFormat, v: i128) -> BigFloat {
        ff.decode_big_float_big(&BigInt::from(v))
    }

    fn assert_host(ff: &FloatFormat, expect: f64, enc: i64) {
        let got = ff.decode_host_float(enc);
        if expect.is_nan() {
            assert!(got.is_nan(), "expected NaN, got {}", got);
        }
        else {
            assert_eq!(expect, got);
        }
    }

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorFloatFloat2Float::new().opcode(), OpCode::FloatFloat2Float as i32);
    }

    #[test]
    fn evaluate_unary_long() {
        let op = OpBehaviorFloatFloat2Float::new();
        let ff8 = ff(8);
        let ff4 = ff(4);
        for v in [1.75f64, -1.75, f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            assert_host(ff8, v, op.evaluate_unary_i64(8, 4, ff4.get_encoding(v)));
        }
        // 0.1 (double) -> 0.1f (0x3dcccccd), rounding to nearest
        assert_eq!(0x3dcccccd, op.evaluate_unary_i64(4, 8, 0.1f64.to_bits() as i64));
        // double max -> float +inf
        assert_eq!(0x7f800000, op.evaluate_unary_i64(4, 8, f64::MAX.to_bits() as i64));
    }

    #[test]
    fn evaluate_unary_big() {
        let op = OpBehaviorFloatFloat2Float::new();
        let ff8 = ff(8);
        let ff4 = ff(4);
        let a = big_int_to_i128(&ff4.get_encoding_big(&ff4.get_big_float_f64(1.75)));
        assert_eq!(ff8.get_big_float_f64(1.75), big_dec(ff8, op.evaluate_unary_i128(8, 4, a)));
        let a = big_int_to_i128(&ff4.get_encoding_big(&ff4.get_big_float_f64(-1.75)));
        assert_eq!(ff8.get_big_float_f64(-1.75), big_dec(ff8, op.evaluate_unary_i128(8, 4, a)));
        let a = big_int_to_i128(&ff4.get_encoding_big(&ff4.get_big_infinity(false)));
        assert_eq!(ff8.get_big_infinity(false), big_dec(ff8, op.evaluate_unary_i128(8, 4, a)));
        let a = big_int_to_i128(&ff4.get_encoding_big(&ff4.get_big_infinity(true)));
        assert_eq!(ff8.get_big_infinity(true), big_dec(ff8, op.evaluate_unary_i128(8, 4, a)));
        let a = big_int_to_i128(&ff4.get_encoding_big(&ff4.get_big_nan(false)));
        assert_eq!(ff8.get_big_nan(false), big_dec(ff8, op.evaluate_unary_i128(8, 4, a)));
        // double 1.5 -> x87 80-bit: 0x3fff c000000000000000
        let r = op.evaluate_unary_i128(10, 8, 1.5f64.to_bits() as i128);
        assert_eq!((0x3fff << 64) | 0xc000000000000000, r);
        // and back
        assert_eq!(1.5f64.to_bits() as i128, op.evaluate_unary_i128(8, 10, r));
    }
}

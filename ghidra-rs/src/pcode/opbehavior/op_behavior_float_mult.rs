//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatMult`.

use super::op_behavior::OpBehavior;
use super::binary_op_behavior::BinaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_MULT p-code operation behavior: floating-point multiplication.
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
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatMult`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatMult {
    base: OpBehavior,
}

impl OpBehaviorFloatMult {
    /// Construct a new `OpBehaviorFloatMult` for [`OpCode::FloatMult`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatMult as i32) }
    }
}

impl Default for OpBehaviorFloatMult {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorFloatMult {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateBinary(int, int, long, long)`.
    fn evaluate_binary_i64(&self, _sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        let format = format_for(sizein);
        format.op_mult(in1, in2)
    }

    /// Port of `evaluateBinary(int, int, BigInteger, BigInteger)`.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        let format = format_for(sizein);
        big_int_to_i128(&format.op_mult_big(&BigInt::from(in1), &BigInt::from(in2)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::floatformat::{get_float_format, BigFloat, FloatFormat};

    fn ff(size: i32) -> &'static FloatFormat {
        get_float_format(size).unwrap()
    }

    /// `ff.getEncoding(ff.getBigFloat(d))` as this crate's `i128` BigInteger stand-in.
    fn big_enc(ff: &FloatFormat, d: f64) -> i128 {
        big_int_to_i128(&ff.get_encoding_big(&ff.get_big_float_f64(d)))
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
        assert_eq!(OpBehaviorFloatMult::new().opcode(), OpCode::FloatMult as i32);
    }

    #[test]
    fn evaluate_binary_long() {
        let op = OpBehaviorFloatMult::new();
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding(d);
        assert_host(ff, 3.75, op.evaluate_binary_i64(8, 8, e(2.5), e(1.5)));
        assert_host(ff, f64::INFINITY, op.evaluate_binary_i64(8, 8, e(2.5), e(f64::INFINITY)));
        assert_host(ff, f64::NEG_INFINITY, op.evaluate_binary_i64(8, 8, e(f64::NEG_INFINITY), e(f64::INFINITY)));
        assert_host(ff, f64::NAN, op.evaluate_binary_i64(8, 8, e(f64::NEG_INFINITY), e(f64::NAN)));
        assert_host(ff, f64::NAN, op.evaluate_binary_i64(8, 8, e(0.0), e(f64::INFINITY)));
        // float max * 2 overflows to +inf
        assert_eq!(0x7f800000, op.evaluate_binary_i64(4, 4, 0x7f7fffff, 0x40000000));
    }

    #[test]
    fn evaluate_binary_big() {
        let op = OpBehaviorFloatMult::new();
        let ff = ff(8);
        let inf = big_int_to_i128(&ff.get_big_infinity_encoding(false));
        let ninf = big_int_to_i128(&ff.get_big_infinity_encoding(true));
        let nan = big_int_to_i128(&ff.get_big_nan_encoding(false));
        assert_eq!(ff.get_big_float_f64(3.75), big_dec(ff, op.evaluate_binary_i128(8, 8, big_enc(ff, 2.5), big_enc(ff, 1.5))));
        assert_eq!(ff.get_big_infinity(false), big_dec(ff, op.evaluate_binary_i128(8, 8, big_enc(ff, 2.5), inf)));
        assert_eq!(ff.get_big_infinity(true), big_dec(ff, op.evaluate_binary_i128(8, 8, ninf, inf)));
        assert_eq!(ff.get_big_nan(false), big_dec(ff, op.evaluate_binary_i128(8, 8, ninf, nan)));
        // smallest double subnormal * 0.5 rounds half-even to +0
        let min = f64::from_bits(1).to_bits() as i128;
        assert_eq!(0, op.evaluate_binary_i128(8, 8, min, 0.5f64.to_bits() as i128));
    }
}

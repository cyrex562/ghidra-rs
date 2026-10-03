//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatAdd`.

use super::op_behavior::OpBehavior;
use super::binary_op_behavior::BinaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_ADD p-code operation behavior: floating-point addition.
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
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatAdd`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatAdd {
    base: OpBehavior,
}

impl OpBehaviorFloatAdd {
    /// Construct a new `OpBehaviorFloatAdd` for [`OpCode::FloatAdd`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatAdd as i32) }
    }
}

impl Default for OpBehaviorFloatAdd {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorFloatAdd {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateBinary(int, int, long, long)`.
    fn evaluate_binary_i64(&self, _sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        let format = format_for(sizein);
        format.op_add(in1, in2)
    }

    /// Port of `evaluateBinary(int, int, BigInteger, BigInteger)`.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        let format = format_for(sizein);
        big_int_to_i128(&format.op_add_big(&BigInt::from(in1), &BigInt::from(in2)))
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
        assert_eq!(OpBehaviorFloatAdd::new().opcode(), OpCode::FloatAdd as i32);
    }

    #[test]
    fn evaluate_binary_long() {
        let op = OpBehaviorFloatAdd::new();
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding(d);
        assert_host(ff, 2.357, op.evaluate_binary_i64(8, 8, e(1.234), e(1.123)));
        assert_host(ff, 0.0, op.evaluate_binary_i64(8, 8, e(-1.123), e(1.123)));
        assert_host(ff, f64::INFINITY, op.evaluate_binary_i64(8, 8, e(f64::INFINITY), e(1.123)));
        assert_host(ff, f64::NEG_INFINITY, op.evaluate_binary_i64(8, 8, e(f64::NEG_INFINITY), e(1.123)));
        assert_host(ff, f64::NEG_INFINITY, op.evaluate_binary_i64(8, 8, e(f64::NEG_INFINITY), e(f64::NEG_INFINITY)));
        assert_host(ff, f64::NAN, op.evaluate_binary_i64(8, 8, e(f64::NEG_INFINITY), e(f64::INFINITY)));
        assert_host(ff, f64::NAN, op.evaluate_binary_i64(8, 8, e(f64::NAN), e(1.123)));
        // 1.0f + 2^-24 (a tie) rounds half-even to 1.0f
        assert_eq!(0x3f800000, op.evaluate_binary_i64(4, 4, 0x3f800000, 0x33800000));
    }

    #[test]
    fn evaluate_binary_big() {
        let op = OpBehaviorFloatAdd::new();
        let ff = ff(8);
        let inf = big_int_to_i128(&ff.get_big_infinity_encoding(false));
        let ninf = big_int_to_i128(&ff.get_big_infinity_encoding(true));
        let nan = big_int_to_i128(&ff.get_big_nan_encoding(false));
        let b = big_enc(ff, 1.123);
        assert_eq!(ff.get_big_float_f64(2.357), big_dec(ff, op.evaluate_binary_i128(8, 8, big_enc(ff, 1.234), b)));
        assert_eq!(ff.get_big_zero(false), big_dec(ff, op.evaluate_binary_i128(8, 8, big_enc(ff, -1.123), b)));
        assert_eq!(ff.get_big_infinity(false), big_dec(ff, op.evaluate_binary_i128(8, 8, inf, b)));
        assert_eq!(ff.get_big_infinity(true), big_dec(ff, op.evaluate_binary_i128(8, 8, ninf, b)));
        assert_eq!(ff.get_big_infinity(true), big_dec(ff, op.evaluate_binary_i128(8, 8, ninf, ninf)));
        assert_eq!(ff.get_big_nan(false), big_dec(ff, op.evaluate_binary_i128(8, 8, ninf, inf)));
        assert_eq!(ff.get_big_nan(false), big_dec(ff, op.evaluate_binary_i128(8, 8, nan, b)));
        // x87 80-bit 1.0 + 2.0 = 3.0 (0x4000 c000000000000000)
        let one: i128 = (0x3fff << 64) | 0x8000000000000000;
        let two: i128 = (0x4000 << 64) | 0x8000000000000000;
        assert_eq!((0x4000 << 64) | 0xc000000000000000, op.evaluate_binary_i128(10, 10, one, two));
    }
}

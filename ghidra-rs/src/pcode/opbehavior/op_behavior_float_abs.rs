//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatAbs`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_ABS p-code operation behavior: floating-point absolute value.
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
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatAbs`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatAbs {
    base: OpBehavior,
}

impl OpBehaviorFloatAbs {
    /// Construct a new `OpBehaviorFloatAbs` for [`OpCode::FloatAbs`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatAbs as i32) }
    }
}

impl Default for OpBehaviorFloatAbs {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorFloatAbs {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`.
    fn evaluate_unary_i64(&self, _sizeout: i32, sizein: i32, in1: i64) -> i64 {
        let format = format_for(sizein);
        format.op_abs(in1)
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`.
    fn evaluate_unary_i128(&self, _sizeout: i32, sizein: i32, in1: i128) -> i128 {
        let format = format_for(sizein);
        big_int_to_i128(&format.op_abs_big(&BigInt::from(in1)))
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
        assert_eq!(OpBehaviorFloatAbs::new().opcode(), OpCode::FloatAbs as i32);
    }

    #[test]
    fn evaluate_unary_long() {
        let op = OpBehaviorFloatAbs::new();
        let ff = ff(8);
        for (v, expect) in [(2.5, 2.5), (-2.5, 2.5), (f64::INFINITY, f64::INFINITY), (f64::NEG_INFINITY, f64::INFINITY), (f64::NAN, f64::NAN)] {
            assert_host(ff, expect, op.evaluate_unary_i64(8, 8, ff.get_encoding(v)));
        }
        // -2.5f (0xc0200000) -> 2.5f (0x40200000)
        assert_eq!(0x40200000, op.evaluate_unary_i64(4, 4, 0xc0200000));
    }

    #[test]
    fn evaluate_unary_big() {
        let op = OpBehaviorFloatAbs::new();
        let ff = ff(8);
        assert_eq!(ff.get_big_float_f64(2.5), big_dec(ff, op.evaluate_unary_i128(8, 8, big_enc(ff, 2.5))));
        assert_eq!(ff.get_big_float_f64(2.5), big_dec(ff, op.evaluate_unary_i128(8, 8, big_enc(ff, -2.5))));
        let ninf = big_int_to_i128(&ff.get_big_infinity_encoding(true));
        assert_eq!(ff.get_big_infinity(false), big_dec(ff, op.evaluate_unary_i128(8, 8, ninf)));
        let nan = big_int_to_i128(&ff.get_big_nan_encoding(false));
        assert_eq!(ff.get_big_nan(false), big_dec(ff, op.evaluate_unary_i128(8, 8, nan)));
        // x87 80-bit -1.0 (sign|0x3fff, mantissa 0x8000000000000000) -> +1.0
        let neg_one: i128 = (0xbfff << 64) | 0x8000000000000000;
        assert_eq!((0x3fff << 64) | 0x8000000000000000, op.evaluate_unary_i128(10, 10, neg_one));
    }
}

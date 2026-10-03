//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatFloor`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_FLOOR p-code operation behavior: floating-point floor.
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
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatFloor`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatFloor {
    base: OpBehavior,
}

impl OpBehaviorFloatFloor {
    /// Construct a new `OpBehaviorFloatFloor` for [`OpCode::FloatFloor`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatFloor as i32) }
    }
}

impl Default for OpBehaviorFloatFloor {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorFloatFloor {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`.
    fn evaluate_unary_i64(&self, _sizeout: i32, sizein: i32, in1: i64) -> i64 {
        let format = format_for(sizein);
        format.op_floor(in1)
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`.
    fn evaluate_unary_i128(&self, _sizeout: i32, sizein: i32, in1: i128) -> i128 {
        let format = format_for(sizein);
        big_int_to_i128(&format.op_floor_big(&BigInt::from(in1)))
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
        assert_eq!(OpBehaviorFloatFloor::new().opcode(), OpCode::FloatFloor as i32);
    }

    #[test]
    fn evaluate_unary_long() {
        let op = OpBehaviorFloatFloor::new();
        let ff = ff(8);
        for (v, expect) in [(2.5, 2.0), (-2.0, -2.0), (-2.5, -3.0), (f64::INFINITY, f64::INFINITY), (f64::NEG_INFINITY, f64::NEG_INFINITY), (f64::NAN, f64::NAN)] {
            assert_host(ff, expect, op.evaluate_unary_i64(8, 8, ff.get_encoding(v)));
        }
    }

    #[test]
    fn evaluate_unary_big() {
        let op = OpBehaviorFloatFloor::new();
        let ff = ff(8);
        assert_eq!(ff.get_big_float_f64(2.0), big_dec(ff, op.evaluate_unary_i128(8, 8, big_enc(ff, 2.5))));
        assert_eq!(ff.get_big_float_f64(-2.0), big_dec(ff, op.evaluate_unary_i128(8, 8, big_enc(ff, -2.0))));
        assert_eq!(ff.get_big_float_f64(-3.0), big_dec(ff, op.evaluate_unary_i128(8, 8, big_enc(ff, -2.5))));
        let inf = big_int_to_i128(&ff.get_big_infinity_encoding(false));
        assert_eq!(ff.get_big_infinity(false), big_dec(ff, op.evaluate_unary_i128(8, 8, inf)));
        let nan = big_int_to_i128(&ff.get_big_nan_encoding(false));
        assert_eq!(ff.get_big_nan(false), big_dec(ff, op.evaluate_unary_i128(8, 8, nan)));
        // x87 80-bit 2.75 -> 2.0
        let ff10 = super::format_for(10);
        let v = big_int_to_i128(&ff10.get_encoding_big(&ff10.get_big_float_f64(2.75)));
        let r = op.evaluate_unary_i128(10, 10, v);
        assert_eq!(ff10.get_big_float_f64(2.0), ff10.decode_big_float_big(&BigInt::from(r)));
    }
}

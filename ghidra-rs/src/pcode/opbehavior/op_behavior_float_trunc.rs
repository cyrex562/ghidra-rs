//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatTrunc`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_TRUNC p-code operation behavior: floating-point conversion to a `sizeout`-byte integer, rounding toward zero.
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
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatTrunc`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatTrunc {
    base: OpBehavior,
}

impl OpBehaviorFloatTrunc {
    /// Construct a new `OpBehaviorFloatTrunc` for [`OpCode::FloatTrunc`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatTrunc as i32) }
    }
}

impl Default for OpBehaviorFloatTrunc {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorFloatTrunc {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`.
    fn evaluate_unary_i64(&self, sizeout: i32, sizein: i32, in1: i64) -> i64 {
        let format = format_for(sizein);
        format.op_trunc(in1, sizeout)
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`.
    fn evaluate_unary_i128(&self, sizeout: i32, sizein: i32, in1: i128) -> i128 {
        let format = format_for(sizein);
        big_int_to_i128(&format.op_trunc_big(&BigInt::from(in1), sizeout))
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
        assert_eq!(OpBehaviorFloatTrunc::new().opcode(), OpCode::FloatTrunc as i32);
    }

    #[test]
    fn evaluate_unary_long() {
        let op = OpBehaviorFloatTrunc::new();
        let ff = ff(8);
        assert_eq!(2, op.evaluate_unary_i64(8, 8, ff.get_encoding(2.5)));
        assert_eq!(-2, op.evaluate_unary_i64(8, 8, ff.get_encoding(-2.5)));
        assert_eq!(i64::MAX, op.evaluate_unary_i64(8, 8, ff.get_encoding(f64::INFINITY)));
        assert_eq!(i64::MIN, op.evaluate_unary_i64(8, 8, ff.get_encoding(f64::NEG_INFINITY)));
        assert_eq!(0, op.evaluate_unary_i64(8, 8, ff.get_encoding(f64::NAN)));
        // -2.5f to a 4-byte int: 0xfffffffe
        assert_eq!(0xfffffffe, op.evaluate_unary_i64(4, 4, 0xc0200000));
    }

    #[test]
    fn evaluate_unary_big() {
        let op = OpBehaviorFloatTrunc::new();
        let ff = ff(8);
        assert_eq!(2, op.evaluate_unary_i128(8, 8, big_enc(ff, 2.5)));
        assert_eq!(-2, op.evaluate_unary_i128(8, 8, big_enc(ff, -2.5)));
        assert_eq!(i64::MAX as i128, op.evaluate_unary_i128(8, 8, big_int_to_i128(&ff.get_big_infinity_encoding(false))));
        assert_eq!(i64::MIN as i128, op.evaluate_unary_i128(8, 8, big_int_to_i128(&ff.get_big_infinity_encoding(true))));
        assert_eq!(0, op.evaluate_unary_i128(8, 8, big_int_to_i128(&ff.get_big_nan_encoding(false))));
        // x87 80-bit -1e20 truncates exactly
        let ff10 = super::format_for(10);
        let v = big_int_to_i128(&ff10.get_encoding_big(&ff10.get_big_float_f64(-1e20)));
        assert_eq!(-100000000000000000000i128, op.evaluate_unary_i128(16, 10, v));
    }
}

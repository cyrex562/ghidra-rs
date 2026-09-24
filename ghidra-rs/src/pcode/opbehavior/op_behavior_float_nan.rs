//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatNan`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_NAN p-code operation behavior: floating-point NaN test.
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
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatNan`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatNan {
    base: OpBehavior,
}

impl OpBehaviorFloatNan {
    /// Construct a new `OpBehaviorFloatNan` for [`OpCode::FloatNan`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatNan as i32) }
    }
}

impl Default for OpBehaviorFloatNan {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorFloatNan {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`.
    fn evaluate_unary_i64(&self, _sizeout: i32, sizein: i32, in1: i64) -> i64 {
        let format = format_for(sizein);
        format.op_nan(in1)
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`.
    fn evaluate_unary_i128(&self, _sizeout: i32, sizein: i32, in1: i128) -> i128 {
        let format = format_for(sizein);
        big_int_to_i128(&format.op_nan_big(&BigInt::from(in1)))
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
        assert_eq!(OpBehaviorFloatNan::new().opcode(), OpCode::FloatNan as i32);
    }

    #[test]
    fn evaluate_unary_long() {
        let op = OpBehaviorFloatNan::new();
        let ff = ff(8);
        assert_eq!(1, op.evaluate_unary_i64(1, 8, ff.get_encoding(f64::NAN)));
        assert_eq!(0, op.evaluate_unary_i64(1, 8, ff.get_encoding(0.0)));
        assert_eq!(0, op.evaluate_unary_i64(1, 8, ff.get_encoding(1.234)));
        // signaling NaN 0x7f800001 and quiet NaN 0xffc00000 in single precision; +inf is not NaN
        assert_eq!(1, op.evaluate_unary_i64(1, 4, 0x7f800001));
        assert_eq!(1, op.evaluate_unary_i64(1, 4, 0xffc00000));
        assert_eq!(0, op.evaluate_unary_i64(1, 4, 0x7f800000));
    }

    #[test]
    fn evaluate_unary_big() {
        let op = OpBehaviorFloatNan::new();
        let ff = ff(8);
        assert_eq!(1, op.evaluate_unary_i128(1, 8, big_int_to_i128(&ff.get_big_nan_encoding(false))));
        assert_eq!(0, op.evaluate_unary_i128(1, 8, big_int_to_i128(&ff.get_big_zero_encoding(false))));
        assert_eq!(0, op.evaluate_unary_i128(1, 8, big_enc(ff, 1.234)));
        // binary128 NaN with the sign bit set: the i128 is negative, but is read as unsigned
        let ff16 = super::format_for(16);
        let neg_nan = big_int_to_i128(&ff16.get_big_nan_encoding(true));
        assert!(neg_nan < 0);
        assert_eq!(1, op.evaluate_unary_i128(1, 16, neg_nan));
    }
}

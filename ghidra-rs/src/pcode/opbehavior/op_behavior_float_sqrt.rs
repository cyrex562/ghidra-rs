//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatSqrt`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_SQRT p-code operation behavior: floating-point square root.
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
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatSqrt`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatSqrt {
    base: OpBehavior,
}

impl OpBehaviorFloatSqrt {
    /// Construct a new `OpBehaviorFloatSqrt` for [`OpCode::FloatSqrt`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatSqrt as i32) }
    }
}

impl Default for OpBehaviorFloatSqrt {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorFloatSqrt {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`.
    fn evaluate_unary_i64(&self, _sizeout: i32, sizein: i32, in1: i64) -> i64 {
        let format = format_for(sizein);
        format.op_sqrt(in1)
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`.
    fn evaluate_unary_i128(&self, _sizeout: i32, sizein: i32, in1: i128) -> i128 {
        let format = format_for(sizein);
        big_int_to_i128(&format.op_sqrt_big(&BigInt::from(in1)))
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

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorFloatSqrt::new().opcode(), OpCode::FloatSqrt as i32);
    }

    #[test]
    fn evaluate_unary_long() {
        let op = OpBehaviorFloatSqrt::new();
        let ff = ff(8);
        let r = op.evaluate_unary_i64(8, 8, ff.get_encoding(2.0));
        assert_eq!(1.4142135623730951, ff.decode_host_float(r));
        assert!(ff.decode_host_float(op.evaluate_unary_i64(8, 8, ff.get_encoding(-1.0))).is_nan());
        // sqrt(4.0f) = 2.0f
        assert_eq!(0x40000000, op.evaluate_unary_i64(4, 4, 0x40800000));
    }

    #[test]
    fn evaluate_unary_big() {
        let op = OpBehaviorFloatSqrt::new();
        let ff = ff(8);
        let r = big_dec(ff, op.evaluate_unary_i128(8, 8, big_enc(ff, 2.0)));
        assert_eq!("1.414213562373095", ff.round(&r).unwrap().to_string());
        assert_eq!(ff.get_big_float_f64(2f64.sqrt()), r);
        // x87 80-bit sqrt(2): 0x3fff b504f333f9de6484 (64-bit significand, rounded to nearest)
        let two: i128 = (0x4000 << 64) | 0x8000000000000000;
        assert_eq!((0x3fff << 64) | 0xb504f333f9de6484, op.evaluate_unary_i128(10, 10, two));
    }
}

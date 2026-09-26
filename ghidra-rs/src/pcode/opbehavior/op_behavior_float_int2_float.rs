//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatInt2Float`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_INT2FLOAT p-code operation behavior: floating-point conversion of a signed `sizein`-byte integer to a `sizeout`-byte float.
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
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatInt2Float`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatInt2Float {
    base: OpBehavior,
}

impl OpBehaviorFloatInt2Float {
    /// Construct a new `OpBehaviorFloatInt2Float` for [`OpCode::FloatInt2Float`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatInt2Float as i32) }
    }
}

impl Default for OpBehaviorFloatInt2Float {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorFloatInt2Float {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`.
    fn evaluate_unary_i64(&self, sizeout: i32, sizein: i32, in1: i64) -> i64 {
        let format = format_for(sizeout);
        format.op_int2float(in1, sizein)
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`.
    fn evaluate_unary_i128(&self, sizeout: i32, sizein: i32, in1: i128) -> i128 {
        let format = format_for(sizeout);
        big_int_to_i128(&format.op_int2float_big(&BigInt::from(in1), sizein, true))
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

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorFloatInt2Float::new().opcode(), OpCode::FloatInt2Float as i32);
    }

    #[test]
    fn evaluate_unary_long() {
        let op = OpBehaviorFloatInt2Float::new();
        let ff = ff(4);
        for (v, expect) in [(2i64, 2.0f64), (-2, -2.0), (0, 0.0), (0x0ffffffff, -1.0)] {
            let result = op.evaluate_unary_i64(4, 4, v);
            assert_eq!(0, result & 0xffffffff00000000u64 as i64); // only 4 bytes are used
            assert_eq!(expect, ff.decode_host_float(result));
        }
        // 16777217 is not representable in single precision: rounds half-even to 16777216
        assert_eq!(0x4b800000, op.evaluate_unary_i64(4, 4, 16777217));
        // 1-byte 0x80 is -128 -> double 0xc060000000000000
        assert_eq!(0xc060000000000000u64 as i64, op.evaluate_unary_i64(8, 1, 0x80));
    }

    #[test]
    fn evaluate_unary_big() {
        let op = OpBehaviorFloatInt2Float::new();
        let ff = ff(4);
        let limit: i128 = 1 << 32;
        let r = op.evaluate_unary_i128(4, 4, 2);
        assert!(r < limit);
        assert_eq!(ff.get_big_float_f64(2.0), big_dec(ff, r));
        let r = op.evaluate_unary_i128(4, 4, -2);
        assert!(r < limit);
        assert_eq!(ff.get_big_float_f64(-2.0), big_dec(ff, r));
        let r = op.evaluate_unary_i128(4, 4, 0);
        assert_eq!(ff.get_big_zero(false), big_dec(ff, r));
        let neg_one = crate::pcode::utils::bytes_to_big_integer(&[0xff, 0xff, 0xff, 0xff], 4, false, false);
        assert_eq!(ff.get_big_float_f64(-1.0), big_dec(ff, op.evaluate_unary_i128(4, 4, neg_one)));
        // 8-byte i64::MIN into x87 80-bit: exactly -2^63
        let r = op.evaluate_unary_i128(10, 8, i64::MIN as u64 as i128);
        assert_eq!((0xc03e << 64) | 0x8000000000000000, r);
    }
}

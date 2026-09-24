//! Port of `ghidra.pcode.opbehavior.OpBehaviorFloatRound`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use num_bigint::BigInt;

use super::float_format_for as format_for;
use crate::pcode::utils::big_int_to_i128;
use crate::program::model::pcode::OpCode;

/// FLOAT_ROUND p-code operation behavior: floating-point round to nearest integer (halves away from negative infinity: `floor(x + 0.5)`).
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
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorFloatRound`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorFloatRound {
    base: OpBehavior,
}

impl OpBehaviorFloatRound {
    /// Construct a new `OpBehaviorFloatRound` for [`OpCode::FloatRound`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::FloatRound as i32) }
    }
}

impl Default for OpBehaviorFloatRound {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorFloatRound {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`.
    fn evaluate_unary_i64(&self, _sizeout: i32, sizein: i32, in1: i64) -> i64 {
        let format = format_for(sizein);
        format.op_round(in1)
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`.
    fn evaluate_unary_i128(&self, _sizeout: i32, sizein: i32, in1: i128) -> i128 {
        let format = format_for(sizein);
        big_int_to_i128(&format.op_round_big(&BigInt::from(in1)))
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
        assert_eq!(OpBehaviorFloatRound::new().opcode(), OpCode::FloatRound as i32);
    }

    const ROUNDS: [(f64, f64); 6] = [(2.5, 3.0), (2.25, 2.0), (2.75, 3.0), (-2.5, -2.0), (-2.25, -2.0), (-2.75, -3.0)];

    #[test]
    fn evaluate_unary_long() {
        let op = OpBehaviorFloatRound::new();
        let ff = ff(8);
        for (v, expect) in ROUNDS {
            assert_host(ff, expect, op.evaluate_unary_i64(8, 8, ff.get_encoding(v)));
        }
        for v in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            assert_host(ff, v, op.evaluate_unary_i64(8, 8, ff.get_encoding(v)));
        }
    }

    #[test]
    fn evaluate_unary_big() {
        let op = OpBehaviorFloatRound::new();
        let ff = ff(8);
        for (v, expect) in ROUNDS {
            assert_eq!(ff.get_big_float_f64(expect), big_dec(ff, op.evaluate_unary_i128(8, 8, big_enc(ff, v))), "round {}", v);
        }
        let inf = big_int_to_i128(&ff.get_big_infinity_encoding(false));
        assert_eq!(ff.get_big_infinity(false), big_dec(ff, op.evaluate_unary_i128(8, 8, inf)));
        let ninf = big_int_to_i128(&ff.get_big_infinity_encoding(true));
        assert_eq!(ff.get_big_infinity(true), big_dec(ff, op.evaluate_unary_i128(8, 8, ninf)));
        let nan = big_int_to_i128(&ff.get_big_nan_encoding(false));
        assert_eq!(ff.get_big_nan(false), big_dec(ff, op.evaluate_unary_i128(8, 8, nan)));
    }
}

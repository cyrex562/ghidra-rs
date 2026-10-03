//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntSborrow`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// INT_SBORROW p-code operation behavior: `1` if signed subtraction of the two operands borrows
/// (overflows), within `sizein` bytes.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntSborrow`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSborrow {
    base: OpBehavior,
}

impl OpBehaviorIntSborrow {
    /// Construct a new `OpBehaviorIntSborrow` for [`OpCode::IntSborrow`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntSborrow as i32) }
    }
}

impl Default for OpBehaviorIntSborrow {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntSborrow {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        let res = in1.wrapping_sub(in2);

        let shift = sizein.wrapping_mul(8).wrapping_sub(1);
        let mut a = (in1 >> shift) & 1; // Grab sign bit
        let b = (in2 >> shift) & 1; // Grab sign bit
        let mut r = (res >> shift) & 1; // Grab sign bit

        a ^= r;
        r ^= b;
        r ^= 1;
        a &= r;
        a
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        let res = in1.wrapping_sub(in2);

        let bit = sizein.wrapping_mul(8).wrapping_sub(1);
        let mut a = test_bit(in1, bit); // Grab sign bit
        let b = test_bit(in2, bit); // Grab sign bit
        let mut r = test_bit(res, bit); // Grab sign bit

        a ^= r;
        r ^= b;
        r ^= true;
        a &= r;
        if a { 1 } else { 0 }
    }
}

fn test_bit(val: i128, bit: i32) -> bool {
    if !(0..128).contains(&bit) {
        return false;
    }
    ((val >> bit) & 1) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntSborrow::new().opcode(), OpCode::IntSborrow as i32);
    }

    #[test]
    fn no_overflow_for_ordinary_subtraction() {
        let b = OpBehaviorIntSborrow::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 5, 3), 0);
    }

    #[test]
    fn overflow_subtracting_negative_from_max_positive() {
        let b = OpBehaviorIntSborrow::new();
        // 0x7f (127, max positive signed byte) - 0xff (-1 signed byte) = 128, which overflows the
        // signed byte range [-128, 127].
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x7f, 0xff), 1);
    }

    #[test]
    fn overflow_subtracting_positive_from_min_negative() {
        let b = OpBehaviorIntSborrow::new();
        // 0x80 (-128) - 0x01 (1) = -129, which overflows the signed byte range.
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x80, 0x01), 1);
    }

    #[test]
    fn i128_matches_i64() {
        let b = OpBehaviorIntSborrow::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 5, 3), 0);
        assert_eq!(b.evaluate_binary_i128(1, 1, 0x7f, 0xff), 1);
        assert_eq!(b.evaluate_binary_i128(1, 1, 0x80, 0x01), 1);
    }
}

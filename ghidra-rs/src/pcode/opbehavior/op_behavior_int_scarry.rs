//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntScarry`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// INT_SCARRY p-code operation behavior: `1` if signed addition of the two operands overflows
/// (carries), within `sizein` bytes.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntScarry`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntScarry {
    base: OpBehavior,
}

impl OpBehaviorIntScarry {
    /// Construct a new `OpBehaviorIntScarry` for [`OpCode::IntScarry`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntScarry as i32) }
    }
}

impl Default for OpBehaviorIntScarry {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntScarry {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        let res = in1.wrapping_add(in2);

        let shift = sizein.wrapping_mul(8).wrapping_sub(1);
        let mut a = (in1 >> shift) & 1; // Grab sign bit
        let b = (in2 >> shift) & 1; // Grab sign bit
        let mut r = (res >> shift) & 1; // Grab sign bit

        r ^= a;
        a ^= b;
        a ^= 1;
        r &= a;
        r
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        let res = in1.wrapping_add(in2);

        let bit = sizein.wrapping_mul(8).wrapping_sub(1);
        let mut a = test_bit(in1, bit); // Grab sign bit
        let b = test_bit(in2, bit); // Grab sign bit
        let mut r = test_bit(res, bit); // Grab sign bit

        r ^= a;
        a ^= b;
        a ^= true;
        r &= a;
        if r { 1 } else { 0 }
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
        assert_eq!(OpBehaviorIntScarry::new().opcode(), OpCode::IntScarry as i32);
    }

    #[test]
    fn no_overflow_for_ordinary_addition() {
        let b = OpBehaviorIntScarry::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 2, 3), 0);
    }

    #[test]
    fn overflow_adding_two_positives_past_max() {
        let b = OpBehaviorIntScarry::new();
        // 0x7f (127) + 0x01 (1) = 128, which overflows the signed byte range [-128, 127].
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x7f, 0x01), 1);
    }

    #[test]
    fn overflow_adding_two_negatives_past_min() {
        let b = OpBehaviorIntScarry::new();
        // 0x80 (-128) + 0xff (-1) = -129, which overflows the signed byte range.
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x80, 0xff), 1);
    }

    #[test]
    fn no_overflow_adding_positive_and_negative() {
        let b = OpBehaviorIntScarry::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x7f, 0xff), 0);
    }

    #[test]
    fn i128_matches_i64() {
        let b = OpBehaviorIntScarry::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 2, 3), 0);
        assert_eq!(b.evaluate_binary_i128(1, 1, 0x7f, 0x01), 1);
        assert_eq!(b.evaluate_binary_i128(1, 1, 0x80, 0xff), 1);
    }
}

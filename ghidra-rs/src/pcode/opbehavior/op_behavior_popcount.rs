//! Port of `ghidra.pcode.opbehavior.OpBehaviorPopcount`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use crate::program::model::pcode::OpCode;

/// POPCOUNT p-code operation behavior: counts the number of set bits.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorPopcount`.
///
/// # Quirk: counts bits across the full container width, not just `sizein` bytes
/// Java's `evaluateUnary(long)` calls `Long.bitCount(val)`, which counts set bits across the
/// entire 64-bit `long`, not just the low `sizein` bytes; likewise the `BigInteger` overload
/// counts every set bit of `unsignedIn1` regardless of `sizein`. Neither overload masks to
/// `sizein` first. This relies on the (documented) calling convention that inputs are already
/// zero-extended to exactly their meaningful width, so it is faithfully preserved here rather
/// than "fixed" to mask by `sizein`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorPopcount {
    base: OpBehavior,
}

impl OpBehaviorPopcount {
    /// Construct a new `OpBehaviorPopcount` for [`OpCode::Popcount`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::Popcount as i32) }
    }
}

impl Default for OpBehaviorPopcount {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorPopcount {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_unary_i64(&self, _sizeout: i32, _sizein: i32, val: i64) -> i64 {
        (val as u64).count_ones() as i64
    }

    fn evaluate_unary_i128(&self, _sizeout: i32, _sizein: i32, unsigned_in1: i128) -> i128 {
        (unsigned_in1 as u128).count_ones() as i128
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorPopcount::new().opcode(), OpCode::Popcount as i32);
    }

    #[test]
    fn counts_set_bits() {
        let b = OpBehaviorPopcount::new();
        assert_eq!(b.evaluate_unary_i64(1, 1, 0x00), 0);
        assert_eq!(b.evaluate_unary_i64(1, 1, 0xff), 8);
        assert_eq!(b.evaluate_unary_i64(1, 4, 0b1011), 3);
    }

    #[test]
    fn counts_bits_of_negative_bit_pattern() {
        let b = OpBehaviorPopcount::new();
        assert_eq!(b.evaluate_unary_i64(8, 8, -1i64), 64);
    }

    #[test]
    fn i128_counts_set_bits() {
        let b = OpBehaviorPopcount::new();
        assert_eq!(b.evaluate_unary_i128(1, 1, 0xff), 8);
        assert_eq!(b.evaluate_unary_i128(1, 1, 0), 0);
    }
}

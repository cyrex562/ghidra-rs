//! Port of `ghidra.pcode.opbehavior.OpBehaviorPiece`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::program::model::pcode::OpCode;

/// PIECE p-code operation behavior: concatenates two inputs, `in1` as the high part and `in2` as
/// the low part, with `in1` shifted left by `sizein` bytes (the size of `in1`, per
/// `BinaryOpBehavior`'s "`sizein` is `in1` size" contract).
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorPiece`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorPiece {
    base: OpBehavior,
}

impl OpBehaviorPiece {
    /// Construct a new `OpBehaviorPiece` for [`OpCode::Piece`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::Piece as i32) }
    }
}

impl Default for OpBehaviorPiece {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorPiece {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateBinary(int, int, long, long)`: `(in1 << (sizein * 8)) | in2`.
    ///
    /// Uses `wrapping_shl` to match Java's `long` shift semantics, where the shift distance is
    /// taken modulo 64 (JLS 15.19) rather than saturating or panicking.
    fn evaluate_binary_i64(&self, _sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        in1.wrapping_shl((sizein.wrapping_mul(8)) as u32) | in2
    }

    /// Port of `evaluateBinary(int, int, BigInteger, BigInteger)`:
    /// `in1.shiftLeft(sizein * 8).or(in2)`.
    ///
    /// Unlike Java's arbitrary-precision `BigInteger`, this crate represents unsigned values in a
    /// bounded `i128`; a shift distance of 128 or more would push every significant bit out, so
    /// (matching this crate's established `calc_bigmask`/`pow2_bits` convention for the same
    /// 128-bit boundary) the shifted term is treated as `0` in that case instead of panicking.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        let shift = sizein.wrapping_mul(8);
        let shifted = if (0..128).contains(&shift) { in1 << shift } else { 0 };
        shifted | in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorPiece::new().opcode(), OpCode::Piece as i32);
    }

    #[test]
    fn combines_high_and_low_bytes() {
        let b = OpBehaviorPiece::new();
        // in1 = 0x12 (1 byte high part), in2 = 0x34 (1 byte low part) -> 0x1234
        assert_eq!(b.evaluate_binary_i64(2, 1, 0x12, 0x34), 0x1234);
    }

    #[test]
    fn combines_four_byte_pieces() {
        let b = OpBehaviorPiece::new();
        assert_eq!(b.evaluate_binary_i64(8, 4, 0xDEAD_BEEFu32 as i64, 0xCAFE_BABEu32 as i64), 0xDEAD_BEEF_CAFE_BABEu64 as i64);
    }

    #[test]
    fn zero_high_part_yields_low_part() {
        let b = OpBehaviorPiece::new();
        assert_eq!(b.evaluate_binary_i64(4, 2, 0, 0x1234), 0x1234);
    }

    #[test]
    fn i128_combines_pieces() {
        let b = OpBehaviorPiece::new();
        assert_eq!(b.evaluate_binary_i128(2, 1, 0x12, 0x34), 0x1234);
    }

    #[test]
    fn i128_full_shift_out_treated_as_zero() {
        let b = OpBehaviorPiece::new();
        // sizein = 16 -> shift of 128 bits, pushing everything out of the 128-bit container.
        assert_eq!(b.evaluate_binary_i128(16, 16, 1, 5), 5);
    }
}

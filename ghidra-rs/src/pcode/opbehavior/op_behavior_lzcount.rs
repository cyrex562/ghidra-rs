//! Port of `ghidra.pcode.opbehavior.OpBehaviorLzcount`.

use super::op_behavior::OpBehavior;
use super::unary_op_behavior::UnaryOpBehavior;
use crate::program::model::pcode::OpCode;

/// LZCOUNT p-code operation behavior: counts leading zero bits within the `sizein`-byte input.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorLzcount`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorLzcount {
    base: OpBehavior,
}

impl OpBehaviorLzcount {
    /// Construct a new `OpBehaviorLzcount` for [`OpCode::Lzcount`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::Lzcount as i32) }
    }
}

impl Default for OpBehaviorLzcount {
    fn default() -> Self {
        Self::new()
    }
}

impl UnaryOpBehavior for OpBehaviorLzcount {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateUnary(int, int, long)`.
    ///
    /// # Quirk: result is not masked to `sizeout`, unlike the `BigInteger` overload
    /// Java's `long` overload returns the raw leading-zero count with no `sizeout` masking at
    /// all, while the `BigInteger` overload below conditionally masks to `0xff`/`0xffff` when
    /// `sizeout` is `1`/`2`. Since the count for any `sizein <= 8` never exceeds `64`, this
    /// asymmetry has no observable effect in practice, but it is faithfully preserved (not
    /// "fixed" to match the other overload) since some future caller with a larger `sizein` could
    /// observe it.
    fn evaluate_unary_i64(&self, _sizeout: i32, sizein: i32, val: i64) -> i64 {
        let mut mask: i64 = 1i64.wrapping_shl((sizein.wrapping_mul(8)).wrapping_sub(1) as u32);
        let mut count: i64 = 0;
        while mask != 0 {
            if (mask & val) != 0 {
                break;
            }
            count += 1;
            mask = ((mask as u64) >> 1) as i64;
        }
        count
    }

    /// Port of `evaluateUnary(int, int, BigInteger)`.
    fn evaluate_unary_i128(&self, sizeout: i32, sizein: i32, unsigned_in1: i128) -> i128 {
        let mut bit = sizein.wrapping_mul(8).wrapping_sub(1);
        let mut bitcount: i128 = 0;
        while bit >= 0 {
            if bit < 128 && ((unsigned_in1 >> bit) & 1) != 0 {
                break;
            }
            bitcount += 1;
            bit -= 1;
        }
        if sizeout == 1 {
            bitcount &= 0xff;
        }
        else if sizeout == 2 {
            bitcount &= 0xffff;
        }
        bitcount
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorLzcount::new().opcode(), OpCode::Lzcount as i32);
    }

    #[test]
    fn counts_leading_zeros_one_byte() {
        let b = OpBehaviorLzcount::new();
        assert_eq!(b.evaluate_unary_i64(1, 1, 0x01), 7);
        assert_eq!(b.evaluate_unary_i64(1, 1, 0x80), 0);
        assert_eq!(b.evaluate_unary_i64(1, 1, 0x00), 8);
    }

    #[test]
    fn counts_leading_zeros_four_bytes() {
        let b = OpBehaviorLzcount::new();
        assert_eq!(b.evaluate_unary_i64(1, 4, 0x0000_0001), 31);
        assert_eq!(b.evaluate_unary_i64(1, 4, 0x8000_0000u32 as i64), 0);
    }

    #[test]
    fn i128_counts_leading_zeros() {
        let b = OpBehaviorLzcount::new();
        assert_eq!(b.evaluate_unary_i128(1, 1, 0x01), 7);
        assert_eq!(b.evaluate_unary_i128(1, 1, 0x00), 8);
    }
}

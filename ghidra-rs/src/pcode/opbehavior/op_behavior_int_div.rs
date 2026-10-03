//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntDiv`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::{bytes_to_big_integer, calc_mask, convert_to_unsigned_value, long_to_bytes};
use crate::program::model::pcode::OpCode;

/// INT_DIV p-code operation behavior: unsigned integer division.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntDiv`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntDiv {
    base: OpBehavior,
}

impl OpBehaviorIntDiv {
    /// Construct a new `OpBehaviorIntDiv` for [`OpCode::IntDiv`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntDiv as i32) }
    }
}

impl Default for OpBehaviorIntDiv {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntDiv {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateBinary(int, int, long, long)`.
    ///
    /// # Quirk: `sizein == 8` mask is Java's shift-truncation bug, not the sign bit
    /// Java's condition for taking the slow `BigInteger`-based unsigned-division fallback path
    /// checks `long mask = (0x1 << 63)`. `0x1` is an `int` literal, and Java's `<<` on `int`
    /// operands uses only the low 5 bits of the shift distance (JLS 15.19), so `0x1 << 63`
    /// computes as `0x1 << 31` == `Integer.MIN_VALUE` (`0x80000000`), which is then
    /// *sign-extended* to `long` when assigned to `mask`, yielding `0xFFFFFFFF80000000` (bits
    /// 31..=63 all set) rather than the probably-intended `0x8000000000000000` (bit 63 only). This
    /// makes the "does either operand need the slow path" check over-eager (any of bits 31..=63
    /// set, not just bit 63) but does not change the final result, since the fallback path is
    /// still correct for the extra inputs it now also catches. Faithfully reproduced (not "fixed"
    /// to `1i64 << 63`).
    fn evaluate_binary_i64(&self, sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        if sizein <= 0 || in2 == 0 {
            return 0;
        }
        if in1 == in2 {
            return 1;
        }
        if sizein == 8 {
            let mask: i64 = 0xFFFFFFFF80000000u64 as i64;
            let bit1 = in1 & mask;
            let bit2 = in2 & mask;
            if bit1 != 0 || bit2 != 0 {
                let sizein_u = sizein as usize;
                let mut big_in1 = bytes_to_big_integer(&long_to_bytes(in1, sizein_u, true), sizein_u, true, false);
                if big_in1 < 0 {
                    big_in1 = convert_to_unsigned_value(big_in1, sizein);
                }
                let mut big_in2 = bytes_to_big_integer(&long_to_bytes(in2, sizein_u, true), sizein_u, true, false);
                if big_in2 < 0 {
                    big_in2 = convert_to_unsigned_value(big_in2, sizein);
                }
                let result = big_in1 / big_in2;
                return (result as i64) & calc_mask(sizeout);
            }
        }

        (in1 / in2) & calc_mask(sizeout)
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        if sizein <= 0 || in2 == 0 {
            return 0;
        }
        in1 / in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntDiv::new().opcode(), OpCode::IntDiv as i32);
    }

    #[test]
    fn divides_small_values() {
        let b = OpBehaviorIntDiv::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 10, 3), 3);
    }

    #[test]
    fn zero_divisor_yields_zero() {
        let b = OpBehaviorIntDiv::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 10, 0), 0);
    }

    #[test]
    fn equal_operands_yield_one() {
        let b = OpBehaviorIntDiv::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 42, 42), 1);
    }

    #[test]
    fn eight_byte_unsigned_division_with_high_bit_set() {
        let b = OpBehaviorIntDiv::new();
        // in1 = u64::MAX (looks negative as a signed i64), divided by 2 should be treated as
        // unsigned division: u64::MAX / 2.
        let in1 = -1i64; // 0xFFFFFFFFFFFFFFFF as u64::MAX
        let expected = (u64::MAX / 2) as i64;
        assert_eq!(b.evaluate_binary_i64(8, 8, in1, 2), expected);
    }

    #[test]
    fn i128_divides_small_values() {
        let b = OpBehaviorIntDiv::new();
        assert_eq!(b.evaluate_binary_i128(4, 4, 10, 3), 3);
    }

    #[test]
    fn i128_zero_divisor_yields_zero() {
        let b = OpBehaviorIntDiv::new();
        assert_eq!(b.evaluate_binary_i128(4, 4, 10, 0), 0);
    }
}

//! Port of `ghidra.pcode.opbehavior.OpBehaviorSubpiece`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::calc_mask;
use crate::program::model::pcode::OpCode;

/// SUBPIECE p-code operation behavior: extracts a truncated sub-value from `in1`, skipping
/// `in2` low-order bytes.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorSubpiece`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorSubpiece {
    base: OpBehavior,
}

impl OpBehaviorSubpiece {
    /// Construct a new `OpBehaviorSubpiece` for [`OpCode::Subpiece`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::Subpiece as i32) }
    }
}

impl Default for OpBehaviorSubpiece {
    fn default() -> Self {
        Self::new()
    }
}

/// Tests bit `bit` of `val`'s two's-complement representation, mirroring `BigInteger.testBit`.
/// Out-of-range (`bit >= 128`) is treated as "no more significant bits" and returns `false`,
/// matching this crate's established bounded-128-bit convention (see `calc_bigmask`).
fn test_bit_128(val: i128, bit: i32) -> bool {
    if !(0..128).contains(&bit) {
        return false;
    }
    ((val >> bit) & 1) != 0
}

/// Clears bit `bit` of `val`, mirroring `BigInteger.clearBit`. A no-op for `bit >= 128`.
fn clear_bit_128(val: i128, bit: i32) -> i128 {
    if !(0..128).contains(&bit) {
        return val;
    }
    val & !(1i128 << bit)
}

/// Sets bit `bit` of `val`, mirroring `BigInteger.setBit`. A no-op for `bit >= 128`.
fn set_bit_128(val: i128, bit: i32) -> i128 {
    if !(0..128).contains(&bit) {
        return val;
    }
    val | (1i128 << bit)
}

impl BinaryOpBehavior for OpBehaviorSubpiece {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// Port of `evaluateBinary(int, int, long, long)`: `(in1 >>> (in2 * 8)) & calc_mask(sizeout)`.
    ///
    /// Uses `wrapping_shr` (on the unsigned reinterpretation of `in1`) to match Java's `>>>`
    /// shift-distance-modulo-64 semantics for `long` operands (JLS 15.19).
    fn evaluate_binary_i64(&self, sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
        let shift = in2.wrapping_mul(8);
        let res = (in1 as u64).wrapping_shr(shift as u32) as i64;
        res & calc_mask(sizeout)
    }

    /// Port of `evaluateBinary(int, int, BigInteger, BigInteger)`.
    ///
    /// Java's version must eliminate sign-extension bits `BigInteger.shiftRight` would otherwise
    /// introduce for a value whose `sizein`-scoped sign bit happens to be set: it temporarily
    /// clears that bit before shifting and restores the (now-shifted) bit afterward if it still
    /// falls within the result's range. This crate's `i128` already behaves like `BigInteger`'s
    /// two's-complement representation for the bounded (<=128-bit) domain this crate supports, so
    /// the same bit-level algorithm carries over directly.
    ///
    /// # Quirk: unlike the `i64` overload, this never masks the result to `sizeout`
    /// The `i64` overload above explicitly ANDs its result with `calc_mask(sizeout)` before
    /// returning. This overload does not perform any equivalent masking of its own: it relies
    /// entirely on `in2 * 8` bits already having been shifted away, so the result only happens to
    /// fit within `sizeout` bytes when `sizein - in2 <= sizeout`. For a small `in2` and a
    /// `sizeout` narrower than `sizein - in2` (e.g. `in2 == 0` with `sizeout < sizein`), the
    /// returned value can carry bits beyond `sizeout`. This is consistent with
    /// [`BinaryOpBehavior`]'s general documented contract that overflowing bits may be left for
    /// the caller to truncate, but is a genuine inconsistency against the `i64` overload's own
    /// eager truncation -- faithfully preserved here, not "fixed" to also mask by `sizeout`.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        let signbit_start = sizein.wrapping_mul(8).wrapping_sub(1);
        let mut res = in1;
        let negative = test_bit_128(res, signbit_start);
        if negative {
            res &= crate::pcode::utils::calc_bigmask(sizein);
            res = clear_bit_128(res, signbit_start);
        }
        let shift = (in2 as i32).wrapping_mul(8);
        res = if shift <= 0 {
            res
        }
        else if shift >= 128 {
            if res < 0 { -1 } else { 0 }
        }
        else {
            res >> shift
        };
        let signbit = signbit_start.wrapping_sub(shift);
        if negative && signbit >= 0 {
            res = set_bit_128(res, signbit);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorSubpiece::new().opcode(), OpCode::Subpiece as i32);
    }

    #[test]
    fn extracts_low_byte_with_zero_offset() {
        let b = OpBehaviorSubpiece::new();
        assert_eq!(b.evaluate_binary_i64(1, 4, 0x1234_5678, 0), 0x78);
    }

    #[test]
    fn extracts_high_byte_with_offset() {
        let b = OpBehaviorSubpiece::new();
        assert_eq!(b.evaluate_binary_i64(1, 4, 0x1234_5678, 3), 0x12);
    }

    #[test]
    fn extracts_middle_bytes() {
        let b = OpBehaviorSubpiece::new();
        assert_eq!(b.evaluate_binary_i64(2, 4, 0x1234_5678, 1), 0x3456);
    }

    #[test]
    fn i128_matches_i64_when_the_shift_alone_fits_sizeout() {
        let b = OpBehaviorSubpiece::new();
        // With in2 = 3, shifting away 3 bytes leaves exactly 1 byte, which happens to coincide
        // with sizeout = 1, so this one matches the i64 overload's result.
        assert_eq!(b.evaluate_binary_i128(1, 4, 0x1234_5678, 3), 0x12);
    }

    /// Java quirk: unlike the `i64` overload (which explicitly ANDs with `calc_mask(sizeout)`),
    /// the `BigInteger` overload never masks its result to `sizeout` at all. With `in2 = 0` (no
    /// shift) and `sizeout` narrower than `sizein`, the full unmasked `in1` comes back instead of
    /// the low `sizeout` bytes the `i64` overload would return (`0x78`).
    #[test]
    fn i128_does_not_mask_to_sizeout_unlike_i64_overload() {
        let b = OpBehaviorSubpiece::new();
        assert_eq!(b.evaluate_binary_i64(1, 4, 0x1234_5678, 0), 0x78);
        assert_eq!(b.evaluate_binary_i128(1, 4, 0x1234_5678, 0), 0x1234_5678);
    }

    #[test]
    fn i128_preserves_sign_scoped_bit_after_shift() {
        let b = OpBehaviorSubpiece::new();
        // sizein = 4, signbit = 31. in1 has bit 31 set (0x8000_0001), shift by 1 byte (8 bits):
        // expected result is in1 (as an unsigned 32-bit magnitude) logically shifted right by 8,
        // i.e. 0x00800000, with the sizein-scoped sign bit (originally bit 31, now bit 23)
        // restored.
        let in1: i128 = 0x8000_0001;
        let result = b.evaluate_binary_i128(3, 4, in1, 1);
        assert_eq!(result, 0x0080_0000);
    }
}

//! General-purpose bit-manipulation and byte/`BigInteger` conversion helpers for p-code.
//!
//! Corresponds to `ghidra.pcode.utils.Utils`.

use crate::util::{big_endian_data_converter, little_endian_data_converter, DataConverter};

/// Platform line separator, mirroring `Utils.endl` (`System.getProperty("line.separator")`).
#[cfg(unix)]
pub const ENDL: &str = "\n";
#[cfg(windows)]
pub const ENDL: &str = "\r\n";

const UINTB_MASKS: [i64; 9] = [
    0,
    0xff,
    0xffff,
    0xffffff,
    0xffffffffu32 as i64,
    0xffffffffffi64,
    0xffffffffffffi64,
    0xffffffffffffffi64,
    0xffffffffffffffffu64 as i64,
];

/// `2^bits` truncated to the 128-bit range used to represent `BigInteger` values in this
/// crate; `bits >= 128` truncates to `0`, matching two's-complement wraparound at the 16-byte
/// boundary (the largest size [`DataConverter::get_big_integer_at`] supports).
fn pow2_bits(bits: u32) -> i128 {
    if bits >= 128 {
        0
    } else {
        1i128 << bits
    }
}

/// Converts `val` to its signed two's-complement interpretation as a `byte_size`-byte value.
pub fn convert_to_signed_value(val: i128, byte_size: i32) -> i128 {
    let signbit = (byte_size * 8 - 1) as u32;
    if val < 0 || (val & pow2_bits(signbit)) == 0 {
        return val; // positive value or already signed
    }
    val.wrapping_sub(pow2_bits(signbit + 1))
}

/// Converts `val` to its unsigned interpretation as a `byte_size`-byte value.
pub fn convert_to_unsigned_value(val: i128, byte_size: i32) -> i128 {
    if val >= 0 {
        return val;
    }
    let mask = pow2_bits((byte_size * 8) as u32).wrapping_sub(1);
    val & mask
}

/// Returns a mask covering the low `size` bytes (clamped to 8 bytes / 64 bits).
pub fn calc_mask(size: i32) -> i64 {
    UINTB_MASKS[if size < 8 { size } else { 8 } as usize]
}

/// Returns a mask covering the low `size` bytes as a 128-bit value.
pub fn calc_bigmask(size: i32) -> i128 {
    pow2_bits((size * 8) as u32).wrapping_sub(1)
}

/// Returns true if the sign bit of a `size`-byte value is set (negative).
pub fn signbit_negative(val: i64, size: i32) -> bool {
    let mut mask: i64 = 0x80;
    mask <<= 8 * (size - 1);
    (val & mask) != 0
}

/// Inverts the bits of `in_` within a `size`-byte value.
pub fn uintb_negate(in_: i64, size: i32) -> i64 {
    (!in_) & calc_mask(size)
}

/// Sign-extends `in_` from `sizein` bytes to `sizeout` bytes.
pub fn sign_extend(mut in_: i64, sizein: i32, sizeout: i32) -> i64 {
    let signbit = sizein * 8 - 1;
    in_ &= calc_mask(sizein);
    if sizein >= sizeout {
        return in_;
    }
    if ((in_ as u64) >> signbit) != 0 {
        let mask = calc_mask(sizeout);
        let mut tmp = mask << signbit; // Split shift into two pieces
        tmp = (tmp << 1) & mask; // In case, everything is shifted out
        in_ |= tmp;
    }
    in_
}

/// Sign-extends `val` above bit `bit`.
pub fn zzz_sign_extend(mut val: i64, bit: i32) -> i64 {
    let mask: i64 = (!0i64) << bit;
    if ((val as u64) >> bit) & 1 != 0 {
        val |= mask;
    }
    else {
        val &= !mask;
    }
    val
}

/// Clears all bits in `val` above bit `bit`.
pub fn zzz_zero_extend(mut val: i64, bit: i32) -> i64 {
    let mut mask: i64 = (!0i64) << bit;
    mask <<= 1;
    val &= !mask;
    val
}

/// Swaps the least-significant `size` bytes of `val`.
pub fn byte_swap(mut val: i64, mut size: i32) -> i64 {
    let mut res: i64 = 0;
    while size > 0 {
        res <<= 8;
        res |= val & 0xff;
        val = ((val as u64) >> 8) as i64;
        size -= 1;
    }
    res
}

/// Swaps the bytes of a 4-byte int.
///
/// Package-private and non-`static` (and uncalled) in the Java source; kept module-private here.
#[allow(dead_code)]
fn byte_swap_int(mut val: i32) -> i64 {
    let mut res: i64 = 0;
    for _ in 0..4 {
        res <<= 8;
        res |= (val & 0xff) as i64;
        val = ((val as u32) >> 8) as i32;
    }
    res
}

/// Reads the first `size` bytes of `byte_buf` as a `long`, in the given byte order.
pub fn bytes_to_long(byte_buf: &[u8], size: usize, big_endian: bool) -> i64 {
    let mut value: i64 = 0;
    for &b in byte_buf.iter().take(size) {
        value = (value << 8) | (b as i64 & 0xff);
    }
    if !big_endian {
        value = byte_swap(value, size as i32);
    }
    value
}

/// Writes `val` into a new `size`-byte array, in the given byte order.
pub fn long_to_bytes(val: i64, size: usize, big_endian: bool) -> Vec<u8> {
    let mut value = val;
    let mut bytes = vec![0u8; size];
    for i in 0..size {
        let index = if big_endian { size - i - 1 } else { i };
        bytes[index] = value as u8;
        value >>= 8;
    }
    bytes
}

/// Reads the first `size` bytes of `byte_buf` as a `BigInteger`-equivalent `i128`, in the
/// given byte order and signedness.
pub fn bytes_to_big_integer(byte_buf: &[u8], size: usize, big_endian: bool, signed: bool) -> i128 {
    if big_endian {
        big_endian_data_converter::INSTANCE.get_big_integer(byte_buf, size, signed)
    }
    else {
        little_endian_data_converter::INSTANCE.get_big_integer(byte_buf, size, signed)
    }
}

/// Writes `val` into a new `size`-byte array, in the given byte order.
pub fn big_integer_to_bytes(val: i128, size: usize, big_endian: bool) -> Vec<u8> {
    if big_endian {
        big_endian_data_converter::INSTANCE.big_integer_to_bytes(val, size)
    }
    else {
        little_endian_data_converter::INSTANCE.big_integer_to_bytes(val, size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_to_signed_value_high_bit_set() {
        assert_eq!(convert_to_signed_value(0x80, 1), -128);
        assert_eq!(convert_to_signed_value(0x7f, 1), 0x7f);
        assert_eq!(convert_to_signed_value(0xffffffffu32 as i128, 4), -1);
        assert_eq!(convert_to_signed_value(-5, 1), -5);
    }

    #[test]
    fn convert_to_unsigned_value_masks_negative() {
        assert_eq!(convert_to_unsigned_value(-128, 1), 0x80);
        assert_eq!(convert_to_unsigned_value(-1, 4), 0xffffffffu32 as i128);
        assert_eq!(convert_to_unsigned_value(5, 1), 5);
    }

    #[test]
    fn signed_unsigned_round_trip() {
        for size in [1, 2, 4, 8] {
            let unsigned = calc_bigmask(size); // all-ones pattern for this size
            let signed = convert_to_signed_value(unsigned, size);
            assert_eq!(convert_to_unsigned_value(signed, size), unsigned);
        }
    }

    #[test]
    fn calc_mask_clamps_at_eight() {
        assert_eq!(calc_mask(0), 0);
        assert_eq!(calc_mask(1), 0xff);
        assert_eq!(calc_mask(4), 0xffffffffu32 as i64);
        assert_eq!(calc_mask(8), 0xffffffffffffffffu64 as i64);
        assert_eq!(calc_mask(100), 0xffffffffffffffffu64 as i64);
    }

    #[test]
    fn calc_bigmask_matches_java_biginteger() {
        assert_eq!(calc_bigmask(1), 0xff);
        assert_eq!(calc_bigmask(4), 0xffffffffu32 as i128);
        assert_eq!(calc_bigmask(8), 0xffffffffffffffffu64 as i128);
    }

    #[test]
    fn signbit_negative_detects_high_bit() {
        assert!(signbit_negative(0x80, 1));
        assert!(!signbit_negative(0x7f, 1));
        assert!(signbit_negative(0x8000, 2));
    }

    #[test]
    fn uintb_negate_inverts_within_size() {
        assert_eq!(uintb_negate(0, 1), 0xff);
        assert_eq!(uintb_negate(0xff, 1), 0);
    }

    #[test]
    fn sign_extend_preserves_or_extends() {
        assert_eq!(sign_extend(0xff, 1, 4), 0xffffffffu32 as i64);
        assert_eq!(sign_extend(0x7f, 1, 4), 0x7f);
        assert_eq!(sign_extend(0x12, 1, 1), 0x12);
    }

    #[test]
    fn zzz_sign_and_zero_extend() {
        assert_eq!(zzz_sign_extend(0b1, 0), -1);
        assert_eq!(zzz_sign_extend(0b0, 0), 0);
        assert_eq!(zzz_zero_extend(-1, 3), 0xf);
    }

    #[test]
    fn byte_swap_reverses_bytes() {
        assert_eq!(byte_swap(0x0102, 2), 0x0201);
        assert_eq!(byte_swap(0x01020304, 4), 0x04030201);
    }

    #[test]
    fn byte_swap_int_matches_java_semantics() {
        assert_eq!(byte_swap_int(0x01020304u32 as i32), 0x04030201);
    }

    #[test]
    fn bytes_to_long_big_endian() {
        let bytes = [0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(bytes_to_long(&bytes, 8, true), 1);
        let bytes = [1, 2, 3, 4];
        assert_eq!(bytes_to_long(&bytes, 4, true), 0x01020304);
    }

    #[test]
    fn bytes_to_long_little_endian_swaps() {
        let bytes = [1, 2, 3, 4];
        assert_eq!(bytes_to_long(&bytes, 4, false), 0x04030201);
    }

    #[test]
    fn long_to_bytes_round_trips_with_bytes_to_long() {
        let val = 0x0102_0304_0506_0708i64;
        for &big_endian in &[true, false] {
            let bytes = long_to_bytes(val, 8, big_endian);
            assert_eq!(bytes_to_long(&bytes, 8, big_endian), val);
        }
    }

    #[test]
    fn long_to_bytes_big_endian_orders_most_significant_first() {
        assert_eq!(long_to_bytes(0x0102_0304, 4, true), vec![1, 2, 3, 4]);
    }

    #[test]
    fn long_to_bytes_little_endian_orders_least_significant_first() {
        assert_eq!(long_to_bytes(0x0102_0304, 4, false), vec![4, 3, 2, 1]);
    }

    #[test]
    fn bytes_to_big_integer_matches_data_converters() {
        let bytes = [0xff, 0xff];
        assert_eq!(bytes_to_big_integer(&bytes, 2, true, true), -1);
        assert_eq!(bytes_to_big_integer(&bytes, 2, true, false), 0xffff);
        assert_eq!(bytes_to_big_integer(&bytes, 2, false, true), -1);
    }

    #[test]
    fn big_integer_to_bytes_round_trips() {
        for &big_endian in &[true, false] {
            let bytes = big_integer_to_bytes(-1, 4, big_endian);
            assert_eq!(bytes, vec![0xff, 0xff, 0xff, 0xff]);
            assert_eq!(bytes_to_big_integer(&bytes, 4, big_endian, true), -1);
        }
    }

    #[test]
    fn endl_is_platform_appropriate() {
        assert!(ENDL == "\n" || ENDL == "\r\n");
    }
}

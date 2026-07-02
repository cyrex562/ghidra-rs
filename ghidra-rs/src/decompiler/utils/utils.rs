//! Bit-manipulation and unsigned-arithmetic helpers shared across the p-code compiler.
//!
//! Corresponds to `ghidra.pcodeCPort.utils.Utils`.

use crate::decompiler::context::SleighError;
use crate::decompiler::utils::MutableInt;
use crate::sleigh::grammar::Location;

/// Line separator used by the original Java code (`Utils.endl`).
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

/// Returns a mask covering the low `size` bytes (clamped to 8 bytes / 64 bits).
pub fn calc_mask(size: i32) -> i64 {
    let index = if unsigned_compare_i32(size, 8) < 0 {
        size
    } else {
        8
    };
    UINTB_MASKS[index as usize]
}

/// Logical (unsigned) right shift of `val` by `sa` bits; `0` if `sa >= 64`.
pub fn pcode_right(val: i64, sa: i32) -> i64 {
    if sa >= 64 {
        return 0;
    }
    ((val as u64) >> sa) as i64
}

/// Left shift of `val` by `sa` bits; `0` if `sa >= 64`.
pub fn pcode_left(val: i64, sa: i32) -> i64 {
    if sa >= 64 {
        return 0;
    }
    val << sa
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
        let mut tmp = mask << signbit;
        tmp = (tmp << 1) & mask;
        in_ |= tmp;
    }
    in_
}

/// Sign-extends `val` above bit `bit`.
pub fn zzz_sign_extend(mut val: i64, bit: i32) -> i64 {
    let mask: i64 = (!0i64) << bit;
    if ((val as u64) >> bit) & 1 != 0 {
        val |= mask;
    } else {
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
/// Package-private (non-`static`, no callers) in the Java source; kept module-private here.
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

/// Returns true if `c` is a printable ASCII character.
pub fn isprint(c: i32) -> bool {
    (32..=126).contains(&c)
}

/// Returns true if `c` is in the ASCII range.
pub fn isascii(c: i32) -> bool {
    (0..=127).contains(&c)
}

/// Returns the bit number (0 = lsb) of the least significant set bit, or -1 if none set.
pub fn leastsigbit_set(mut val: i64) -> i32 {
    if val == 0 {
        return -1;
    }
    let mut res: i32 = 0;
    let mut sz: i32 = 32;
    let mut mask: i64 = -1;
    loop {
        mask = ((mask as u64) >> sz) as i64;
        if (mask & val) == 0 {
            res += sz;
            val = ((val as u64) >> sz) as i64;
        }
        sz >>= 1;
        if sz == 0 {
            break;
        }
    }
    res
}

/// Returns the bit number (0 = lsb) of the most significant set bit, or -1 if none set.
pub fn mostsigbit_set(mut val: i64) -> i32 {
    if val == 0 {
        return -1;
    }
    let mut res: i32 = 63;
    let mut sz: i32 = 32;
    let mut mask: i64 = -1;
    loop {
        mask <<= sz;
        if (mask & val) == 0 {
            res -= sz;
            val <<= sz;
        }
        sz >>= 1;
        if sz == 0 {
            break;
        }
    }
    res
}

/// Returns the smallest number of the form `2^n - 1` that is >= `val`.
pub fn coveringmask(val: i64) -> i64 {
    let mut res = val;
    let mut sz: i32 = 1;
    while sz < 64 {
        res |= ((res as u64) >> sz) as i64;
        sz <<= 1;
    }
    res
}

/// Formats `value` as hex, zero-padded on the left to `pad_length` characters.
pub fn padded_hex_string(value: i64, pad_length: usize) -> String {
    let decoded = format!("{:x}", value);
    if decoded.len() >= pad_length {
        return decoded;
    }
    let mut buffer = String::with_capacity(pad_length);
    for _ in 0..(pad_length - decoded.len()) {
        buffer.push('0');
    }
    buffer.push_str(&decoded);
    buffer
}

/// Compares `v1` and `v2` as unsigned 64-bit integers.
pub fn unsigned_compare(v1: i64, v2: i64) -> i32 {
    match (v1 as u64).cmp(&(v2 as u64)) {
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
    }
}

/// Compares `v1` and `v2` as unsigned 32-bit integers.
pub fn unsigned_compare_i32(v1: i32, v2: i32) -> i32 {
    match (v1 as u32).cmp(&(v2 as u32)) {
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
    }
}

/// Computes the machine-word index, shift, and mask covering bits `[sbit, ebit]`.
///
/// `sbit` and `ebit` must lie within the same 32-bit machine word, otherwise a
/// [`SleighError`] is raised at `location`.
pub fn calc_maskword(
    location: &Location,
    mut sbit: i32,
    mut ebit: i32,
    num: &mut MutableInt,
    shift: &mut MutableInt,
    mask: &mut MutableInt,
) -> Result<(), SleighError> {
    num.set(unsigned_divide(sbit, 8 * 4));
    if num.get() != unsigned_divide(ebit, 8 * 4) {
        return Err(SleighError::new(
            "Context field not contained within one machine int",
            location.clone(),
        ));
    }
    sbit -= (unsigned_int(num.get()) * 8 * 4) as i32;
    ebit -= (unsigned_int(num.get()) * 8 * 4) as i32;

    shift.set(8 * 4 - ebit - 1);
    let mut m: i32 = ((-1i32 as u32) >> (sbit + shift.get())) as i32;
    m <<= shift.get();
    mask.set(m);
    Ok(())
}

/// Reads 4 bytes from `bytes` as a big- or little-endian `i32`.
pub fn bytes_to_int(bytes: &[u8], big_endian: bool) -> i32 {
    let mut result: i32 = 0;
    if big_endian {
        for &b in bytes.iter().take(4) {
            result <<= 8;
            result |= b as i32;
        }
    } else {
        for i in (0..4).rev() {
            result <<= 8;
            result |= bytes[i] as i32;
        }
    }
    result
}

/// Shifts `a` left by `b` bits (`b` taken mod 256); `0` if the effective shift is >= 64.
pub fn shift_left(a: i64, b: i64) -> i64 {
    let b = b & 0xff;
    if b >= 64 {
        return 0;
    }
    a << b
}

/// Arithmetic (sign-extending) right shift of `a` by `b` bits (`b` taken mod 256).
pub fn ashift_right(a: i64, b: i64) -> i64 {
    let b = b & 0xff;
    if b >= 64 {
        return -1;
    }
    a >> b
}

/// Logical (unsigned) right shift of `a` by `b` bits (`b` taken mod 256).
pub fn lshift_right(a: i64, b: i64) -> i64 {
    let b = b & 0xff;
    if b >= 64 {
        return 0;
    }
    ((a as u64) >> b) as i64
}

/// Widens a 32-bit int to a 64-bit unsigned value stored in an `i64`.
pub fn unsigned_int(a: i32) -> i64 {
    (a as u32) as i64
}

/// Divides `a` by `b` treating both as unsigned 32-bit integers.
pub fn unsigned_divide(a: i32, b: i32) -> i32 {
    ((a as u32) / (b as u32)) as i32
}

/// Computes `a % b` treating both as unsigned 32-bit integers.
pub fn unsigned_modulo(a: i32, b: i32) -> i32 {
    ((a as u32) % (b as u32)) as i32
}

/// Formats `n` as unsigned hex, treating it as an unsigned 32-bit integer.
pub fn to_unsigned_int_hex(n: i32) -> String {
    format!("{:x}", unsigned_int(n))
}

/// Reads the first 8 bytes of `byte_buf` as a big-endian `i64`.
///
/// Matches the Java source's byte-to-long promotion exactly: each byte is treated as
/// **signed**, so a byte with its high bit set sign-extends to all-ones before the OR,
/// clobbering previously shifted-in bits. This reproduces `Utils.bytesToLong`'s behavior,
/// bug-for-bug.
pub fn bytes_to_long(byte_buf: &[u8]) -> i64 {
    let mut value: i64 = 0;
    for &b in byte_buf.iter().take(8) {
        value = (value << 8) | (b as i8 as i64);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calc_mask_clamps_at_eight() {
        assert_eq!(calc_mask(0), 0);
        assert_eq!(calc_mask(1), 0xff);
        assert_eq!(calc_mask(4), 0xffffffffu32 as i64);
        assert_eq!(calc_mask(8), 0xffffffffffffffffu64 as i64);
        assert_eq!(calc_mask(100), 0xffffffffffffffffu64 as i64);
    }

    #[test]
    fn pcode_right_and_left_shift() {
        assert_eq!(pcode_right(-1i64, 60), 0xfi64);
        assert_eq!(pcode_right(1, 64), 0);
        assert_eq!(pcode_left(1, 4), 16);
        assert_eq!(pcode_left(1, 64), 0);
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
    fn isprint_and_isascii_bounds() {
        assert!(isprint(b'A' as i32));
        assert!(!isprint(31));
        assert!(!isprint(127));
        assert!(isascii(127));
        assert!(!isascii(128));
        assert!(!isascii(-1));
    }

    #[test]
    fn leastsigbit_and_mostsigbit() {
        assert_eq!(leastsigbit_set(0), -1);
        assert_eq!(leastsigbit_set(0b1000), 3);
        assert_eq!(leastsigbit_set(1), 0);
        assert_eq!(mostsigbit_set(0), -1);
        assert_eq!(mostsigbit_set(0b1000), 3);
        assert_eq!(mostsigbit_set(-1), 63);
    }

    #[test]
    fn coveringmask_rounds_up() {
        assert_eq!(coveringmask(0), 0);
        assert_eq!(coveringmask(1), 1);
        assert_eq!(coveringmask(5), 7);
        assert_eq!(coveringmask(16), 31);
    }

    #[test]
    fn padded_hex_string_pads_and_passes_through() {
        assert_eq!(padded_hex_string(0xab, 4), "00ab");
        assert_eq!(padded_hex_string(0xabcdef, 2), "abcdef");
    }

    #[test]
    fn unsigned_compare_variants() {
        assert_eq!(unsigned_compare(1, 2), -1);
        assert_eq!(unsigned_compare(-1, 0), 1);
        assert_eq!(unsigned_compare(5, 5), 0);
        assert_eq!(unsigned_compare_i32(-1, 0), 1);
        assert_eq!(unsigned_compare_i32(2, 3), -1);
    }

    #[test]
    fn calc_maskword_computes_fields() {
        let loc = Location::new("test.sla", 1);
        let mut num = MutableInt::default();
        let mut shift = MutableInt::default();
        let mut mask = MutableInt::default();
        calc_maskword(&loc, 0, 7, &mut num, &mut shift, &mut mask).unwrap();
        assert_eq!(num.get(), 0);
        assert_eq!(shift.get(), 24);
    }

    #[test]
    fn calc_maskword_errors_across_words() {
        let loc = Location::new("test.sla", 1);
        let mut num = MutableInt::default();
        let mut shift = MutableInt::default();
        let mut mask = MutableInt::default();
        let err = calc_maskword(&loc, 0, 40, &mut num, &mut shift, &mut mask).unwrap_err();
        assert!(err.message().contains("Context field"));
    }

    #[test]
    fn bytes_to_int_endianness() {
        let bytes = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(bytes_to_int(&bytes, true), 0x01020304);
        assert_eq!(bytes_to_int(&bytes, false), 0x04030201);
    }

    #[test]
    fn shift_helpers() {
        assert_eq!(shift_left(1, 4), 16);
        assert_eq!(shift_left(1, 64), 0);
        assert_eq!(ashift_right(-8, 1), -4);
        assert_eq!(ashift_right(1, 64), -1);
        assert_eq!(lshift_right(-1, 60), 0xf);
        assert_eq!(lshift_right(1, 64), 0);
    }

    #[test]
    fn unsigned_int_widens_negative() {
        assert_eq!(unsigned_int(-1), 0xffffffffi64);
        assert_eq!(unsigned_int(1), 1);
    }

    #[test]
    fn unsigned_divide_and_modulo_treat_as_unsigned() {
        assert_eq!(unsigned_divide(-8, 32), 134217727);
        assert_eq!(unsigned_modulo(-8, 32), 24);
    }

    #[test]
    fn to_unsigned_int_hex_formats_negative() {
        assert_eq!(to_unsigned_int_hex(-1), "ffffffff");
        assert_eq!(to_unsigned_int_hex(255), "ff");
    }

    #[test]
    fn bytes_to_long_reads_big_endian() {
        let bytes = [0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(bytes_to_long(&bytes), 1);
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(bytes_to_long(&bytes), 72623859790382856);
    }

    #[test]
    fn bytes_to_long_matches_java_sign_extension_bug() {
        // A high-bit-set byte sign-extends to all-ones and clobbers earlier bits,
        // matching `Utils.bytesToLong`'s Java promotion semantics exactly.
        let bytes = [0xff, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(bytes_to_long(&bytes), -72057594037927936);
        let bytes = [0x80, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(bytes_to_long(&bytes), -9223372036854775807);
    }
}

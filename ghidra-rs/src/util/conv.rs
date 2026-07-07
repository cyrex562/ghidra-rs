/// Helper methods for converting between number data types without negative
/// promotion.
///
/// Most methods in this struct mirror deprecated Java APIs. Prefer Rust's
/// native casts (`b as u8 as u32`, etc.) or `format!` macros over these
/// helpers.
pub struct Conv;

impl Conv {
    /// A byte mask (`0xff`).
    #[deprecated(note = "Use explicit casting (`b as u8`) instead")]
    pub const BYTE_MASK: u32 = 0xff;

    /// A short mask (`0xffff`).
    #[deprecated(note = "Use explicit casting (`s as u16`) instead")]
    pub const SHORT_MASK: u32 = 0xffff;

    /// An integer mask (`0x00000000ffffffff`).
    #[deprecated(note = "Use explicit casting (`i as u64`) instead")]
    pub const INT_MASK: u64 = 0x00000000ffffffff;

    /// Returns the unsigned 16-bit value of a signed byte.
    #[deprecated(note = "Use `(b as u8) as i16` instead")]
    pub fn byte_to_short(b: i8) -> i16 {
        (b as u8) as i16
    }

    /// Returns the unsigned 32-bit value of a signed byte.
    #[deprecated(note = "Use `b as u8 as i32` instead")]
    pub fn byte_to_int(b: i8) -> i32 {
        b as u8 as i32
    }

    /// Returns the unsigned 64-bit value of a signed byte.
    #[deprecated(note = "Use `b as u8 as i64` instead")]
    pub fn byte_to_long(b: i8) -> i64 {
        b as u8 as i64
    }

    /// Returns the unsigned 32-bit value of a signed short.
    #[deprecated(note = "Use `s as u16 as i32` instead")]
    pub fn short_to_int(s: i16) -> i32 {
        s as u16 as i32
    }

    /// Returns the unsigned 64-bit value of a signed short.
    #[deprecated(note = "Use `s as u16 as i64` instead")]
    pub fn short_to_long(s: i16) -> i64 {
        s as u16 as i64
    }

    /// Returns the unsigned 64-bit value of a signed integer.
    #[deprecated(note = "Use `i as u32 as i64` instead")]
    pub fn int_to_long(i: i32) -> i64 {
        i as u32 as i64
    }

    /// Old and **incorrect** way to build a `String` from bytes by casting each
    /// byte value to a `char`. Do not use; prefer `String::from_utf8_lossy` or
    /// an encoding-aware conversion instead.
    ///
    /// Mirrors Java's `(char) b` cast: each byte is sign-extended to 32 bits
    /// and then the low 16 bits are taken as a Unicode scalar value.
    #[deprecated(
        note = "Incorrect encoding; use `String::from_utf8_lossy` or \
                an encoding-aware conversion instead"
    )]
    pub fn bytes_to_string(array: &[u8]) -> String {
        array
            .iter()
            .map(|&b| {
                let code = (b as i8 as i32 as u32) & 0xFFFF;
                char::from_u32(code).unwrap_or('\u{FFFD}')
            })
            .collect()
    }

    /// Converts a byte into a 2-character zero-padded lowercase hex string.
    ///
    /// Equivalent to `format!("{:02x}", b)`.
    pub fn to_hex_string_byte(b: u8) -> String {
        format!("{:02x}", b)
    }

    /// Converts a short into a 4-character zero-padded lowercase hex string.
    ///
    /// Equivalent to `format!("{:04x}", s)`.
    pub fn to_hex_string_short(s: u16) -> String {
        format!("{:04x}", s)
    }

    /// Converts an integer into an 8-character zero-padded lowercase hex string.
    ///
    /// The bit pattern is interpreted as unsigned (two's complement), so negative
    /// values produce their full 8-digit hex representation.
    /// Equivalent to `format!("{:08x}", i as u32)`.
    pub fn to_hex_string_int(i: i32) -> String {
        format!("{:08x}", i as u32)
    }

    /// Converts a long into a 16-character zero-padded lowercase hex string.
    ///
    /// The bit pattern is interpreted as unsigned (two's complement).
    /// Equivalent to `format!("{:016x}", l as u64)`.
    pub fn to_hex_string_long(l: i64) -> String {
        format!("{:016x}", l as u64)
    }

    /// Returns a string left-padded with `'0'` to at least `len` characters.
    ///
    /// If `s` is already `len` or more characters, it is returned unchanged.
    pub fn zeropad(s: &str, len: usize) -> String {
        if s.len() >= len {
            return s.to_string();
        }
        let zeros_needed = len - s.len();
        let mut result = String::with_capacity(len);
        for _ in 0..zeros_needed {
            result.push('0');
        }
        result.push_str(s);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- to_hex_string_byte ----

    #[test]
    fn hex_byte_zero() {
        assert_eq!(Conv::to_hex_string_byte(0x00), "00");
    }

    #[test]
    fn hex_byte_max() {
        assert_eq!(Conv::to_hex_string_byte(0xff), "ff");
    }

    #[test]
    fn hex_byte_leading_zero() {
        assert_eq!(Conv::to_hex_string_byte(0x0a), "0a");
    }

    // ---- to_hex_string_short ----

    #[test]
    fn hex_short_zero() {
        assert_eq!(Conv::to_hex_string_short(0x0000), "0000");
    }

    #[test]
    fn hex_short_max() {
        assert_eq!(Conv::to_hex_string_short(0xffff), "ffff");
    }

    #[test]
    fn hex_short_leading_zeros() {
        assert_eq!(Conv::to_hex_string_short(0x00ab), "00ab");
    }

    // ---- to_hex_string_int ----

    #[test]
    fn hex_int_zero() {
        assert_eq!(Conv::to_hex_string_int(0), "00000000");
    }

    #[test]
    fn hex_int_negative_one_is_all_fs() {
        assert_eq!(Conv::to_hex_string_int(-1), "ffffffff");
    }

    #[test]
    fn hex_int_positive() {
        assert_eq!(Conv::to_hex_string_int(0x0000_00ff), "000000ff");
    }

    // ---- to_hex_string_long ----

    #[test]
    fn hex_long_zero() {
        assert_eq!(Conv::to_hex_string_long(0), "0000000000000000");
    }

    #[test]
    fn hex_long_negative_one_is_all_fs() {
        assert_eq!(Conv::to_hex_string_long(-1), "ffffffffffffffff");
    }

    #[test]
    fn hex_long_positive() {
        assert_eq!(Conv::to_hex_string_long(0x0000_0000_0000_00ff), "00000000000000ff");
    }

    // ---- zeropad ----

    #[test]
    fn zeropad_pads_short_string() {
        assert_eq!(Conv::zeropad("ff", 4), "00ff");
    }

    #[test]
    fn zeropad_exact_length_unchanged() {
        assert_eq!(Conv::zeropad("ff", 2), "ff");
    }

    #[test]
    fn zeropad_longer_than_len_unchanged() {
        assert_eq!(Conv::zeropad("ffff", 2), "ffff");
    }

    #[test]
    fn zeropad_empty_string() {
        assert_eq!(Conv::zeropad("", 4), "0000");
    }

    #[test]
    fn zeropad_to_zero_len() {
        assert_eq!(Conv::zeropad("ab", 0), "ab");
    }

    // ---- deprecated conversions ----

    #[test]
    #[allow(deprecated)]
    fn byte_to_short_positive() {
        assert_eq!(Conv::byte_to_short(65i8), 65i16);
    }

    #[test]
    #[allow(deprecated)]
    fn byte_to_short_negative_treated_as_unsigned() {
        // -1i8 == 0xFF; unsigned value 255 fits in i16
        assert_eq!(Conv::byte_to_short(-1i8), 255i16);
    }

    #[test]
    #[allow(deprecated)]
    fn byte_to_int_negative() {
        assert_eq!(Conv::byte_to_int(-1i8), 255i32);
    }

    #[test]
    #[allow(deprecated)]
    fn byte_to_int_positive() {
        assert_eq!(Conv::byte_to_int(1i8), 1i32);
    }

    #[test]
    #[allow(deprecated)]
    fn byte_to_long_negative() {
        assert_eq!(Conv::byte_to_long(-1i8), 255i64);
    }

    #[test]
    #[allow(deprecated)]
    fn short_to_int_negative() {
        assert_eq!(Conv::short_to_int(-1i16), 65535i32);
    }

    #[test]
    #[allow(deprecated)]
    fn short_to_long_negative() {
        assert_eq!(Conv::short_to_long(-1i16), 65535i64);
    }

    #[test]
    #[allow(deprecated)]
    fn int_to_long_negative() {
        // -1i32 == 0xFFFFFFFF; unsigned value is 4294967295
        assert_eq!(Conv::int_to_long(-1i32), 4_294_967_295i64);
    }

    #[test]
    #[allow(deprecated)]
    fn bytes_to_string_ascii() {
        assert_eq!(Conv::bytes_to_string(b"hello"), "hello");
    }

    #[test]
    #[allow(deprecated)]
    fn bytes_to_string_high_byte() {
        // 0xFF byte: i8 = -1, sign-extended = 0xFFFFFFFF, low 16 = 0xFFFF
        let result = Conv::bytes_to_string(&[0xFFu8]);
        assert_eq!(result.chars().next().unwrap(), '\u{FFFF}');
    }

    #[test]
    #[allow(deprecated)]
    fn bytes_to_string_empty() {
        assert_eq!(Conv::bytes_to_string(&[]), "");
    }
}

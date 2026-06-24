use thiserror::Error;

/// URL- and filename-safe Base64 alphabet (RFC 4648, Table 2).
///
/// Maps each 6-bit index (0–63) to its encoded ASCII byte.
/// Mirrors `Base64Lite.encode` from the Java source.
pub const ENCODE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const fn build_decode() -> [i8; 128] {
    let encode = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut table = [-1i8; 128];
    let mut i = 0usize;
    while i < 64 {
        table[encode[i] as usize] = i as i8;
        i += 1;
    }
    table
}

/// Reverse-lookup table: `DECODE[c as usize]` is the 6-bit value of ASCII byte `c`,
/// or `-1` if `c` is not a valid Base64Lite character.
///
/// Mirrors `Base64Lite.decode` from the Java source.
pub const DECODE: [i8; 128] = build_decode();

/// Error returned when a string contains an invalid Base64Lite character.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Base64LiteError {
    #[error("Bad base64 encoding")]
    BadEncoding,
}

/// Encode `val` as Base64Lite characters, appending to `buf`.
///
/// When `val` is zero exactly one `'A'` is written. For any other value all eleven
/// 6-bit groups are written MSB-first, faithfully mirroring the Java implementation
/// (both branches of the internal `if`/`else` always append).
///
/// Mirrors `Base64Lite.encodeLongBase64(StringBuilder, long)`.
pub fn encode_long_base64_to_buf(buf: &mut String, val: i64) {
    if val == 0 {
        buf.push(ENCODE[0] as char);
        return;
    }
    let mut seen_non_zero = false;
    let mut i = 60i32;
    while i >= 0 {
        let chunk = ((val >> i) & 0x3f) as usize;
        if chunk == 0 && seen_non_zero {
            buf.push(ENCODE[chunk] as char);
        } else {
            buf.push(ENCODE[chunk] as char);
            seen_non_zero = true;
        }
        i -= 6;
    }
}

/// Encode `val` as exactly 11 Base64Lite characters, appending to `buf`.
///
/// Mirrors `Base64Lite.encodeLongBase64Padded(StringBuilder, long)`.
pub fn encode_long_base64_padded_to_buf(buf: &mut String, val: i64) {
    let mut i = 60i32;
    while i >= 0 {
        let chunk = ((val >> i) & 0x3f) as usize;
        buf.push(ENCODE[chunk] as char);
        i -= 6;
    }
}

/// Encode `val` as a Base64Lite string.
///
/// Mirrors `Base64Lite.encodeLongBase64(long)`.
pub fn encode_long_base64(val: i64) -> String {
    let mut buf = String::with_capacity(11);
    if val == 0 {
        buf.push(ENCODE[0] as char);
        return buf;
    }
    let mut seen_non_zero = false;
    let mut i = 60i32;
    while i >= 0 {
        let chunk = ((val >> i) & 0x3f) as usize;
        if chunk == 0 && seen_non_zero {
            buf.push(ENCODE[chunk] as char);
        } else {
            buf.push(ENCODE[chunk] as char);
            seen_non_zero = true;
        }
        i -= 6;
    }
    buf
}

/// Decode up to 11 Base64Lite characters into an `i64`.
///
/// Returns [`Base64LiteError::BadEncoding`] if any character is not in the Base64Lite
/// alphabet or has a code point ≥ 128.
///
/// Mirrors `Base64Lite.decodeLongBase64(String)`.
pub fn decode_long_base64(val: &str) -> Result<i64, Base64LiteError> {
    let mut res: i64 = 0;
    for ch in val.chars() {
        let c = ch as u32;
        if c >= 128 {
            return Err(Base64LiteError::BadEncoding);
        }
        let chunk = DECODE[c as usize];
        if chunk < 0 {
            return Err(Base64LiteError::BadEncoding);
        }
        res <<= 6;
        res |= chunk as i64;
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ENCODE / DECODE table consistency ────────────────────────────────────

    #[test]
    fn test_encode_array_length() {
        assert_eq!(ENCODE.len(), 64);
    }

    #[test]
    fn test_encode_decode_roundtrip_via_tables() {
        for (i, &byte) in ENCODE.iter().enumerate() {
            assert_eq!(DECODE[byte as usize], i as i8, "index {i}");
        }
    }

    #[test]
    fn test_decode_invalid_chars_are_negative_one() {
        // '!' and '=' are not in the alphabet
        assert_eq!(DECODE[b'!' as usize], -1);
        assert_eq!(DECODE[b'=' as usize], -1);
        assert_eq!(DECODE[b'+' as usize], -1);
        assert_eq!(DECODE[b'/' as usize], -1);
    }

    // ── encode_long_base64 (String form) ─────────────────────────────────────

    #[test]
    fn test_encode_zero_is_single_a() {
        assert_eq!(encode_long_base64(0), "A");
    }

    #[test]
    fn test_encode_one_is_eleven_chars_ending_in_b() {
        let s = encode_long_base64(1);
        assert_eq!(s.len(), 11);
        assert_eq!(s, "AAAAAAAAAAB");
    }

    #[test]
    fn test_encode_63_is_eleven_chars_ending_in_underscore() {
        let s = encode_long_base64(63);
        assert_eq!(s.len(), 11);
        // ENCODE[63] == '_'
        assert!(s.ends_with('_'));
        assert_eq!(&s[..10], "AAAAAAAAAA");
    }

    #[test]
    fn test_encode_64_places_b_at_second_to_last_position() {
        // 64 = 0b1_000000: second-to-last 6-bit group = 1 ('B'), last = 0 ('A')
        let s = encode_long_base64(64);
        assert_eq!(s.len(), 11);
        assert_eq!(&s[9..], "BA");
    }

    #[test]
    fn test_encode_nonzero_always_produces_eleven_chars() {
        for val in [1i64, 42, 63, 1000, i64::MAX, i64::MIN, -1] {
            let s = encode_long_base64(val);
            assert_eq!(s.len(), 11, "val={val}");
        }
    }

    // ── encode_long_base64_to_buf ─────────────────────────────────────────────

    #[test]
    fn test_encode_to_buf_zero() {
        let mut buf = String::new();
        encode_long_base64_to_buf(&mut buf, 0);
        assert_eq!(buf, "A");
    }

    #[test]
    fn test_encode_to_buf_appends() {
        let mut buf = String::from("prefix:");
        encode_long_base64_to_buf(&mut buf, 1);
        assert_eq!(&buf[..7], "prefix:");
        assert_eq!(buf.len(), 7 + 11);
    }

    #[test]
    fn test_encode_to_buf_matches_string_form() {
        for val in [0i64, 1, 42, 1000, i64::MAX, i64::MIN, -1] {
            let mut buf = String::new();
            encode_long_base64_to_buf(&mut buf, val);
            assert_eq!(buf, encode_long_base64(val), "val={val}");
        }
    }

    // ── encode_long_base64_padded_to_buf ─────────────────────────────────────

    #[test]
    fn test_padded_zero_is_eleven_as() {
        let mut buf = String::new();
        encode_long_base64_padded_to_buf(&mut buf, 0);
        assert_eq!(buf, "AAAAAAAAAAA");
    }

    #[test]
    fn test_padded_always_eleven_chars() {
        for val in [0i64, 1, 63, 64, 1000, i64::MAX, i64::MIN, -1] {
            let mut buf = String::new();
            encode_long_base64_padded_to_buf(&mut buf, val);
            assert_eq!(buf.len(), 11, "val={val}");
        }
    }

    #[test]
    fn test_padded_nonzero_last_eleven_chars_match_unpadded() {
        // For non-zero, unpadded also produces 11 chars, so they should be equal.
        for val in [1i64, 42, 1000, i64::MAX, i64::MIN, -1] {
            let mut padded = String::new();
            encode_long_base64_padded_to_buf(&mut padded, val);
            assert_eq!(padded, encode_long_base64(val), "val={val}");
        }
    }

    // ── decode_long_base64 ────────────────────────────────────────────────────

    #[test]
    fn test_decode_a_is_zero() {
        assert_eq!(decode_long_base64("A").unwrap(), 0);
    }

    #[test]
    fn test_decode_b_is_one() {
        // 'B' is index 1 in ENCODE, so decoding "B" gives 1.
        assert_eq!(decode_long_base64("B").unwrap(), 1);
    }

    #[test]
    fn test_decode_eleven_as_is_zero() {
        assert_eq!(decode_long_base64("AAAAAAAAAAA").unwrap(), 0);
    }

    #[test]
    fn test_decode_invalid_char_returns_error() {
        assert_eq!(decode_long_base64("!"), Err(Base64LiteError::BadEncoding));
        assert_eq!(decode_long_base64("="), Err(Base64LiteError::BadEncoding));
    }

    #[test]
    fn test_decode_high_codepoint_returns_error() {
        // 'é' has code point 233 ≥ 128
        assert_eq!(decode_long_base64("é"), Err(Base64LiteError::BadEncoding));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        for val in [0i64, 1, 42, 63, 64, 1000, i64::MAX / 2, -1] {
            let encoded = encode_long_base64(val);
            let decoded = decode_long_base64(&encoded).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for val={val}");
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_i64_max() {
        let val = i64::MAX;
        let encoded = encode_long_base64(val);
        assert_eq!(decode_long_base64(&encoded).unwrap(), val);
    }

    #[test]
    fn test_encode_decode_roundtrip_i64_min() {
        let val = i64::MIN;
        let encoded = encode_long_base64(val);
        assert_eq!(decode_long_base64(&encoded).unwrap(), val);
    }

    #[test]
    fn test_decode_empty_string_is_zero() {
        assert_eq!(decode_long_base64("").unwrap(), 0);
    }

    #[test]
    fn test_encode_negative_one_all_underscores() {
        // -1i64 = 0xFFFFFFFFFFFFFFFF; every 6-bit group is 63 → '_'
        let s = encode_long_base64(-1);
        assert_eq!(s, "___________");
    }
}

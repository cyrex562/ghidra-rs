//! Helper methods for converting between number data types without negative promotion.

pub const BYTE_MASK: u32 = 0xff;
pub const SHORT_MASK: u32 = 0xffff;
pub const INT_MASK: u64 = 0x00000000ffffffff;

/// Converts a byte to a `u16` (equivalent to Java's unsigned byte-to-short).
pub fn byte_to_short(b: u8) -> u16 {
    b as u16
}

/// Converts a byte to a `u32` without sign extension.
pub fn byte_to_int(b: u8) -> u32 {
    b as u32
}

/// Converts a byte to a `u64` without sign extension.
pub fn byte_to_long(b: u8) -> u64 {
    b as u64
}

/// Converts a `u16` to a `u32` without sign extension.
pub fn short_to_int(s: u16) -> u32 {
    s as u32
}

/// Converts a `u16` to a `u64` without sign extension.
pub fn short_to_long(s: u16) -> u64 {
    s as u64
}

/// Converts a `u32` to a `u64` without sign extension.
pub fn int_to_long(i: u32) -> u64 {
    i as u64
}

/// Interprets a byte slice as a Latin-1 string (each byte becomes its char equivalent).
pub fn bytes_to_string(array: &[u8]) -> String {
    array.iter().map(|&b| b as char).collect()
}

/// Returns the byte value formatted as a zero-padded 2-digit hex string.
pub fn byte_to_hex_string(b: u8) -> String {
    format!("{:02x}", b)
}

/// Returns the `u16` value formatted as a zero-padded 4-digit hex string.
pub fn short_to_hex_string(s: u16) -> String {
    format!("{:04x}", s)
}

/// Returns the `u32` value formatted as a zero-padded 8-digit hex string.
pub fn int_to_hex_string(i: u32) -> String {
    format!("{:08x}", i)
}

/// Returns the `u64` value formatted as a zero-padded 16-digit hex string.
pub fn long_to_hex_string(l: u64) -> String {
    format!("{:016x}", l)
}

/// Pads a string with leading zeros to reach `len` characters.
/// If `s` is already longer than `len`, it is returned unchanged.
pub fn zeropad(s: &str, len: usize) -> String {
    if s.len() >= len {
        s.to_string()
    } else {
        format!("{:0>width$}", s, width = len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_to_short_no_sign_extension() {
        assert_eq!(byte_to_short(0xff), 0x00ff);
        assert_eq!(byte_to_short(0x80), 0x0080);
        assert_eq!(byte_to_short(0x00), 0x0000);
    }

    #[test]
    fn test_byte_to_int_no_sign_extension() {
        assert_eq!(byte_to_int(0xff), 0xff);
        assert_eq!(byte_to_int(0x80), 0x80);
    }

    #[test]
    fn test_byte_to_long_no_sign_extension() {
        assert_eq!(byte_to_long(0xff), 0x00000000000000ff);
        assert_eq!(byte_to_long(0x80), 0x0000000000000080);
    }

    #[test]
    fn test_short_to_int_no_sign_extension() {
        assert_eq!(short_to_int(0xffff), 0x0000ffff);
        assert_eq!(short_to_int(0x8000), 0x00008000);
    }

    #[test]
    fn test_short_to_long_no_sign_extension() {
        assert_eq!(short_to_long(0xffff), 0x000000000000ffff);
    }

    #[test]
    fn test_int_to_long_no_sign_extension() {
        assert_eq!(int_to_long(0xffffffff), 0x00000000ffffffff);
        assert_eq!(int_to_long(0x80000000), 0x0000000080000000);
    }

    #[test]
    fn test_bytes_to_string() {
        assert_eq!(bytes_to_string(b"hello"), "hello");
        assert_eq!(bytes_to_string(&[0x41, 0x42, 0x43]), "ABC");
        assert_eq!(bytes_to_string(&[]), "");
    }

    #[test]
    fn test_byte_to_hex_string() {
        assert_eq!(byte_to_hex_string(0xff), "ff");
        assert_eq!(byte_to_hex_string(0x0a), "0a");
        assert_eq!(byte_to_hex_string(0x00), "00");
    }

    #[test]
    fn test_short_to_hex_string() {
        assert_eq!(short_to_hex_string(0xffff), "ffff");
        assert_eq!(short_to_hex_string(0x000a), "000a");
    }

    #[test]
    fn test_int_to_hex_string() {
        assert_eq!(int_to_hex_string(0xffffffff), "ffffffff");
        assert_eq!(int_to_hex_string(0x0000000a), "0000000a");
    }

    #[test]
    fn test_long_to_hex_string() {
        assert_eq!(long_to_hex_string(0xffffffffffffffff), "ffffffffffffffff");
        assert_eq!(long_to_hex_string(0x000000000000000a), "000000000000000a");
    }

    #[test]
    fn test_zeropad_shorter_than_len() {
        assert_eq!(zeropad("ab", 4), "00ab");
        assert_eq!(zeropad("", 3), "000");
    }

    #[test]
    fn test_zeropad_exact_len() {
        assert_eq!(zeropad("abcd", 4), "abcd");
    }

    #[test]
    fn test_zeropad_longer_than_len() {
        assert_eq!(zeropad("abcde", 4), "abcde");
    }

    #[test]
    fn test_constants() {
        assert_eq!(BYTE_MASK, 0xff);
        assert_eq!(SHORT_MASK, 0xffff);
        assert_eq!(INT_MASK, 0x00000000ffffffff);
    }
}

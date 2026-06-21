/// Converts an integer into a string by treating its 4 bytes as characters (big-endian).
///
/// For example, `0x41424344i32` returns `"ABCD"`.
///
/// Mirrors `GStringUtilities.toString(int)`.
pub fn int_to_string(value: i32) -> String {
    let mut bytes = [0u8; 4];
    let mut byte_index: i32 = 3;
    let mut val = value;
    while val != 0 {
        if byte_index < 0 {
            break;
        }
        bytes[byte_index as usize] = val as u8;
        val >>= 8;
        byte_index -= 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Converts a byte slice to a lowercase hex string.
///
/// Only the first `length` bytes are converted; each byte becomes exactly two hex characters.
///
/// Mirrors `GStringUtilities.convertBytesToString(byte[], int)`.
pub fn convert_bytes_to_string(bytes: &[u8], length: usize) -> String {
    let mut s = String::with_capacity(length * 2);
    for &b in &bytes[..length] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Parses a hex string into bytes.
///
/// Returns `None` if the string has an odd length or contains non-hex characters,
/// mirroring the `null` return of `GStringUtilities.convertStringToBytes(String)`.
pub fn convert_string_to_bytes(hexstr: &str) -> Option<Vec<u8>> {
    if hexstr.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hexstr.len() / 2);
    let mut i = 0;
    while i < hexstr.len() {
        let b = u8::from_str_radix(&hexstr[i..i + 2], 16).ok()?;
        bytes.push(b);
        i += 2;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_to_string_abcd_packed_int() {
        assert_eq!(int_to_string(0x41424344i32), "ABCD");
    }

    #[test]
    fn int_to_string_zero_produces_four_null_bytes() {
        let result = int_to_string(0);
        assert_eq!(result.len(), 4);
        assert!(result.bytes().all(|b| b == 0));
    }

    #[test]
    fn int_to_string_single_byte() {
        // 0x41 → bytes = [0, 0, 0, 0x41]
        let result = int_to_string(0x41i32);
        assert_eq!(result.as_bytes()[3], b'A');
        assert_eq!(result.as_bytes()[..3], [0, 0, 0]);
    }

    #[test]
    fn int_to_string_two_bytes() {
        // 0x4142 → bytes = [0, 0, 0x41, 0x42]
        let result = int_to_string(0x4142i32);
        assert_eq!(&result.as_bytes()[2..], b"AB");
        assert_eq!(&result.as_bytes()[..2], &[0, 0]);
    }

    #[test]
    fn convert_bytes_to_string_basic() {
        let bytes = [0x0A_u8, 0xFF, 0x42];
        assert_eq!(convert_bytes_to_string(&bytes, 3), "0aff42");
    }

    #[test]
    fn convert_bytes_to_string_pads_single_digit_hex() {
        let bytes = [0x00_u8, 0x0F];
        assert_eq!(convert_bytes_to_string(&bytes, 2), "000f");
    }

    #[test]
    fn convert_bytes_to_string_partial_length() {
        let bytes = [0x01_u8, 0x02, 0x03];
        assert_eq!(convert_bytes_to_string(&bytes, 2), "0102");
    }

    #[test]
    fn convert_bytes_to_string_zero_length() {
        assert_eq!(convert_bytes_to_string(&[], 0), "");
    }

    #[test]
    fn convert_bytes_to_string_all_values() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let result = convert_bytes_to_string(&bytes, 256);
        assert_eq!(result.len(), 512);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn convert_string_to_bytes_basic() {
        assert_eq!(
            convert_string_to_bytes("0aff42"),
            Some(vec![0x0A, 0xFF, 0x42])
        );
    }

    #[test]
    fn convert_string_to_bytes_empty() {
        assert_eq!(convert_string_to_bytes(""), Some(vec![]));
    }

    #[test]
    fn convert_string_to_bytes_odd_length_returns_none() {
        assert_eq!(convert_string_to_bytes("abc"), None);
    }

    #[test]
    fn convert_string_to_bytes_invalid_hex_returns_none() {
        assert_eq!(convert_string_to_bytes("zz"), None);
    }

    #[test]
    fn convert_string_to_bytes_uppercase() {
        assert_eq!(convert_string_to_bytes("0AFF"), Some(vec![0x0A, 0xFF]));
    }

    #[test]
    fn roundtrip_convert_bytes_and_back() {
        let original = vec![0xDE_u8, 0xAD, 0xBE, 0xEF];
        let hex = convert_bytes_to_string(&original, 4);
        let back = convert_string_to_bytes(&hex).unwrap();
        assert_eq!(back, original);
    }
}

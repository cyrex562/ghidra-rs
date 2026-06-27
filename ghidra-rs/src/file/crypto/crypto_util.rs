/// Translates an integer from host byte order to network byte order (big-endian).
pub fn htonl(value: i32) -> [u8; 4] {
    value.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_produces_all_zeros() {
        assert_eq!(htonl(0), [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn known_value_big_endian_layout() {
        // 0x01020304 → bytes [0x01, 0x02, 0x03, 0x04]
        assert_eq!(htonl(0x01020304), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn lsb_in_last_byte() {
        assert_eq!(htonl(0x000000FF), [0x00, 0x00, 0x00, 0xFF]);
    }

    #[test]
    fn msb_in_first_byte() {
        // Java: (value >> 24) & 0xff lands at bytes[0]
        assert_eq!(htonl(0x7F000000_u32 as i32), [0x7F, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn negative_value_matches_java_semantics() {
        // Java int -1 == 0xFFFF_FFFF; each byte is 0xFF
        assert_eq!(htonl(-1), [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn i32_min_value() {
        // 0x8000_0000 → [0x80, 0x00, 0x00, 0x00]
        assert_eq!(htonl(i32::MIN), [0x80, 0x00, 0x00, 0x00]);
    }
}

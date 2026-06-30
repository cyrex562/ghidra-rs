/// Static utility methods for formatting numeric values as hexadecimal strings.
pub struct StringFormat;

impl StringFormat {
    /// Returns a two-digit uppercase hexadecimal representation of a byte value.
    pub fn hex_byte_string(b: i8) -> String {
        format!("{:02X}", b as u8)
    }

    /// Returns a four-digit uppercase hexadecimal representation of a short value.
    pub fn hex_word_string(s: i16) -> String {
        Self::pad_it(&format!("{:X}", s as u16), 4, '\0', true)
    }

    /// Returns a string left-padded with `'0'` characters to `padlen`, then optionally
    /// suffixed with `endchar`.
    ///
    /// If `padded` is `true` and `str` is shorter than `padlen`, zeros are prepended until
    /// the total length reaches `padlen`. If `endchar` is the null character (`'\0'`), no
    /// suffix is appended.
    pub fn pad_it(str: &str, padlen: usize, endchar: char, padded: bool) -> String {
        let mut buf = String::new();
        if padded {
            let len = str.len();
            if len < padlen {
                for _ in 0..(padlen - len) {
                    buf.push('0');
                }
            }
        }
        buf.push_str(str);
        if endchar != '\0' {
            buf.push(endchar);
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- hex_byte_string ---

    #[test]
    fn hex_byte_string_zero() {
        assert_eq!(StringFormat::hex_byte_string(0), "00");
    }

    #[test]
    fn hex_byte_string_single_digit() {
        assert_eq!(StringFormat::hex_byte_string(0x0A), "0A");
    }

    #[test]
    fn hex_byte_string_two_digits() {
        assert_eq!(StringFormat::hex_byte_string(0x7F), "7F");
    }

    #[test]
    fn hex_byte_string_negative_treated_unsigned() {
        // -1i8 as u8 == 0xFF
        assert_eq!(StringFormat::hex_byte_string(-1), "FF");
        // -128i8 as u8 == 0x80
        assert_eq!(StringFormat::hex_byte_string(-128), "80");
    }

    #[test]
    fn hex_byte_string_max() {
        assert_eq!(StringFormat::hex_byte_string(i8::MAX), "7F");
    }

    // --- hex_word_string ---

    #[test]
    fn hex_word_string_zero() {
        assert_eq!(StringFormat::hex_word_string(0), "0000");
    }

    #[test]
    fn hex_word_string_small_value_padded() {
        assert_eq!(StringFormat::hex_word_string(1), "0001");
        assert_eq!(StringFormat::hex_word_string(0xFF), "00FF");
    }

    #[test]
    fn hex_word_string_max() {
        assert_eq!(StringFormat::hex_word_string(i16::MAX), "7FFF");
    }

    #[test]
    fn hex_word_string_negative_treated_unsigned() {
        // -1i16 as u16 == 0xFFFF
        assert_eq!(StringFormat::hex_word_string(-1), "FFFF");
    }

    // --- pad_it ---

    #[test]
    fn pad_it_no_padding_needed() {
        assert_eq!(StringFormat::pad_it("ABCD", 4, '\0', true), "ABCD");
    }

    #[test]
    fn pad_it_adds_leading_zeros() {
        assert_eq!(StringFormat::pad_it("AB", 4, '\0', true), "00AB");
    }

    #[test]
    fn pad_it_padded_false_skips_padding() {
        assert_eq!(StringFormat::pad_it("A", 4, '\0', false), "A");
    }

    #[test]
    fn pad_it_with_endchar() {
        assert_eq!(StringFormat::pad_it("AB", 4, 'h', true), "00ABh");
    }

    #[test]
    fn pad_it_endchar_no_padding() {
        assert_eq!(StringFormat::pad_it("AB", 4, 'h', false), "ABh");
    }

    #[test]
    fn pad_it_longer_than_padlen_no_truncation() {
        assert_eq!(StringFormat::pad_it("ABCDEF", 4, '\0', true), "ABCDEF");
    }

    #[test]
    fn pad_it_empty_string() {
        assert_eq!(StringFormat::pad_it("", 4, '\0', true), "0000");
    }
}

//! Port of `ghidra.program.model.data.StringRenderBuilder`.
//!
//! Builds the human-readable, quoted/escaped rendering of string bytes that the string and char
//! data types display, e.g. `"Test\tstring",01h,02h,"Second\npart"`.
//!
//! Decoding goes through [`JavaCharset`], which reproduces the JDK decoders' error reporting, so
//! the streaming "decode what you can, render the bad bytes as `XXh` values, carry on" loop of
//! `decodeBytesUsingCharset` is the Java one. The decoded text is kept as Java UTF-16 code units
//! until it is rendered; the only place Rust's `String` cannot follow Java is an unpaired
//! surrogate the decoder produced (possible only from `UTF-32`), which renders as `U+FFFD` where
//! Java would append the lone surrogate.

use std::fmt;

use crate::program::model::data::render_unicode_settings_definition::RenderEnum;
use crate::util::charset::java_charset::{char_count, code_point_at, JavaCharset};
use crate::util::charset::unicode_data::{is_defined, is_iso_control};
use crate::util::string_utilities::{
    convert_code_point_to_escape_sequence, is_control_character_or_backslash_code_point,
    is_displayable, UNICODE_BE_BYTE_ORDER_MARK,
};

const MAX_ASCII: u32 = 0x80;

/// Helper used to build up a formatted (for human consumption) string representation returned by
/// Unicode and String data types.
///
/// Call [`build`](StringRenderBuilder::build) to retrieve the formatted string.
///
/// Example (quotes are part of result): `"Test\tstring",01h,02h,"Second\npart"`
///
/// Port of `ghidra.program.model.data.StringRenderBuilder`.
#[derive(Debug, Clone)]
pub struct StringRenderBuilder {
    sb: String,
    cs: JavaCharset,
    char_size: i32,
    utf_charset: bool,
    quote_char: char,
    byte_mode: bool,
}

impl StringRenderBuilder {
    /// Port of `StringRenderBuilder.DOUBLE_QUOTE`.
    pub const DOUBLE_QUOTE: char = '"';
    /// Port of `StringRenderBuilder.SINGLE_QUOTE`.
    pub const SINGLE_QUOTE: char = '\'';

    /// Port of `StringRenderBuilder(Charset cs, int charSize)`, quoting with
    /// [`DOUBLE_QUOTE`](Self::DOUBLE_QUOTE).
    pub fn new(cs: JavaCharset, char_size: i32) -> Self {
        Self::with_quote_char(cs, char_size, Self::DOUBLE_QUOTE)
    }

    /// Port of `StringRenderBuilder(Charset cs, int charSize, char quoteChar)`.
    pub fn with_quote_char(cs: JavaCharset, char_size: i32, quote_char: char) -> Self {
        StringRenderBuilder {
            sb: String::new(),
            utf_charset: cs.name().starts_with("UTF"),
            cs,
            char_size,
            quote_char,
            byte_mode: true,
        }
    }

    /// Add a unicode codepoint as its escaped hex value, with an escape character prefix of `x`,
    /// `u` or `U` depending on the magnitude of the codepoint value:
    /// `15 -> \x0F`, `65535 -> \uFFFF`, `65536 -> \U00010000`.
    ///
    /// Port of `StringRenderBuilder.addEscapedCodePoint(int)`.
    pub fn add_escaped_code_point(&mut self, code_point: u32) {
        self.ensure_text_mode();
        let (escape_char, digits) = if code_point < MAX_ASCII {
            ('x', 2)
        } else if code_point <= 0xFFFF {
            ('u', 4)
        } else {
            ('U', 8)
        };
        self.sb.push('\\');
        self.sb.push(escape_char);
        self.sb.push_str(&format!("{code_point:0digits$X}"));
    }

    /// Adds the characters found in `bytes` to the result.
    ///
    /// Any portions of the bytes that cause problems for the charset codec are added as a byte
    /// sequence. Characters outside the traditional ASCII range are rendered as-is or as escape
    /// sequences, depending on `render_setting`. When `trim_trailing_nulls` is set, trailing null
    /// characters are not included in the rendered output.
    ///
    /// Port of `StringRenderBuilder.decodeBytesUsingCharset(ByteBuffer, RENDER_ENUM, boolean)`.
    pub fn decode_bytes_using_charset(&mut self, bytes: &[u8], render_setting: RenderEnum, trim_trailing_nulls: bool) {
        if bytes.is_empty() {
            // early exit avoids problems trying to flush un-initialized codec later
            return;
        }
        let mut codec = self.cs.new_decoder();
        let mut cb: Vec<u16> = Vec::with_capacity(bytes.len().max(10));
        let mut pos = 0;
        while pos < bytes.len() {
            cb.clear();
            let cr = codec.decode(bytes, &mut pos, &mut cb);
            if pos == bytes.len() && trim_trailing_nulls {
                // if this is the last chunk of text, trim nulls if necessary
                while cb.last() == Some(&0) {
                    cb.pop();
                }
            }
            self.render_chars(&cb, render_setting);
            match cr.error_length() {
                Some(len) => {
                    self.add_byte_seq(&bytes[pos..pos + len]);
                    pos += len;
                }
                None => {
                    // Everything was consumed; any trailing partial character was reported as
                    // an error above.
                    self.add_byte_seq(&bytes[pos..]);
                    pos = bytes.len();
                }
            }
        }
    }

    fn add_string(&mut self, s: &str) {
        self.ensure_text_mode();
        self.sb.push_str(s);
    }

    fn add_code_point_char(&mut self, code_point: u32) {
        self.ensure_text_mode();
        if code_point == self.quote_char as u32 {
            self.sb.push('\\');
        }
        self.sb.push(char::from_u32(code_point).unwrap_or(char::REPLACEMENT_CHARACTER));
    }

    fn add_byte_seq(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.ensure_byte_mode();
            self.sb.push_str(&format!("{b:02X}h"));
        }
    }

    /// Port of the private `addByteSeq(int codePoint)`: runs the code point back through the
    /// charset (with replacement, as `Charset.encode` does) to recover its original bytes.
    fn add_byte_seq_for_code_point(&mut self, code_point: u32) {
        let units: Vec<u16> = match char::from_u32(code_point) {
            Some(c) => {
                let mut buf = [0u16; 2];
                c.encode_utf16(&mut buf).to_vec()
            }
            None => vec![code_point as u16],
        };
        let bytes = self.cs.encode_units_replacing(&units);
        self.add_byte_seq(&bytes);
    }

    fn render_chars(&mut self, string_value: &[u16], render_setting: RenderEnum) {
        let mut i = 0;
        while i < string_value.len() {
            let code_point = code_point_at(string_value, i);

            if is_control_character_or_backslash_code_point(code_point) {
                self.add_string(&convert_code_point_to_escape_sequence(code_point));
            } else if code_point == 0 {
                if self.byte_mode {
                    self.add_byte_seq_for_code_point(0);
                } else {
                    self.add_string("\\0");
                }
            } else if is_iso_control(code_point) || !is_defined(code_point) {
                self.add_byte_seq_for_code_point(code_point);
            } else if is_displayable(code_point) {
                self.add_code_point_char(code_point);
            } else if code_point == UNICODE_BE_BYTE_ORDER_MARK {
                self.add_escaped_code_point(code_point);
            } else {
                match render_setting {
                    RenderEnum::All => self.add_code_point_char(code_point),
                    RenderEnum::ByteSeq => self.add_byte_seq_for_code_point(code_point),
                    RenderEnum::EscSeq => self.add_escaped_code_point(code_point),
                }
            }

            i += char_count(code_point);
        }
    }

    fn ensure_text_mode(&mut self) {
        if self.sb.is_empty() {
            self.sb.push(self.quote_char);
        } else if self.byte_mode {
            self.sb.push(',');
            self.sb.push(self.quote_char);
        }
        self.byte_mode = false;
    }

    fn ensure_byte_mode(&mut self) {
        if !self.byte_mode {
            self.sb.push(self.quote_char);
        }
        if !self.sb.is_empty() {
            self.sb.push(',');
        }
        self.byte_mode = true;
    }

    /// Port of `StringRenderBuilder.build()`: the rendering, with a `u8`/`u`/`U` prefix when a
    /// UTF charset produced quoted text.
    pub fn build(&self) -> String {
        let s = if !self.sb.is_empty() {
            self.to_string()
        } else {
            format!("{0}{0}", self.quote_char)
        };
        let mut prefix = "";
        if self.utf_charset && s.starts_with(self.quote_char) {
            prefix = match self.char_size {
                1 => "u8",
                2 => "u",
                4 => "U",
                _ => "",
            };
        }
        format!("{prefix}{s}")
    }
}

impl fmt::Display for StringRenderBuilder {
    /// Port of `StringRenderBuilder.toString()`: the accumulated text, closing an open quoted
    /// run. Example (quotes are part of result): `"Test\tstring",01,02,"Second\npart",00`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.sb)?;
        if !self.byte_mode {
            // close the quoted text mode in the local string
            write!(f, "{}", self.quote_char)?;
        }
        Ok(())
    }
}

/// Port of `ghidra.program.model.data.StringRenderBuilderTest`.
#[cfg(test)]
mod tests {
    use super::*;

    fn us_ascii() -> JavaCharset {
        JavaCharset::us_ascii()
    }

    fn render(cs: JavaCharset, char_size: i32, bytes: &[u8], setting: RenderEnum, trim: bool) -> String {
        let mut srb = StringRenderBuilder::with_quote_char(cs, char_size, StringRenderBuilder::DOUBLE_QUOTE);
        srb.decode_bytes_using_charset(bytes, setting, trim);
        srb.build()
    }

    #[test]
    fn test_empty_string() {
        let srb = StringRenderBuilder::with_quote_char(us_ascii(), 1, StringRenderBuilder::DOUBLE_QUOTE);
        assert_eq!(srb.build(), "\"\"");
    }

    #[test]
    fn test_empty_wchar2_string() {
        let srb = StringRenderBuilder::with_quote_char(JavaCharset::UTF_16, 2, StringRenderBuilder::DOUBLE_QUOTE);
        assert_eq!(srb.build(), "u\"\"");
    }

    #[test]
    fn test_empty_wchar4_string() {
        let srb = StringRenderBuilder::with_quote_char(JavaCharset::UTF_32, 4, StringRenderBuilder::DOUBLE_QUOTE);
        assert_eq!(srb.build(), "U\"\"");
    }

    #[test]
    fn test_empty_string_with_nulls() {
        assert_eq!(render(us_ascii(), 1, &[0, 0, 0], RenderEnum::All, true), "\"\"");
    }

    #[test]
    fn test_empty_string_with_nulls_no_trim() {
        assert_eq!(render(us_ascii(), 1, &[0, 0, 0], RenderEnum::All, false), "00h,00h,00h");
    }

    #[test]
    fn test_interior_nulls() {
        assert_eq!(render(us_ascii(), 1, b"te\0st\0", RenderEnum::All, true), "\"te\\0st\"");
    }

    #[test]
    fn test_simple_string() {
        assert_eq!(render(us_ascii(), 1, b"test", RenderEnum::All, true), "\"test\"");
    }

    #[test]
    fn test_standard_escaped_chars() {
        assert_eq!(render(us_ascii(), 1, b"test\n\t\r", RenderEnum::All, true), "\"test\\n\\t\\r\"");
    }

    #[test]
    fn test_quoted_quotes_chars() {
        assert_eq!(render(us_ascii(), 1, b"test\"123", RenderEnum::All, true), "\"test\\\"123\"");
    }

    #[test]
    fn test_single_quote_chars() {
        assert_eq!(render(us_ascii(), 1, b"test'123", RenderEnum::All, true), "\"test'123\"");
    }

    #[test]
    fn test_simple_string_with_trailing_nulls() {
        assert_eq!(render(us_ascii(), 1, b"test\0\0\0", RenderEnum::All, true), "\"test\"");
    }

    #[test]
    fn test_simple_string_with_trailing_nulls_no_trim() {
        assert_eq!(render(us_ascii(), 1, b"test\0\0\0", RenderEnum::All, false), "\"test\\0\\0\\0\"");
    }

    #[test]
    fn test_utf8_string() {
        assert_eq!(render(JavaCharset::UTF_8, 1, &[0xE1, 0x84, 0xA2], RenderEnum::All, true), "u8\"\u{1122}\"");
    }

    #[test]
    fn test_utf8_no_render_non_latin_string() {
        assert_eq!(render(JavaCharset::UTF_8, 1, &[0xE1, 0x84, 0xA2], RenderEnum::EscSeq, true), "u8\"\\u1122\"");
    }

    #[test]
    fn test_bad_bytes_usascii() {
        assert_eq!(render(us_ascii(), 1, &[b't', b'e', b's', b't', 0x80], RenderEnum::All, true), "\"test\",80h");
    }

    #[test]
    fn test_bad_bytes_usascii2() {
        // bad bytes in interior of string, switching modes
        assert_eq!(render(us_ascii(), 1, &[b't', b'e', 0x80, b's', b't'], RenderEnum::All, true), "\"te\",80h,\"st\"");
    }

    #[test]
    fn test_bad_bytes_usascii3() {
        // bad bytes at beginning of string
        assert_eq!(render(us_ascii(), 1, &[0x80, b't', b'e', b's', b't'], RenderEnum::All, true), "80h,\"test\"");
    }

    #[test]
    fn test_truncated_utf8() {
        assert_eq!(render(JavaCharset::UTF_8, 1, &[b't', b'e', b's', b't', 0xE1, 0x84], RenderEnum::All, true), "u8\"test\",E1h,84h");
    }

    #[test]
    fn test_utf16() {
        assert_eq!(render(JavaCharset::UTF_16LE, 2, &[b't', 0, b'e', 0, b's', 0, b't', 0], RenderEnum::All, true), "u\"test\"");
    }

    #[test]
    fn test_utf16_bom_le() {
        let bytes = [0xff, 0xfe, b't', 0, b'e', 0, b's', 0, b't', 0];
        assert_eq!(render(JavaCharset::UTF_16LE, 2, &bytes, RenderEnum::All, true), "u\"\\uFEFFtest\"");
    }

    #[test]
    fn test_utf32_bom_le() {
        // This test demonstrates the inconsistency of decoding a BOM in UTF-16 vs UTF-32: UTF-16
        // charset impls preserve the BOM in the result, whereas UTF-32 does not.
        let bytes = [0xff, 0xfe, 0, 0, b't', 0, 0, 0, b'e', 0, 0, 0, b's', 0, 0, 0, b't', 0, 0, 0];
        assert_eq!(render(JavaCharset::UTF_32LE, 4, &bytes, RenderEnum::All, true), "U\"test\"");
    }

    // ---- beyond the Java test class ----

    #[test]
    fn escaped_code_point_widths() {
        let mut b = StringRenderBuilder::new(us_ascii(), 1);
        b.add_escaped_code_point(15);
        assert_eq!(b.build(), "\"\\x0F\"");
        let mut b = StringRenderBuilder::new(us_ascii(), 1);
        b.add_escaped_code_point(0xFFFF);
        assert_eq!(b.build(), "\"\\uFFFF\"");
        let mut b = StringRenderBuilder::new(us_ascii(), 1);
        b.add_escaped_code_point(0x10000);
        assert_eq!(b.build(), "\"\\U00010000\"");
    }

    #[test]
    fn leading_null_renders_as_a_byte_while_in_byte_mode() {
        assert_eq!(render(us_ascii(), 1, b"\0hi", RenderEnum::All, false), "00h,\"hi\"");
    }

    #[test]
    fn unassigned_and_iso_control_code_points_render_as_bytes() {
        // U+0378 is unassigned; U+0085 is an ISO control.
        assert_eq!(render(JavaCharset::UTF_8, 1, &[b'a', 0xCD, 0xB8], RenderEnum::All, false), "u8\"a\",CDh,B8h");
        assert_eq!(render(JavaCharset::UTF_8, 1, &[0xC2, 0x85], RenderEnum::All, false), "C2h,85h");
    }

    #[test]
    fn render_settings_for_non_ascii() {
        let nbsp = "\u{00A0}".as_bytes();
        assert_eq!(render(JavaCharset::UTF_8, 1, nbsp, RenderEnum::All, false), "u8\"\u{00A0}\"");
        assert_eq!(render(JavaCharset::UTF_8, 1, nbsp, RenderEnum::ByteSeq, false), "C2h,A0h");
        assert_eq!(render(JavaCharset::UTF_8, 1, nbsp, RenderEnum::EscSeq, false), "u8\"\\u00A0\"");
    }

    #[test]
    fn trailing_nulls_before_a_bad_byte_are_kept() {
        // The trim only applies when the decoder consumed everything.
        assert_eq!(render(us_ascii(), 1, &[b'a', 0, 0x80], RenderEnum::All, true), "\"a\\0\",80h");
    }

    #[test]
    fn display_leaves_a_trailing_byte_run_unquoted() {
        let mut b = StringRenderBuilder::new(us_ascii(), 1);
        b.decode_bytes_using_charset(&[b'T', 0x80], RenderEnum::All, false);
        assert_eq!(b.to_string(), "\"T\",80h");
        assert_eq!(b.build(), "\"T\",80h");
    }
}

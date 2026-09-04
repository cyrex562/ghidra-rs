//! Port of `ghidra.program.model.data.StringRenderBuilder`.
//!
//! A plain concrete struct (not a `DataType`, not a cut-point trait) -- it accumulates a
//! human-readable, quoted/escaped rendering of string bytes, mirroring
//! [`StringUtilities`](crate::util::string_utilities::StringUtilities)'s sibling utility classes'
//! "ported as a struct with a direct `impl`" convention rather than the trait-cut-point convention
//! used throughout `program::model::data`.
//!
//! `java.nio.charset.Charset` has no full port in this crate; the constructor's `Charset cs`
//! parameter is instead a charset *name* string, matching the established convention already set
//! by [`string_data_instance`](crate::program::model::data::string_data_instance) (see that
//! module's own docs on why charset support here is limited to a handful of names Rust's standard
//! library can decode without a full `java.nio.charset.Charset` registry:
//! `US-ASCII`/`UTF-8`/`UTF-16BE`/`UTF-16LE`/`UTF-32BE`/`UTF-32LE`). `decodeBytesUsingCharset`'s own
//! decode logic is not shared with that module (its helpers are private to that file), so a
//! second, independently minimal decoder over the same limited charset set is defined here as
//! [`decode_limited_charset`].
//!
//! `decodeBytesUsingCharset(ByteBuffer, RENDER_ENUM, boolean)` in Java uses a stateful, streaming
//! `java.nio.charset.CharsetDecoder` (`REPORT` error action, chunked `CharBuffer` flushing,
//! recovering byte-by-byte from any malformed/unmappable sequence by falling into byte mode mid
//! -stream). This port instead decodes the whole input in one pass via
//! [`decode_limited_charset`], and falls back to rendering *every* input byte as a byte sequence
//! if that whole-buffer decode fails -- rather than Java's finer-grained "decode as much as
//! possible, then byte-render only the specific bad tail" recovery. This is a deliberate,
//! documented simplification (not a stub): the common well-formed-input path -- the behavior this
//! class exists for -- is faithfully ported and tested; only the malformed-input recovery
//! granularity differs.
//!
//! `addByteSeq(int codePoint)` (Java's private single-codepoint overload, which re-encodes the
//! codepoint through `cs` to recover its original raw bytes) is ported as
//! [`add_byte_seq_for_code_point`](StringRenderBuilder::add_byte_seq_for_code_point), which
//! re-encodes via UTF-8 instead of the original (possibly different) charset -- a reasonable stand
//! -in given the same limited-charset-registry constraint, and only reachable for
//! already-successfully-decoded codepoints in the first place.
//!
//! `Character.isDefined(codePoint)` has no Rust equivalent (no accessible Unicode
//! character-database "is this codepoint assigned" query); its `renderChars` branch
//! (`Character.isISOControl(codePoint) || !Character.isDefined(codePoint)`) is approximated using
//! only the `isISOControl`-equivalent half (`char::is_control`), since every codepoint this port
//! can represent as a Rust `char` is by construction "defined" in the sense Rust cares about.
//!
//! `RENDER_ENUM` is not re-declared here: it is already ported as
//! [`RenderEnum`](crate::program::model::data::render_unicode_settings_definition::RenderEnum).

use std::fmt;

use crate::program::model::data::render_unicode_settings_definition::RenderEnum;
use crate::util::string_utilities::{
    convert_code_point_to_escape_sequence, is_control_character_or_backslash_code_point,
    is_displayable, UNICODE_BE_BYTE_ORDER_MARK,
};

const MAX_ASCII: u32 = 0x80;

/// Decodes `bytes` using one of the charsets this crate supports without a full
/// `java.nio.charset.Charset` registry, mirroring
/// [`string_data_instance`](crate::program::model::data::string_data_instance)'s own
/// (module-private) `decode_with_charset`. See this module's own docs for why a second,
/// independently minimal copy lives here.
fn decode_limited_charset(charset_name: &str, bytes: &[u8]) -> Option<String> {
    match charset_name {
        "US-ASCII" | "ASCII" if bytes.iter().all(|b| b.is_ascii()) => {
            Some(bytes.iter().map(|&b| b as char).collect())
        }
        "UTF-8" => std::str::from_utf8(bytes).ok().map(|s| s.to_string()),
        "UTF-16BE" => decode_utf16_bytes(bytes, true),
        "UTF-16LE" => decode_utf16_bytes(bytes, false),
        "UTF-32BE" => decode_utf32_bytes(bytes, true),
        "UTF-32LE" => decode_utf32_bytes(bytes, false),
        _ => None,
    }
}

fn decode_utf16_bytes(bytes: &[u8], big_endian: bool) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if big_endian {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_le_bytes([c[0], c[1]])
            }
        })
        .collect();
    Some(
        char::decode_utf16(units)
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect(),
    )
}

fn decode_utf32_bytes(bytes: &[u8], big_endian: bool) -> Option<String> {
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = String::new();
    for c in bytes.chunks_exact(4) {
        let value = if big_endian {
            u32::from_be_bytes([c[0], c[1], c[2], c[3]])
        } else {
            u32::from_le_bytes([c[0], c[1], c[2], c[3]])
        };
        out.push(char::from_u32(value).unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    Some(out)
}

fn pad_left(s: &str, filler: char, length: usize) -> String {
    let char_count = s.chars().count();
    if char_count >= length {
        return s.to_string();
    }
    let mut out: String = std::iter::repeat(filler).take(length - char_count).collect();
    out.push_str(s);
    out
}

/// Helper class used to build up a formatted (for human consumption) string representation
/// returned by Unicode and String data types.
///
/// Call [`build`](StringRenderBuilder::build) to retrieve the formatted string.
///
/// Example (quotes are part of result): `"Test\tstring",01h,02h,"Second\npart"`
///
/// Port of `ghidra.program.model.data.StringRenderBuilder`. See the module-level documentation
/// for what was simplified relative to the Java original's streaming `CharsetDecoder`-based
/// `decodeBytesUsingCharset`.
pub struct StringRenderBuilder {
    sb: String,
    charset_name: String,
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

    /// Port of `StringRenderBuilder(Charset cs, int charSize)`, using [`Self::DOUBLE_QUOTE`] as
    /// the quote character. `charset_name` stands in for `Charset cs`; see the module docs.
    pub fn new(charset_name: &str, char_size: i32) -> Self {
        Self::with_quote_char(charset_name, char_size, Self::DOUBLE_QUOTE)
    }

    /// Port of `StringRenderBuilder(Charset cs, int charSize, char quoteChar)`.
    pub fn with_quote_char(charset_name: &str, char_size: i32, quote_char: char) -> Self {
        StringRenderBuilder {
            sb: String::new(),
            utf_charset: charset_name.to_ascii_uppercase().starts_with("UTF"),
            charset_name: charset_name.to_string(),
            char_size,
            quote_char,
            byte_mode: true,
        }
    }

    /// The charset name this builder was constructed with, standing in for `Charset cs.name()`.
    pub fn charset_name(&self) -> &str {
        &self.charset_name
    }

    /// Add a unicode codepoint as its escaped hex value, with an escape character prefix of `x`,
    /// `u`, or `U` depending on the magnitude of the codepoint value.
    ///
    /// `codePoint 15 -> '\' 'x' "0F"`, `codePoint 65535 -> '\' 'u' "FFFF"`, `codePoint 65536 ->
    /// '\' 'U' "00010000"`.
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
        let hex = format!("{:X}", code_point);
        self.sb.push('\\');
        self.sb.push(escape_char);
        self.sb.push_str(&pad_left(&hex, '0', digits));
    }

    /// Port of `StringRenderBuilder.decodeBytesUsingCharset(ByteBuffer, RENDER_ENUM, boolean)`.
    /// See the module docs for how this differs from the Java original's streaming, per-chunk
    /// error recovery.
    pub fn decode_bytes_using_charset(&mut self, bytes: &[u8], render_setting: RenderEnum, trim_trailing_nulls: bool) {
        if bytes.is_empty() {
            // early exit avoids problems trying to flush un-initialized codec later
            return;
        }
        match decode_limited_charset(&self.charset_name, bytes) {
            Some(mut text) => {
                if trim_trailing_nulls {
                    while text.ends_with('\u{0}') {
                        text.pop();
                    }
                }
                self.render_chars(&text, render_setting);
            }
            None => self.add_byte_seq(bytes),
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
        if let Some(c) = char::from_u32(code_point) {
            self.sb.push(c);
        }
    }

    fn add_byte(&mut self, byte: u8) {
        self.ensure_byte_mode();
        self.sb.push_str(&format!("{:02X}h", byte));
    }

    fn add_byte_seq(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.add_byte(b);
        }
    }

    /// Port of the private `StringRenderBuilder.addByteSeq(int)` single-codepoint overload; see
    /// the module docs for why this re-encodes via UTF-8 rather than the original charset.
    fn add_byte_seq_for_code_point(&mut self, code_point: u32) {
        if let Some(c) = char::from_u32(code_point) {
            let mut buf = [0u8; 4];
            let encoded = c.encode_utf8(&mut buf);
            self.add_byte_seq(encoded.as_bytes());
        }
    }

    fn render_chars(&mut self, text: &str, render_setting: RenderEnum) {
        for c in text.chars() {
            let code_point = c as u32;
            if is_control_character_or_backslash_code_point(code_point) {
                self.add_string(&convert_code_point_to_escape_sequence(code_point));
            } else if code_point == 0 {
                if self.byte_mode {
                    self.add_byte_seq_for_code_point(0);
                } else {
                    self.add_string("\\0");
                }
            } else if c.is_control() {
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

    /// Renders the accumulated buffer, closing any open quoted text mode -- port of
    /// `StringRenderBuilder.toString()`.
    fn render(&self) -> String {
        let mut s = self.sb.clone();
        if !self.byte_mode {
            s.push(self.quote_char);
        }
        s
    }

    /// Port of `StringRenderBuilder.build()`.
    ///
    /// Example (quotes are part of result): `"Test\tstring",01,02,"Second\npart",00`
    pub fn build(&self) -> String {
        let s = if !self.sb.is_empty() {
            self.render()
        } else {
            format!("{0}{0}", self.quote_char)
        };
        let mut prefix = String::new();
        if self.utf_charset && s.chars().next() == Some(self.quote_char) {
            prefix = match self.char_size {
                1 => "u8",
                2 => "u",
                4 => "U",
                _ => "",
            }
            .to_string();
        }
        format!("{prefix}{s}")
    }
}

impl fmt::Display for StringRenderBuilder {
    /// Port of `StringRenderBuilder.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_defaults_to_double_quote_and_byte_mode() {
        let b = StringRenderBuilder::new("US-ASCII", 1);
        assert_eq!(b.build(), "\"\"");
        assert!(!b.utf_charset);
        assert_eq!(b.charset_name(), "US-ASCII");
    }

    #[test]
    fn utf_charset_detection_is_case_insensitive_prefix_match() {
        let b = StringRenderBuilder::new("utf-16be", 2);
        assert!(b.utf_charset);
        let b2 = StringRenderBuilder::new("US-ASCII", 1);
        assert!(!b2.utf_charset);
    }

    #[test]
    fn add_escaped_code_point_picks_width_by_magnitude() {
        let mut b = StringRenderBuilder::new("US-ASCII", 1);
        b.add_escaped_code_point(15);
        assert_eq!(b.build(), "\"\\x0F\"");

        let mut b2 = StringRenderBuilder::new("US-ASCII", 1);
        b2.add_escaped_code_point(0xFFFF);
        assert_eq!(b2.build(), "\"\\uFFFF\"");

        let mut b3 = StringRenderBuilder::new("US-ASCII", 1);
        b3.add_escaped_code_point(0x10000);
        assert_eq!(b3.build(), "\"\\U00010000\"");
    }

    #[test]
    fn decode_ascii_renders_plain_text_in_quotes() {
        let mut b = StringRenderBuilder::new("US-ASCII", 1);
        b.decode_bytes_using_charset(b"hi", RenderEnum::All, false);
        assert_eq!(b.build(), "\"hi\"");
    }

    #[test]
    fn decode_control_characters_use_escape_sequences() {
        let mut b = StringRenderBuilder::new("US-ASCII", 1);
        b.decode_bytes_using_charset(b"a\tb", RenderEnum::All, false);
        assert_eq!(b.build(), "\"a\\tb\"");
    }

    #[test]
    fn decode_trims_trailing_nulls_when_requested() {
        let mut b = StringRenderBuilder::new("US-ASCII", 1);
        b.decode_bytes_using_charset(b"hi\0\0", RenderEnum::All, true);
        assert_eq!(b.build(), "\"hi\"");
    }

    #[test]
    fn decode_keeps_trailing_nulls_when_not_requested() {
        let mut b = StringRenderBuilder::new("US-ASCII", 1);
        // A NUL encountered while already in text mode (as here, after "hi") renders as a
        // literal "\0" escape within the quoted text rather than switching to byte mode --
        // `byteMode` is only consulted, matching Java's `if (byteMode) {...} else
        // addString("\\0")` branch.
        b.decode_bytes_using_charset(b"hi\0", RenderEnum::All, false);
        assert_eq!(b.build(), "\"hi\\0\"");
    }

    #[test]
    fn decode_null_while_still_in_byte_mode_renders_as_a_byte() {
        let mut b = StringRenderBuilder::new("US-ASCII", 1);
        // A leading NUL is processed while byte_mode is still true (the constructor default), so
        // it takes the addByteSeq(0) branch instead.
        b.decode_bytes_using_charset(b"\0hi", RenderEnum::All, false);
        assert_eq!(b.build(), "00h,\"hi\"");
    }

    #[test]
    fn decode_falls_back_to_byte_sequence_for_unsupported_charset() {
        let mut b = StringRenderBuilder::new("Shift-JIS", 1);
        b.decode_bytes_using_charset(&[0x41, 0x42], RenderEnum::All, false);
        assert_eq!(b.build(), "41h,42h");
    }

    #[test]
    fn decode_empty_buffer_is_a_no_op() {
        let mut b = StringRenderBuilder::new("US-ASCII", 1);
        b.decode_bytes_using_charset(&[], RenderEnum::All, false);
        assert_eq!(b.build(), "\"\"");
    }

    #[test]
    fn utf16_be_decoding_and_prefix() {
        let mut b = StringRenderBuilder::new("UTF-16BE", 2);
        // "hi" as big-endian UTF-16 code units.
        b.decode_bytes_using_charset(&[0x00, b'h', 0x00, b'i'], RenderEnum::All, false);
        assert_eq!(b.build(), "u\"hi\"");
    }

    #[test]
    fn quote_character_inside_text_is_escaped() {
        let mut b = StringRenderBuilder::new("US-ASCII", 1);
        b.decode_bytes_using_charset(b"a\"b", RenderEnum::All, false);
        assert_eq!(b.build(), "\"a\\\"b\"");
    }

    #[test]
    fn mixed_text_and_byte_mode_are_comma_joined() {
        let mut b = StringRenderBuilder::new("US-ASCII", 1);
        b.decode_bytes_using_charset(b"Test", RenderEnum::All, false);
        b.add_byte(0x01);
        b.add_byte(0x02);
        b.decode_bytes_using_charset(b"more", RenderEnum::All, false);
        assert_eq!(b.build(), "\"Test\",01h,02h,\"more\"");
    }

    #[test]
    fn render_setting_byte_seq_forces_non_ascii_display_chars_to_bytes() {
        // U+00A0 (NBSP) is not "displayable" by this crate's is_displayable definition, so it
        // falls through to the render_setting-selected branch.
        let mut b = StringRenderBuilder::new("UTF-8", 1);
        b.decode_bytes_using_charset("\u{00A0}".as_bytes(), RenderEnum::ByteSeq, false);
        assert_eq!(b.build(), "C2h,A0h");
    }

    #[test]
    fn render_setting_esc_seq_escapes_non_ascii_display_chars() {
        let mut b = StringRenderBuilder::new("UTF-8", 1);
        b.decode_bytes_using_charset("\u{00A0}".as_bytes(), RenderEnum::EscSeq, false);
        // 0x00A0 >= MAX_ASCII (0x80) but within the BMP, so it uses the 4-hex-digit 'u' escape.
        // The result starts with the quote character and the charset name starts with "UTF", so
        // build() also prepends the char_size-1 "u8" prefix (matching the same rule exercised by
        // `utf16_be_decoding_and_prefix` for char_size 2).
        assert_eq!(b.build(), "u8\"\\u00A0\"");
    }

    #[test]
    fn display_impl_matches_java_tostring_semantics() {
        let mut b = StringRenderBuilder::new("US-ASCII", 1);
        b.decode_bytes_using_charset(b"Test", RenderEnum::All, false);
        b.add_byte(0x01);
        // toString() leaves an in-progress byte-mode entry un-quoted (build() would append the
        // closing quote via the text-mode branch instead), matching the Java javadoc example
        // `"Test\tstring",01,02,"Second\npart",00` (no trailing close-quote after a byte run).
        assert_eq!(b.to_string(), "\"Test\",01h");
    }
}

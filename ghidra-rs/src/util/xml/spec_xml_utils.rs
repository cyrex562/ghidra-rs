//! Encoding and decoding utilities for XML data types used in SLEIGH/Decompiler
//! specification files (`.ldef`, `.pspec`, `.cspec`, `.sla`).
//!
//! Mirrors `ghidra.util.xml.SpecXmlUtils`.
//!
//! The encode helpers write into a `String` buffer (the Java `StringBuilder`
//! equivalent); the decode helpers parse attribute strings, treating an empty
//! `&str` as the absent/null case from Java.

/// Decodes a boolean-valued XML attribute string, returning `None` for an
/// empty or unrecognised value.
///
/// Only the first byte is inspected:
/// `y`, `t`, `1` → `Some(true)`; `n`, `f`, `0` → `Some(false)`.
pub(crate) fn decode_nullable_boolean(val: &str) -> Option<bool> {
    match val.bytes().next()? {
        b'y' | b't' | b'1' => Some(true),
        b'n' | b'f' | b'0' => Some(false),
        _ => None,
    }
}

/// Decodes a boolean-valued XML attribute string, returning `false` for an
/// empty or unrecognised value.
pub(crate) fn decode_boolean(val: &str) -> bool {
    decode_nullable_boolean(val).unwrap_or(false)
}

/// Decodes a boolean-valued XML attribute string, returning `default_value`
/// for an empty or unrecognised value.
pub(crate) fn decode_boolean_default(val: &str, default_value: bool) -> bool {
    decode_nullable_boolean(val).unwrap_or(default_value)
}

/// Encodes a boolean as `"true"` or `"false"`.
pub(crate) fn encode_boolean(val: bool) -> &'static str {
    if val { "true" } else { "false" }
}

/// Appends ` nm="true"` or ` nm="false"` to `buf`.
pub(crate) fn encode_boolean_attribute(buf: &mut String, nm: &str, val: bool) {
    buf.push(' ');
    buf.push_str(nm);
    buf.push_str("=\"");
    buf.push_str(if val { "true" } else { "false" });
    buf.push('"');
}

/// Appends ` nm="val"` to `buf` without XML-escaping the value.
pub(crate) fn encode_string_attribute(buf: &mut String, nm: &str, val: &str) {
    buf.push(' ');
    buf.push_str(nm);
    buf.push_str("=\"");
    buf.push_str(val);
    buf.push('"');
}

/// Encodes a signed 64-bit integer as a decimal string.
pub(crate) fn encode_signed_integer(val: i64) -> String {
    val.to_string()
}

/// Encodes a 64-bit value as `"0x"` followed by its lowercase hex digits,
/// treating the bit-pattern as unsigned (matching Java's `Long.toHexString`).
pub(crate) fn encode_unsigned_integer(val: i64) -> String {
    format!("0x{:x}", val as u64)
}

/// Appends ` nm="val"` (decimal) to `buf`.
pub(crate) fn encode_signed_integer_attribute(buf: &mut String, nm: &str, val: i64) {
    buf.push(' ');
    buf.push_str(nm);
    buf.push_str("=\"");
    buf.push_str(&val.to_string());
    buf.push('"');
}

/// Appends ` nm="0xval"` (hex) to `buf`, treating `val` as unsigned.
pub(crate) fn encode_unsigned_integer_attribute(buf: &mut String, nm: &str, val: i64) {
    buf.push(' ');
    buf.push_str(nm);
    buf.push_str("=\"");
    buf.push_str(&format!("0x{:x}", val as u64));
    buf.push('"');
}

/// Appends ` nm="val"` (double) to `buf`.
pub(crate) fn encode_double_attribute(buf: &mut String, nm: &str, val: f64) {
    buf.push(' ');
    buf.push_str(nm);
    buf.push_str("=\"");
    buf.push_str(&val.to_string());
    buf.push('"');
}

/// Parses an XML integer attribute: `0x`-prefixed hex, `0`-prefixed octal, or
/// plain decimal.
///
/// Returns `0` for `None` or an empty string.  The result is truncated to 32
/// bits, matching Java's `BigInteger.intValue()`.
pub(crate) fn decode_int(int_string: Option<&str>) -> i32 {
    let s = match int_string {
        None | Some("") => return 0,
        Some(s) => s,
    };
    if s == "0" {
        return 0;
    }
    let (digits, radix) = if let Some(hex) = s.strip_prefix("0x") {
        (hex, 16_u32)
    } else if s.starts_with('0') {
        (&s[1..], 8_u32)
    } else {
        (s, 10_u32)
    };
    i128::from_str_radix(digits, radix).unwrap_or(0) as i32
}

/// Parses an XML long attribute: `0x`-prefixed hex, `0`-prefixed octal, or
/// plain decimal.
///
/// Returns `0` for `None` or an empty string.  The result is truncated to 64
/// bits, matching Java's `BigInteger.longValue()`.
pub(crate) fn decode_long(long_string: Option<&str>) -> i64 {
    let s = match long_string {
        None | Some("") => return 0,
        Some(s) => s,
    };
    if s == "0" {
        return 0;
    }
    let (digits, radix) = if let Some(hex) = s.strip_prefix("0x") {
        (hex, 16_u32)
    } else if s.starts_with('0') {
        (&s[1..], 8_u32)
    } else {
        (s, 10_u32)
    };
    i128::from_str_radix(digits, radix).unwrap_or(0) as i64
}

/// Appends the XML-escaped form of `val` to `buf`.
///
/// Escapes `&`, `<`, `>`, `"`, and `'`; all other characters are appended
/// verbatim.
pub(crate) fn xml_escape(buf: &mut String, val: &str) {
    for c in val.chars() {
        match c {
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
            '"' => buf.push_str("&quot;"),
            '\'' => buf.push_str("&apos;"),
            other => buf.push(other),
        }
    }
}

/// Appends ` nm="escaped-val"` to `buf`, XML-escaping the value.
pub(crate) fn xml_escape_attribute(buf: &mut String, nm: &str, val: &str) {
    buf.push(' ');
    buf.push_str(nm);
    buf.push_str("=\"");
    xml_escape(buf, val);
    buf.push('"');
}

/// Writes the XML-escaped form of `val` to `writer`.
pub(crate) fn xml_escape_writer<W: std::io::Write>(
    writer: &mut W,
    val: &str,
) -> std::io::Result<()> {
    for c in val.chars() {
        match c {
            '&' => writer.write_all(b"&amp;")?,
            '<' => writer.write_all(b"&lt;")?,
            '>' => writer.write_all(b"&gt;")?,
            '"' => writer.write_all(b"&quot;")?,
            '\'' => writer.write_all(b"&apos;")?,
            other => {
                let mut tmp = [0u8; 4];
                writer.write_all(other.encode_utf8(&mut tmp).as_bytes())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- decode_nullable_boolean ---

    #[test]
    fn decode_nullable_boolean_true_prefixes() {
        assert_eq!(decode_nullable_boolean("yes"), Some(true));
        assert_eq!(decode_nullable_boolean("true"), Some(true));
        assert_eq!(decode_nullable_boolean("1"), Some(true));
    }

    #[test]
    fn decode_nullable_boolean_false_prefixes() {
        assert_eq!(decode_nullable_boolean("no"), Some(false));
        assert_eq!(decode_nullable_boolean("false"), Some(false));
        assert_eq!(decode_nullable_boolean("0"), Some(false));
    }

    #[test]
    fn decode_nullable_boolean_empty_returns_none() {
        assert_eq!(decode_nullable_boolean(""), None);
    }

    #[test]
    fn decode_nullable_boolean_unknown_first_char_returns_none() {
        assert_eq!(decode_nullable_boolean("maybe"), None);
        assert_eq!(decode_nullable_boolean("2"), None);
    }

    // --- decode_boolean ---

    #[test]
    fn decode_boolean_returns_false_for_unknown() {
        assert!(!decode_boolean(""));
        assert!(!decode_boolean("x"));
    }

    #[test]
    fn decode_boolean_recognises_values() {
        assert!(decode_boolean("t"));
        assert!(!decode_boolean("f"));
    }

    // --- decode_boolean_default ---

    #[test]
    fn decode_boolean_default_uses_default_when_unknown() {
        assert!(decode_boolean_default("", true));
        assert!(!decode_boolean_default("", false));
    }

    #[test]
    fn decode_boolean_default_overrides_when_recognised() {
        assert!(!decode_boolean_default("false", true));
        assert!(decode_boolean_default("true", false));
    }

    // --- encode_boolean ---

    #[test]
    fn encode_boolean_true() {
        assert_eq!(encode_boolean(true), "true");
    }

    #[test]
    fn encode_boolean_false() {
        assert_eq!(encode_boolean(false), "false");
    }

    // --- encode_boolean_attribute ---

    #[test]
    fn encode_boolean_attribute_true_format() {
        let mut buf = String::new();
        encode_boolean_attribute(&mut buf, "flag", true);
        assert_eq!(buf, r#" flag="true""#);
    }

    #[test]
    fn encode_boolean_attribute_false_format() {
        let mut buf = String::new();
        encode_boolean_attribute(&mut buf, "flag", false);
        assert_eq!(buf, r#" flag="false""#);
    }

    // --- encode_string_attribute ---

    #[test]
    fn encode_string_attribute_format() {
        let mut buf = String::new();
        encode_string_attribute(&mut buf, "name", "hello");
        assert_eq!(buf, r#" name="hello""#);
    }

    // --- encode_signed_integer / encode_unsigned_integer ---

    #[test]
    fn encode_signed_integer_positive() {
        assert_eq!(encode_signed_integer(255), "255");
    }

    #[test]
    fn encode_signed_integer_negative() {
        assert_eq!(encode_signed_integer(-42), "-42");
    }

    #[test]
    fn encode_signed_integer_zero() {
        assert_eq!(encode_signed_integer(0), "0");
    }

    #[test]
    fn encode_unsigned_integer_hex_prefix() {
        assert_eq!(encode_unsigned_integer(0), "0x0");
        assert_eq!(encode_unsigned_integer(255), "0xff");
    }

    #[test]
    fn encode_unsigned_integer_treats_bits_as_unsigned() {
        assert_eq!(encode_unsigned_integer(-1_i64), "0xffffffffffffffff");
    }

    // --- encode_signed_integer_attribute / encode_unsigned_integer_attribute ---

    #[test]
    fn encode_signed_integer_attribute_format() {
        let mut buf = String::new();
        encode_signed_integer_attribute(&mut buf, "size", -10);
        assert_eq!(buf, r#" size="-10""#);
    }

    #[test]
    fn encode_unsigned_integer_attribute_format() {
        let mut buf = String::new();
        encode_unsigned_integer_attribute(&mut buf, "addr", 255);
        assert_eq!(buf, r#" addr="0xff""#);
    }

    // --- encode_double_attribute ---

    #[test]
    fn encode_double_attribute_format() {
        let mut buf = String::new();
        encode_double_attribute(&mut buf, "pi", 3.14);
        assert_eq!(buf, " pi=\"3.14\"");
    }

    // --- decode_int ---

    #[test]
    fn decode_int_none_is_zero() {
        assert_eq!(decode_int(None), 0);
    }

    #[test]
    fn decode_int_empty_is_zero() {
        assert_eq!(decode_int(Some("")), 0);
    }

    #[test]
    fn decode_int_zero_string() {
        assert_eq!(decode_int(Some("0")), 0);
    }

    #[test]
    fn decode_int_decimal() {
        assert_eq!(decode_int(Some("42")), 42);
        assert_eq!(decode_int(Some("-1")), -1);
    }

    #[test]
    fn decode_int_hex() {
        assert_eq!(decode_int(Some("0xff")), 255);
        assert_eq!(decode_int(Some("0x10")), 16);
    }

    #[test]
    fn decode_int_octal() {
        assert_eq!(decode_int(Some("010")), 8);
        assert_eq!(decode_int(Some("017")), 15);
    }

    #[test]
    fn decode_int_truncates_to_32_bits() {
        // 0x1_0000_0001 low 32 bits = 1
        assert_eq!(decode_int(Some("0x100000001")), 1);
    }

    // --- decode_long ---

    #[test]
    fn decode_long_none_is_zero() {
        assert_eq!(decode_long(None), 0);
    }

    #[test]
    fn decode_long_empty_is_zero() {
        assert_eq!(decode_long(Some("")), 0);
    }

    #[test]
    fn decode_long_zero_string() {
        assert_eq!(decode_long(Some("0")), 0);
    }

    #[test]
    fn decode_long_decimal() {
        assert_eq!(decode_long(Some("1234567890")), 1234567890);
    }

    #[test]
    fn decode_long_hex_wraps_to_negative() {
        assert_eq!(decode_long(Some("0xffffffffffffffff")), -1);
    }

    #[test]
    fn decode_long_octal() {
        assert_eq!(decode_long(Some("010")), 8);
    }

    // --- xml_escape ---

    #[test]
    fn xml_escape_plain_text_unchanged() {
        let mut buf = String::new();
        xml_escape(&mut buf, "hello world");
        assert_eq!(buf, "hello world");
    }

    #[test]
    fn xml_escape_ampersand() {
        let mut buf = String::new();
        xml_escape(&mut buf, "a&b");
        assert_eq!(buf, "a&amp;b");
    }

    #[test]
    fn xml_escape_lt_and_gt() {
        let mut buf = String::new();
        xml_escape(&mut buf, "<tag>");
        assert_eq!(buf, "&lt;tag&gt;");
    }

    #[test]
    fn xml_escape_double_quote_and_apostrophe() {
        let mut buf = String::new();
        xml_escape(&mut buf, "\"it's\"");
        assert_eq!(buf, "&quot;it&apos;s&quot;");
    }

    #[test]
    fn xml_escape_all_special_chars() {
        let mut buf = String::new();
        xml_escape(&mut buf, "&<>\"'");
        assert_eq!(buf, "&amp;&lt;&gt;&quot;&apos;");
    }

    // --- xml_escape_attribute ---

    #[test]
    fn xml_escape_attribute_format() {
        let mut buf = String::new();
        xml_escape_attribute(&mut buf, "desc", "a<b");
        assert_eq!(buf, r#" desc="a&lt;b""#);
    }

    // --- xml_escape_writer ---

    #[test]
    fn xml_escape_writer_special_chars() {
        let mut out: Vec<u8> = Vec::new();
        xml_escape_writer(&mut out, "&<>\"'").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "&amp;&lt;&gt;&quot;&apos;");
    }

    #[test]
    fn xml_escape_writer_plain_text() {
        let mut out: Vec<u8> = Vec::new();
        xml_escape_writer(&mut out, "hello").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "hello");
    }

    #[test]
    fn xml_escape_writer_multibyte_unicode() {
        let mut out: Vec<u8> = Vec::new();
        xml_escape_writer(&mut out, "caf\u{00e9}").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "caf\u{00e9}");
    }
}

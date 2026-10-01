//! Port of `ghidra.program.model.data.CharDataTypesRenderTest`: rendering and encoding of the
//! char data types.

use crate::program::model::data::char_data_type::CharDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::render_unicode_settings_definition::RenderEnum;
use crate::program::model::data::string_data_instance::test_support::{mb, SettingsBuilder};
use crate::program::model::data::unsigned_char_data_type::UnsignedCharDataType;
use crate::program::model::data::wide_char16_data_type::WideChar16DataType;
use crate::program::model::data::wide_char32_data_type::WideChar32DataType;
use crate::program::model::data::wide_char_data_type::WideCharDataType;
use crate::util::charset::JavaCharset;

fn newset() -> SettingsBuilder {
    SettingsBuilder::new()
}

fn thai_cs() -> JavaCharset {
    JavaCharset::for_name("IBM-Thai").expect("IBM-Thai is available")
}

fn rep(dt: &dyn DataType, bytes: &[u8], big_endian: bool, settings: &SettingsBuilder) -> String {
    dt.get_representation(&mb(big_endian, bytes), settings, dt.get_length())
}

fn enc(dt: &dyn DataType, repr: &str, big_endian: bool, settings: &SettingsBuilder) -> Vec<u8> {
    dt.encode_representation(repr, &mb(big_endian, &[]), settings, -1).unwrap()
}

fn assert_contains_str(expected_substr: &str, actual: &str) {
    assert!(actual.contains(expected_substr), "Substring [{expected_substr}] is not present in actual string [{actual}]");
}

#[test]
fn test_simple_ascii_char() {
    assert_eq!(rep(&CharDataType::new(None), b"a", false, &newset()), "'a'");
    assert_eq!(rep(&UnsignedCharDataType::new(None), b"a", false, &newset()), "'a'");
    assert_eq!(rep(&WideCharDataType::new(None), &[b'a', 0], false, &newset()), "u'a'");
    assert_eq!(rep(&WideChar16DataType::new(None), &[b'a', 0], false, &newset()), "u'a'");
    assert_eq!(rep(&WideChar32DataType::new(None), &[b'a', 0, 0, 0], false, &newset()), "U'a'");
}

#[test]
fn test_encode_simple_ascii_char() {
    assert_eq!(enc(&CharDataType::new(None), "'a'", false, &newset()), b"a");
    assert_eq!(enc(&UnsignedCharDataType::new(None), "'a'", false, &newset()), b"a");
    assert_eq!(enc(&WideCharDataType::new(None), "u'a'", false, &newset()), vec![b'a', 0]);
    assert_eq!(enc(&WideChar16DataType::new(None), "u'a'", false, &newset()), vec![b'a', 0]);
    assert_eq!(enc(&WideChar32DataType::new(None), "U'a'", false, &newset()), vec![b'a', 0, 0, 0]);

    assert_eq!(enc(&CharDataType::new(None), "'a'", true, &newset()), b"a");
    assert_eq!(enc(&UnsignedCharDataType::new(None), "'a'", true, &newset()), b"a");
    assert_eq!(enc(&WideCharDataType::new(None), "u'a'", true, &newset()), vec![0, b'a']);
    assert_eq!(enc(&WideChar16DataType::new(None), "u'a'", true, &newset()), vec![0, b'a']);
    assert_eq!(enc(&WideChar32DataType::new(None), "U'a'", true, &newset()), vec![0, 0, 0, b'a']);
}

#[test]
fn test_wide_chars_non_ascii() {
    let buf_thai: &[u8] = &[66];
    let buf_be16: &[u8] = &[0xcc, 0x01];
    let buf_be32: &[u8] = &[0, 0, 0xcc, 0x01];
    let buf_le1632: &[u8] = &[0x01, 0xcc, 0, 0];
    let wchar = WideCharDataType::new(None);
    let wchar16 = WideChar16DataType::new(None);
    let wchar32 = WideChar32DataType::new(None);

    assert_eq!(rep(&CharDataType::new(None), buf_thai, false, &newset().charset(thai_cs())), "'\u{0e01}'");
    assert_eq!(rep(&wchar, buf_be16, true, &newset()), "u'\u{cc01}'");
    assert_eq!(rep(&wchar, buf_le1632, false, &newset()), "u'\u{cc01}'");
    assert_eq!(rep(&wchar16, buf_be16, true, &newset()), "u'\u{cc01}'");
    assert_eq!(rep(&wchar16, buf_le1632, false, &newset()), "u'\u{cc01}'");
    assert_eq!(rep(&wchar32, buf_be32, true, &newset()), "U'\u{cc01}'");
    assert_eq!(rep(&wchar32, buf_le1632, false, &newset()), "U'\u{cc01}'");
}

#[test]
fn test_encode_wide_chars_non_ascii() {
    assert_eq!(enc(&CharDataType::new(None), "'\u{0e01}'", false, &newset().charset(thai_cs())), vec![66]);
    for (dt, repr) in [
        (&WideCharDataType::new(None) as &dyn DataType, "u'\u{cc01}'"),
        (&WideChar16DataType::new(None), "u'\u{cc01}'"),
    ] {
        assert_eq!(enc(dt, repr, true, &newset()), vec![0xcc, 0x01]);
        assert_eq!(enc(dt, repr, false, &newset()), vec![0x01, 0xcc]);
    }
    assert_eq!(enc(&WideChar32DataType::new(None), "U'\u{cc01}'", true, &newset()), vec![0, 0, 0xcc, 0x01]);
    assert_eq!(enc(&WideChar32DataType::new(None), "U'\u{cc01}'", false, &newset()), vec![0x01, 0xcc, 0, 0]);
}

#[test]
fn test_wide_chars_non_ascii_esc_seq() {
    let buf_thai: &[u8] = &[66];
    let buf_be16: &[u8] = &[0xcc, 0x01];
    let buf_be32: &[u8] = &[0, 0, 0xcc, 0x01];
    let buf_le1632: &[u8] = &[0x01, 0xcc, 0, 0];
    let escseq = newset().render(RenderEnum::EscSeq);

    assert_contains_str(
        "'\\u0E01'",
        &rep(&CharDataType::new(None), buf_thai, false, &newset().charset(thai_cs()).render(RenderEnum::EscSeq)),
    );
    assert_eq!(rep(&WideCharDataType::new(None), buf_be16, true, &escseq), "u'\\uCC01'");
    assert_eq!(rep(&WideCharDataType::new(None), buf_le1632, false, &escseq), "u'\\uCC01'");
    assert_eq!(rep(&WideChar16DataType::new(None), buf_be16, true, &escseq), "u'\\uCC01'");
    assert_eq!(rep(&WideChar16DataType::new(None), buf_le1632, false, &escseq), "u'\\uCC01'");
    assert_eq!(rep(&WideChar32DataType::new(None), buf_be32, true, &escseq), "U'\\uCC01'");
    assert_eq!(rep(&WideChar32DataType::new(None), buf_le1632, false, &escseq), "U'\\uCC01'");
}

#[test]
fn test_encode_wide_chars_non_ascii_esc_seq() {
    assert_eq!(enc(&CharDataType::new(None), "'\\u0e01'", false, &newset().charset(thai_cs())), vec![66]);
    for (dt, repr) in [
        (&WideCharDataType::new(None) as &dyn DataType, "u'\\ucc01'"),
        (&WideChar16DataType::new(None), "u'\\ucc01'"),
    ] {
        assert_eq!(enc(dt, repr, true, &newset()), vec![0xcc, 0x01]);
        assert_eq!(enc(dt, repr, false, &newset()), vec![0x01, 0xcc]);
    }
    assert_eq!(enc(&WideChar32DataType::new(None), "U'\\ucc01'", true, &newset()), vec![0, 0, 0xcc, 0x01]);
    assert_eq!(enc(&WideChar32DataType::new(None), "U'\\ucc01'", false, &newset()), vec![0x01, 0xcc, 0, 0]);
}

#[test]
fn test_non_ascii_charset() {
    // in thai charset, byte 73 ('I') maps to the normal ascii char '['
    assert_eq!(rep(&CharDataType::new(None), &[73], false, &newset().charset(thai_cs())), "'['");
}

#[test]
fn test_encode_non_ascii_charset() {
    assert_eq!(enc(&CharDataType::new(None), "'['", false, &newset().charset(thai_cs())), vec![73]);
}

#[test]
fn test_escape_sequence_render_singlebyte_to_multibyte() {
    // in thai charset, byte 66 ('B') maps to a 'n' looking thing with a line
    let result = rep(&CharDataType::new(None), &[66], false, &newset().charset(thai_cs()).render(RenderEnum::EscSeq));
    assert_contains_str("'\\u0E01'", &result);
}

#[test]
fn test_render_invalid_values() {
    // With us-ascii charset, bytes values above 0x7f are invalid. With utf-16, 0xD800-0xDFFF are
    // reserved. With utf-32, not all possible integer values are valid unicode codepoints. An
    // invalid value forces the render mode to byte_seq.
    let normset = newset();
    let escseq = newset().render(RenderEnum::EscSeq);
    let byteseq = newset().render(RenderEnum::ByteSeq);
    for set in [&normset, &escseq, &byteseq] {
        assert_eq!(rep(&WideChar32DataType::new(None), &[0xaa, 0xaa, 0xaa, 0xaa], false, set), "AAh,AAh,AAh,AAh");
        assert_eq!(rep(&WideChar16DataType::new(None), &[0xd8, 0x00], true, set), "D8h,00h");
        assert_eq!(rep(&CharDataType::new(None), &[0x85], false, set), "85h");
    }
}

#[test]
fn test_escape_sequence_render_literal_unicode_replacement_char() {
    // char literal 0xfffd.
    let dt = WideChar16DataType::new(None);
    assert_eq!(rep(&dt, &[0xfd, 0xff], false, &newset()), "u'\u{FFFD}'");
    assert_eq!(rep(&dt, &[0xfd, 0xff], false, &newset().render(RenderEnum::EscSeq)), "u'\\uFFFD'");
    assert_eq!(rep(&dt, &[0xfd, 0xff], false, &newset().render(RenderEnum::ByteSeq)), "FDh,FFh");
}

#[test]
fn test_encode_byte_sequence() {
    assert_eq!(enc(&CharDataType::new(None), "AAh,FFh,FDh", true, &newset()), vec![0xaa, 0xff, 0xfd]);
}

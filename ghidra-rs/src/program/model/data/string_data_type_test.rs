//! Port of `ghidra.program.model.data.StringDataTypeTest`.

use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::data::pascal_string255_data_type::PascalString255DataType;
use crate::program::model::data::pascal_string_data_type::PascalStringDataType;
use crate::program::model::data::pascal_unicode_data_type::PascalUnicodeDataType;
use crate::program::model::data::render_unicode_settings_definition::RenderEnum;
use crate::program::model::data::string_data_instance::test_support::{mb, SettingsBuilder};
use crate::program::model::data::string_data_instance::{StringDataInstance, MAX_STRING_LENGTH};
use crate::program::model::data::string_data_type::StringDataType;
use crate::program::model::data::string_utf8_data_type::StringUTF8DataType;
use crate::program::model::data::terminated_string_data_type::TerminatedStringDataType;
use crate::program::model::data::terminated_unicode32_data_type::TerminatedUnicode32DataType;
use crate::program::model::data::terminated_unicode_data_type::TerminatedUnicodeDataType;
use crate::program::model::data::unicode32_data_type::Unicode32DataType;
use crate::program::model::data::unicode_data_type::UnicodeDataType;
use crate::program::model::mem::{ByteMemBufferImpl, MemBuffer};
use crate::util::charset::JavaCharset;

fn fixedlen_string() -> StringDataType {
    StringDataType::new(None)
}
fn fixed_utf8_string() -> StringUTF8DataType {
    StringUTF8DataType::new(None)
}
fn fixed_utf16_string() -> UnicodeDataType {
    UnicodeDataType::new(None)
}
fn fixed_utf32_string() -> Unicode32DataType {
    Unicode32DataType::new(None)
}
fn term_string() -> TerminatedStringDataType {
    TerminatedStringDataType::new(None)
}
fn term_utf16_string() -> TerminatedUnicodeDataType {
    TerminatedUnicodeDataType::new(None)
}
fn term_utf32_string() -> TerminatedUnicode32DataType {
    TerminatedUnicode32DataType::new(None)
}
fn pascal255_string() -> PascalString255DataType {
    PascalString255DataType::new(None)
}
fn pascal_string() -> PascalStringDataType {
    PascalStringDataType::new(None)
}
fn pascal_utf16_string() -> PascalUnicodeDataType {
    PascalUnicodeDataType::new(None)
}

fn newset() -> SettingsBuilder {
    SettingsBuilder::new()
}

fn value(dt: &dyn DataType, buf: &dyn MemBuffer, settings: &dyn Settings, len: i32) -> Option<String> {
    dt.get_value(buf, settings, len).map(|v| v.downcast_ref::<String>().unwrap().clone())
}

fn mk_sdi<'a>(dt: &dyn AbstractStringDataType, buf: &'a ByteMemBufferImpl, settings: &dyn Settings, length: i32) -> StringDataInstance<'a> {
    StringDataInstance::new(dt, settings, buf, length)
}

/// `DataOrgDTM`: a manager reporting a given data organization.
struct DataOrgDtm(DataOrganizationImpl);
impl DataTypeManager for DataOrgDtm {
    fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        Arc::new(self.0.clone())
    }
}

// ---- get string length ----

#[test]
fn test_probe_get_string_len() {
    let buf = mb(false, b"hello\0xy\0");
    // all probes with unknown len are null-term string probes
    assert_eq!(fixedlen_string().get_dynamic_length(&buf, -1), 6);
    assert_eq!(term_string().get_dynamic_length(&buf, -1), 6);
    assert_eq!(fixed_utf8_string().get_dynamic_length(&buf, -1), 6);
}

#[test]
fn test_probe_get_string_len_eof() {
    let buf = mb(false, b"hello");
    // terminated string probe should fail if hit EOF before null-term char
    assert_eq!(fixedlen_string().get_dynamic_length(&buf, -1), -1);
    assert_eq!(term_string().get_dynamic_length(&buf, -1), -1);
}

#[test]
fn test_probe_get_string_len_utf16() {
    let buf = mb(false, &[b'h', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0, 0, 0, b'x', 0, b'y', 0]);
    assert_eq!(fixed_utf16_string().get_dynamic_length(&buf, -1), 12);
    assert_eq!(term_utf16_string().get_dynamic_length(&buf, -1), 12);
}

#[test]
fn test_probe_get_string_len_utf32() {
    let mut bytes = Vec::new();
    for c in b"hello\0xy" {
        bytes.extend_from_slice(&[*c, 0, 0, 0]);
    }
    let buf = mb(false, &bytes);
    assert_eq!(fixed_utf32_string().get_dynamic_length(&buf, -1), 24);
    assert_eq!(term_utf32_string().get_dynamic_length(&buf, -1), 24);
}

#[test]
fn test_probe_get_string_len_p255() {
    let buf = mb(false, &[5, b'h', b'e', b'l', b'l', b'o', b'x', b'y', 0]);
    assert_eq!(pascal255_string().get_dynamic_length(&buf, -1), 6);
    assert_eq!(pascal255_string().get_dynamic_length(&buf, buf.get_length() as i32), 6);
}

#[test]
fn test_probe_get_string_len_p() {
    let buf = mb(false, &[5, 0, b'h', b'e', b'l', b'l', b'o', b'x', b'y', 0]);
    assert_eq!(pascal_string().get_dynamic_length(&buf, -1), 7);
    assert_eq!(pascal_string().get_dynamic_length(&buf, buf.get_length() as i32), 7);
}

#[test]
fn test_probe_get_string_len_utf16_p() {
    let buf = mb(false, &[5, 0, b'h', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0, b'x', 0, b'y', 0, 0]);
    assert_eq!(pascal_utf16_string().get_dynamic_length(&buf, -1), 12);
    assert_eq!(pascal_utf16_string().get_dynamic_length(&buf, buf.get_length() as i32), 12);
}

#[test]
fn test_known_get_string_len() {
    let buf = mb(false, b"hello\0xy\0");
    assert_eq!(term_string().get_dynamic_length(&buf, buf.get_length() as i32), 6);
    assert_eq!(term_string().get_dynamic_length(&buf, 1), 6);

    assert_eq!(fixedlen_string().get_dynamic_length(&buf, 1), 1);
    assert_eq!(fixedlen_string().get_dynamic_length(&buf, 6), 6);
    assert_eq!(fixedlen_string().get_dynamic_length(&buf, 7), 7);

    assert_eq!(fixed_utf8_string().get_dynamic_length(&buf, 1), 1);
    assert_eq!(fixed_utf8_string().get_dynamic_length(&buf, 6), 6);
    assert_eq!(fixed_utf8_string().get_dynamic_length(&buf, 7), 7);
}

#[test]
fn test_probe_oversize_string_len() {
    let mut chars = vec![b'a'; MAX_STRING_LENGTH as usize + 1];
    let n = chars.len();
    chars[n - 1] = 0;
    let buf = mb(false, &chars);
    // Should fail when trying to find null term with strings larger than 16k
    assert_eq!(term_string().get_dynamic_length(&buf, buf.get_length() as i32), -1);

    chars[n - 2] = 0;
    let buf = mb(false, &chars);
    // Should work when trying to find null term with strings smaller than 16k
    assert_eq!(term_string().get_dynamic_length(&buf, buf.get_length() as i32), MAX_STRING_LENGTH);
}

// ---- stringValue ----

#[test]
fn test_probe_get_string_value() {
    let buf = mb(false, b"hello\0xy\0");
    // getValue always returns null with unknown string field length
    assert_eq!(value(&fixedlen_string(), &buf, &newset(), -1), None);
    assert_eq!(value(&term_string(), &buf, &newset(), -1), None);
}

#[test]
fn test_get_string_value() {
    let buf = mb(false, b"hello\0xy\0");
    let len = buf.get_length() as i32;
    // term & unbounded should get the first null term string regardless of containing field length
    for l in [1, 5, 6, len] {
        assert_eq!(value(&term_string(), &buf, &newset(), l).as_deref(), Some("hello"));
    }
    // fixedlen & bounded should get exactly what len param specifies
    assert_eq!(value(&fixedlen_string(), &buf, &newset(), 1).as_deref(), Some("h"));
    assert_eq!(value(&fixedlen_string(), &buf, &newset(), 5).as_deref(), Some("hello"));
    assert_eq!(value(&fixedlen_string(), &buf, &newset(), 6).as_deref(), Some("hello"));
    assert_eq!(value(&fixedlen_string(), &buf, &newset(), len).as_deref(), Some("hello\0xy"));
}

#[test]
fn test_get_string_value_utf8() {
    // "ab" and 2 ideographic characters cc01 & 1202 encoded as UTF-8
    let buf = mb(false, &[b'a', b'b', 0xec, 0xb0, 0x81, 0xe1, 0x88, 0x82]);
    let actual = value(&fixed_utf8_string(), &buf, &newset(), buf.get_length() as i32);
    assert_eq!(actual.as_deref(), Some("ab\u{cc01}\u{1202}"));
}

#[test]
fn test_get_string_value_utf8_2bytechar_dataorg() {
    // test UTF-8 when the dataorg specifies a 2byte character (ie. JVM)
    let buf = mb(false, b"abc");
    let mut data_org = DataOrganizationImpl::get_default_organization(None);
    data_org.set_char_size(2);
    let dtm = DataOrgDtm(data_org);
    let wide_char_utf8_dt = StringUTF8DataType::new(Some(&dtm));
    assert_eq!(value(&wide_char_utf8_dt, &buf, &newset(), buf.get_length() as i32).as_deref(), Some("abc"));
}

#[test]
fn test_get_string_value_utf16_le() {
    let buf = mb(false, &[b'h', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0, 0, 0, b'x', 0, b'y', 0]);
    let len = buf.get_length() as i32;
    for l in [2, 10, 12, len] {
        assert_eq!(value(&term_utf16_string(), &buf, &newset(), l).as_deref(), Some("hello"));
    }
    assert_eq!(value(&fixed_utf16_string(), &buf, &newset(), 2).as_deref(), Some("h"));
    assert_eq!(value(&fixed_utf16_string(), &buf, &newset(), 10).as_deref(), Some("hello"));
    assert_eq!(value(&fixed_utf16_string(), &buf, &newset(), 12).as_deref(), Some("hello"));
    assert_eq!(value(&fixed_utf16_string(), &buf, &newset(), len).as_deref(), Some("hello\0xy"));
}

#[test]
fn test_get_string_value_utf_bom() {
    // test reading BE and LE utf-* string that is determined by the BOM at the start of the string.
    assert_eq!(value(&fixed_utf16_string(), &mb(false, &[0xfe, 0xff, 0, b'A']), &newset(), 4).as_deref(), Some("A"));
    assert_eq!(value(&fixed_utf16_string(), &mb(false, &[0xff, 0xfe, b'A', 0]), &newset(), 4).as_deref(), Some("A"));
    assert_eq!(
        value(&fixed_utf32_string(), &mb(false, &[0x00, 0x00, 0xfe, 0xff, 0, 0, 0, b'A']), &newset(), 8).as_deref(),
        Some("A")
    );
    assert_eq!(
        value(&fixed_utf32_string(), &mb(false, &[0xff, 0xfe, 0x00, 0x00, b'A', 0, 0, 0]), &newset(), 8).as_deref(),
        Some("A")
    );

    // test reading BE and LE utf-* string with missing BOM and relying on mem endianness
    assert_eq!(value(&fixed_utf16_string(), &mb(true, &[0, b'A']), &newset(), 2).as_deref(), Some("A"));
    assert_eq!(value(&fixed_utf16_string(), &mb(false, &[b'A', 0]), &newset(), 2).as_deref(), Some("A"));
    assert_eq!(value(&fixed_utf32_string(), &mb(true, &[0, 0, 0, b'A']), &newset(), 4).as_deref(), Some("A"));
    assert_eq!(value(&fixed_utf32_string(), &mb(false, &[b'A', 0, 0, 0]), &newset(), 4).as_deref(), Some("A"));
}

#[test]
fn test_get_string_value_utf32() {
    let mut bytes = Vec::new();
    for c in b"hello\0xy" {
        bytes.extend_from_slice(&[*c, 0, 0, 0]);
    }
    let buf = mb(false, &bytes);
    let len = buf.get_length() as i32;
    for l in [4, 20, 24, len] {
        assert_eq!(value(&term_utf32_string(), &buf, &newset(), l).as_deref(), Some("hello"));
    }
    assert_eq!(value(&fixed_utf32_string(), &buf, &newset(), 4).as_deref(), Some("h"));
    assert_eq!(value(&fixed_utf32_string(), &buf, &newset(), 20).as_deref(), Some("hello"));
    assert_eq!(value(&fixed_utf32_string(), &buf, &newset(), 24).as_deref(), Some("hello"));
    assert_eq!(value(&fixed_utf32_string(), &buf, &newset(), len).as_deref(), Some("hello\0xy"));
}

#[test]
fn test_get_string_value_p255() {
    let buf = mb(false, &[5, b'h', b'e', b'l', b'l', b'o', b'x', b'y', 0]);
    assert_eq!(value(&pascal255_string(), &buf, &newset(), -1), None);
    assert_eq!(value(&pascal255_string(), &buf, &newset(), 1).as_deref(), Some("hello"));
    assert_eq!(value(&pascal255_string(), &buf, &newset(), buf.get_length() as i32).as_deref(), Some("hello"));
}

#[test]
fn test_get_string_value_pascal_eof() {
    // Pascal string with length past end of mem should return null
    assert_eq!(value(&pascal255_string(), &mb(false, &[5, b'h', b'e', b'l', b'l']), &newset(), -1), None);
    assert_eq!(value(&pascal_string(), &mb(false, &[5, 0, b'h', b'e', b'l', b'l']), &newset(), -1), None);
    assert_eq!(value(&pascal_utf16_string(), &mb(false, &[5, 0, b'h', 0]), &newset(), -1), None);
}

#[test]
fn test_get_string_value_p() {
    let buf = mb(false, &[5, 0, b'h', b'e', b'l', b'l', b'o', b'x', b'y', 0]);
    assert_eq!(value(&pascal_string(), &buf, &newset(), -1), None);
    assert_eq!(value(&pascal_string(), &buf, &newset(), 1).as_deref(), Some("hello"));
    assert_eq!(value(&pascal_string(), &buf, &newset(), buf.get_length() as i32).as_deref(), Some("hello"));
}

#[test]
fn test_get_string_value_utf16_p() {
    let buf = mb(false, &[5, 0, b'h', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0, b'x', 0, b'y', 0, 0]);
    assert_eq!(value(&pascal_utf16_string(), &buf, &newset(), -1), None);
    assert_eq!(value(&pascal_utf16_string(), &buf, &newset(), 1).as_deref(), Some("hello"));
    assert_eq!(value(&pascal_utf16_string(), &buf, &newset(), buf.get_length() as i32).as_deref(), Some("hello"));
}

// ---- getRepresentation ----

#[test]
fn test_probe_get_string_rep_probe() {
    let buf = mb(false, b"hello\0xy\0");
    // getRep always returns error str with unknown string field length
    assert_eq!(fixedlen_string().get_representation(&buf, &newset(), -1), "??");
}

#[test]
fn test_probe_get_string_rep_leading_binary_bytes() {
    let buf = mb(false, &[1, 2, b'x']);
    assert_eq!(fixedlen_string().get_representation(&buf, &newset(), buf.get_length() as i32), "01h,02h,\"x\"");
}

#[test]
fn test_probe_encode_string_rep_leading_binary_bytes() {
    let bytes = [1u8, 2, b'x'];
    assert_eq!(
        fixedlen_string().encode_representation("01h,02h,\"x\"", &mb(false, &[]), &newset(), bytes.len() as i32).unwrap(),
        bytes
    );
}

#[test]
fn test_get_string_rep_fixed_len() {
    let buf = mb(false, &[b'h', b'e', b'l', b'l', b'o', 0, b'a', b'\n', b'b', 255, 0]);
    // US-ASCII charset doesn't map 0x80-0xff, they result in error characters
    assert_eq!(fixedlen_string().get_representation(&buf, &newset(), buf.get_length() as i32), "\"hello\\0a\\nb\",FFh");
}

#[test]
fn test_encode_string_rep_fixed_len() {
    let bytes = [b'h', b'e', b'l', b'l', b'o', 0, b'a', b'\n', b'b', 255, 0];
    assert_eq!(
        fixedlen_string()
            .encode_representation("\"hello\\0a\\nb\",FFh", &mb(false, &[]), &newset(), bytes.len() as i32)
            .unwrap(),
        bytes
    );
}

#[test]
fn test_get_string_rep_empty_term() {
    let buf = mb(false, &[0, 0]);
    assert_eq!(term_string().get_representation(&buf, &newset(), buf.get_length() as i32), "\"\"");
}

#[test]
fn test_encode_string_rep_empty_term() {
    // NOTE: Differs from inverse test above.
    assert_eq!(term_string().encode_representation("\"\"", &mb(false, &[]), &newset(), -1).unwrap(), vec![0]);
}

#[test]
fn test_get_string_rep_empty_term_utf16() {
    let buf = mb(false, &[0, 0]);
    assert_eq!(term_utf16_string().get_representation(&buf, &newset(), buf.get_length() as i32), "u\"\"");
}

#[test]
fn test_encode_string_rep_empty_term_utf16() {
    assert_eq!(term_utf16_string().encode_representation("u\"\"", &mb(false, &[]), &newset(), -1).unwrap(), vec![0, 0]);
}

#[test]
fn test_get_string_rep_empty_fixed_len() {
    let buf = mb(false, &[0, 0, 0, 0, 0]);
    assert_eq!(fixedlen_string().get_representation(&buf, &newset(), buf.get_length() as i32), "\"\"");
}

#[test]
fn test_encode_string_rep_empty_fixed_len() {
    let bytes = [0u8; 5];
    assert_eq!(fixedlen_string().encode_representation("\"\"", &mb(false, &[]), &newset(), bytes.len() as i32).unwrap(), bytes);
}

#[test]
fn test_get_string_rep_empty_p() {
    let buf = mb(false, &[0, 0]);
    assert_eq!(pascal_string().get_representation(&buf, &newset(), buf.get_length() as i32), "\"\"");
}

#[test]
fn test_encode_string_rep_empty_p() {
    assert_eq!(pascal_string().encode_representation("\"\"", &mb(false, &[]), &newset(), -1).unwrap(), vec![0, 0]);
}

const ALL_CHARS_REPR: &str = concat!(
    "00h,01h,02h,03h,04h,05h,06h,",
    "\"\\a\\b\\t\\n\\v\\f\\r\",0Eh,0Fh,10h,11h,12h,13h,14h,15h,16h,17h,18h,19h,1Ah,1Bh,1Ch,1Dh,1Eh,1Fh,\"",
    " !\\\"#$%&'()*+,-./0123456789:;<=>?@",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_`",
    "abcdefghijklmnopqrstuvwxyz{|}~\",7Fh,",
    "80h,81h,82h,83h,84h,85h,86h,87h,88h,89h,8Ah,8Bh,8Ch,8Dh,8Eh,8Fh,",
    "90h,91h,92h,93h,94h,95h,96h,97h,98h,99h,9Ah,9Bh,9Ch,9Dh,9Eh,9Fh,",
    "A0h,A1h,A2h,A3h,A4h,A5h,A6h,A7h,A8h,A9h,AAh,ABh,ACh,ADh,AEh,AFh,",
    "B0h,B1h,B2h,B3h,B4h,B5h,B6h,B7h,B8h,B9h,BAh,BBh,BCh,BDh,BEh,BFh,",
    "C0h,C1h,C2h,C3h,C4h,C5h,C6h,C7h,C8h,C9h,CAh,CBh,CCh,CDh,CEh,CFh,",
    "D0h,D1h,D2h,D3h,D4h,D5h,D6h,D7h,D8h,D9h,DAh,DBh,DCh,DDh,DEh,DFh,",
    "E0h,E1h,E2h,E3h,E4h,E5h,E6h,E7h,E8h,E9h,EAh,EBh,ECh,EDh,EEh,EFh,",
    "F0h,F1h,F2h,F3h,F4h,F5h,F6h,F7h,F8h,F9h,FAh,FBh,FCh,FDh,FEh,FFh",
);

#[test]
fn test_get_string_rep_all_chars() {
    let all: Vec<u8> = (0..=255u8).collect();
    let buf = mb(false, &all);
    let actual = fixedlen_string().get_representation(&buf, &newset().charset(JavaCharset::us_ascii()), buf.get_length() as i32);
    assert_eq!(actual, ALL_CHARS_REPR, "String rep w/java US-ASCII charset mapping failed");
}

#[test]
fn test_encode_string_rep_all_chars() {
    let all: Vec<u8> = (0..=255u8).collect();
    assert_eq!(
        fixedlen_string()
            .encode_representation(ALL_CHARS_REPR, &mb(false, &[]), &newset().charset(JavaCharset::us_ascii()), -1)
            .unwrap(),
        all
    );
}

#[test]
fn test_get_string_rep_utf16_le() {
    let buf = mb(false, &[b'h', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0, 0, 0, b'x', 0, b'y', 0]);
    assert_eq!(fixed_utf16_string().get_representation(&buf, &newset(), buf.get_length() as i32), "u\"hello\\0xy\"");
}

#[test]
fn test_encode_string_rep_utf16_le() {
    assert_eq!(
        fixed_utf16_string().encode_representation("U\"hello\\0xy\"", &mb(false, &[]), &newset(), -1).unwrap(),
        vec![b'h', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0, 0, 0, b'x', 0, b'y', 0]
    );
}

#[test]
fn test_get_string_rep_utf16_ideographic() {
    // "ab" and 2 random ideographic characters cc01 & 1202 (big & little endian)
    let buf_be = mb(true, &[0, b'a', 0, b'b', 0xcc, 0x01, 0x12, 0x02]);
    let buf_le = mb(false, &[b'a', 0, b'b', 0, 0x01, 0xcc, 0x02, 0x12]);
    let len = 8;
    let dt = fixed_utf16_string();

    let e1 = "u\"ab\u{cc01}\u{1202}\"";
    assert_eq!(dt.get_representation(&buf_be, &newset(), len), e1);
    assert_eq!(dt.get_representation(&buf_le, &newset(), len), e1);

    assert_eq!(dt.get_representation(&buf_be, &newset().render(RenderEnum::ByteSeq), len), "u\"ab\",CCh,01h,12h,02h");
    assert_eq!(dt.get_representation(&buf_le, &newset().render(RenderEnum::ByteSeq), len), "u\"ab\",01h,CCh,02h,12h");

    let e3 = "u\"ab\\uCC01\\u1202\"";
    assert_eq!(dt.get_representation(&buf_be, &newset().render(RenderEnum::EscSeq), len), e3);
    assert_eq!(dt.get_representation(&buf_le, &newset().render(RenderEnum::EscSeq), len), e3);
}

#[test]
fn test_encode_string_rep_utf16_ideographic() {
    let bytes_be = vec![0, b'a', 0, b'b', 0xcc, 0x01, 0x12, 0x02];
    let bytes_le = vec![b'a', 0, b'b', 0, 0x01, 0xcc, 0x02, 0x12];
    let dt = fixed_utf16_string();

    let e1 = "u\"ab\u{cc01}\u{1202}\"";
    assert_eq!(dt.encode_representation(e1, &mb(true, &[]), &newset(), -1).unwrap(), bytes_be);
    assert_eq!(dt.encode_representation(e1, &mb(false, &[]), &newset(), -1).unwrap(), bytes_le);

    assert_eq!(dt.encode_representation("u\"ab\",CCh,01h,12h,02h", &mb(true, &[]), &newset(), -1).unwrap(), bytes_be);
    assert_eq!(dt.encode_representation("u\"ab\",01h,CCh,02h,12h", &mb(false, &[]), &newset(), -1).unwrap(), bytes_le);

    let e3 = "u\"ab\\uCC01\\u1202\"";
    assert_eq!(dt.encode_representation(e3, &mb(true, &[]), &newset(), -1).unwrap(), bytes_be);
    assert_eq!(dt.encode_representation(e3, &mb(false, &[]), &newset(), -1).unwrap(), bytes_le);
}

#[test]
fn test_get_string_rep_utf16_escapeseq_u() {
    // 2 utf-16 chars that create a single code point. Should get a 32bit escape seq even though
    // this is 16 bit string.
    let buf_be = mb(true, &[0, b'a', 0, b'b', 0xd8, 0x00, 0xdd, 0x12, 0, b'c']);
    assert_eq!(
        fixed_utf16_string().get_representation(&buf_be, &newset().render(RenderEnum::EscSeq), buf_be.get_length() as i32),
        "u\"ab\\U00010112c\""
    );
}

#[test]
fn test_encode_string_rep_utf16_escapeseq_u() {
    assert_eq!(
        fixed_utf16_string().encode_representation("u\"ab\\U00010112c\"", &mb(true, &[]), &newset(), -1).unwrap(),
        vec![0, b'a', 0, b'b', 0xd8, 0x00, 0xdd, 0x12, 0, b'c']
    );
}

#[test]
fn test_get_string_rep_utf32() {
    let mut bytes = Vec::new();
    for c in b"hello\0xy" {
        bytes.extend_from_slice(&[*c, 0, 0, 0]);
    }
    let buf = mb(false, &bytes);
    assert_eq!(fixed_utf32_string().get_representation(&buf, &newset(), buf.get_length() as i32), "U\"hello\\0xy\"");
}

#[test]
fn test_encode_string_rep_utf32() {
    let mut bytes = Vec::new();
    for c in b"hello\0xy" {
        bytes.extend_from_slice(&[*c, 0, 0, 0]);
    }
    assert_eq!(fixed_utf32_string().encode_representation("U\"hello\\0xy\"", &mb(false, &[]), &newset(), -1).unwrap(), bytes);
}

#[test]
fn test_get_string_rep_pascal_eof() {
    // Pascal string with length past end of mem should return error... string
    assert_eq!(pascal255_string().get_representation(&mb(false, &[5, b'h', b'e', b'l', b'l']), &newset(), 5), "??...");
}

// ---- StringDataInstance.isMissingNullTerminator() ----

#[test]
fn test_has_null_term() {
    let buf = mb(false, &[b'a', b'b', 0]);
    assert!(!mk_sdi(&term_string(), &buf, &newset(), buf.get_length() as i32).is_missing_null_terminator());
}

#[test]
fn test_has_null_term_eof() {
    let buf = mb(false, &[b'a', b'b']);
    assert!(mk_sdi(&term_string(), &buf, &newset(), buf.get_length() as i32).is_missing_null_terminator());
}

#[test]
fn test_has_null_term_utf16() {
    let buf = mb(false, &[b'a', 0, b'b', 0, 0, 0]);
    assert!(!mk_sdi(&term_utf16_string(), &buf, &newset(), buf.get_length() as i32).is_missing_null_terminator());
}

#[test]
fn test_has_null_term_fixed() {
    let buf = mb(false, &[b'a', b'b', b'c', 0, 0, 0]);
    assert!(mk_sdi(&fixedlen_string(), &buf, &newset(), 2).is_missing_null_terminator());
    assert!(mk_sdi(&fixedlen_string(), &buf, &newset(), 3).is_missing_null_terminator());
    assert!(!mk_sdi(&fixedlen_string(), &buf, &newset(), 4).is_missing_null_terminator());
}

#[test]
fn test_has_null_term_fixed_utf16() {
    let buf = mb(false, &[b'a', 0, b'b', 0, b'c', 0, 0, 0, 0, 0]);
    assert!(mk_sdi(&fixed_utf16_string(), &buf, &newset(), 4).is_missing_null_terminator());
    assert!(mk_sdi(&fixed_utf16_string(), &buf, &newset(), 6).is_missing_null_terminator());
    assert!(!mk_sdi(&fixed_utf16_string(), &buf, &newset(), 8).is_missing_null_terminator());
}

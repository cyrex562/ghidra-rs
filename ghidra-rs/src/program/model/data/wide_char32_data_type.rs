//! Port of `ghidra.program.model.data.WideChar32DataType`, promoted to a trait for the same
//! reason and following the same conventions as its sibling
//! [`WideChar16DataType`](super::wide_char16_data_type::WideChar16DataType) -- see that module's
//! docs for the general rationale (name-clash renaming, `getBuiltInSettingsDefinitions`
//! omitting `TranslationSettingsDefinition.TRANSLATION`, the two sibling `string_data_instance`
//! methods needing trait-qualified calls).
//!
//! The one behavioral difference from `WideChar16DataType`: `getValue(MemBuffer, Settings, int)`
//! returns a signed 32-bit [`Scalar`] (`new Scalar(32, buf.getInt(0), true)`, per a `// TODO: Not
//! sure how we should encode this` comment in the Java source, carried over here verbatim) rather
//! than a bare `char`-sized value, and `getValueClass` reports [`Scalar`]'s [`TypeId`] rather than
//! `Character`'s.
//!
//! `clone(DataTypeManager)` is left as a required method (no default), mirroring every other
//! `BuiltIn`-derived cut-point trait in this crate.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct).

use std::any::{Any, TypeId};

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::array_stringable::ArrayStringable;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::abstract_string_data_type::{
    DEFAULT_UNICODE_ABBREV_PREFIX, DEFAULT_UNICODE_LABEL, DEFAULT_UNICODE_LABEL_PREFIX,
};
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_type_with_charset::{
    CharacterValue, DataTypeEncodeError, DataTypeWithCharset,
};
use crate::program::model::data::endian_settings_definition::EndianSettingsDefinition;
use crate::program::model::data::render_unicode_settings_definition::RenderUnicodeSettingsDefinition;
use crate::program::model::mem::MemBuffer;
use crate::program::model::scalar::scalar::Scalar;
use crate::program::seam_stubs::CHARSET_UTF32;
use crate::util::string_utilities;

/// Provides a definition of a 32-bit "wide" character (UTF-32 code point) in a program.
///
/// Port of `ghidra.program.model.data.WideChar32DataType`. See the module docs (and
/// [`WideChar16DataType`](super::wide_char16_data_type::WideChar16DataType)'s docs) for what was
/// ported, added, and omitted.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait WideChar32DataType: BuiltIn + ArrayStringable + DataTypeWithCharset {
    /// Port of `WideChar32DataType.getLength()`, which overrides the default `DataType.getLength()`.
    fn wide_char32_length(&self) -> i32 {
        4
    }

    /// Port of `WideChar32DataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn wide_char32_description(&self) -> String {
        "Wide-Character (32-bit/UTF32)".to_string()
    }

    /// Port of `WideChar32DataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Always `"wchar32"`.
    fn wide_char32_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "wchar32".to_string()
    }

    /// Port of the protected `WideChar32DataType.getBuiltInSettingsDefinitions()`. See
    /// [`WideChar16DataType::wide_char16_built_in_settings_definitions`] for why
    /// `TranslationSettingsDefinition.TRANSLATION` is omitted.
    fn wide_char32_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        vec![
            Box::new(EndianSettingsDefinition::DEF),
            Box::new(RenderUnicodeSettingsDefinition::DEF),
        ]
    }

    /// Port of `WideChar32DataType.getRepresentation(MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.getRepresentation(...)`.
    fn wide_char32_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = length;
        DataTypeWithCharset::string_data_instance(self, settings, buf).get_char_representation()
    }

    /// Port of `WideChar32DataType.getValue(MemBuffer, Settings, int)`, which overrides the
    /// default `DataType.getValue(...)`. Boxes a signed 32-bit [`Scalar`] built from the raw
    /// 32-bit read (`new Scalar(32, buf.getInt(0), true)`), or `None` on a failed read.
    fn wide_char32_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        let raw = buf.get_int(0).ok()?;
        Some(Box::new(Scalar::new(32, raw as i64)) as Box<dyn Any>)
    }

    /// Port of `WideChar32DataType.isEncodable()`, which overrides the default
    /// `DataType.isEncodable()`. Always `true`.
    fn wide_char32_is_encodable(&self) -> bool {
        true
    }

    /// Port of `WideChar32DataType.encodeValue(Object, MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.encodeValue(...)`. Delegates to
    /// [`DataTypeWithCharset::encode_character_value`].
    fn wide_char32_encode_value(
        &self,
        value: CharacterValue,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let _ = length;
        self.encode_character_value(value, buf, settings)
    }

    /// Port of `WideChar32DataType.encodeRepresentation(String, MemBuffer, Settings, int)`, which
    /// overrides the default `DataType.encodeRepresentation(...)`. Delegates to
    /// [`DataTypeWithCharset::encode_character_representation`].
    fn wide_char32_encode_representation(
        &self,
        repr: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let _ = length;
        self.encode_character_representation(repr, buf, settings)
    }

    /// Port of `WideChar32DataType.getValueClass(Settings)`, which overrides the default
    /// `DataType.getValueClass(Settings)`. Returns the [`TypeId`] of [`Scalar`].
    fn wide_char32_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<Scalar>())
    }

    /// Port of `WideChar32DataType.getDefaultLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions)`, which overrides the default `DataType.getDefaultLabelPrefix(...)`.
    /// Builds `"WCHAR32_"` followed by the literal ASCII character (if in range) or its lowercase
    /// hex value plus `'h'`, or `"WCHAR32_??"` if the read fails.
    fn wide_char32_default_label_prefix_for_data(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        let _ = (settings, length, options);
        let mut out = String::from("WCHAR32_");
        match buf.get_int(0) {
            Ok(raw) => {
                let val = raw as u32;
                if string_utilities::is_ascii_code_point(val) {
                    out.push(val as u8 as char);
                } else {
                    out.push_str(&format!("{val:x}"));
                    out.push('h');
                }
            }
            Err(_) => out.push_str("??"),
        }
        Some(out)
    }

    /// Port of `WideChar32DataType.getDefaultLabelPrefix()`, which overrides the default
    /// `DataType.getDefaultLabelPrefix()`. Always `Some("WCHAR32")`.
    fn wide_char32_default_label_prefix(&self) -> Option<String> {
        Some("WCHAR32".to_string())
    }

    /// Port of `WideChar32DataType.getArrayDefaultLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions)`, which overrides the required
    /// [`ArrayStringable::get_array_default_label_prefix`]. A concrete `impl ArrayStringable for
    /// ...` should delegate `get_array_default_label_prefix` to this.
    fn wide_char32_array_default_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        let sdi = ArrayStringable::string_data_instance(self, buf, settings, len);
        Some(sdi.get_label(
            &format!("{DEFAULT_UNICODE_ABBREV_PREFIX}_"),
            DEFAULT_UNICODE_LABEL_PREFIX,
            DEFAULT_UNICODE_LABEL,
            options,
        ))
    }

    /// Port of `WideChar32DataType.getArrayDefaultOffcutLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions, int)`, which overrides the required
    /// [`ArrayStringable::get_array_default_offcut_label_prefix`]. A concrete `impl ArrayStringable
    /// for ...` should delegate `get_array_default_offcut_label_prefix` to this.
    fn wide_char32_array_default_offcut_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
        offcut_offset: i32,
    ) -> Option<String> {
        let sdi = ArrayStringable::string_data_instance(self, buf, settings, len);
        Some(sdi.get_offcut_label_string(
            &format!("{DEFAULT_UNICODE_ABBREV_PREFIX}_"),
            DEFAULT_UNICODE_LABEL_PREFIX,
            DEFAULT_UNICODE_LABEL,
            options,
            offcut_offset,
        ))
    }

    /// Port of `WideChar32DataType.getCharsetName(Settings)`, which overrides the default
    /// [`DataTypeWithCharset::get_charset_name`]. Always `"UTF-32"`.
    fn wide_char32_charset_name(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        CHARSET_UTF32.to_string()
    }

    /// Port of `WideChar32DataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn wide_char32_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn WideChar32DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DEFAULT as DEFAULT_DISPLAY_OPTIONS;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::mem::MemoryAccessException;
    use crate::util::UniversalID;
    use std::sync::{Arc, Weak};

    struct MockSettings;
    impl Settings for MockSettings {}

    struct FixedMemBuffer(Vec<u8>);
    impl MemBuffer for FixedMemBuffer {
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let mut n = 0;
            for (i, slot) in buf.iter_mut().enumerate() {
                match self.0.get(start + i) {
                    Some(&b) => {
                        *slot = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            n
        }
        fn is_big_endian(&self) -> bool {
            true
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.0
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
    }

    struct MockStringDataInstance {
        char_repr: String,
    }
    impl StringDataInstance for MockStringDataInstance {
        fn encode_replacement_from_char_value(&self, value: &[char]) -> Result<Vec<u8>, String> {
            Ok(value.iter().collect::<String>().into_bytes())
        }
        fn encode_replacement_from_char_representation(&self, repr: &str) -> Result<Vec<u8>, String> {
            Ok(repr.as_bytes().to_vec())
        }
        fn get_char_representation(&self) -> String {
            self.char_repr.clone()
        }
        fn get_label(
            &self,
            prefix_str: &str,
            _abbrev_prefix_str: &str,
            _default_str: &str,
            _options: &dyn DataTypeDisplayOptions,
        ) -> String {
            format!("{prefix_str}LABEL")
        }
        fn get_offcut_label_string(
            &self,
            prefix_str: &str,
            _abbrev_prefix_str: &str,
            _default_str: &str,
            _options: &dyn DataTypeDisplayOptions,
            byte_offset: i32,
        ) -> String {
            format!("{prefix_str}OFFCUT{byte_offset}")
        }
    }

    #[derive(Clone)]
    struct MockWideChar32;

    impl DataType for MockWideChar32 {
        fn get_name(&self) -> String {
            "wchar32".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.wide_char32_length()
        }
        fn get_description(&self) -> String {
            self.wide_char32_description()
        }
    }

    impl DataTypeImpl for MockWideChar32 {
        fn stored_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
        fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}
        fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
            None
        }
        fn set_stored_source_archive(&mut self, _archive: Option<Box<dyn SourceArchive>>) {}
        fn stored_universal_id(&self) -> UniversalID {
            UniversalID::new(0)
        }
        fn stored_last_change_time(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time(&mut self, _last_change_time: i64) {}
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, _last_change_time: i64) {}
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            Vec::new()
        }
        fn set_stored_parent_refs(&mut self, _parents: Vec<Weak<dyn DataType>>) {}
    }

    impl BuiltInDataType for MockWideChar32 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockWideChar32 {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl ArrayStringable for MockWideChar32 {
        fn has_string_value(&self, _settings: &dyn Settings) -> bool {
            true
        }
        fn string_data_instance(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _length: i32,
        ) -> Box<dyn StringDataInstance> {
            Box::new(MockStringDataInstance { char_repr: "'A'".to_string() })
        }
        fn get_array_default_label_prefix(
            &self,
            buf: &dyn MemBuffer,
            settings: &dyn Settings,
            len: i32,
            options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            self.wide_char32_array_default_label_prefix(buf, settings, len, options)
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            buf: &dyn MemBuffer,
            settings: &dyn Settings,
            len: i32,
            options: &dyn DataTypeDisplayOptions,
            offcut_offset: i32,
        ) -> Option<String> {
            self.wide_char32_array_default_offcut_label_prefix(buf, settings, len, options, offcut_offset)
        }
    }

    impl DataTypeWithCharset for MockWideChar32 {
        fn string_data_instance(
            &self,
            _settings: &dyn Settings,
            _buf: &dyn MemBuffer,
        ) -> Box<dyn StringDataInstance> {
            Box::new(MockStringDataInstance { char_repr: "'A'".to_string() })
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.wide_char32_charset_name(settings)
        }
    }

    impl WideChar32DataType for MockWideChar32 {
        fn wide_char32_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn WideChar32DataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockWideChar32;
        let dyn_dt: &dyn WideChar32DataType = &dt;
        assert_eq!(dyn_dt.wide_char32_length(), 4);
        assert_eq!(DataType::get_length(dyn_dt), 4);
        assert_eq!(dyn_dt.wide_char32_description(), "Wide-Character (32-bit/UTF32)");
        assert_eq!(dyn_dt.wide_char32_mnemonic(&MockSettings), "wchar32");
        assert!(dyn_dt.wide_char32_is_encodable());
        assert_eq!(
            dyn_dt.wide_char32_value_class(&MockSettings),
            Some(TypeId::of::<Scalar>())
        );
    }

    #[test]
    fn value_reads_a_signed_32_bit_scalar() {
        let dt = MockWideChar32;
        let buf = FixedMemBuffer(vec![0x00, 0x00, 0x00, 0x41]);
        let value = dt.wide_char32_value(&buf, &MockSettings, 4).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_signed_value(), 0x41);
    }

    #[test]
    fn value_is_none_when_the_read_fails() {
        let dt = MockWideChar32;
        let buf = FixedMemBuffer(vec![0x00]);
        assert!(dt.wide_char32_value(&buf, &MockSettings, 4).is_none());
    }

    #[test]
    fn representation_delegates_to_the_string_data_instance() {
        let dt = MockWideChar32;
        let buf = FixedMemBuffer(vec![0x00, 0x00, 0x00, 0x41]);
        assert_eq!(dt.wide_char32_representation(&buf, &MockSettings, 4), "'A'");
    }

    #[test]
    fn default_label_prefix_for_data_uses_ascii_char_when_in_range() {
        let dt = MockWideChar32;
        let buf = FixedMemBuffer(vec![0x00, 0x00, 0x00, 0x41]); // 'A'
        assert_eq!(
            dt.wide_char32_default_label_prefix_for_data(&buf, &MockSettings, 4, &DEFAULT_DISPLAY_OPTIONS),
            Some("WCHAR32_A".to_string())
        );
    }

    #[test]
    fn default_label_prefix_for_data_uses_hex_when_out_of_ascii_range() {
        let dt = MockWideChar32;
        let buf = FixedMemBuffer(vec![0x00, 0x01, 0x00, 0x00]); // 0x10000
        assert_eq!(
            dt.wide_char32_default_label_prefix_for_data(&buf, &MockSettings, 4, &DEFAULT_DISPLAY_OPTIONS),
            Some("WCHAR32_10000h".to_string())
        );
    }

    #[test]
    fn default_label_prefix_for_data_is_question_marks_when_the_read_fails() {
        let dt = MockWideChar32;
        let buf = FixedMemBuffer(vec![0x00]);
        assert_eq!(
            dt.wide_char32_default_label_prefix_for_data(&buf, &MockSettings, 4, &DEFAULT_DISPLAY_OPTIONS),
            Some("WCHAR32_??".to_string())
        );
    }

    #[test]
    fn default_label_prefix_no_arg_is_wchar32() {
        let dt = MockWideChar32;
        assert_eq!(dt.wide_char32_default_label_prefix(), Some("WCHAR32".to_string()));
    }

    #[test]
    fn array_default_label_prefix_uses_unicode_prefixes() {
        let dt = MockWideChar32;
        let buf = FixedMemBuffer(vec![0x00, 0x00, 0x00, 0x41]);
        assert_eq!(
            dt.wide_char32_array_default_label_prefix(&buf, &MockSettings, 4, &DEFAULT_DISPLAY_OPTIONS),
            Some("u_LABEL".to_string())
        );
    }

    #[test]
    fn array_default_offcut_label_prefix_passes_through_the_offset() {
        let dt = MockWideChar32;
        let buf = FixedMemBuffer(vec![0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x42]);
        assert_eq!(
            dt.wide_char32_array_default_offcut_label_prefix(&buf, &MockSettings, 8, &DEFAULT_DISPLAY_OPTIONS, 4),
            Some("u_OFFCUT4".to_string())
        );
    }

    #[test]
    fn charset_name_is_utf32() {
        let dt = MockWideChar32;
        assert_eq!(dt.wide_char32_charset_name(&MockSettings), "UTF-32");
    }

    #[test]
    fn encode_value_and_representation_delegate_to_data_type_with_charset() {
        let dt = MockWideChar32;
        let buf = FixedMemBuffer(vec![0x00, 0x00, 0x00, 0x41]);
        let encoded = dt
            .wide_char32_encode_value(CharacterValue::Char('a'), &buf, &MockSettings, 4)
            .unwrap();
        assert_eq!(encoded, b"a".to_vec());
        let encoded_repr = dt
            .wide_char32_encode_representation("z", &buf, &MockSettings, 4)
            .unwrap();
        assert_eq!(encoded_repr, b"z".to_vec());
    }

    #[test]
    fn clone_produces_an_equivalent_instance() {
        let dt = MockWideChar32;
        let cloned = dt.wide_char32_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }
}

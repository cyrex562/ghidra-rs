//! Port of `ghidra.program.model.data.WideChar16DataType`, promoted to a trait because its
//! established sibling ([`CharDataType`](super::char_data_type::CharDataType)) was ported the
//! same way and this class shares its shape.
//!
//! The Java class `extends BuiltIn implements ArrayStringable, DataTypeWithCharset`, so this
//! trait extends all three already-ported traits directly: [`BuiltIn`], [`ArrayStringable`], and
//! [`DataTypeWithCharset`].
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]/
//! [`BuiltIn`] (`getLength`, `getDescription`, `getMnemonic(Settings)`, `getBuiltInSettingsDefinitions`,
//! `getRepresentation`, `getValue`, `isEncodable`, `encodeValue`, `encodeRepresentation`,
//! `getValueClass`, `getDefaultLabelPrefix` (both overloads), `getCharsetName`). Rust does not
//! allow a subtrait to override a supertrait's same-named default without creating an ambiguous
//! call site, so -- mirroring [`CharDataType`]'s `char_*` convention -- those overrides are
//! exposed here under distinct `wide_char16_*` names. A concrete `impl DataType + BuiltIn +
//! ArrayStringable + DataTypeWithCharset for ...` should delegate to these.
//!
//! [`ArrayStringable::string_data_instance`] and [`DataTypeWithCharset::string_data_instance`] are
//! two *different* required methods (different signatures) that happen to share a name across
//! sibling supertraits; every call site here that needs one qualifies it with
//! `ArrayStringable::string_data_instance(...)` / `DataTypeWithCharset::string_data_instance(...)`
//! to avoid the same "ambiguous same-named method" problem described above.
//!
//! `getBuiltInSettingsDefinitions()` returns `WideCharDataType.DEFAULT_WIDE_CHAR_SETTINGS` in
//! Java (`{ EndianSettingsDefinition.DEF, RenderUnicodeSettingsDefinition.RENDER,
//! TranslationSettingsDefinition.TRANSLATION }`); [`WideCharDataType`] itself is not yet ported,
//! so -- mirroring [`CharDataType::char_settings_definitions`]'s precedent for the same situation
//! -- [`wide_char16_built_in_settings_definitions`](WideChar16DataType::wide_char16_built_in_settings_definitions)
//! reproduces just the two settings definitions directly, omitting
//! `TranslationSettingsDefinition.TRANSLATION` because the ported
//! [`TranslationSettingsDefinition`](super::translation_settings_definition::TranslationSettingsDefinition)
//! does not yet implement [`SettingsDefinition`] itself (only its internal
//! `JavaEnumSettingsDefinition` does).
//!
//! `getValue(MemBuffer, Settings, int)` reads an unsigned 16-bit code unit (`Character`), which
//! Java gets via `buf.getUnsignedShort(0)`; ported here via [`MemBuffer::get_short`] reinterpreted
//! as `u16`, matching [`SegmentedCodePointerDataType`](super::segmented_code_pointer_data_type)'s
//! precedent of doing the unsigned mask by hand rather than needing a new `MemBuffer` method.
//! Both this and `getDefaultLabelPrefix(MemBuffer, Settings, int, DataTypeDisplayOptions)`
//! collapse a `MemoryAccessException` to `None`/`"??"` respectively, matching the Java `catch
//! (MemoryAccessException e)` blocks doing nothing (or appending `"??"`) and falling through.
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
use crate::program::seam_stubs::CHARSET_UTF16;
use crate::util::string_utilities;

/// Provides a definition of a 16-bit "wide" character (UTF-16 code unit) in a program.
///
/// Port of `ghidra.program.model.data.WideChar16DataType`. See the module docs for what was
/// ported, added, and omitted.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait WideChar16DataType: BuiltIn + ArrayStringable + DataTypeWithCharset {
    /// Port of `WideChar16DataType.getLength()`, which overrides the default `DataType.getLength()`.
    fn wide_char16_length(&self) -> i32 {
        2
    }

    /// Port of `WideChar16DataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn wide_char16_description(&self) -> String {
        "Wide-Character (16-bit/UTF16)".to_string()
    }

    /// Port of `WideChar16DataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Always `"wchar16"`.
    fn wide_char16_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "wchar16".to_string()
    }

    /// Port of the protected `WideChar16DataType.getBuiltInSettingsDefinitions()`. See the module
    /// docs for why `TranslationSettingsDefinition.TRANSLATION` is omitted.
    fn wide_char16_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        vec![
            Box::new(EndianSettingsDefinition::DEF),
            Box::new(RenderUnicodeSettingsDefinition::DEF),
        ]
    }

    /// Port of `WideChar16DataType.getRepresentation(MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.getRepresentation(...)`.
    fn wide_char16_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = length;
        DataTypeWithCharset::string_data_instance(self, settings, buf).get_char_representation()
    }

    /// Port of `WideChar16DataType.getValue(MemBuffer, Settings, int)`, which overrides the
    /// default `DataType.getValue(...)`. Boxes the decoded unsigned 16-bit code unit (`u16`,
    /// standing in for `Character`), or `None` on a failed read. See the module docs for the
    /// exception this collapses.
    fn wide_char16_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        let value = buf.get_short(0).ok()? as u16;
        Some(Box::new(value) as Box<dyn Any>)
    }

    /// Port of `WideChar16DataType.isEncodable()`, which overrides the default
    /// `DataType.isEncodable()`. Always `true`.
    fn wide_char16_is_encodable(&self) -> bool {
        true
    }

    /// Port of `WideChar16DataType.encodeValue(Object, MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.encodeValue(...)`. Delegates to
    /// [`DataTypeWithCharset::encode_character_value`].
    fn wide_char16_encode_value(
        &self,
        value: CharacterValue,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let _ = length;
        self.encode_character_value(value, buf, settings)
    }

    /// Port of `WideChar16DataType.encodeRepresentation(String, MemBuffer, Settings, int)`, which
    /// overrides the default `DataType.encodeRepresentation(...)`. Delegates to
    /// [`DataTypeWithCharset::encode_character_representation`].
    fn wide_char16_encode_representation(
        &self,
        repr: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let _ = length;
        self.encode_character_representation(repr, buf, settings)
    }

    /// Port of `WideChar16DataType.getValueClass(Settings)`, which overrides the default
    /// `DataType.getValueClass(Settings)`. Returns the [`TypeId`] of `u16`, standing in for
    /// `Character.class`.
    fn wide_char16_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<u16>())
    }

    /// Port of `WideChar16DataType.getDefaultLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions)`, which overrides the default `DataType.getDefaultLabelPrefix(...)`.
    /// Builds `"WCHAR16_"` followed by the literal ASCII character (if in range) or its lowercase
    /// hex value plus `'h'`, or `"WCHAR16_??"` if the read fails.
    fn wide_char16_default_label_prefix_for_data(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        let _ = (settings, length, options);
        let mut out = String::from("WCHAR16_");
        match buf.get_short(0) {
            Ok(raw) => {
                let val = raw as u16 as u32;
                if string_utilities::is_ascii_code_point(val) {
                    if let Some(c) = char::from_u32(val) {
                        out.push(c);
                    }
                } else {
                    out.push_str(&format!("{val:x}"));
                    out.push('h');
                }
            }
            Err(_) => out.push_str("??"),
        }
        Some(out)
    }

    /// Port of `WideChar16DataType.getDefaultLabelPrefix()`, which overrides the default
    /// `DataType.getDefaultLabelPrefix()`. Always `Some("WCHAR16")`.
    fn wide_char16_default_label_prefix(&self) -> Option<String> {
        Some("WCHAR16".to_string())
    }

    /// Port of `WideChar16DataType.getArrayDefaultLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions)`, which overrides the required
    /// [`ArrayStringable::get_array_default_label_prefix`]. A concrete `impl ArrayStringable for
    /// ...` should delegate `get_array_default_label_prefix` to this.
    fn wide_char16_array_default_label_prefix(
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

    /// Port of `WideChar16DataType.getArrayDefaultOffcutLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions, int)`, which overrides the required
    /// [`ArrayStringable::get_array_default_offcut_label_prefix`]. A concrete `impl ArrayStringable
    /// for ...` should delegate `get_array_default_offcut_label_prefix` to this.
    fn wide_char16_array_default_offcut_label_prefix(
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

    /// Port of `WideChar16DataType.getCharsetName(Settings)`, which overrides the default
    /// [`DataTypeWithCharset::get_charset_name`]. Always `"UTF-16"`.
    fn wide_char16_charset_name(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        CHARSET_UTF16.to_string()
    }

    /// Port of `WideChar16DataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn wide_char16_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn WideChar16DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
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
    struct MockWideChar16;

    impl DataType for MockWideChar16 {
        fn get_name(&self) -> String {
            "wchar16".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.wide_char16_length()
        }
        fn get_description(&self) -> String {
            self.wide_char16_description()
        }
    }

    impl DataTypeImpl for MockWideChar16 {
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

    impl BuiltInDataType for MockWideChar16 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockWideChar16 {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl ArrayStringable for MockWideChar16 {
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
            self.wide_char16_array_default_label_prefix(buf, settings, len, options)
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            buf: &dyn MemBuffer,
            settings: &dyn Settings,
            len: i32,
            options: &dyn DataTypeDisplayOptions,
            offcut_offset: i32,
        ) -> Option<String> {
            self.wide_char16_array_default_offcut_label_prefix(buf, settings, len, options, offcut_offset)
        }
    }

    impl DataTypeWithCharset for MockWideChar16 {
        fn string_data_instance(
            &self,
            _settings: &dyn Settings,
            _buf: &dyn MemBuffer,
        ) -> Box<dyn StringDataInstance> {
            Box::new(MockStringDataInstance { char_repr: "'A'".to_string() })
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.wide_char16_charset_name(settings)
        }
    }

    impl WideChar16DataType for MockWideChar16 {
        fn wide_char16_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn WideChar16DataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockWideChar16;
        let dyn_dt: &dyn WideChar16DataType = &dt;
        assert_eq!(dyn_dt.wide_char16_length(), 2);
        assert_eq!(DataType::get_length(dyn_dt), 2);
        assert_eq!(dyn_dt.wide_char16_description(), "Wide-Character (16-bit/UTF16)");
        assert_eq!(dyn_dt.wide_char16_mnemonic(&MockSettings), "wchar16");
        assert!(dyn_dt.wide_char16_is_encodable());
        assert_eq!(
            dyn_dt.wide_char16_value_class(&MockSettings),
            Some(TypeId::of::<u16>())
        );
    }

    #[test]
    fn built_in_settings_definitions_include_endian_and_render_unicode() {
        let dt = MockWideChar16;
        let names: Vec<String> = dt
            .wide_char16_built_in_settings_definitions()
            .iter()
            .map(|d| d.get_name())
            .collect();
        assert!(names.iter().any(|n| n == "Endian"));
        assert!(names.iter().any(|n| n == "Render non-ASCII Unicode"));
    }

    #[test]
    fn value_reads_unsigned_short_as_a_character_code_unit() {
        let dt = MockWideChar16;
        let buf = FixedMemBuffer(vec![0xFF, 0xFF]);
        let value = dt.wide_char16_value(&buf, &MockSettings, 2).unwrap();
        assert_eq!(*value.downcast_ref::<u16>().unwrap(), 0xFFFFu16);
    }

    #[test]
    fn value_is_none_when_the_read_fails() {
        let dt = MockWideChar16;
        let buf = FixedMemBuffer(vec![0x00]);
        assert!(dt.wide_char16_value(&buf, &MockSettings, 2).is_none());
    }

    #[test]
    fn representation_delegates_to_the_string_data_instance() {
        let dt = MockWideChar16;
        let buf = FixedMemBuffer(vec![0x00, 0x41]);
        assert_eq!(dt.wide_char16_representation(&buf, &MockSettings, 2), "'A'");
    }

    #[test]
    fn default_label_prefix_for_data_uses_ascii_char_when_in_range() {
        let dt = MockWideChar16;
        let buf = FixedMemBuffer(vec![0x00, 0x41]); // 0x0041 = 'A'
        assert_eq!(
            dt.wide_char16_default_label_prefix_for_data(&buf, &MockSettings, 2, &DEFAULT_DISPLAY_OPTIONS),
            Some("WCHAR16_A".to_string())
        );
    }

    #[test]
    fn default_label_prefix_for_data_uses_hex_when_out_of_ascii_range() {
        let dt = MockWideChar16;
        let buf = FixedMemBuffer(vec![0x30, 0x39]); // 0x3039 = 12345, not in 0x20..=0x7f
        assert_eq!(
            dt.wide_char16_default_label_prefix_for_data(&buf, &MockSettings, 2, &DEFAULT_DISPLAY_OPTIONS),
            Some("WCHAR16_3039h".to_string())
        );
    }

    #[test]
    fn default_label_prefix_for_data_is_question_marks_when_the_read_fails() {
        let dt = MockWideChar16;
        let buf = FixedMemBuffer(vec![0x00]);
        assert_eq!(
            dt.wide_char16_default_label_prefix_for_data(&buf, &MockSettings, 2, &DEFAULT_DISPLAY_OPTIONS),
            Some("WCHAR16_??".to_string())
        );
    }

    #[test]
    fn default_label_prefix_no_arg_is_wchar16() {
        let dt = MockWideChar16;
        assert_eq!(dt.wide_char16_default_label_prefix(), Some("WCHAR16".to_string()));
    }

    #[test]
    fn array_default_label_prefix_uses_unicode_prefixes() {
        let dt = MockWideChar16;
        let buf = FixedMemBuffer(vec![0x00, 0x41]);
        assert_eq!(
            dt.wide_char16_array_default_label_prefix(&buf, &MockSettings, 2, &DEFAULT_DISPLAY_OPTIONS),
            Some("u_LABEL".to_string())
        );
    }

    #[test]
    fn array_default_offcut_label_prefix_passes_through_the_offset() {
        let dt = MockWideChar16;
        let buf = FixedMemBuffer(vec![0x00, 0x41, 0x00, 0x42]);
        assert_eq!(
            dt.wide_char16_array_default_offcut_label_prefix(&buf, &MockSettings, 4, &DEFAULT_DISPLAY_OPTIONS, 2),
            Some("u_OFFCUT2".to_string())
        );
    }

    #[test]
    fn charset_name_is_utf16() {
        let dt = MockWideChar16;
        assert_eq!(dt.wide_char16_charset_name(&MockSettings), "UTF-16");
    }

    #[test]
    fn encode_value_and_representation_delegate_to_data_type_with_charset() {
        let dt = MockWideChar16;
        let buf = FixedMemBuffer(vec![0x00, 0x41]);
        let encoded = dt
            .wide_char16_encode_value(CharacterValue::Char('a'), &buf, &MockSettings, 2)
            .unwrap();
        assert_eq!(encoded, b"a".to_vec());
        let encoded_repr = dt
            .wide_char16_encode_representation("z", &buf, &MockSettings, 2)
            .unwrap();
        assert_eq!(encoded_repr, b"z".to_vec());
    }

    #[test]
    fn clone_produces_an_equivalent_instance() {
        let dt = MockWideChar16;
        let cloned = dt.wide_char16_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }
}

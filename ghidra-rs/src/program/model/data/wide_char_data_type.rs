//! Port of `ghidra.program.model.data.WideCharDataType`, following the same conventions as its
//! siblings [`WideChar16DataType`](super::wide_char16_data_type::WideChar16DataType) and
//! [`WideChar32DataType`](super::wide_char32_data_type::WideChar32DataType) -- see that first
//! module's docs for the general rationale (name-clash renaming, `getBuiltInSettingsDefinitions`
//! omitting `TranslationSettingsDefinition.TRANSLATION`, the two sibling `string_data_instance`
//! methods needing trait-qualified calls).
//!
//! Unlike those two fixed-size siblings, `WideCharDataType.getLength()` is *runtime-configurable*:
//! it returns `getDataOrganization().getWideCharSize()` rather than a hardcoded `2` or `4`, mirroring
//! a compiler's actual `wchar_t` size (2 on Windows, 4 almost everywhere else). Every method here
//! that switches on the character size (`getValue`, `getValueClass`, `getCharsetName`) therefore
//! switches on the *computed* [`WideCharDataType::wide_char_length`] rather than a compile-time
//! constant, falling through to a "neither 2 nor 4" branch that Java expresses as a missing
//! `switch` case (implicitly falling out to `return null`/`return
//! StringDataInstance.DEFAULT_CHARSET_NAME`); [`getDefaultLabelPrefix(MemBuffer, Settings, int,
//! DataTypeDisplayOptions)`][wide_char_default_label_prefix_for_data], however, switches on the
//! *passed-in* `length` parameter instead (matching Java precisely -- this one method never calls
//! `getLength()` at all).
//!
//! `getCTypeDeclaration(DataOrganization)` is overridden directly here (not inherited from
//! [`BuiltIn`]'s own generic version), calling the protected `getCTypeDeclaration(String, int,
//! boolean, DataOrganization, boolean)` helper
//! ([`BuiltIn::get_c_type_declaration_len`](super::built_in::BuiltIn::get_c_type_declaration_len))
//! directly with `getName()`, the computed wide-char size, `signed = true`, and `useDefine =
//! false` -- it does not perform `BuiltIn.getCTypeDeclaration(DataOrganization)`'s
//! `Dynamic`/`FactoryDataType` check, since `WideCharDataType` can never be either.
//!
//! `getValue(MemBuffer, Settings, int)` immediately overwrites its `length` parameter with
//! `getLength()` in Java (`length = getLength();`) before an unused local afterwards; ported here
//! by simply ignoring the `length` parameter and computing [`Self::wide_char_length`] directly,
//! which is behaviorally identical.
//!
//! `hasLanguageDependantLength()` (overriding the default `DataType.hasLanguageDependantLength()`,
//! always `false`) is exposed as [`Self::wide_char_has_language_dependant_length`], always `true`,
//! for the same "same-named supertrait default" reason as every other override here.
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
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_type_with_charset::{
    CharacterValue, DataTypeEncodeError, DataTypeWithCharset,
};
use crate::program::model::data::endian_settings_definition::EndianSettingsDefinition;
use crate::program::model::data::render_unicode_settings_definition::RenderUnicodeSettingsDefinition;
use crate::program::model::data::string_data_instance::DEFAULT_CHARSET_NAME;
use crate::program::model::mem::MemBuffer;
use crate::program::model::scalar::scalar::Scalar;
use crate::program::seam_stubs::{CHARSET_UTF16, CHARSET_UTF32};
use crate::util::string_utilities;

/// Provides a definition of a primitive wide-character in a program, whose size is determined by
/// the data organization of the associated data type manager (2 bytes on Windows, 4 bytes almost
/// everywhere else).
///
/// Port of `ghidra.program.model.data.WideCharDataType`. See the module docs for what was ported,
/// added, and omitted.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait WideCharDataType: BuiltIn + ArrayStringable + DataTypeWithCharset {
    /// Port of `WideCharDataType.getLength()`, which overrides the default `DataType.getLength()`.
    /// Unlike [`WideChar16DataType::wide_char16_length`](super::wide_char16_data_type::WideChar16DataType::wide_char16_length)/
    /// [`WideChar32DataType::wide_char32_length`](super::wide_char32_data_type::WideChar32DataType::wide_char32_length),
    /// this is runtime-configurable via [`DataType::get_data_organization`](crate::program::model::data::data_type::DataType::get_data_organization).
    fn wide_char_length(&self) -> i32 {
        self.get_data_organization().get_wide_char_size()
    }

    /// Port of `WideCharDataType.hasLanguageDependantLength()`, exposed under a distinct name
    /// since [`DataType::has_language_dependant_length`](crate::program::model::data::data_type::DataType::has_language_dependant_length)
    /// already provides a (`false`) default. Always `true`.
    fn wide_char_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Port of `WideCharDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn wide_char_description(&self) -> String {
        "Wide-Character (compiler-specific size)".to_string()
    }

    /// Port of the protected `WideCharDataType.getBuiltInSettingsDefinitions()`. See
    /// [`WideChar16DataType`](super::wide_char16_data_type::WideChar16DataType)'s module docs for
    /// why `TranslationSettingsDefinition.TRANSLATION` is omitted.
    fn wide_char_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        vec![
            Box::new(EndianSettingsDefinition::DEF),
            Box::new(RenderUnicodeSettingsDefinition::DEF),
        ]
    }

    /// Port of `WideCharDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)` directly (not via
    /// `BuiltIn`'s own generic override -- see the module docs for why). A concrete `impl
    /// BuiltInDataType for ...` should delegate `get_c_type_declaration` to this.
    fn wide_char_c_type_declaration(
        &self,
        data_organization: Option<&dyn DataOrganization>,
    ) -> Option<String> {
        data_organization.map(|org| {
            self.get_c_type_declaration_len(&self.get_name(), org.get_wide_char_size(), true, org, false)
        })
    }

    /// Port of `WideCharDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Always `"wchar_t"`.
    fn wide_char_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "wchar_t".to_string()
    }

    /// Port of `WideCharDataType.getRepresentation(MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.getRepresentation(...)`.
    fn wide_char_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = length;
        DataTypeWithCharset::string_data_instance(self, settings, buf).get_char_representation()
    }

    /// Port of `WideCharDataType.getValue(MemBuffer, Settings, int)`, which overrides the default
    /// `DataType.getValue(...)`. The `length` parameter is ignored (matching Java's own
    /// `length = getLength();` overwrite -- see the module docs); boxes an unsigned 16-bit code
    /// unit (`u16`, standing in for `Character`) when the computed length is 2, a signed 32-bit
    /// [`Scalar`] when it is 4, or `None` otherwise (including on a failed read).
    fn wide_char_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        match self.wide_char_length() {
            2 => {
                let value = buf.get_short(0).ok()? as u16;
                Some(Box::new(value) as Box<dyn Any>)
            }
            4 => {
                let raw = buf.get_int(0).ok()?;
                Some(Box::new(Scalar::new(32, raw as i64)) as Box<dyn Any>)
            }
            _ => None,
        }
    }

    /// Port of `WideCharDataType.isEncodable()`, which overrides the default
    /// `DataType.isEncodable()`. Always `true`.
    fn wide_char_is_encodable(&self) -> bool {
        true
    }

    /// Port of `WideCharDataType.encodeValue(Object, MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.encodeValue(...)`. Delegates to
    /// [`DataTypeWithCharset::encode_character_value`].
    fn wide_char_encode_value(
        &self,
        value: CharacterValue,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let _ = length;
        self.encode_character_value(value, buf, settings)
    }

    /// Port of `WideCharDataType.encodeRepresentation(String, MemBuffer, Settings, int)`, which
    /// overrides the default `DataType.encodeRepresentation(...)`. Delegates to
    /// [`DataTypeWithCharset::encode_character_representation`].
    fn wide_char_encode_representation(
        &self,
        repr: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let _ = length;
        self.encode_character_representation(repr, buf, settings)
    }

    /// Port of `WideCharDataType.getValueClass(Settings)`, which overrides the default
    /// `DataType.getValueClass(Settings)`. Returns the [`TypeId`] of `u16` (standing in for
    /// `Character.class`) when the computed length is 2, of [`Scalar`] when it is 4, or `None`
    /// otherwise.
    fn wide_char_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        match self.wide_char_length() {
            2 => Some(TypeId::of::<u16>()),
            4 => Some(TypeId::of::<Scalar>()),
            _ => None,
        }
    }

    /// Port of `WideCharDataType.getDefaultLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions)`, which overrides the default `DataType.getDefaultLabelPrefix(...)`.
    /// Unlike every other method here, this one switches on the *passed-in* `length` parameter
    /// rather than [`Self::wide_char_length`], matching Java precisely. Builds `"WCHAR_"` followed
    /// by the literal ASCII character (if in range) or its lowercase hex value plus `'h'`, or
    /// `"WCHAR_??"` if `length` is neither 2 nor 4, or if the read fails.
    fn wide_char_default_label_prefix_for_data(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        let _ = (settings, options);
        if length != 2 && length != 4 {
            return Some("WCHAR_??".to_string());
        }

        let mut out = String::from("WCHAR_");
        let read = if length == 2 {
            buf.get_short(0).map(|raw| raw as u16 as u32)
        } else {
            buf.get_int(0).map(|raw| raw as u32)
        };
        match read {
            Ok(val) => {
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

    /// Port of `WideCharDataType.getDefaultLabelPrefix()`, which overrides the default
    /// `DataType.getDefaultLabelPrefix()`. Always `Some("WCHAR")`.
    fn wide_char_default_label_prefix(&self) -> Option<String> {
        Some("WCHAR".to_string())
    }

    /// Port of `WideCharDataType.getArrayDefaultLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions)`, which overrides the required
    /// [`ArrayStringable::get_array_default_label_prefix`]. A concrete `impl ArrayStringable for
    /// ...` should delegate `get_array_default_label_prefix` to this.
    fn wide_char_array_default_label_prefix(
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

    /// Port of `WideCharDataType.getArrayDefaultOffcutLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions, int)`, which overrides the required
    /// [`ArrayStringable::get_array_default_offcut_label_prefix`]. A concrete `impl ArrayStringable
    /// for ...` should delegate `get_array_default_offcut_label_prefix` to this.
    fn wide_char_array_default_offcut_label_prefix(
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

    /// Port of `WideCharDataType.getCharsetName(Settings)`, which overrides the default
    /// [`DataTypeWithCharset::get_charset_name`]. `"UTF-16"` when the computed length is 2,
    /// `"UTF-32"` when it is 4, or [`DEFAULT_CHARSET_NAME`] (`"US-ASCII"`) otherwise.
    fn wide_char_charset_name(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        match self.wide_char_length() {
            2 => CHARSET_UTF16.to_string(),
            4 => CHARSET_UTF32.to_string(),
            _ => DEFAULT_CHARSET_NAME.to_string(),
        }
    }

    /// Port of `WideCharDataType.clone(DataTypeManager)`. Left as a required method (no default);
    /// see [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn wide_char_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn WideCharDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
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

    struct MockDataOrganization {
        wide_char_size: i32,
    }
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            8
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            true
        }
        fn get_char_size(&self) -> i32 {
            1
        }
        fn get_wide_char_size(&self) -> i32 {
            self.wide_char_size
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            8
        }
        fn get_long_long_size(&self) -> i32 {
            8
        }
        fn get_float_size(&self) -> i32 {
            4
        }
        fn get_double_size(&self) -> i32 {
            8
        }
        fn get_long_double_size(&self) -> i32 {
            8
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            0
        }
        fn get_machine_alignment(&self) -> i32 {
            8
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            8
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            1
        }
        fn get_bit_field_packing(
            &self,
        ) -> Box<dyn crate::program::model::data::bit_field_packing::BitFieldPacking> {
            Box::new(crate::program::model::data::bit_field_packing_impl::BitFieldPackingImpl::new())
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, size: i32, signed: bool) -> String {
            format!("{}int{}", if signed { "" } else { "unsigned " }, size * 8)
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

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
    struct MockWideChar {
        wide_char_size: i32,
    }

    impl DataType for MockWideChar {
        fn get_name(&self) -> String {
            "wchar_t".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.wide_char_length()
        }
        fn get_description(&self) -> String {
            self.wide_char_description()
        }
        fn has_language_dependant_length(&self) -> bool {
            self.wide_char_has_language_dependant_length()
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization { wide_char_size: self.wide_char_size })
        }
    }

    impl DataTypeImpl for MockWideChar {
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

    impl BuiltInDataType for MockWideChar {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            self.wide_char_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockWideChar {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl ArrayStringable for MockWideChar {
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
            self.wide_char_array_default_label_prefix(buf, settings, len, options)
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            buf: &dyn MemBuffer,
            settings: &dyn Settings,
            len: i32,
            options: &dyn DataTypeDisplayOptions,
            offcut_offset: i32,
        ) -> Option<String> {
            self.wide_char_array_default_offcut_label_prefix(buf, settings, len, options, offcut_offset)
        }
    }

    impl DataTypeWithCharset for MockWideChar {
        fn string_data_instance(
            &self,
            _settings: &dyn Settings,
            _buf: &dyn MemBuffer,
        ) -> Box<dyn StringDataInstance> {
            Box::new(MockStringDataInstance { char_repr: "'A'".to_string() })
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.wide_char_charset_name(settings)
        }
    }

    impl WideCharDataType for MockWideChar {
        fn wide_char_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn WideCharDataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    fn windows_wchar() -> MockWideChar {
        MockWideChar { wide_char_size: 2 }
    }

    fn unix_wchar() -> MockWideChar {
        MockWideChar { wide_char_size: 4 }
    }

    #[test]
    fn length_is_driven_by_data_organization() {
        assert_eq!(windows_wchar().wide_char_length(), 2);
        assert_eq!(unix_wchar().wide_char_length(), 4);
        assert_eq!(DataType::get_length(&windows_wchar()), 2);
        assert_eq!(DataType::get_length(&unix_wchar()), 4);
    }

    #[test]
    fn has_language_dependant_length_is_true() {
        assert!(windows_wchar().wide_char_has_language_dependant_length());
        assert!(DataType::has_language_dependant_length(&windows_wchar()));
    }

    #[test]
    fn description_and_mnemonic() {
        let dt = windows_wchar();
        assert_eq!(dt.wide_char_description(), "Wide-Character (compiler-specific size)");
        assert_eq!(dt.wide_char_mnemonic(&MockSettings), "wchar_t");
    }

    #[test]
    fn built_in_settings_definitions_include_endian_and_render_unicode() {
        let dt = windows_wchar();
        let names: Vec<String> = dt
            .wide_char_built_in_settings_definitions()
            .iter()
            .map(|d| d.get_name())
            .collect();
        assert!(names.iter().any(|n| n == "Endian"));
        assert!(names.iter().any(|n| n == "Render non-ASCII Unicode"));
    }

    #[test]
    fn value_reads_unsigned_short_when_length_is_two() {
        let dt = windows_wchar();
        let buf = FixedMemBuffer(vec![0xFF, 0xFF]);
        let value = dt.wide_char_value(&buf, &MockSettings, 999).unwrap();
        assert_eq!(*value.downcast_ref::<u16>().unwrap(), 0xFFFFu16);
    }

    #[test]
    fn value_reads_scalar_when_length_is_four() {
        let dt = unix_wchar();
        let buf = FixedMemBuffer(vec![0x00, 0x00, 0x00, 0x41]);
        let value = dt.wide_char_value(&buf, &MockSettings, 999).unwrap();
        assert_eq!(*value.downcast_ref::<Scalar>().unwrap(), Scalar::new(32, 0x41));
    }

    #[test]
    fn value_is_none_when_the_read_fails() {
        let dt = windows_wchar();
        let buf = FixedMemBuffer(vec![0x00]);
        assert!(dt.wide_char_value(&buf, &MockSettings, 2).is_none());
    }

    #[test]
    fn value_class_matches_computed_length() {
        assert_eq!(windows_wchar().wide_char_value_class(&MockSettings), Some(TypeId::of::<u16>()));
        assert_eq!(unix_wchar().wide_char_value_class(&MockSettings), Some(TypeId::of::<Scalar>()));
    }

    #[test]
    fn charset_name_matches_computed_length() {
        assert_eq!(windows_wchar().wide_char_charset_name(&MockSettings), "UTF-16");
        assert_eq!(unix_wchar().wide_char_charset_name(&MockSettings), "UTF-32");
    }

    #[test]
    fn representation_delegates_to_the_string_data_instance() {
        let dt = windows_wchar();
        let buf = FixedMemBuffer(vec![0x00, 0x41]);
        assert_eq!(dt.wide_char_representation(&buf, &MockSettings, 2), "'A'");
    }

    #[test]
    fn default_label_prefix_for_data_uses_the_passed_length_not_the_computed_one() {
        // `dt` reports a computed length of 4 (unix), but the *passed* `length` of 2 should
        // still drive a 2-byte read, matching Java's method (which never calls `getLength()`
        // here at all).
        let dt = unix_wchar();
        let buf = FixedMemBuffer(vec![0x00, 0x41]); // 0x0041 = 'A'
        assert_eq!(
            dt.wide_char_default_label_prefix_for_data(&buf, &MockSettings, 2, &DEFAULT_DISPLAY_OPTIONS),
            Some("WCHAR_A".to_string())
        );
    }

    #[test]
    fn default_label_prefix_for_data_uses_hex_when_out_of_ascii_range() {
        let dt = windows_wchar();
        let buf = FixedMemBuffer(vec![0x30, 0x39]); // 0x3039 = 12345, not in 0x20..=0x7f
        assert_eq!(
            dt.wide_char_default_label_prefix_for_data(&buf, &MockSettings, 2, &DEFAULT_DISPLAY_OPTIONS),
            Some("WCHAR_3039h".to_string())
        );
    }

    #[test]
    fn default_label_prefix_for_data_is_question_marks_when_the_read_fails() {
        let dt = windows_wchar();
        let buf = FixedMemBuffer(vec![0x00]);
        assert_eq!(
            dt.wide_char_default_label_prefix_for_data(&buf, &MockSettings, 2, &DEFAULT_DISPLAY_OPTIONS),
            Some("WCHAR_??".to_string())
        );
    }

    #[test]
    fn default_label_prefix_for_data_rejects_lengths_other_than_two_or_four() {
        let dt = windows_wchar();
        let buf = FixedMemBuffer(vec![0x41, 0x41, 0x41]);
        assert_eq!(
            dt.wide_char_default_label_prefix_for_data(&buf, &MockSettings, 3, &DEFAULT_DISPLAY_OPTIONS),
            Some("WCHAR_??".to_string())
        );
    }

    #[test]
    fn default_label_prefix_no_arg_is_wchar() {
        assert_eq!(windows_wchar().wide_char_default_label_prefix(), Some("WCHAR".to_string()));
    }

    #[test]
    fn array_default_label_prefix_uses_unicode_prefixes() {
        let dt = windows_wchar();
        let buf = FixedMemBuffer(vec![0x00, 0x41]);
        assert_eq!(
            dt.wide_char_array_default_label_prefix(&buf, &MockSettings, 2, &DEFAULT_DISPLAY_OPTIONS),
            Some("u_LABEL".to_string())
        );
    }

    #[test]
    fn array_default_offcut_label_prefix_passes_through_the_offset() {
        let dt = windows_wchar();
        let buf = FixedMemBuffer(vec![0x00, 0x41, 0x00, 0x42]);
        assert_eq!(
            dt.wide_char_array_default_offcut_label_prefix(&buf, &MockSettings, 4, &DEFAULT_DISPLAY_OPTIONS, 2),
            Some("u_OFFCUT2".to_string())
        );
    }

    #[test]
    fn encode_value_and_representation_delegate_to_data_type_with_charset() {
        let dt = windows_wchar();
        let buf = FixedMemBuffer(vec![0x00, 0x41]);
        let encoded = dt
            .wide_char_encode_value(CharacterValue::Char('a'), &buf, &MockSettings, 2)
            .unwrap();
        assert_eq!(encoded, b"a".to_vec());
        let encoded_repr = dt
            .wide_char_encode_representation("z", &buf, &MockSettings, 2)
            .unwrap();
        assert_eq!(encoded_repr, b"z".to_vec());
    }

    #[test]
    fn is_encodable_is_true() {
        assert!(windows_wchar().wide_char_is_encodable());
    }

    #[test]
    fn c_type_declaration_uses_computed_wide_char_size_and_is_signed() {
        let dt = windows_wchar();
        let org = MockDataOrganization { wide_char_size: 2 };
        let decl = dt.wide_char_c_type_declaration(Some(&org)).unwrap();
        // `get_c_type_declaration_len` formats via `get_integer_c_type_approximation`; just
        // confirm the real (non-default) branch produced *some* typedef/define text mentioning
        // this type's name, rather than re-deriving that helper's own formatting here.
        assert!(decl.contains("wchar_t"));
    }

    #[test]
    fn c_type_declaration_is_none_without_a_data_organization() {
        let dt = windows_wchar();
        assert!(dt.wide_char_c_type_declaration(None).is_none());
    }

    #[test]
    fn clone_produces_an_equivalent_instance() {
        let dt = windows_wchar();
        let cloned = dt.wide_char_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }
}

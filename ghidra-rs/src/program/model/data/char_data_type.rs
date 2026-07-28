use crate::docking::settings::format_settings_definition::FormatSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_mnemonic_settings_definition::DataTypeMnemonicSettingsDefinition;
use crate::program::model::data::data_type_with_charset::DataTypeWithCharset;
use crate::program::model::data::endian_settings_definition::EndianSettingsDefinition;
use crate::program::model::data::padding_settings_definition::PaddingSettingsDefinition;
use crate::program::model::data::render_unicode_settings_definition::RenderUnicodeSettingsDefinition;
use crate::program::model::data::string_data_instance::DEFAULT_CHARSET_NAME;
use crate::program::seam_stubs::{CharsetSettingsDefinition, MemBuffer, CHARSET_UTF16, CHARSET_UTF32};

/// Provides a definition of a primitive char in a program. The size and signed-ness of this type
/// is determined by the data organization of the associated data type manager.
///
/// Port of `ghidra.program.model.data.CharDataType`, promoted straight to a trait because it was
/// selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractIntegerDataType implements DataTypeWithCharset`.
/// `AbstractIntegerDataType` itself is not yet ported, but every member `CharDataType` actually
/// calls on it (`getDataOrganization()`/`getLength()` from [`DataType`], and the protected static
/// `PADDING`/`ENDIAN`/`MNEMONIC` settings definitions) is already covered by an already-ported
/// trait or type, so no `seam_stubs` placeholder for `AbstractIntegerDataType` is needed.
///
/// Methods that only *override* an already-ported supertrait method with CharDataType-specific
/// behavior (`getLength`, `getValue`, `isEncodable`, `encodeValue`, `encodeRepresentation`,
/// `getValueClass`, `clone`, `getDefaultLabelPrefix`, `getDescription`,
/// `hasLanguageDependantLength`, `getCTypeDeclaration`, `getCharsetName`,
/// `getBuiltInSettingsDefinitions`) cannot be redeclared here without creating an ambiguous
/// method name with [`DataType`]/[`BuiltInDataType`]/[`DataTypeWithCharset`] (Rust does not allow
/// a subtrait to "override" a supertrait's default method by re-declaring it). Instead, the real
/// CharDataType-specific algorithms for those overrides are exposed here under distinct
/// `char_*` names; a future concrete implementation (once `AbstractIntegerDataType` and the
/// `SignedCharDataType`/`UnsignedCharDataType` singletons are ported) should implement
/// `DataType`/`BuiltInDataType`/`DataTypeWithCharset` directly and delegate to these helpers.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `ClassTranslator.put(...)` legacy-name registration (needs `ClassTranslator`, not yet ported).
pub trait CharDataType: DataType + DataTypeWithCharset + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of `CharDataType.isSigned()`, which implements the abstract
    /// `AbstractIntegerDataType.isSigned()`.
    fn is_signed(&self) -> bool {
        self.get_data_organization().is_signed_char()
    }

    /// Returns the C style data-type declaration for this data-type, or `None` if no appropriate
    /// declaration exists.
    ///
    /// Port of `CharDataType.getCDeclaration()`, which overrides the public (not abstract)
    /// `AbstractIntegerDataType.getCDeclaration()`. That method is not part of any already-ported
    /// trait, so it is exposed here directly.
    fn get_c_declaration(&self) -> Option<String> {
        Some(self.get_name())
    }

    /// Returns the data-type with the opposite signedness from this data-type (e.g. an unsigned
    /// char type for a signed char type).
    ///
    /// Port of `CharDataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method
    /// (no default) since the real implementation clones the `SignedCharDataType`/
    /// `UnsignedCharDataType` singletons, neither of which is ported yet.
    fn get_opposite_signedness_data_type(&self) -> Box<dyn CharDataType>;

    /// True if this char occupies more than one byte (a "wide" UTF-16/UTF-32 char), in which case
    /// no charset setting is offered (the charset is implied by the width).
    ///
    /// Port of the private `CharDataType.isWideUTFChar()`.
    fn is_wide_utf_char(&self) -> bool {
        self.get_length() != 1
    }

    /// Builds the settings definitions this data type exposes, standing in for the CharDataType
    /// constant arrays `CHAR_SETTINGS_DEFS`/`WIDE_UTF_CHAR_SETTINGS_DEFS` selected by
    /// `getBuiltInSettingsDefinitions()`. A concrete `impl DataType for ...` should delegate
    /// `get_settings_definitions` to this.
    ///
    /// Note: the Java arrays also include `TranslationSettingsDefinition.TRANSLATION`, omitted
    /// here because the ported [`TranslationSettingsDefinition`] does not yet implement
    /// [`SettingsDefinition`] itself (only its internal `JavaEnumSettingsDefinition` does).
    fn char_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        let mut defs: Vec<Box<dyn SettingsDefinition>> = vec![
            Box::new(FormatSettingsDefinition::DEF_CHAR),
            Box::new(PaddingSettingsDefinition::DEF),
            Box::new(EndianSettingsDefinition::DEF),
            Box::new(DataTypeMnemonicSettingsDefinition::DEF),
        ];
        if !self.is_wide_utf_char() {
            defs.push(Box::new(CharsetSettingsDefinition::CHARSET));
        }
        defs.push(Box::new(RenderUnicodeSettingsDefinition::DEF));
        defs
    }

    /// Get the character set for a specific data type and settings, standing in for
    /// `CharDataType.getCharsetName(Settings)`, which overrides
    /// [`DataTypeWithCharset::get_charset_name`]. A concrete `impl DataTypeWithCharset for ...`
    /// should delegate `get_charset_name` to this.
    fn char_charset_name(&self, settings: &dyn Settings) -> String {
        match self.get_length() {
            1 => CharsetSettingsDefinition::CHARSET.get_charset(settings, DEFAULT_CHARSET_NAME),
            2 => CHARSET_UTF16.to_string(),
            4 => CHARSET_UTF32.to_string(),
            _ => DEFAULT_CHARSET_NAME.to_string(),
        }
    }

    /// Returns the interpreted data value at `buf`, standing in for
    /// `CharDataType.getValue(MemBuffer, Settings, int)`, which overrides
    /// [`DataType::get_value`]. Returns the decoded UTF-16 code unit (0..=0xFFFF), or `None` if
    /// the bytes cannot be read or do not represent a valid `char` value, mirroring the Java
    /// method's `null` returns. A concrete `impl DataType for ...` should delegate `get_value` to
    /// this.
    fn char_value(&self, buf: &dyn MemBuffer) -> Option<u32> {
        let size = self.get_length();
        if size == 1 {
            return buf.get_unsigned_byte(0).ok().map(|b| b as u32);
        }
        let val: i64 = if size == 2 {
            buf.get_short(0).ok()? as i64
        } else if size == 4 {
            buf.get_int(0).ok()? as i64
        } else {
            -1
        };
        if (0..=0xFFFF).contains(&val) {
            Some(val as u32)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::mem::MemoryAccessException;

    struct MockBitFieldPacking;
    impl BitFieldPacking for MockBitFieldPacking {
        fn use_ms_convention(&self) -> bool {
            false
        }
        fn is_type_alignment_enabled(&self) -> bool {
            true
        }
        fn get_zero_length_boundary(&self) -> i32 {
            0
        }
    }

    struct MockDataOrganization {
        char_size: i32,
        signed_char: bool,
    }

    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            true
        }
        fn get_pointer_size(&self) -> i32 {
            8
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            self.signed_char
        }
        fn get_char_size(&self) -> i32 {
            self.char_size
        }
        fn get_wide_char_size(&self) -> i32 {
            4
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
        fn get_size_alignment(&self, size: i32) -> i32 {
            size
        }
        fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking> {
            Box::new(MockBitFieldPacking)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            String::new()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    struct FixedMemBuffer(Vec<u8>);
    impl MemBuffer for FixedMemBuffer {
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_byte(&self, offset: i32) -> Result<i8, MemoryAccessException> {
            self.0
                .get(offset as usize)
                .map(|b| *b as i8)
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_short(&self, offset: i32) -> Result<i16, MemoryAccessException> {
            let o = offset as usize;
            let bytes = self
                .0
                .get(o..o + 2)
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))?;
            Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
        }
        fn get_int(&self, offset: i32) -> Result<i32, MemoryAccessException> {
            let o = offset as usize;
            let bytes = self
                .0
                .get(o..o + 4)
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))?;
            Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
    }

    struct MockCharDataType {
        char_size: i32,
        signed_char: bool,
    }

    impl DataType for MockCharDataType {
        fn get_name(&self) -> String {
            "char".to_string()
        }
        fn get_length(&self) -> i32 {
            self.char_size
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization {
                char_size: self.char_size,
                signed_char: self.signed_char,
            })
        }
    }

    impl DataTypeWithCharset for MockCharDataType {
        fn string_data_instance(
            &self,
            _settings: &dyn Settings,
            _buf: &dyn MemBuffer,
        ) -> Box<dyn crate::program::model::data::string_data_instance::StringDataInstance> {
            unimplemented!("not exercised by these tests")
        }

        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.char_charset_name(settings)
        }
    }

    impl BuiltInDataType for MockCharDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl CharDataType for MockCharDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn CharDataType> {
            Box::new(MockCharDataType {
                char_size: self.char_size,
                signed_char: !self.signed_char,
            })
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockCharDataType {
            char_size: 1,
            signed_char: true,
        };
        let dyn_dt: &dyn CharDataType = &dt;
        assert!(dyn_dt.is_signed());
        assert_eq!(dyn_dt.get_c_declaration(), Some("char".to_string()));
        assert!(!dyn_dt.is_wide_utf_char());
    }

    #[test]
    fn is_signed_delegates_to_data_organization() {
        let signed = MockCharDataType {
            char_size: 1,
            signed_char: true,
        };
        let unsigned = MockCharDataType {
            char_size: 1,
            signed_char: false,
        };
        assert!(signed.is_signed());
        assert!(!unsigned.is_signed());
    }

    #[test]
    fn opposite_signedness_flips_sign() {
        let signed = MockCharDataType {
            char_size: 1,
            signed_char: true,
        };
        let opposite = signed.get_opposite_signedness_data_type();
        assert!(!opposite.is_signed());
    }

    #[test]
    fn char_value_reads_single_byte_as_unsigned() {
        let dt = MockCharDataType {
            char_size: 1,
            signed_char: true,
        };
        let buf = FixedMemBuffer(vec![0x41]);
        assert_eq!(dt.char_value(&buf), Some(0x41));
    }

    #[test]
    fn char_value_reads_two_byte_within_range() {
        let dt = MockCharDataType {
            char_size: 2,
            signed_char: false,
        };
        let buf = FixedMemBuffer(vec![0x12, 0x34]);
        assert_eq!(dt.char_value(&buf), Some(0x1234));
    }

    #[test]
    fn char_value_rejects_negative_two_byte_value() {
        let dt = MockCharDataType {
            char_size: 2,
            signed_char: true,
        };
        // 0xFFFF as a signed i16 is -1, which is out of the valid char range.
        let buf = FixedMemBuffer(vec![0xFF, 0xFF]);
        assert_eq!(dt.char_value(&buf), None);
    }

    #[test]
    fn char_value_none_when_read_fails() {
        let dt = MockCharDataType {
            char_size: 2,
            signed_char: false,
        };
        let buf = FixedMemBuffer(vec![0x00]);
        assert_eq!(dt.char_value(&buf), None);
    }

    #[test]
    fn char_charset_name_by_length() {
        let settings = MockSettings;
        let one = MockCharDataType {
            char_size: 1,
            signed_char: true,
        };
        let two = MockCharDataType {
            char_size: 2,
            signed_char: true,
        };
        let four = MockCharDataType {
            char_size: 4,
            signed_char: true,
        };
        assert_eq!(one.char_charset_name(&settings), "US-ASCII");
        assert_eq!(two.char_charset_name(&settings), "UTF-16");
        assert_eq!(four.char_charset_name(&settings), "UTF-32");
    }

    #[test]
    fn char_settings_definitions_include_charset_only_for_single_byte() {
        let one = MockCharDataType {
            char_size: 1,
            signed_char: true,
        };
        let two = MockCharDataType {
            char_size: 2,
            signed_char: true,
        };

        let one_names: Vec<String> =
            one.char_settings_definitions().iter().map(|d| d.get_name()).collect();
        let two_names: Vec<String> =
            two.char_settings_definitions().iter().map(|d| d.get_name()).collect();

        assert!(one_names.contains(&"Charset".to_string()));
        assert!(!two_names.contains(&"Charset".to_string()));
    }
}

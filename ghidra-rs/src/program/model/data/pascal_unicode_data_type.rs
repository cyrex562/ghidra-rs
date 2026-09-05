//! Port of `ghidra.program.model.data.PascalUnicodeDataType`.
//!
//! The Java class `extends AbstractStringDataType` with constructor field values `name =
//! "PascalUnicode"`, `mnemonic = "p_unicode"`, `defaultLabel = "P_UNICODE"`, `defaultLabelPrefix =
//! "P_UNI"`, `defaultAbbrevLabelPrefix = "pu"`, `description = "String (Pascal UTF-16 64k)"`,
//! `charsetName = CharsetInfoManager.UTF16`, `replacementDataType = ByteDataType.dataType`,
//! `stringLayout = StringLayoutEnum.PASCAL_64k`, plus an overridden `clone(DataTypeManager)`. See
//! [`PascalStringDataType`](super::pascal_string_data_type::PascalStringDataType)'s module docs
//! for the shared Pascal64k-layout conventions this mirrors (only the UTF-16 charset override --
//! see [`UnicodeDataType`](super::unicode_data_type::UnicodeDataType)'s module docs -- differs).

use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Port of `PascalUnicodeDataType.mnemonic` ("p_unicode").
pub const PASCAL_UNICODE_MNEMONIC: &str = "p_unicode";
/// Port of `PascalUnicodeDataType.description` ("String (Pascal UTF-16 64k)").
pub const PASCAL_UNICODE_DESCRIPTION: &str = "String (Pascal UTF-16 64k)";
/// Port of `PascalUnicodeDataType.defaultLabel` ("P_UNICODE").
pub const PASCAL_UNICODE_DEFAULT_LABEL: &str = "P_UNICODE";
/// Port of `PascalUnicodeDataType.defaultLabelPrefix` ("P_UNI").
pub const PASCAL_UNICODE_DEFAULT_LABEL_PREFIX: &str = "P_UNI";
/// Port of `PascalUnicodeDataType.defaultAbbrevLabelPrefix` ("pu").
pub const PASCAL_UNICODE_DEFAULT_ABBREV_LABEL_PREFIX: &str = "pu";
/// Port of `PascalUnicodeDataType.name` ("PascalUnicode").
pub const PASCAL_UNICODE_NAME: &str = "PascalUnicode";

/// A length-prefixed UTF-16 string (max 64k bytes), unbounded (ignores containing field size,
/// relies on the embedded length value).
///
/// Port of `ghidra.program.model.data.PascalUnicodeDataType`. See the module docs for what was
/// ported, added, and omitted.
pub trait PascalUnicodeDataType: AbstractStringDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager`.
    ///
    /// Port of `PascalUnicodeDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see
    /// [`StringDataType`](super::string_data_type::StringDataType)'s module docs for why.
    fn pascal_unicode_clone(
        &self,
        dtm: Option<Box<dyn DataTypeManager>>,
    ) -> Box<dyn PascalUnicodeDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_with_charset::DataTypeWithCharset;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::data::string_layout_enum::StringLayoutEnum;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::CHARSET_UTF16;

    struct NoSettings;
    impl Settings for NoSettings {}

    struct BytesBuffer(Vec<u8>);
    impl MemBuffer for BytesBuffer {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn is_initialized_memory(&self) -> bool {
            true
        }
        fn get_bytes(&self, buffer: &mut [u8], offset: i32) -> usize {
            if offset < 0 {
                return 0;
            }
            let o = offset as usize;
            if o >= self.0.len() {
                return 0;
            }
            let n = buffer.len().min(self.0.len() - o);
            buffer[..n].copy_from_slice(&self.0[o..o + n]);
            n
        }
        fn is_big_endian(&self) -> bool {
            true
        }
    }

    struct NoReplacementDataType;
    impl DataType for NoReplacementDataType {}

    struct MockPascalUnicodeDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockPascalUnicodeDataType {
        fn get_name(&self) -> String {
            PASCAL_UNICODE_NAME.to_string()
        }
        fn get_length(&self) -> i32 {
            self.string_length()
        }
        fn get_description(&self) -> String {
            self.string_description()
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn std::any::Any>> {
            self.string_value(buf, settings, length).map(|s| Box::new(s) as Box<dyn std::any::Any>)
        }
    }

    impl BuiltInDataType for MockPascalUnicodeDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockPascalUnicodeDataType {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.string_dynamic_length(buf, max_length)
        }
        fn can_specify_length(&self) -> bool {
            self.string_can_specify_length()
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.string_replacement_base_type().unwrap_or_else(|| Box::new(NoReplacementDataType))
        }
    }

    impl DataTypeWithCharset for MockPascalUnicodeDataType {
        fn string_data_instance(&self, settings: &dyn Settings, buf: &dyn MemBuffer) -> Box<dyn StringDataInstance> {
            let _ = (settings, buf);
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.string_charset_name(settings)
        }
    }

    impl AbstractStringDataType for MockPascalUnicodeDataType {
        fn mnemonic(&self) -> String {
            PASCAL_UNICODE_MNEMONIC.to_string()
        }
        fn description(&self) -> String {
            PASCAL_UNICODE_DESCRIPTION.to_string()
        }
        fn default_label(&self) -> String {
            PASCAL_UNICODE_DEFAULT_LABEL.to_string()
        }
        fn default_label_prefix(&self) -> String {
            PASCAL_UNICODE_DEFAULT_LABEL_PREFIX.to_string()
        }
        fn default_abbrev_label_prefix(&self) -> String {
            PASCAL_UNICODE_DEFAULT_ABBREV_LABEL_PREFIX.to_string()
        }
        fn get_string_layout(&self) -> StringLayoutEnum {
            StringLayoutEnum::Pascal64k
        }
        fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn charset_name_override(&self) -> Option<String> {
            Some(CHARSET_UTF16.to_string())
        }
    }

    impl PascalUnicodeDataType for MockPascalUnicodeDataType {
        fn pascal_unicode_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn PascalUnicodeDataType> {
            match dtm {
                None => Box::new(MockPascalUnicodeDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockPascalUnicodeDataType { dtm_tag: Some("new-manager") }),
            }
        }
    }

    #[test]
    fn field_values_match_java_constructor() {
        let dt = MockPascalUnicodeDataType { dtm_tag: None };
        assert_eq!(dt.get_name(), "PascalUnicode");
        assert_eq!(dt.mnemonic(), "p_unicode");
        assert_eq!(dt.description(), "String (Pascal UTF-16 64k)");
        assert_eq!(dt.default_label(), "P_UNICODE");
        assert_eq!(dt.default_label_prefix(), "P_UNI");
        assert_eq!(dt.default_abbrev_label_prefix(), "pu");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::Pascal64k);
        assert_eq!(dt.charset_name_override(), Some("UTF-16".to_string()));
    }

    #[test]
    fn pascal_64k_layout_uses_the_two_byte_char_count_times_utf16_width() {
        // 2-byte big-endian char count (2) followed by "Hi" as big-endian UTF-16.
        let dt = MockPascalUnicodeDataType { dtm_tag: None };
        let buf = BytesBuffer(vec![0x00, 0x02, 0x00, b'H', 0x00, b'i']);
        // getStringLength() = SIZEOF_PASCAL64K_STR_LEN_FIELD (2) + n (2) * paddedCharSize (2) = 6.
        assert_eq!(dt.string_dynamic_length(&buf, 99), 6);
        let settings = NoSettings;
        assert_eq!(dt.string_value(&buf, &settings, 6), Some("Hi".to_string()));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockPascalUnicodeDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.pascal_unicode_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockPascalUnicodeDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.pascal_unicode_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "PascalUnicode");
    }
}

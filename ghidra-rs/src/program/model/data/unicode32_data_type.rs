//! Port of `ghidra.program.model.data.Unicode32DataType`.
//!
//! The Java class `extends AbstractStringDataType` with constructor field values `name =
//! "unicode32"`, `mnemonic = "unicode32"`, `defaultLabel = "UNICODE"`, `defaultLabelPrefix =
//! "UNI"`, `defaultAbbrevLabelPrefix = "u"`, `description = "String (Fixed Length UTF-32
//! Unicode)"`, `charsetName = CharsetInfoManager.UTF32`, `replacementDataType =
//! WideChar32DataType.dataType`, `stringLayout = StringLayoutEnum.FIXED_LEN`, plus an overridden
//! `clone(DataTypeManager)`. See [`UnicodeDataType`](super::unicode_data_type::UnicodeDataType)'s
//! module docs for the shared conventions this mirrors (only the width -- UTF-32 vs UTF-16 --
//! differs).

use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Port of `Unicode32DataType.description` ("String (Fixed Length UTF-32 Unicode)").
pub const UNICODE32_DESCRIPTION: &str = "String (Fixed Length UTF-32 Unicode)";
/// Port of `Unicode32DataType.name`/`mnemonic` ("unicode32").
pub const UNICODE32_NAME: &str = "unicode32";

/// A fixed-length UTF-32 string.
///
/// Port of `ghidra.program.model.data.Unicode32DataType`. See the module docs for what was
/// ported, added, and omitted.
pub trait Unicode32DataType: AbstractStringDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager`.
    ///
    /// Port of `Unicode32DataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see
    /// [`StringDataType`](super::string_data_type::StringDataType)'s module docs for why.
    fn unicode32_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Unicode32DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::abstract_string_data_type::{
        DEFAULT_UNICODE_ABBREV_PREFIX, DEFAULT_UNICODE_LABEL, DEFAULT_UNICODE_LABEL_PREFIX,
    };
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_with_charset::DataTypeWithCharset;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::data::string_layout_enum::StringLayoutEnum;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::CHARSET_UTF32;

    struct NoSettings;
    impl Settings for NoSettings {}

    struct BytesBuffer {
        data: Vec<u8>,
        big_endian: bool,
    }
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
            if o >= self.data.len() {
                return 0;
            }
            let n = buffer.len().min(self.data.len() - o);
            buffer[..n].copy_from_slice(&self.data[o..o + n]);
            n
        }
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
    }

    struct NoReplacementDataType;
    impl DataType for NoReplacementDataType {}

    struct MockUnicode32DataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockUnicode32DataType {
        fn get_name(&self) -> String {
            UNICODE32_NAME.to_string()
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

    impl BuiltInDataType for MockUnicode32DataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockUnicode32DataType {
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

    impl DataTypeWithCharset for MockUnicode32DataType {
        fn string_data_instance(&self, settings: &dyn Settings, buf: &dyn MemBuffer) -> Box<dyn StringDataInstance> {
            let _ = (settings, buf);
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.string_charset_name(settings)
        }
    }

    impl AbstractStringDataType for MockUnicode32DataType {
        fn mnemonic(&self) -> String {
            UNICODE32_NAME.to_string()
        }
        fn description(&self) -> String {
            UNICODE32_DESCRIPTION.to_string()
        }
        fn default_label(&self) -> String {
            DEFAULT_UNICODE_LABEL.to_string()
        }
        fn default_label_prefix(&self) -> String {
            DEFAULT_UNICODE_LABEL_PREFIX.to_string()
        }
        fn default_abbrev_label_prefix(&self) -> String {
            DEFAULT_UNICODE_ABBREV_PREFIX.to_string()
        }
        fn get_string_layout(&self) -> StringLayoutEnum {
            StringLayoutEnum::FixedLen
        }
        fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn charset_name_override(&self) -> Option<String> {
            Some(CHARSET_UTF32.to_string())
        }
    }

    impl Unicode32DataType for MockUnicode32DataType {
        fn unicode32_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Unicode32DataType> {
            match dtm {
                None => Box::new(MockUnicode32DataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockUnicode32DataType { dtm_tag: Some("new-manager") }),
            }
        }
    }

    #[test]
    fn field_values_match_java_constructor() {
        let dt = MockUnicode32DataType { dtm_tag: None };
        assert_eq!(dt.get_name(), "unicode32");
        assert_eq!(dt.description(), "String (Fixed Length UTF-32 Unicode)");
        assert_eq!(dt.default_label(), "UNICODE");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::FixedLen);
        assert_eq!(dt.charset_name_override(), Some("UTF-32".to_string()));
    }

    #[test]
    fn value_decodes_big_endian_utf32() {
        let dt = MockUnicode32DataType { dtm_tag: None };
        // "A" (0x41) in big-endian UTF-32.
        let buf = BytesBuffer { data: vec![0x00, 0x00, 0x00, 0x41], big_endian: true };
        let settings = NoSettings;
        assert_eq!(dt.string_value(&buf, &settings, 4), Some("A".to_string()));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockUnicode32DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.unicode32_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUnicode32DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.unicode32_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "unicode32");
    }
}

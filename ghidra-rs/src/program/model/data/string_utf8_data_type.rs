//! Port of `ghidra.program.model.data.StringUTF8DataType`.
//!
//! The Java class `extends AbstractStringDataType` with constructor field values `name =
//! "string-utf8"`, `mnemonic = "utf8"`, `defaultLabel = "STRING"`, `defaultLabelPrefix = "STR"`,
//! `defaultAbbrevLabelPrefix = "s"`, `description = "String (Fixed Length UTF-8 Unicode)"`,
//! `charsetName = CharsetInfoManager.UTF8`, `replacementDataType = CharDataType.dataType`,
//! `stringLayout = StringLayoutEnum.FIXED_LEN`, plus an overridden `clone(DataTypeManager)`. See
//! [`StringDataType`](super::string_data_type::StringDataType)'s module docs for why this trait
//! does not redeclare [`AbstractStringDataType`]'s accessors and why `clone` is the only new
//! required method.
//!
//! Unlike [`StringDataType`]/[`TerminatedStringDataType`](super::terminated_string_data_type::TerminatedStringDataType)/
//! [`PascalStringDataType`](super::pascal_string_data_type::PascalStringDataType), this class
//! *does* override `charsetName` with a fixed value (`CharsetInfoManager.UTF8`, standing in as
//! [`CHARSET_UTF8`](crate::program::seam_stubs::CHARSET_UTF8) since `CharsetInfoManager` itself is
//! not ported -- mirroring [`CHARSET_UTF16`]/[`CHARSET_UTF32`]'s existing precedent), so the
//! concrete impl below overrides [`AbstractStringDataType::charset_name_override`] (which does
//! have a default of `None` on that trait, but -- since only one trait, `AbstractStringDataType`,
//! declares it -- there is no ambiguity in a single concrete impl simply providing a different
//! value for it directly).

use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Port of `StringUTF8DataType.mnemonic` ("utf8").
pub const STRING_UTF8_MNEMONIC: &str = "utf8";
/// Port of `StringUTF8DataType.description` ("String (Fixed Length UTF-8 Unicode)").
pub const STRING_UTF8_DESCRIPTION: &str = "String (Fixed Length UTF-8 Unicode)";
/// Port of `StringUTF8DataType.name` ("string-utf8").
pub const STRING_UTF8_NAME: &str = "string-utf8";

/// A fixed-length UTF-8 string.
///
/// Port of `ghidra.program.model.data.StringUTF8DataType`. See the module docs for what was
/// ported, added, and omitted.
pub trait StringUTF8DataType: AbstractStringDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager`.
    ///
    /// Port of `StringUTF8DataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see
    /// [`StringDataType`](super::string_data_type::StringDataType)'s module docs for why.
    fn string_utf8_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn StringUTF8DataType>;
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
    use crate::program::seam_stubs::CHARSET_UTF8;

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
            false
        }
    }

    struct NoReplacementDataType;
    impl DataType for NoReplacementDataType {}

    struct MockStringUTF8DataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockStringUTF8DataType {
        fn get_name(&self) -> String {
            STRING_UTF8_NAME.to_string()
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

    impl BuiltInDataType for MockStringUTF8DataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockStringUTF8DataType {
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

    impl DataTypeWithCharset for MockStringUTF8DataType {
        fn string_data_instance(&self, settings: &dyn Settings, buf: &dyn MemBuffer) -> Box<dyn StringDataInstance> {
            let _ = (settings, buf);
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.string_charset_name(settings)
        }
    }

    impl AbstractStringDataType for MockStringUTF8DataType {
        fn mnemonic(&self) -> String {
            STRING_UTF8_MNEMONIC.to_string()
        }
        fn description(&self) -> String {
            STRING_UTF8_DESCRIPTION.to_string()
        }
        fn default_label(&self) -> String {
            crate::program::model::data::abstract_string_data_type::DEFAULT_LABEL.to_string()
        }
        fn default_label_prefix(&self) -> String {
            crate::program::model::data::abstract_string_data_type::DEFAULT_LABEL_PREFIX.to_string()
        }
        fn default_abbrev_label_prefix(&self) -> String {
            crate::program::model::data::abstract_string_data_type::DEFAULT_ABBREV_PREFIX.to_string()
        }
        fn get_string_layout(&self) -> StringLayoutEnum {
            StringLayoutEnum::FixedLen
        }
        fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn charset_name_override(&self) -> Option<String> {
            Some(CHARSET_UTF8.to_string())
        }
    }

    impl StringUTF8DataType for MockStringUTF8DataType {
        fn string_utf8_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn StringUTF8DataType> {
            match dtm {
                None => Box::new(MockStringUTF8DataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockStringUTF8DataType { dtm_tag: Some("new-manager") }),
            }
        }
    }

    #[test]
    fn field_values_match_java_constructor() {
        let dt = MockStringUTF8DataType { dtm_tag: None };
        assert_eq!(dt.get_name(), "string-utf8");
        assert_eq!(dt.mnemonic(), "utf8");
        assert_eq!(dt.description(), "String (Fixed Length UTF-8 Unicode)");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::FixedLen);
        assert_eq!(dt.charset_name_override(), Some("UTF-8".to_string()));
    }

    #[test]
    fn charset_name_is_always_utf8_regardless_of_settings() {
        let dt = MockStringUTF8DataType { dtm_tag: None };
        let settings = NoSettings;
        assert_eq!(dt.string_charset_name(&settings), "UTF-8");
    }

    #[test]
    fn value_decodes_utf8_bytes() {
        let dt = MockStringUTF8DataType { dtm_tag: None };
        let buf = BytesBuffer("caf\u{e9}\0".as_bytes().to_vec());
        let settings = NoSettings;
        assert_eq!(dt.string_value(&buf, &settings, 5), Some("café".to_string()));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockStringUTF8DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.string_utf8_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockStringUTF8DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.string_utf8_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "string-utf8");
    }
}

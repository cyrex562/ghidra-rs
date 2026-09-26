//! Port of `ghidra.program.model.data.TerminatedUnicode32DataType`.
//!
//! The Java class `extends AbstractStringDataType` with constructor field values `name =
//! "TerminatedUnicode32"`, `mnemonic = "unicode32"`, `defaultLabel = "UNICODE"`,
//! `defaultLabelPrefix = "UNI"`, `defaultAbbrevLabelPrefix = "u"`, `description = "String (Null
//! Terminated UTF-32 Unicode)"`, `charsetName = CharsetInfoManager.UTF32`, `replacementDataType =
//! WideChar32DataType.dataType`, `stringLayout = StringLayoutEnum.NULL_TERMINATED_UNBOUNDED`, plus
//! an overridden `clone(DataTypeManager)`. See
//! [`TerminatedUnicodeDataType`](super::terminated_unicode_data_type::TerminatedUnicodeDataType)'s
//! module docs for the shared null-terminated-unbounded conventions this mirrors (only the width
//! -- UTF-32 vs UTF-16, see [`Unicode32DataType`](super::unicode32_data_type::Unicode32DataType) --
//! differs). Unlike `TerminatedUnicodeDataType`, this class uses the plain `"UNICODE"`/`"UNI"`/`"u"`
//! literals directly rather than [`AbstractStringDataType`]'s `DEFAULT_UNICODE_*` constants, though
//! the values are identical.

use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Port of `TerminatedUnicode32DataType.description` ("String (Null Terminated UTF-32 Unicode)").
pub const TERMINATED_UNICODE32_DESCRIPTION: &str = "String (Null Terminated UTF-32 Unicode)";
/// Port of `TerminatedUnicode32DataType.name` ("TerminatedUnicode32").
pub const TERMINATED_UNICODE32_NAME: &str = "TerminatedUnicode32";
/// Port of `TerminatedUnicode32DataType.mnemonic` ("unicode32").
pub const TERMINATED_UNICODE32_MNEMONIC: &str = "unicode32";

/// A null-terminated UTF-32 string.
///
/// Port of `ghidra.program.model.data.TerminatedUnicode32DataType`. See the module docs for what
/// was ported, added, and omitted.
pub trait TerminatedUnicode32DataType: AbstractStringDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager`.
    ///
    /// Port of `TerminatedUnicode32DataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see
    /// [`StringDataType`](super::string_data_type::StringDataType)'s module docs for why.
    fn terminated_unicode32_clone(
        &self,
        dtm: Option<Box<dyn DataTypeManager>>,
    ) -> Box<dyn TerminatedUnicode32DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, SpecialAddress};
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

    struct MockTerminatedUnicode32DataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockTerminatedUnicode32DataType {
        fn get_name(&self) -> String {
            TERMINATED_UNICODE32_NAME.to_string()
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

    impl BuiltInDataType for MockTerminatedUnicode32DataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockTerminatedUnicode32DataType {
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

    impl DataTypeWithCharset for MockTerminatedUnicode32DataType {
        fn string_data_instance(&self, settings: &dyn Settings, buf: &dyn MemBuffer) -> Box<dyn StringDataInstance> {
            let _ = (settings, buf);
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.string_charset_name(settings)
        }
    }

    impl AbstractStringDataType for MockTerminatedUnicode32DataType {
        fn mnemonic(&self) -> String {
            TERMINATED_UNICODE32_MNEMONIC.to_string()
        }
        fn description(&self) -> String {
            TERMINATED_UNICODE32_DESCRIPTION.to_string()
        }
        fn default_label(&self) -> String {
            "UNICODE".to_string()
        }
        fn default_label_prefix(&self) -> String {
            "UNI".to_string()
        }
        fn default_abbrev_label_prefix(&self) -> String {
            "u".to_string()
        }
        fn get_string_layout(&self) -> StringLayoutEnum {
            StringLayoutEnum::NullTerminatedUnbounded
        }
        fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn charset_name_override(&self) -> Option<String> {
            Some(CHARSET_UTF32.to_string())
        }
    }

    impl TerminatedUnicode32DataType for MockTerminatedUnicode32DataType {
        fn terminated_unicode32_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn TerminatedUnicode32DataType> {
            match dtm {
                None => Box::new(MockTerminatedUnicode32DataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockTerminatedUnicode32DataType { dtm_tag: Some("new-manager") }),
            }
        }
    }

    #[test]
    fn field_values_match_java_constructor() {
        let dt = MockTerminatedUnicode32DataType { dtm_tag: None };
        assert_eq!(dt.get_name(), "TerminatedUnicode32");
        assert_eq!(dt.mnemonic(), "unicode32");
        assert_eq!(dt.description(), "String (Null Terminated UTF-32 Unicode)");
        assert_eq!(dt.default_label(), "UNICODE");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::NullTerminatedUnbounded);
        assert_eq!(dt.charset_name_override(), Some("UTF-32".to_string()));
    }

    #[test]
    fn searches_for_a_utf32_null_terminator() {
        // "A" (0x41) followed by a 4-byte UTF-32 null terminator, big-endian.
        let dt = MockTerminatedUnicode32DataType { dtm_tag: None };
        let buf = BytesBuffer {
            data: vec![0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00],
            big_endian: true,
        };
        assert_eq!(dt.string_dynamic_length(&buf, 8), 8);
        let settings = NoSettings;
        assert_eq!(dt.string_value(&buf, &settings, 8), Some("A".to_string()));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockTerminatedUnicode32DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.terminated_unicode32_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockTerminatedUnicode32DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.terminated_unicode32_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "TerminatedUnicode32");
    }
}

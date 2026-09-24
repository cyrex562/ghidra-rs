//! Port of `ghidra.program.model.data.PascalStringDataType`.
//!
//! The Java class `extends AbstractStringDataType` with constructor field values `name =
//! "PascalString"`, `mnemonic = "p_string"`, `defaultLabel = "P_STRING"`, `defaultLabelPrefix =
//! "P_STR"`, `defaultAbbrevLabelPrefix = "p"`, `description = "String (Pascal 64k)"`, `charsetName
//! = USE_CHARSET_DEF_DEFAULT`, `replacementDataType = ByteDataType.dataType`, `stringLayout =
//! StringLayoutEnum.PASCAL_64k`, plus an overridden `clone(DataTypeManager)`. See
//! [`StringDataType`](super::string_data_type::StringDataType)'s module docs for why this trait
//! does not redeclare [`AbstractStringDataType`]'s accessors and why `clone` is the only new
//! required method.

use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Port of `PascalStringDataType.mnemonic` ("p_string").
pub const PASCAL_STRING_MNEMONIC: &str = "p_string";
/// Port of `PascalStringDataType.description` ("String (Pascal 64k)").
pub const PASCAL_STRING_DESCRIPTION: &str = "String (Pascal 64k)";
/// Port of `PascalStringDataType.defaultLabel` ("P_STRING").
pub const PASCAL_STRING_DEFAULT_LABEL: &str = "P_STRING";
/// Port of `PascalStringDataType.defaultLabelPrefix` ("P_STR").
pub const PASCAL_STRING_DEFAULT_LABEL_PREFIX: &str = "P_STR";
/// Port of `PascalStringDataType.defaultAbbrevLabelPrefix` ("p").
pub const PASCAL_STRING_DEFAULT_ABBREV_LABEL_PREFIX: &str = "p";
/// Port of `PascalStringDataType.name` ("PascalString").
pub const PASCAL_STRING_NAME: &str = "PascalString";

/// A length-prefixed string (max 64k bytes), char size of 1 byte, user-settable charset (default
/// ASCII), unbounded (ignores containing field size, relies on the embedded length value).
///
/// Port of `ghidra.program.model.data.PascalStringDataType`. See the module docs for what was
/// ported, added, and omitted.
pub trait PascalStringDataType: AbstractStringDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager`.
    ///
    /// Port of `PascalStringDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see
    /// [`StringDataType`](super::string_data_type::StringDataType)'s module docs for why.
    fn pascal_string_clone(
        &self,
        dtm: Option<Box<dyn DataTypeManager>>,
    ) -> Box<dyn PascalStringDataType>;
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

    struct MockPascalStringDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockPascalStringDataType {
        fn get_name(&self) -> String {
            PASCAL_STRING_NAME.to_string()
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

    impl BuiltInDataType for MockPascalStringDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockPascalStringDataType {
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

    impl DataTypeWithCharset for MockPascalStringDataType {
        fn string_data_instance(&self, settings: &dyn Settings, buf: &dyn MemBuffer) -> Box<dyn StringDataInstance> {
            let _ = (settings, buf);
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.string_charset_name(settings)
        }
    }

    impl AbstractStringDataType for MockPascalStringDataType {
        fn mnemonic(&self) -> String {
            PASCAL_STRING_MNEMONIC.to_string()
        }
        fn description(&self) -> String {
            PASCAL_STRING_DESCRIPTION.to_string()
        }
        fn default_label(&self) -> String {
            PASCAL_STRING_DEFAULT_LABEL.to_string()
        }
        fn default_label_prefix(&self) -> String {
            PASCAL_STRING_DEFAULT_LABEL_PREFIX.to_string()
        }
        fn default_abbrev_label_prefix(&self) -> String {
            PASCAL_STRING_DEFAULT_ABBREV_LABEL_PREFIX.to_string()
        }
        fn get_string_layout(&self) -> StringLayoutEnum {
            StringLayoutEnum::Pascal64k
        }
        fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
    }

    impl PascalStringDataType for MockPascalStringDataType {
        fn pascal_string_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn PascalStringDataType> {
            match dtm {
                None => Box::new(MockPascalStringDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockPascalStringDataType { dtm_tag: Some("new-manager") }),
            }
        }
    }

    #[test]
    fn field_values_match_java_constructor() {
        let dt = MockPascalStringDataType { dtm_tag: None };
        assert_eq!(dt.get_name(), "PascalString");
        assert_eq!(dt.mnemonic(), "p_string");
        assert_eq!(dt.description(), "String (Pascal 64k)");
        assert_eq!(dt.default_label(), "P_STRING");
        assert_eq!(dt.default_label_prefix(), "P_STR");
        assert_eq!(dt.default_abbrev_label_prefix(), "p");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::Pascal64k);
    }

    #[test]
    fn pascal_64k_layout_uses_the_embedded_two_byte_length() {
        // 2-byte big-endian length prefix (3) followed by "ABC".
        let dt = MockPascalStringDataType { dtm_tag: None };
        let buf = BytesBuffer(vec![0x00, 0x03, b'A', b'B', b'C']);
        // getStringLength() = SIZEOF_PASCAL64K_STR_LEN_FIELD (2) + n (3) * paddedCharSize (1) = 5.
        assert_eq!(dt.string_dynamic_length(&buf, 99), 5);
        let settings = NoSettings;
        assert_eq!(dt.string_value(&buf, &settings, 5), Some("ABC".to_string()));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockPascalStringDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.pascal_string_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockPascalStringDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.pascal_string_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "PascalString");
    }
}

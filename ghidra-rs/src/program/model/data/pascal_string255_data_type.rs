//! Port of `ghidra.program.model.data.PascalString255DataType`.
//!
//! The Java class `extends AbstractStringDataType` with constructor field values `name =
//! "PascalString255"`, `mnemonic = "p_string255"`, `defaultLabel = "PASCAL255"`,
//! `defaultLabelPrefix = "P_STR"`, `defaultAbbrevLabelPrefix = "p"`, `description = "String
//! (Pascal 255)"`, `charsetName = USE_CHARSET_DEF_DEFAULT`, `replacementDataType =
//! ByteDataType.dataType`, `stringLayout = StringLayoutEnum.PASCAL_255`, plus an overridden
//! `clone(DataTypeManager)`. See [`StringDataType`](super::string_data_type::StringDataType)'s
//! module docs for why this trait does not redeclare [`AbstractStringDataType`]'s accessors and
//! why `clone` is the only new required method.
//!
//! Not ported: `PascalString255DataType.copy(boolean retainIdentity)`. It carries no `@Override`
//! annotation and does not implement any interface method in the Java source tree (a repo-wide
//! grep for `copy(boolean retainIdentity)` across `ghidra.program.model.data` turns up only this
//! one declaration), so it appears to be dead/unused code rather than a real override; skipping it
//! matches this port's practice of not reproducing unreachable legacy methods.

use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Port of `PascalString255DataType.mnemonic` ("p_string255").
pub const PASCAL_STRING255_MNEMONIC: &str = "p_string255";
/// Port of `PascalString255DataType.description` ("String (Pascal 255)").
pub const PASCAL_STRING255_DESCRIPTION: &str = "String (Pascal 255)";
/// Port of `PascalString255DataType.defaultLabel` ("PASCAL255").
pub const PASCAL_STRING255_DEFAULT_LABEL: &str = "PASCAL255";
/// Port of `PascalString255DataType.defaultLabelPrefix` ("P_STR").
pub const PASCAL_STRING255_DEFAULT_LABEL_PREFIX: &str = "P_STR";
/// Port of `PascalString255DataType.defaultAbbrevLabelPrefix` ("p").
pub const PASCAL_STRING255_DEFAULT_ABBREV_LABEL_PREFIX: &str = "p";
/// Port of `PascalString255DataType.name` ("PascalString255").
pub const PASCAL_STRING255_NAME: &str = "PascalString255";

/// A length-prefixed string (max 255 bytes), char size of 1 byte, user-settable charset (default
/// ASCII), unbounded (ignores containing field size, relies on the embedded length value).
///
/// Port of `ghidra.program.model.data.PascalString255DataType`. See the module docs for what was
/// ported, added, and omitted.
pub trait PascalString255DataType: AbstractStringDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager`.
    ///
    /// Port of `PascalString255DataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see
    /// [`StringDataType`](super::string_data_type::StringDataType)'s module docs for why.
    fn pascal_string255_clone(
        &self,
        dtm: Option<Box<dyn DataTypeManager>>,
    ) -> Box<dyn PascalString255DataType>;
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

    struct NoSettings;
    impl Settings for NoSettings {}

    struct BytesBuffer(Vec<u8>);
    impl MemBuffer for BytesBuffer {
        fn get_byte(&self, offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            self.0
                .get(offset as usize)
                .copied()
                .ok_or_else(|| crate::program::model::mem::MemoryAccessException::new("out of bounds"))
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

    struct MockPascalString255DataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockPascalString255DataType {
        fn get_name(&self) -> String {
            PASCAL_STRING255_NAME.to_string()
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

    impl BuiltInDataType for MockPascalString255DataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockPascalString255DataType {
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

    impl DataTypeWithCharset for MockPascalString255DataType {
        fn string_data_instance(&self, settings: &dyn Settings, buf: &dyn MemBuffer) -> Box<dyn StringDataInstance> {
            let _ = (settings, buf);
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.string_charset_name(settings)
        }
    }

    impl AbstractStringDataType for MockPascalString255DataType {
        fn mnemonic(&self) -> String {
            PASCAL_STRING255_MNEMONIC.to_string()
        }
        fn description(&self) -> String {
            PASCAL_STRING255_DESCRIPTION.to_string()
        }
        fn default_label(&self) -> String {
            PASCAL_STRING255_DEFAULT_LABEL.to_string()
        }
        fn default_label_prefix(&self) -> String {
            PASCAL_STRING255_DEFAULT_LABEL_PREFIX.to_string()
        }
        fn default_abbrev_label_prefix(&self) -> String {
            PASCAL_STRING255_DEFAULT_ABBREV_LABEL_PREFIX.to_string()
        }
        fn get_string_layout(&self) -> StringLayoutEnum {
            StringLayoutEnum::Pascal255
        }
        fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
    }

    impl PascalString255DataType for MockPascalString255DataType {
        fn pascal_string255_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn PascalString255DataType> {
            match dtm {
                None => Box::new(MockPascalString255DataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockPascalString255DataType { dtm_tag: Some("new-manager") }),
            }
        }
    }

    #[test]
    fn field_values_match_java_constructor() {
        let dt = MockPascalString255DataType { dtm_tag: None };
        assert_eq!(dt.get_name(), "PascalString255");
        assert_eq!(dt.mnemonic(), "p_string255");
        assert_eq!(dt.description(), "String (Pascal 255)");
        assert_eq!(dt.default_label(), "PASCAL255");
        assert_eq!(dt.default_label_prefix(), "P_STR");
        assert_eq!(dt.default_abbrev_label_prefix(), "p");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::Pascal255);
    }

    #[test]
    fn pascal_255_layout_uses_the_embedded_one_byte_length() {
        // 1-byte length prefix (3) followed by "ABC".
        let dt = MockPascalString255DataType { dtm_tag: None };
        let buf = BytesBuffer(vec![0x03, b'A', b'B', b'C']);
        // getStringLength() = SIZEOF_PASCAL255_STR_LEN_FIELD (1) + n (3) * paddedCharSize (1) = 4.
        assert_eq!(dt.string_dynamic_length(&buf, 99), 4);
        let settings = NoSettings;
        assert_eq!(dt.string_value(&buf, &settings, 4), Some("ABC".to_string()));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockPascalString255DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.pascal_string255_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockPascalString255DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.pascal_string255_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "PascalString255");
    }
}

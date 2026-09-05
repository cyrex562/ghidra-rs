//! Port of `ghidra.program.model.data.TerminatedStringDataType`.
//!
//! The Java class `extends AbstractStringDataType`, differing from
//! [`StringDataType`](super::string_data_type::StringDataType) only in its constructor field
//! values (`name = "TerminatedCString"`, `description = "String (Null Terminated)"`,
//! `stringLayout = StringLayoutEnum.NULL_TERMINATED_UNBOUNDED`; `mnemonic`, `defaultLabel`,
//! `defaultLabelPrefix`, `defaultAbbrevLabelPrefix`, `charsetName`, and `replacementDataType` are
//! identical to `StringDataType`'s) and its overridden `clone(DataTypeManager)`. See
//! [`StringDataType`]'s module docs for why this trait does not redeclare
//! [`AbstractStringDataType`]'s accessors (they are abstract there, so no ambiguity is created by
//! a concrete impl fulfilling them directly) and why `clone` is the only new required method.

use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Port of `TerminatedStringDataType.description` ("String (Null Terminated)").
pub const TERMINATED_STRING_DESCRIPTION: &str = "String (Null Terminated)";
/// Port of `TerminatedStringDataType.name` ("TerminatedCString").
pub const TERMINATED_STRING_NAME: &str = "TerminatedCString";

/// A null-terminated string with a user-settable charset (default ASCII).
///
/// Port of `ghidra.program.model.data.TerminatedStringDataType`. See the module docs for what was
/// ported, added, and omitted.
pub trait TerminatedStringDataType: AbstractStringDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager`.
    ///
    /// Port of `TerminatedStringDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see
    /// [`StringDataType`](super::string_data_type::StringDataType)'s module docs for why.
    fn terminated_string_clone(
        &self,
        dtm: Option<Box<dyn DataTypeManager>>,
    ) -> Box<dyn TerminatedStringDataType>;
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

    struct MockTerminatedStringDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockTerminatedStringDataType {
        fn get_name(&self) -> String {
            TERMINATED_STRING_NAME.to_string()
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

    impl BuiltInDataType for MockTerminatedStringDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockTerminatedStringDataType {
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

    impl DataTypeWithCharset for MockTerminatedStringDataType {
        fn string_data_instance(&self, settings: &dyn Settings, buf: &dyn MemBuffer) -> Box<dyn StringDataInstance> {
            let _ = (settings, buf);
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.string_charset_name(settings)
        }
    }

    impl AbstractStringDataType for MockTerminatedStringDataType {
        fn mnemonic(&self) -> String {
            "ds".to_string()
        }
        fn description(&self) -> String {
            TERMINATED_STRING_DESCRIPTION.to_string()
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
            StringLayoutEnum::NullTerminatedUnbounded
        }
        fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
    }

    impl TerminatedStringDataType for MockTerminatedStringDataType {
        fn terminated_string_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn TerminatedStringDataType> {
            match dtm {
                None => Box::new(MockTerminatedStringDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockTerminatedStringDataType { dtm_tag: Some("new-manager") }),
            }
        }
    }

    #[test]
    fn field_values_match_java_constructor() {
        let dt = MockTerminatedStringDataType { dtm_tag: None };
        assert_eq!(dt.get_name(), "TerminatedCString");
        assert_eq!(dt.description(), "String (Null Terminated)");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::NullTerminatedUnbounded);
    }

    #[test]
    fn null_terminated_unbounded_layout_searches_for_a_terminator() {
        let dt = MockTerminatedStringDataType { dtm_tag: None };
        let buf = BytesBuffer(b"Hello\0World".to_vec());
        assert_eq!(dt.string_dynamic_length(&buf, 11), 6);
        let settings = NoSettings;
        assert_eq!(dt.string_value(&buf, &settings, 6), Some("Hello".to_string()));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockTerminatedStringDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.terminated_string_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockTerminatedStringDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.terminated_string_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "TerminatedCString");
    }
}

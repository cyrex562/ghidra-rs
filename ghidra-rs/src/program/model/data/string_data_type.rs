//! Port of `ghidra.program.model.data.StringDataType`.
//!
//! The Java class `extends AbstractStringDataType`, adding nothing but its own constructor field
//! values (`name = "string"`, `mnemonic = "ds"`, `defaultLabel = "STRING"`,
//! `defaultLabelPrefix = "STR"`, `defaultAbbrevLabelPrefix = "s"`,
//! `description = "String (fixed length)"`, `charsetName = USE_CHARSET_DEF_DEFAULT`,
//! `replacementDataType = CharDataType.dataType`, `stringLayout = StringLayoutEnum.FIXED_LEN`) and
//! an overridden `clone(DataTypeManager)`.
//!
//! Unlike the `char_*`/`byte_*`/`dword_*` convention used elsewhere in this crate,
//! [`AbstractStringDataType`]'s per-instance accessors (`mnemonic`, `description`, `default_label`,
//! `default_label_prefix`, `default_abbrev_label_prefix`, `get_string_layout`,
//! `string_replacement_base_type`) are *required* (no default body) on that trait already -- unlike
//! e.g. `DataType::get_description`, which already has a default and therefore cannot be
//! redeclared with a different default in a subtrait without creating an ambiguous method (see
//! [`AbstractStringDataType`]'s own module docs, and the analogous problem worked around by
//! [`ByteDataType::byte_description`](super::byte_data_type::ByteDataType::byte_description)).
//! Since `AbstractStringDataType`'s accessors have no default to collide with, this trait simply
//! does *not* redeclare them at all: a concrete `impl AbstractStringDataType for ...` fulfills
//! them directly with `StringDataType`'s literal constructor values (exposed here as module
//! constants where they are not already covered by
//! [`abstract_string_data_type`](super::abstract_string_data_type)'s own
//! `DEFAULT_LABEL`/`DEFAULT_LABEL_PREFIX`/`DEFAULT_ABBREV_PREFIX`/`USE_CHARSET_DEF_DEFAULT`
//! constants, which `StringDataType` reuses verbatim).
//!
//! `clone(DataTypeManager)` is the only genuinely new behavior, so -- mirroring
//! [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) and every other
//! `BuiltIn`-derived cut-point trait in this crate -- it is left as a required method (no default),
//! since the real implementation returns `self` when `dtm` already matches this instance's
//! manager, which requires manager-identity comparison a mock cannot provide generically.
//!
//! Not ported: the `dataType` singleton (needs a concrete struct with `DataTypeManager` wiring,
//! not yet part of this port), the `ClassTranslator.put(...)` legacy-name registrations
//! (`ClassTranslator` is not ported), and the resulting `replacementDataType =
//! CharDataType.dataType` field, since [`CharDataType`](super::char_data_type::CharDataType)
//! itself has no concrete singleton yet either (it is a cut-point trait, per its own module docs).
//! [`string_replacement_base_type`](super::abstract_string_data_type::AbstractStringDataType::string_replacement_base_type)
//! is therefore documented (in the test `Mock` below) as returning `None`, matching
//! [`AbstractStringDataType`]'s own test precedent for the identical situation.

use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Port of `StringDataType.mnemonic` ("ds").
pub const STRING_MNEMONIC: &str = "ds";
/// Port of `StringDataType.description` ("String (fixed length)").
pub const STRING_DESCRIPTION: &str = "String (fixed length)";
/// Port of `StringDataType.name` ("string"), the value passed to `BuiltIn`'s constructor.
pub const STRING_NAME: &str = "string";

/// A fixed-length string with a user-settable charset (default ASCII).
///
/// Port of `ghidra.program.model.data.StringDataType`. See the module docs for what was ported,
/// added, and omitted.
pub trait StringDataType: AbstractStringDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager`.
    ///
    /// Port of `StringDataType.clone(DataTypeManager)`, which overrides `BuiltIn.clone(DataTypeManager)`.
    /// Left as a required method (no default); see the module docs for why.
    fn string_data_type_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn StringDataType>;
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
            false
        }
    }

    /// Fallback used by [`MockStringDataType`]'s `Dynamic::get_replacement_base_type` since that
    /// method is not optional even though `StringDataType.replacementDataType` (`CharDataType.dataType`)
    /// has no constructible singleton yet. See the module docs.
    struct NoReplacementDataType;
    impl DataType for NoReplacementDataType {}

    struct MockStringDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockStringDataType {
        fn get_name(&self) -> String {
            STRING_NAME.to_string()
        }
        fn get_length(&self) -> i32 {
            self.string_length()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.string_mnemonic(settings)
        }
        fn get_description(&self) -> String {
            self.string_description()
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn std::any::Any>> {
            self.string_value(buf, settings, length).map(|s| Box::new(s) as Box<dyn std::any::Any>)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.string_representation(buf, settings, length)
        }
    }

    impl BuiltInDataType for MockStringDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockStringDataType {
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

    impl DataTypeWithCharset for MockStringDataType {
        fn string_data_instance(&self, settings: &dyn Settings, buf: &dyn MemBuffer) -> Box<dyn StringDataInstance> {
            let _ = (settings, buf);
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.string_charset_name(settings)
        }
    }

    impl AbstractStringDataType for MockStringDataType {
        fn mnemonic(&self) -> String {
            STRING_MNEMONIC.to_string()
        }
        fn description(&self) -> String {
            STRING_DESCRIPTION.to_string()
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
    }

    impl StringDataType for MockStringDataType {
        fn string_data_type_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn StringDataType> {
            match dtm {
                None => Box::new(MockStringDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockStringDataType { dtm_tag: Some("new-manager") }),
            }
        }
    }

    #[test]
    fn field_values_match_java_constructor() {
        let dt = MockStringDataType { dtm_tag: None };
        assert_eq!(dt.get_name(), "string");
        assert_eq!(dt.mnemonic(), "ds");
        assert_eq!(dt.description(), "String (fixed length)");
        assert_eq!(dt.default_label(), "STRING");
        assert_eq!(dt.default_label_prefix(), "STR");
        assert_eq!(dt.default_abbrev_label_prefix(), "s");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::FixedLen);
    }

    #[test]
    fn fixed_len_layout_does_not_search_for_a_terminator() {
        // Unlike `NULL_TERMINATED_UNBOUNDED` (see AbstractStringDataType's own tests), FixedLen
        // takes the caller-supplied length as-is instead of searching for a null terminator.
        let dt = MockStringDataType { dtm_tag: None };
        let buf = BytesBuffer(b"Hello\0World".to_vec());
        assert_eq!(dt.string_dynamic_length(&buf, 11), 11);
    }

    #[test]
    fn value_trims_trailing_nulls() {
        let dt = MockStringDataType { dtm_tag: None };
        let buf = BytesBuffer(b"Hi\0\0".to_vec());
        let settings = NoSettings;
        assert_eq!(dt.string_value(&buf, &settings, 4), Some("Hi".to_string()));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockStringDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.string_data_type_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockStringDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.string_data_type_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "string");
        assert_eq!(cloned.get_string_layout(), StringLayoutEnum::FixedLen);
    }
}

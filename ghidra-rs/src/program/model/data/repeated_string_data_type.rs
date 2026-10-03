//! Port of `ghidra.program.model.data.RepeatedStringDataType`.
//!
//! `RepeatedStringDataType extends RepeatCountDataType` (not `AbstractStringDataType`): a 2-byte
//! count followed by that many [`StringDataType`] elements. The Java base classes
//! (`RepeatCountDataType` -> `DynamicDataType` -> `BuiltIn`) are the
//! [`RepeatCountDataType`]/[`DynamicDataType`]/[`BuiltIn`](super::built_in::BuiltIn) behaviour
//! traits; this struct carries the [`BuiltInBase`] state and supplies the repeated element.

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::built_in::{built_in_data_type_methods, built_in_singleton, impl_built_in, BuiltIn, BuiltInBase};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::data::dynamic_data_type::DynamicDataType;
use crate::program::model::data::repeat_count_data_type::RepeatCountDataType;
use crate::program::model::data::string_data_type::StringDataType;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::program::model::mem::MemBuffer;

/// Port of `RepeatedStringDataType.getDescription()` ("Repeated String").
pub const REPEATED_STRING_DESCRIPTION: &str = "Repeated String";

/// The name `RepeatedStringDataType` passes to its superclass constructor ("RepString").
pub const REPEATED_STRING_NAME: &str = "RepString";

/// Some number of repeated strings, each of variable length.
///
/// ```text
///    RepeatedStringDT
///        numberOfStrings = N
///        String1
///        String2
///        ...
///        StringN
/// ```
///
/// Port of `ghidra.program.model.data.RepeatedStringDataType`.
#[derive(Debug, Clone)]
pub struct RepeatedStringDataType {
    base: BuiltInBase,
}

impl RepeatedStringDataType {
    /// Port of `RepeatedStringDataType(DataTypeManager)`; `None` is the no-argument constructor.
    pub fn new(dtm: Option<&dyn DataTypeManager>) -> Self {
        Self { base: BuiltInBase::new(None, REPEATED_STRING_NAME, dtm) }
    }

    fn c_type_declaration(&self, data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        BuiltIn::built_in_get_c_type_declaration(self, data_organization)
    }

    fn built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        Vec::new()
    }

    fn decompiler_display_name(&self, _language: DecompilerLanguage) -> String {
        REPEATED_STRING_NAME.to_string()
    }
}

built_in_singleton!(RepeatedStringDataType);
impl_built_in!(RepeatedStringDataType);

impl DataType for RepeatedStringDataType {
    built_in_data_type_methods!();

    fn get_length(&self) -> i32 {
        -1
    }
    fn get_description(&self) -> String {
        REPEATED_STRING_DESCRIPTION.to_string()
    }
    fn get_mnemonic(&self, settings: &dyn Settings) -> String {
        self.repeat_count_mnemonic(settings)
    }
    fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn std::any::Any>> {
        self.repeat_count_value(buf, settings, length)
    }
    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        self.repeat_count_representation(buf, settings, length)
    }
    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        crate::program::model::data::built_in::same_class(self, dt)
    }
    fn is_dynamic_type(&self) -> bool {
        true
    }
    fn as_dynamic(&self) -> Option<&dyn Dynamic> {
        Some(self)
    }
}

impl Dynamic for RepeatedStringDataType {
    fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
        self.dynamic_length_from_components(buf, max_length)
    }
    fn can_specify_length(&self) -> bool {
        false
    }
    fn get_replacement_base_type(&self) -> Box<dyn DataType> {
        self.default_replacement_base_type()
    }
}

impl DynamicDataType for RepeatedStringDataType {
    fn get_all_components(&self, buf: &dyn MemBuffer) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
        self.repeat_count_all_components(buf)
    }
}

impl RepeatCountDataType for RepeatedStringDataType {
    /// The static `datatype` field: a `StringDataType` per repetition.
    fn stored_repeat_data_type(&self) -> Box<dyn DataType> {
        Box::new(StringDataType::new(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::string_data_instance::test_support::{mb, SettingsBuilder};

    #[test]
    fn java_constants() {
        let dt = RepeatedStringDataType::instance();
        assert_eq!(dt.get_name(), "RepString");
        assert_eq!(dt.get_description(), "Repeated String");
        assert_eq!(dt.get_mnemonic(&SettingsBuilder::new()), "RepString");
        assert_eq!(dt.stored_repeat_data_type().get_name(), "string");
        assert!(!dt.can_specify_length());
        assert_eq!(dt.get_representation(&mb(false, &[0, 0]), &SettingsBuilder::new(), 2), "");
        assert!(dt.get_value(&mb(false, &[0, 0]), &SettingsBuilder::new(), 2).is_none());
    }

    #[test]
    fn components_are_the_count_then_null_terminated_strings() {
        // n = 0*16 + 2 + 1 = 3: the Size component plus two strings.
        let dt = RepeatedStringDataType::new(None);
        let buf = mb(true, &[0x00, 0x02, b'h', b'i', 0, b'x', 0]);
        let comps = dt.repeat_count_all_components(&buf).unwrap();
        assert_eq!(comps.len(), 3);
        assert_eq!(comps[0].as_ref().unwrap().get_field_name(), Some("Size".to_string()));
        assert_eq!(comps[1].as_ref().unwrap().get_data_type().get_name(), "string");
        assert_eq!(comps[1].as_ref().unwrap().get_length(), 3);
        assert_eq!(comps[2].as_ref().unwrap().get_offset(), 5);
        assert_eq!(comps[2].as_ref().unwrap().get_length(), 2);
        assert_eq!(dt.get_dynamic_length(&buf, -1), 7);
    }
}

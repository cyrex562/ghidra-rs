use std::any::Any;
use std::collections::HashSet;

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::docking::settings::string_settings_definition::StringSettingsDefinition;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;

const ADDRESS_SPACE_SETTING_NAME: &str = "addr_space_name";
const DESCRIPTION: &str =
    "Identifies the referenced address space name (case-sensitive; ignored if no match)";
const DISPLAY_NAME: &str = "Address Space";

/// A [`StringSettingsDefinition`]/[`TypeDefSettingsDefinition`] which identifies a referenced
/// address space by name.
///
/// Port of `ghidra.program.model.data.AddressSpaceSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressSpaceSettingsDefinition;

impl AddressSpaceSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: AddressSpaceSettingsDefinition = AddressSpaceSettingsDefinition;
}

impl StringSettingsDefinition for AddressSpaceSettingsDefinition {
    fn get_value(&self, settings: &dyn Settings) -> Option<String> {
        settings.get_string(ADDRESS_SPACE_SETTING_NAME)
    }

    fn set_value(&self, settings: &mut dyn Settings, value: &str) {
        if value.trim().is_empty() {
            settings.clear_setting(ADDRESS_SPACE_SETTING_NAME);
        } else {
            settings.set_string(ADDRESS_SPACE_SETTING_NAME, value);
        }
    }

    fn get_suggested_values(&self, settings: &dyn Settings) -> Option<Vec<String>> {
        Some(settings.get_suggested_values(self))
    }

    fn supports_suggested_values(&self) -> bool {
        true
    }

    /// Adds the names of every loaded memory address space of the program architecture
    /// associated with `settings_owner` (when it is a [`DataTypeManager`]).
    fn add_preferred_values(
        &self,
        settings_owner: Option<&dyn Any>,
        set: &mut HashSet<String>,
    ) -> bool {
        let Some(dtm) = settings_owner.and_then(|owner| owner.downcast_ref::<Box<dyn DataTypeManager>>())
        else {
            return false;
        };
        if let Some(arch) = dtm.get_program_architecture() {
            for space in arch.get_address_factory().get_all_address_spaces() {
                if space.is_loaded_memory_space() {
                    set.insert(space.name().to_string());
                }
            }
        }
        true
    }
}

impl SettingsDefinition for AddressSpaceSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        StringSettingsDefinition::get_value(self, settings).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        StringSettingsDefinition::get_value_string(self, settings)
    }

    fn get_name(&self) -> String {
        DISPLAY_NAME.to_string()
    }

    fn get_storage_key(&self) -> String {
        ADDRESS_SPACE_SETTING_NAME.to_string()
    }

    fn get_description(&self) -> String {
        DESCRIPTION.to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(ADDRESS_SPACE_SETTING_NAME);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_string(ADDRESS_SPACE_SETTING_NAME) {
            Some(value) => dest_settings.set_string(ADDRESS_SPACE_SETTING_NAME, &value),
            None => dest_settings.clear_setting(ADDRESS_SPACE_SETTING_NAME),
        }
    }

    fn has_same_value(&self, settings1: &dyn Settings, settings2: &dyn Settings) -> bool {
        StringSettingsDefinition::has_same_value(self, settings1, settings2)
    }
}

impl TypeDefSettingsDefinition for AddressSpaceSettingsDefinition {
    fn get_attribute_specification(&self, settings: &dyn Settings) -> Option<String> {
        let space_name = StringSettingsDefinition::get_value(self, settings)?;
        if space_name.trim().is_empty() {
            None
        } else {
            Some(format!("space({})", space_name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::ProgramArchitecture;
    use crate::program::seam_stubs::{CompilerSpec, CompilerSpecID, Language};
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct MockSettings {
        strings: RefCell<HashMap<String, String>>,
    }

    impl MockSettings {
        fn new() -> Self {
            MockSettings {
                strings: RefCell::new(HashMap::new()),
            }
        }
    }

    impl Settings for MockSettings {
        fn get_string(&self, name: &str) -> Option<String> {
            self.strings.borrow().get(name).cloned()
        }

        fn set_string(&mut self, name: &str, value: &str) {
            self.strings.borrow_mut().insert(name.to_string(), value.to_string());
        }

        fn clear_setting(&mut self, name: &str) {
            self.strings.borrow_mut().remove(name);
        }

        fn is_empty(&self) -> bool {
            self.strings.borrow().is_empty()
        }
    }

    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }
    }

    struct MockCompilerSpec;

    impl CompilerSpec for MockCompilerSpec {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("gcc"))
        }
    }

    struct MockProgramArchitecture {
        factory: DefaultAddressFactory,
    }

    impl ProgramArchitecture for MockProgramArchitecture {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }

        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(self.factory.clone())
        }

        fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            Box::new(MockCompilerSpec)
        }
    }

    struct MockDataTypeManager {
        architecture: Option<MockProgramArchitecture>,
    }

    impl DataTypeManager for MockDataTypeManager {
        fn get_program_architecture(&self) -> Option<Box<dyn ProgramArchitecture>> {
            self.architecture
                .as_ref()
                .map(|_| -> Box<dyn ProgramArchitecture> {
                    Box::new(MockProgramArchitecture {
                        factory: self.architecture.as_ref().unwrap().factory.clone(),
                    })
                })
        }
    }

    #[test]
    fn get_value_returns_none_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(
            AddressSpaceSettingsDefinition::DEF.get_value(&settings),
            None
        );
    }

    #[test]
    fn set_value_then_get_value_round_trips() {
        let mut settings = MockSettings::new();
        let def = AddressSpaceSettingsDefinition::DEF;

        def.set_value(&mut settings, "ram");
        assert_eq!(def.get_value(&settings), Some("ram".to_string()));
    }

    #[test]
    fn set_value_with_blank_string_clears_setting() {
        let mut settings = MockSettings::new();
        let def = AddressSpaceSettingsDefinition::DEF;

        def.set_value(&mut settings, "ram");
        assert!(def.has_value(&settings));

        def.set_value(&mut settings, "   ");
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = AddressSpaceSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_value(&mut settings, "ram");
        assert!(def.has_value(&settings));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = AddressSpaceSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Address Space");
        assert_eq!(def.get_storage_key(), "addr_space_name");
        assert_eq!(
            def.get_description(),
            "Identifies the referenced address space name (case-sensitive; ignored if no match)"
        );
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = AddressSpaceSettingsDefinition::DEF;

        def.set_value(&mut settings, "ram");
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = AddressSpaceSettingsDefinition::DEF;

        def.set_value(&mut src, "ram");
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_value(&dest), Some("ram".to_string()));
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = AddressSpaceSettingsDefinition::DEF;

        def.set_value(&mut dest, "ram");
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn get_attribute_specification_returns_none_when_unset() {
        let settings = MockSettings::new();
        let def = AddressSpaceSettingsDefinition::DEF;

        assert_eq!(def.get_attribute_specification(&settings), None);
    }

    #[test]
    fn get_attribute_specification_returns_none_for_blank_value() {
        let mut settings = MockSettings::new();
        let def = AddressSpaceSettingsDefinition::DEF;

        // Directly force a blank value into settings, bypassing set_value's own blank check.
        settings.set_string(ADDRESS_SPACE_SETTING_NAME, "   ");
        assert_eq!(def.get_attribute_specification(&settings), None);
    }

    #[test]
    fn get_attribute_specification_wraps_space_name() {
        let mut settings = MockSettings::new();
        let def = AddressSpaceSettingsDefinition::DEF;

        def.set_value(&mut settings, "ram");
        assert_eq!(
            def.get_attribute_specification(&settings),
            Some("space(ram)".to_string())
        );
    }

    #[test]
    fn supports_suggested_values_is_true() {
        assert!(AddressSpaceSettingsDefinition::DEF.supports_suggested_values());
    }

    #[test]
    fn add_preferred_values_returns_false_for_unsupported_owner() {
        let def = AddressSpaceSettingsDefinition::DEF;
        let mut set = HashSet::new();

        assert!(!def.add_preferred_values(None, &mut set));
        assert!(set.is_empty());
    }

    #[test]
    fn add_preferred_values_returns_true_without_architecture() {
        let def = AddressSpaceSettingsDefinition::DEF;
        let mut set = HashSet::new();

        let dtm: Box<dyn DataTypeManager> = Box::new(MockDataTypeManager { architecture: None });
        let owner: &dyn Any = &dtm;

        assert!(def.add_preferred_values(Some(owner), &mut set));
        assert!(set.is_empty());
    }

    #[test]
    fn add_preferred_values_collects_loaded_memory_spaces() {
        let def = AddressSpaceSettingsDefinition::DEF;
        let mut set = HashSet::new();

        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let constant = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 1);
        let factory = DefaultAddressFactory::new(vec![ram, constant]);

        let dtm: Box<dyn DataTypeManager> = Box::new(MockDataTypeManager {
            architecture: Some(MockProgramArchitecture { factory }),
        });
        let owner: &dyn Any = &dtm;

        assert!(def.add_preferred_values(Some(owner), &mut set));
        assert_eq!(set.len(), 1);
        assert!(set.contains("ram"));
    }
}

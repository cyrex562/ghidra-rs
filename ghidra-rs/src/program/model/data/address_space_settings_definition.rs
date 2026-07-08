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
    use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::lang::compiler_spec::EvaluationModelType;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::lang::{CompilerSpec, Language, ProgramArchitecture};
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::seam_stubs::{
        CompilerSpecDescription, CompilerSpecID, Encoder, PcodeInjectLibrary, PrototypeModel,
    };
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

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

        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::seam_stubs::LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::seam_stubs::ParallelInstructionLanguageHelper>> {
            None
        }

        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_data_space(
            &self,
        ) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_instruction_alignment(&self) -> i32 {
            1
        }

        fn supports_pcode(&self) -> bool {
            true
        }

        fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
            false
        }

        fn parse(
            &self,
            _buf: &dyn crate::program::seam_stubs::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }

        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }

        fn get_registers_at(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register_in_space(
            &self,
            _addrspc: &std::sync::Arc<crate::program::model::address::AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_register_by_name(
            &self,
            _name: &str,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_register_at(
            &self,
            _addr: &crate::program::model::address::Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_context_base_register(
            &self,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::program::seam_stubs::MemoryBlockDefinition>> {
            Vec::new()
        }

        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }

        fn get_segmented_space(&self) -> String {
            String::new()
        }

        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }

        fn reload_language(
            &self,
            _task_monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::seam_stubs::CompilerSpecDescription>> {
            Vec::new()
        }

        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::seam_stubs::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }

        fn has_property(&self, _key: &str) -> bool {
            false
        }

        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }

        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }

        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }

        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }

        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }

        fn has_manual(&self) -> bool {
            false
        }

        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }

        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }

        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }

        fn get_sorted_vector_registers(
            &self,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct MockCompilerSpecDescription;
    impl CompilerSpecDescription for MockCompilerSpecDescription {}

    struct MockPcodeInjectLibrary;
    impl PcodeInjectLibrary for MockPcodeInjectLibrary {}

    struct MockPrototypeModel;
    impl PrototypeModel for MockPrototypeModel {}

    struct MockCompilerSpec;

    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }

        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            Box::new(MockCompilerSpecDescription)
        }

        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("gcc"))
        }

        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            None
        }

        fn is_stack_right_justified(&self) -> bool {
            false
        }

        fn get_address_space(&self, _space_name: &str) -> Option<Arc<AddressSpace>> {
            None
        }

        fn get_stack_space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
        }

        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            self.get_stack_space()
        }

        fn stack_grows_negative(&self) -> bool {
            true
        }

        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}

        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }

        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }

        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn get_decompiler_output_language(&self) -> DecompilerLanguage {
            DecompilerLanguage::CLanguage
        }

        fn get_prototype_evaluation_model(
            &self,
            _model_type: EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }

        fn is_global(&self, _addr: &Address) -> bool {
            false
        }

        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            Box::new(MockPcodeInjectLibrary)
        }

        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }

        fn find_best_calling_convention(
            &self,
            _params: &[&dyn Parameter],
        ) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }

        fn has_property(&self, _key: &str) -> bool {
            false
        }

        fn does_c_data_type_conversions(&self) -> bool {
            true
        }

        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }

        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }

        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }

        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }

        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }

        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }

        fn is_equivalent(&self, other: &dyn CompilerSpec) -> bool {
            self.get_compiler_spec_id() == other.get_compiler_spec_id()
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

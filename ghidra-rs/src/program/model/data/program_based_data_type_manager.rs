use std::any::Any;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::domain_file_based_data_type_manager::DomainFileBasedDataTypeManager;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::program::Program;
use crate::program::seam_stubs::SettingsDefinition;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Extends [`DomainFileBasedDataTypeManager`] to include methods specific to a data type manager
/// for a program.
///
/// Port of `ghidra.program.model.data.ProgramBasedDataTypeManager`.
pub trait ProgramBasedDataTypeManager: DomainFileBasedDataTypeManager {
    /// Get the program instance associated with this datatype manager.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Determine if a settings change is permitted for the specified settings definition.
    fn is_change_allowed(
        &self,
        data: &dyn Data,
        settings_definition: &dyn SettingsDefinition,
    ) -> bool;

    /// Set the long value for data instance settings. Returns true if the settings actually
    /// changed.
    fn set_long_settings_value(&mut self, data: &dyn Data, name: &str, value: i64) -> bool;

    /// Set the string value for data instance settings. Returns true if the settings actually
    /// changed.
    fn set_string_settings_value(&mut self, data: &dyn Data, name: &str, value: &str) -> bool;

    /// Set the value for data instance settings. `value` must be either a `String`, byte
    /// buffer, or `i64`. Returns true if the settings were updated.
    fn set_settings(&mut self, data: &dyn Data, name: &str, value: Box<dyn Any>) -> bool;

    /// Get the long value for data instance settings, or `None` if the named setting was not
    /// found.
    fn get_long_settings_value(&self, data: &dyn Data, name: &str) -> Option<i64>;

    /// Get the string value for data instance settings, or `None` if the named setting was not
    /// found.
    fn get_string_settings_value(&self, data: &dyn Data, name: &str) -> Option<String>;

    /// Gets the value for data instance settings in `Object` form.
    fn get_settings(&self, data: &dyn Data, name: &str) -> Option<Box<dyn Any>>;

    /// Clear the specified setting for the given data. Returns true if the settings were
    /// cleared.
    fn clear_setting(&mut self, data: &dyn Data, name: &str) -> bool;

    /// Clear all settings for the given data.
    fn clear_all_settings(&mut self, data: &dyn Data);

    /// Returns all the instance settings names used for the specified data.
    fn get_instance_settings_names(&self, data: &dyn Data) -> Vec<String>;

    /// Returns true if no settings are set for the given data.
    fn is_empty_setting(&self, data: &dyn Data) -> bool;

    /// Move the settings in the range to the new start address.
    ///
    /// # Errors
    /// Returns `Err` if the operation was cancelled.
    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: i64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Removes all settings in the range.
    ///
    /// # Errors
    /// Returns `Err` if the user cancelled the operation.
    fn delete_address_range(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager;
    use crate::program::seam_stubs::{CodeUnit, DomainFile, RefType, Reference, Settings};
    use std::any::TypeId;

    struct MockProgram;
    impl Program for MockProgram {
        fn get_name(&self) -> &str {
            "test.bin"
        }
        fn get_language_id(&self) -> &str {
            "test:LE:32:default"
        }
    }

    struct MockDomainFile;
    impl DomainFile for MockDomainFile {}

    struct MockSettingsDefinition;
    impl SettingsDefinition for MockSettingsDefinition {}

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockData;
    impl CodeUnit for MockData {}
    impl Settings for MockData {}
    impl Data for MockData {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            None
        }
        fn get_value_class(&self) -> Option<TypeId> {
            None
        }
        fn has_string_value(&self) -> bool {
            false
        }
        fn is_constant(&self) -> bool {
            false
        }
        fn is_writable(&self) -> bool {
            true
        }
        fn is_volatile(&self) -> bool {
            false
        }
        fn is_defined(&self) -> bool {
            true
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            "mock".to_string()
        }
        fn get_component_path_name(&self) -> String {
            String::new()
        }
        fn is_pointer(&self) -> bool {
            false
        }
        fn is_union(&self) -> bool {
            false
        }
        fn is_structure(&self) -> bool {
            false
        }
        fn is_array(&self) -> bool {
            false
        }
        fn is_dynamic(&self) -> bool {
            false
        }
        fn get_parent(&self) -> Option<Box<dyn Data>> {
            None
        }
        fn get_root(&self) -> Box<dyn Data> {
            Box::new(MockData)
        }
        fn get_root_offset(&self) -> i32 {
            0
        }
        fn get_parent_offset(&self) -> i32 {
            0
        }
        fn get_component(&self, _index: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_path(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_num_components(&self) -> i32 {
            0
        }
        #[allow(deprecated)]
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> {
            None
        }
        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_index(&self) -> i32 {
            -1
        }
        fn get_component_level(&self) -> i32 {
            0
        }
        fn get_default_value_representation(&self) -> String {
            String::new()
        }
        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> {
            None
        }
    }

    struct MockProgramDataTypeManager {
        path: String,
    }

    impl DataTypeManager for MockProgramDataTypeManager {}

    impl FileBasedDataTypeManager for MockProgramDataTypeManager {
        fn get_path(&self) -> String {
            self.path.clone()
        }
    }

    impl DomainFileBasedDataTypeManager for MockProgramDataTypeManager {
        fn get_domain_file(&self) -> Box<dyn DomainFile> {
            Box::new(MockDomainFile)
        }
    }

    impl ProgramBasedDataTypeManager for MockProgramDataTypeManager {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }

        fn is_change_allowed(
            &self,
            _data: &dyn Data,
            _settings_definition: &dyn SettingsDefinition,
        ) -> bool {
            true
        }

        fn set_long_settings_value(&mut self, _data: &dyn Data, _name: &str, _value: i64) -> bool {
            true
        }

        fn set_string_settings_value(&mut self, _data: &dyn Data, _name: &str, _value: &str) -> bool {
            true
        }

        fn set_settings(&mut self, _data: &dyn Data, _name: &str, _value: Box<dyn Any>) -> bool {
            true
        }

        fn get_long_settings_value(&self, _data: &dyn Data, _name: &str) -> Option<i64> {
            None
        }

        fn get_string_settings_value(&self, _data: &dyn Data, _name: &str) -> Option<String> {
            None
        }

        fn get_settings(&self, _data: &dyn Data, _name: &str) -> Option<Box<dyn Any>> {
            None
        }

        fn clear_setting(&mut self, _data: &dyn Data, _name: &str) -> bool {
            true
        }

        fn clear_all_settings(&mut self, _data: &dyn Data) {}

        fn get_instance_settings_names(&self, _data: &dyn Data) -> Vec<String> {
            Vec::new()
        }

        fn is_empty_setting(&self, _data: &dyn Data) -> bool {
            true
        }

        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: i64,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn delete_address_range(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut mgr = MockProgramDataTypeManager {
            path: "/tmp/prog.gpr".to_string(),
        };
        let data = MockData;
        let settings_def = MockSettingsDefinition;

        let dyn_mgr: &mut dyn ProgramBasedDataTypeManager = &mut mgr;
        assert_eq!(dyn_mgr.get_path(), "/tmp/prog.gpr");
        assert_eq!(dyn_mgr.get_program().get_name(), "test.bin");
        assert!(dyn_mgr.is_change_allowed(&data, &settings_def));
        assert!(dyn_mgr.set_long_settings_value(&data, "size", 4));
        assert!(dyn_mgr.is_empty_setting(&data));
    }
}

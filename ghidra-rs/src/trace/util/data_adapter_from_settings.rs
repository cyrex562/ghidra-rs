use crate::program::model::listing::Data;
use crate::program::model::data::mutability_settings_definition::{
    MutabilitySettingsDefinition, CONSTANT, WRITABLE, VOLATILE,
};
use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;

/// Adapter providing settings-based metadata for data implementations.
///
/// Provides default implementations for checking mutability settings on data.
/// When a data implementation needs to support the mutability settings (constant,
/// writable, volatile), this trait can be implemented to provide sensible defaults.
///
/// Port of `ghidra.trace.util.DataAdapterFromSettings`.
pub trait DataAdapterFromSettings: Data {
    /// Get the settings definition of a specified type.
    ///
    /// Searches the base data type's settings definitions for one that is an instance
    /// of the specified type. Returns the first matching definition, or `None` if no
    /// match is found.
    ///
    /// # Arguments
    /// * `check` - A closure that takes a reference to a settings definition and returns
    ///   `true` if it matches the desired type.
    ///
    /// # Returns
    /// A reference to the first matching settings definition, or `None` if no match found.
    fn get_settings_definition<F>(
        &self,
        check: F,
    ) -> Option<std::sync::Arc<dyn crate::docking::settings::settings_definition::SettingsDefinition>>
    where
        F: Fn(&dyn crate::docking::settings::settings_definition::SettingsDefinition) -> bool,
    {
        let dt = self.get_base_data_type();
        let defs = dt.get_settings_definitions();
        defs.into_iter()
            .find(|def| check(def.as_ref()))
            .map(|def| {
                // Convert Box<dyn SettingsDefinition> to Arc<dyn SettingsDefinition>
                // by wrapping in Arc
                std::sync::Arc::from(def)
            })
    }

    /// Check if this data has a specific mutability setting.
    ///
    /// # Arguments
    /// * `mutability_type` - The mutability type to check (CONSTANT, WRITABLE, or VOLATILE).
    ///
    /// # Returns
    /// `true` if the data has the specified mutability setting, `false` otherwise.
    fn has_mutability(&self, mutability_type: i32) -> bool
    where
        Self: Sized,
    {
        let dt = self.get_base_data_type();
        let defs = dt.get_settings_definitions();

        for def in defs.iter() {
            // Check if this is a MutabilitySettingsDefinition by checking its name or storage key
            if def.get_storage_key() == "mutability" {
                // We found the MutabilitySettingsDefinition, now check if it implements
                // EnumSettingsDefinition. Since we can't downcast trait objects directly,
                // we'll check by checking if we can get a choice.
                // For now, we'll use a simpler approach: directly check the mutability mode
                // using the MutabilitySettingsDefinition::DEF singleton
                let def_singleton = MutabilitySettingsDefinition::DEF;
                let choice = def_singleton.get_choice(self);
                return choice == mutability_type;
            }
        }
        false
    }

    /// Determine if this data has been marked as constant.
    ///
    /// Returns `true` if the mutability setting is CONSTANT.
    fn is_constant(&self) -> bool
    where
        Self: Sized,
    {
        self.has_mutability(CONSTANT)
    }

    /// Determine if this data has been marked as writable.
    ///
    /// Returns `true` if the mutability setting is WRITABLE.
    fn is_writable(&self) -> bool
    where
        Self: Sized,
    {
        self.has_mutability(WRITABLE)
    }

    /// Determine if this data has been marked as volatile.
    ///
    /// Returns `true` if the mutability setting is VOLATILE.
    fn is_volatile(&self) -> bool
    where
        Self: Sized,
    {
        self.has_mutability(VOLATILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::{Any, TypeId};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::symbol::{RefType, ReferenceIterator, SourceType, Symbol};
    use crate::program::model::util::PropertySet;
    use crate::program::model::listing::program::Program;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::lang::register::Register;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::seam_stubs::{CommentType, MemBuffer, Reference};
    use std::sync::Arc;

    fn create_test_address_space() -> Arc<AddressSpace> {
        AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    struct MockDataType {
        settings_defs: Vec<Box<dyn crate::docking::settings::settings_definition::SettingsDefinition>>,
    }

    impl DataType for MockDataType {
        fn get_settings_definitions(
            &self,
        ) -> Vec<Box<dyn crate::docking::settings::settings_definition::SettingsDefinition>> {
            // Clone the definitions for testing
            self.settings_defs
                .iter()
                .map(|def| Box::new(MockSettingsDefinition) as Box<dyn crate::docking::settings::settings_definition::SettingsDefinition>)
                .collect()
        }
    }

    struct MockSettingsDefinition;

    impl crate::docking::settings::settings_definition::SettingsDefinition for MockSettingsDefinition {
        fn get_storage_key(&self) -> String {
            "mutability".to_string()
        }
    }

    struct MockData {
        address: Address,
        constant: bool,
        writable: bool,
        volatile: bool,
    }

    impl MemBuffer for MockData {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_bytes(
            &self,
            _start: i32,
            _end: i32,
        ) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![])
        }

        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }

        fn get_short(&self, _offset: i32) -> Result<u16, MemoryAccessException> {
            Ok(0)
        }

        fn get_int(&self, _offset: i32) -> Result<u32, MemoryAccessException> {
            Ok(0)
        }

        fn get_long(&self, _offset: i32) -> Result<u64, MemoryAccessException> {
            Ok(0)
        }

        fn get_var_length(&self) -> i32 {
            1
        }
    }

    impl PropertySet for MockData {
        fn get_property(&self, _property_name: &str) -> Option<Box<dyn Any>> {
            None
        }

        fn set_property(&mut self, _property_name: &str, _property_value: Box<dyn Any>) {}

        fn delete_property(&mut self, _property_name: &str) {}
    }

    impl Settings for MockData {
        fn get_value(&self, key: &str) -> Box<dyn Any> {
            if key == "mutability" {
                if self.constant {
                    Box::new(Some(CONSTANT as i64))
                } else if self.writable {
                    Box::new(Some(WRITABLE as i64))
                } else if self.volatile {
                    Box::new(Some(VOLATILE as i64))
                } else {
                    Box::new(None::<i64>)
                }
            } else {
                Box::new(None::<i64>)
            }
        }

        fn set_value(&mut self, _key: &str, _value: Box<dyn Any>) {}

        fn get_names(&self) -> Vec<String> {
            vec![]
        }

        fn copy_settings(&mut self, _src: &dyn Settings) {}

        fn clear(&mut self) {}

        fn get_default_value(&self, _key: &str) -> Box<dyn Any> {
            Box::new(None::<i32>)
        }

        fn contains(&self, _key: &str) -> bool {
            false
        }

        fn to_string(&self) -> String {
            String::new()
        }

        fn is_immutable(&self) -> bool {
            false
        }

        fn get_long(&self, key: &str) -> Option<i64> {
            if key == "mutability" {
                if self.constant {
                    Some(CONSTANT as i64)
                } else if self.writable {
                    Some(WRITABLE as i64)
                } else if self.volatile {
                    Some(VOLATILE as i64)
                } else {
                    None
                }
            } else {
                None
            }
        }

        fn set_long(&mut self, key: &str, value: i64) {
            if key == "mutability" {
                let mode = value as i32;
                self.constant = mode == CONSTANT;
                self.writable = mode == WRITABLE;
                self.volatile = mode == VOLATILE;
            }
        }

        fn clear_setting(&mut self, _key: &str) {}
    }

    impl CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "00001000".to_string()
        }

        fn get_label(&self) -> Option<String> {
            None
        }

        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            vec![]
        }

        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }

        fn get_min_address(&self) -> Address {
            self.address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.address.clone()
        }

        fn get_mnemonic_string(&self) -> String {
            String::new()
        }

        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            vec![]
        }

        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}

        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}

        fn get_length(&self) -> i32 {
            1
        }

        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![])
        }

        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }

        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }

        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }

        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            vec![]
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            vec![]
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            vec![]
        }

        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            todo!()
        }

        fn get_program(&self) -> Arc<dyn Program> {
            todo!()
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn crate::program::model::symbol::ExternalReference>> {
            None
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}

        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn get_num_operands(&self) -> i32 {
            1
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, _op_index: i32) -> Option<crate::program::model::scalar::Scalar> {
            None
        }
    }

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
            todo!()
        }

        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType {
                settings_defs: vec![Box::new(MockSettingsDefinition)],
            })
        }

        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            vec![]
        }

        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {}

        fn remove_value_reference(&mut self, _ref_addr: Address) {}

        fn get_field_name(&self) -> Option<String> {
            None
        }

        fn get_path_name(&self) -> String {
            String::new()
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
            Box::new(MockData {
                address: self.address.clone(),
                constant: self.constant,
                writable: self.writable,
                volatile: self.volatile,
            })
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
            vec![]
        }

        fn get_num_components(&self) -> i32 {
            0
        }

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

        fn get_default_label_prefix(
            &self,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
    }

    impl DataAdapterFromSettings for MockData {}

    #[test]
    fn test_is_constant_true() {
        let space = create_test_address_space();
        let data = MockData {
            address: addr(&space, 0x1000),
            constant: true,
            writable: false,
            volatile: false,
        };

        assert!(data.is_constant());
    }

    #[test]
    fn test_is_constant_false() {
        let space = create_test_address_space();
        let data = MockData {
            address: addr(&space, 0x1000),
            constant: false,
            writable: true,
            volatile: false,
        };

        assert!(!data.is_constant());
    }

    #[test]
    fn test_is_writable_true() {
        let space = create_test_address_space();
        let data = MockData {
            address: addr(&space, 0x1000),
            constant: false,
            writable: true,
            volatile: false,
        };

        assert!(data.is_writable());
    }

    #[test]
    fn test_is_writable_false() {
        let space = create_test_address_space();
        let data = MockData {
            address: addr(&space, 0x1000),
            constant: true,
            writable: false,
            volatile: false,
        };

        assert!(!data.is_writable());
    }

    #[test]
    fn test_is_volatile_true() {
        let space = create_test_address_space();
        let data = MockData {
            address: addr(&space, 0x1000),
            constant: false,
            writable: false,
            volatile: true,
        };

        assert!(data.is_volatile());
    }

    #[test]
    fn test_is_volatile_false() {
        let space = create_test_address_space();
        let data = MockData {
            address: addr(&space, 0x1000),
            constant: true,
            writable: false,
            volatile: false,
        };

        assert!(!data.is_volatile());
    }

    #[test]
    fn test_has_mutability_constant() {
        let space = create_test_address_space();
        let data = MockData {
            address: addr(&space, 0x1000),
            constant: true,
            writable: false,
            volatile: false,
        };

        assert!(data.has_mutability(CONSTANT));
        assert!(!data.has_mutability(WRITABLE));
        assert!(!data.has_mutability(VOLATILE));
    }

    #[test]
    fn test_has_mutability_writable() {
        let space = create_test_address_space();
        let data = MockData {
            address: addr(&space, 0x1000),
            constant: false,
            writable: true,
            volatile: false,
        };

        assert!(!data.has_mutability(CONSTANT));
        assert!(data.has_mutability(WRITABLE));
        assert!(!data.has_mutability(VOLATILE));
    }

    #[test]
    fn test_has_mutability_volatile() {
        let space = create_test_address_space();
        let data = MockData {
            address: addr(&space, 0x1000),
            constant: false,
            writable: false,
            volatile: true,
        };

        assert!(!data.has_mutability(CONSTANT));
        assert!(!data.has_mutability(WRITABLE));
        assert!(data.has_mutability(VOLATILE));
    }
}

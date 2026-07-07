use crate::program::model::listing::Data;
use crate::program::model::symbol::Reference;
use std::sync::Arc;

/// Operand index for data. Will always be zero.
pub const DATA_OP_INDEX: i32 = 0;

/// Empty integer array.
pub const EMPTY_INT_ARRAY: &[i32] = &[];

/// Minimal adapter for Data implementations.
///
/// Provides default implementations for core data methods. When a data implementation
/// needs only basic functionality, this trait can be implemented to provide sensible
/// defaults for operand handling and symbol naming.
///
/// Port of `ghidra.trace.util.DataAdapterMinimal`.
pub trait DataAdapterMinimal: Data {
    /// Returns the primary symbol name or generates a dynamic name based on the address.
    ///
    /// The dynamic name follows the pattern `DAT_<address>` if no primary symbol is found.
    fn get_primary_symbol_or_dynamic_name(&self) -> String {
        self.get_primary_symbol()
            .map(|s| s.get_name().to_string())
            .unwrap_or_else(|| {
                format!(
                    "DAT_{}",
                    self.get_address_string(false, false)
                )
            })
    }

    /// Returns the number of operands for this data.
    ///
    /// Data has exactly one operand: its value.
    fn get_num_operands(&self) -> i32 {
        1
    }

    /// Returns the references for the data value.
    ///
    /// This delegates to `get_operand_references` with the data operand index.
    fn get_value_references(&self) -> Vec<Arc<dyn Reference>> {
        self.get_operand_references(DATA_OP_INDEX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, Address};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{RefType, ReferenceIterator, SourceType, Symbol};
    use crate::program::model::util::PropertySet;
    use crate::program::model::listing::program::Program;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::lang::register::Register;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::seam_stubs::{CommentType, MemBuffer};
    use std::any::{Any, TypeId};
    use std::sync::Arc;

    fn create_test_address_space() -> Arc<AddressSpace> {
        AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    struct MockSymbol {
        name: String,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            let space = create_test_address_space();
            addr(&space, 0x1000)
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_symbol_type(&self) -> crate::program::model::symbol::SymbolType {
            crate::program::model::symbol::SymbolType::Label
        }

        fn get_source(&self) -> SourceType {
            SourceType::Analysis
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn get_id(&self) -> i64 {
            1
        }

        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockDataAdapterMinimal {
        has_symbol: bool,
        symbol_name: String,
        address: Address,
    }

    impl MemBuffer for MockDataAdapterMinimal {
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

        fn get_short(
            &self,
            _offset: i32,
        ) -> Result<u16, MemoryAccessException> {
            Ok(0)
        }

        fn get_int(&self, _offset: i32) -> Result<u32, MemoryAccessException> {
            Ok(0)
        }

        fn get_long(
            &self,
            _offset: i32,
        ) -> Result<u64, MemoryAccessException> {
            Ok(0)
        }

        fn get_var_length(&self) -> i32 {
            1
        }
    }

    impl PropertySet for MockDataAdapterMinimal {
        fn get_property(&self, _property_name: &str) -> Option<Box<dyn Any>> {
            None
        }

        fn set_property(&mut self, _property_name: &str, _property_value: Box<dyn Any>) {}

        fn delete_property(&mut self, _property_name: &str) {}
    }

    impl Settings for MockDataAdapterMinimal {
        fn get_value(&self, _key: &str) -> Box<dyn Any> {
            Box::new(None::<i32>)
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
    }

    impl CodeUnit for MockDataAdapterMinimal {
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
            if self.has_symbol {
                Some(Arc::new(MockSymbol {
                    name: self.symbol_name.clone(),
                }))
            } else {
                None
            }
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

        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl Data for MockDataAdapterMinimal {
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
            todo!()
        }

        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            vec![]
        }

        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn crate::program::seam_stubs::RefType>) {}

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
            Box::new(MockDataAdapterMinimal {
                has_symbol: self.has_symbol,
                symbol_name: self.symbol_name.clone(),
                address: self.address.clone(),
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

    impl DataAdapterMinimal for MockDataAdapterMinimal {}

    #[test]
    fn test_get_num_operands() {
        let space = create_test_address_space();
        let mock = MockDataAdapterMinimal {
            has_symbol: false,
            symbol_name: String::new(),
            address: addr(&space, 0x1000),
        };

        assert_eq!(mock.get_num_operands(), 1);
    }

    #[test]
    fn test_get_primary_symbol_or_dynamic_name_with_symbol() {
        let space = create_test_address_space();
        let mock = MockDataAdapterMinimal {
            has_symbol: true,
            symbol_name: "my_data".to_string(),
            address: addr(&space, 0x1000),
        };

        assert_eq!(mock.get_primary_symbol_or_dynamic_name(), "my_data");
    }

    #[test]
    fn test_get_primary_symbol_or_dynamic_name_without_symbol() {
        let space = create_test_address_space();
        let mock = MockDataAdapterMinimal {
            has_symbol: false,
            symbol_name: String::new(),
            address: addr(&space, 0x1000),
        };

        let name = mock.get_primary_symbol_or_dynamic_name();
        assert!(name.starts_with("DAT_"));
        assert!(name.contains("00001000"));
    }

    #[test]
    fn test_get_value_references() {
        let space = create_test_address_space();
        let mock = MockDataAdapterMinimal {
            has_symbol: false,
            symbol_name: String::new(),
            address: addr(&space, 0x1000),
        };

        let refs = mock.get_value_references();
        assert_eq!(refs.len(), 0);
    }

    #[test]
    fn test_data_op_index_constant() {
        assert_eq!(DATA_OP_INDEX, 0);
    }

    #[test]
    fn test_empty_int_array_constant() {
        assert_eq!(EMPTY_INT_ARRAY.len(), 0);
    }
}

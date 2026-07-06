use crate::program::model::listing::Data;

/// Iterator over a sequence of Data items.
///
/// This trait mirrors Ghidra's `DataIterator`, which combines the behavior of both
/// Iterator and Iterable in Java. Implementations should provide efficient iteration
/// over Data elements.
pub trait DataIterator: Iterator<Item = Box<dyn Data>> {}

/// Empty data iterator with no items.
#[derive(Debug, Clone, Copy)]
pub struct EmptyDataIterator;

impl Iterator for EmptyDataIterator {
    type Item = Box<dyn Data>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl DataIterator for EmptyDataIterator {}

/// List-based data iterator.
///
/// Wraps a vector of Data items and iterates over them by consuming ownership.
pub struct ListDataIterator {
    iter: std::vec::IntoIter<Box<dyn Data>>,
}

impl ListDataIterator {
    /// Creates a new iterator over the supplied data items.
    pub fn new(items: Vec<Box<dyn Data>>) -> Self {
        Self {
            iter: items.into_iter(),
        }
    }
}

impl Iterator for ListDataIterator {
    type Item = Box<dyn Data>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl DataIterator for ListDataIterator {}

/// Creates an empty data iterator.
pub fn empty() -> Box<dyn DataIterator> {
    Box::new(EmptyDataIterator)
}

/// Creates a data iterator from a vector of data items.
pub fn of(items: Vec<Box<dyn Data>>) -> Box<dyn DataIterator> {
    Box::new(ListDataIterator::new(items))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::Symbol;
    use crate::program::seam_stubs::{CommentType, ExternalReference, MemBuffer, PropertySet, RefType, Reference, Settings};
    use std::any::{Any, TypeId};
    use std::sync::Arc;

    struct MockData;

    impl MemBuffer for MockData {}
    impl PropertySet for MockData {}

    impl CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "00000000".to_string()
        }

        fn get_label(&self) -> Option<String> {
            None
        }

        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }

        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }

        fn get_min_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }

        fn get_max_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }

        fn get_mnemonic_string(&self) -> String {
            String::new()
        }

        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }

        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}

        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}

        fn get_length(&self) -> i32 {
            1
        }

        fn get_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
            Ok(Vec::new())
        }

        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
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
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {
        }

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {
        }

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_references_from(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_reference_iterator_to(&self) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }

        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            struct MockProgram;
            impl crate::program::model::listing::Program for MockProgram {
                fn get_name(&self) -> &str {
                    "mock.bin"
                }

                fn get_language_id(&self) -> &str {
                    "test:LE:32:default"
                }
            }
            Arc::new(MockProgram)
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn crate::program::model::symbol::Reference>) {}

        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }

        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
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
            struct MockDataType;
            impl DataType for MockDataType {}
            Box::new(MockDataType)
        }

        fn get_base_data_type(&self) -> Box<dyn DataType> {
            struct MockDataType;
            impl DataType for MockDataType {}
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

        fn get_default_label_prefix(
            &self,
            _options: &dyn crate::program::model::data::data_type_display_options::DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
    }

    #[test]
    fn empty_iterator_returns_none() {
        let mut iterator = EmptyDataIterator;
        assert!(iterator.next().is_none());
    }

    #[test]
    fn empty_from_factory_returns_none() {
        let mut iterator = empty();
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_iterator_yields_items() {
        let items: Vec<Box<dyn Data>> = vec![Box::new(MockData), Box::new(MockData)];
        let mut iterator = ListDataIterator::new(items);

        assert!(iterator.next().is_some());
        assert!(iterator.next().is_some());
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_from_factory_yields_items() {
        let items: Vec<Box<dyn Data>> = vec![Box::new(MockData), Box::new(MockData)];
        let mut iterator = of(items);

        assert!(iterator.next().is_some());
        assert!(iterator.next().is_some());
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_iterator_empty_list() {
        let items: Vec<Box<dyn Data>> = vec![];
        let mut iterator = ListDataIterator::new(items);

        assert!(iterator.next().is_none());
    }
}

use crate::program::model::listing::Data;
use crate::program::model::listing::DataIterator;

/// Wraps an iterator to implement the [`DataIterator`] interface.
///
/// Analogous to Java's `ghidra.trace.util.WrappingDataIterator`. This provides
/// a generic wrapper for any iterator over Data elements, allowing it to be used as a [`DataIterator`].
pub struct WrappingDataIterator<I: Iterator<Item = Box<dyn Data>>> {
    iter: I,
}

impl<I: Iterator<Item = Box<dyn Data>>> WrappingDataIterator<I> {
    /// Creates a new wrapping iterator.
    ///
    /// # Arguments
    /// * `iter` - The iterator to wrap
    pub fn new(iter: I) -> Self {
        Self { iter }
    }
}

impl<I: Iterator<Item = Box<dyn Data>>> Iterator for WrappingDataIterator<I> {
    type Item = Box<dyn Data>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<I: Iterator<Item = Box<dyn Data>>> DataIterator for WrappingDataIterator<I> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::{Any, TypeId};
    use std::sync::Arc;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::docking::settings::settings::Settings;
    use crate::program::seam_stubs::{CommentType, MemBuffer};

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockData;

    impl MemBuffer for MockData {
        fn get_address(&self) -> Address {
            mock_address(0)
        }
    }

    impl PropertySet for MockData {}

    impl Settings for MockData {}

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
            mock_address(0)
        }

        fn get_max_address(&self) -> Address {
            mock_address(0)
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

        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
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
            Vec::new()
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
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
            Vec::new()
        }

        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
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
            0
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
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

        fn get_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
            struct MockDataType;
            impl crate::program::model::data::data_type::DataType for MockDataType {}
            Box::new(MockDataType)
        }

        fn get_base_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
            struct MockDataType;
            impl crate::program::model::data::data_type::DataType for MockDataType {}
            Box::new(MockDataType)
        }

        fn get_value_references(&self) -> Vec<Box<dyn crate::program::seam_stubs::Reference>> {
            Vec::new()
        }

        fn add_value_reference(&mut self, _ref_addr: crate::program::model::address::Address, _ref_type: Box<dyn crate::program::seam_stubs::RefType>) {}

        fn remove_value_reference(&mut self, _ref_addr: crate::program::model::address::Address) {}

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
    fn wraps_iterator_delegates_to_inner() {
        let data: Vec<Box<dyn Data>> = vec![Box::new(MockData), Box::new(MockData), Box::new(MockData)];
        let mut it = WrappingDataIterator::new(data.into_iter());
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_none());
    }

    #[test]
    fn wraps_empty_iterator() {
        let data: Vec<Box<dyn Data>> = vec![];
        let mut it = WrappingDataIterator::new(data.into_iter());
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_iterator_returns_none_after_exhaustion() {
        let data: Vec<Box<dyn Data>> = vec![Box::new(MockData)];
        let mut it = WrappingDataIterator::new(data.into_iter());
        assert!(it.next().is_some());
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None);
    }
}

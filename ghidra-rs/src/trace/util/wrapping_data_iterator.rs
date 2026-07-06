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

    struct MockData;

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

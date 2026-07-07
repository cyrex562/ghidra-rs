use crate::program::model::listing::{Function, FunctionIterator};
use std::sync::Arc;

/// Wraps an iterator to implement the [`FunctionIterator`] interface.
///
/// Analogous to Java's `ghidra.trace.util.WrappingFunctionIterator`. This provides
/// a generic wrapper for any iterator over Function elements, allowing it to be used as a [`FunctionIterator`].
pub struct WrappingFunctionIterator<I: Iterator<Item = Arc<dyn Function>>> {
    iter: I,
}

impl<I: Iterator<Item = Arc<dyn Function>>> WrappingFunctionIterator<I> {
    /// Creates a new wrapping iterator.
    ///
    /// # Arguments
    /// * `iter` - The iterator to wrap
    pub fn new(iter: I) -> Self {
        Self { iter }
    }
}

impl<I: Iterator<Item = Arc<dyn Function>>> Iterator for WrappingFunctionIterator<I> {
    type Item = Arc<dyn Function>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<I: Iterator<Item = Arc<dyn Function>>> FunctionIterator for WrappingFunctionIterator<I> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::{Any, TypeId};

    struct MockFunction;

    impl Function for MockFunction {
        fn get_body(&self) -> Option<Box<dyn crate::program::model::address::AddressSet>> {
            None
        }

        fn get_entry_point(&self) -> crate::program::model::address::Address {
            crate::program::model::address::Address::new(0)
        }

        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::Address::new(0)
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            None
        }

        fn get_parameters(
            &self,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            Vec::new()
        }

        fn get_repetitions(&self) -> Option<i32> {
            None
        }

        fn is_external(&self) -> bool {
            false
        }

        fn is_inline(&self) -> bool {
            false
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn get_thunked_function(&self) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_calling_convention_name(&self) -> Option<String> {
            None
        }

        fn get_stack_purge_size(&self) -> i32 {
            0
        }

        fn has_no_return(&self) -> bool {
            false
        }

        fn has_custom_variable_storage(&self) -> bool {
            false
        }

        fn uses_custom_variable_storage(&self) -> bool {
            false
        }

        fn get_locals_size(&self) -> i32 {
            0
        }

        fn get_register_save_area_size(&self) -> i32 {
            0
        }

        fn get_preserved_register(&self) -> i32 {
            0
        }

        fn get_all_variables(
            &self,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }

        fn get_parent(&self) -> Option<Arc<dyn crate::program::model::listing::Function>> {
            None
        }

        fn get_children(&self) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }

        fn is_library(&self) -> bool {
            false
        }

        fn get_name(&self) -> String {
            "mock_function".to_string()
        }

        fn set_name(&mut self, _name: String) {}

        fn get_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }

        fn set_namespace(&mut self, _namespace: Arc<dyn crate::program::model::symbol::Namespace>) {}

        fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }

        fn get_value(&self) -> Option<Box<dyn Any>> {
            None
        }

        fn get_value_class(&self) -> Option<TypeId> {
            None
        }

        fn has_string_value(&self) -> bool {
            false
        }
    }

    #[test]
    fn wraps_iterator_delegates_to_inner() {
        let funcs: Vec<Arc<dyn Function>> = vec![
            Arc::new(MockFunction) as Arc<dyn Function>,
            Arc::new(MockFunction),
            Arc::new(MockFunction),
        ];
        let mut it = WrappingFunctionIterator::new(funcs.into_iter());
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_none());
    }

    #[test]
    fn wraps_empty_iterator() {
        let funcs: Vec<Arc<dyn Function>> = vec![];
        let mut it = WrappingFunctionIterator::new(funcs.into_iter());
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_iterator_returns_none_after_exhaustion() {
        let funcs: Vec<Arc<dyn Function>> = vec![Arc::new(MockFunction)];
        let mut it = WrappingFunctionIterator::new(funcs.into_iter());
        assert!(it.next().is_some());
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_filtered_iterator() {
        let funcs: Vec<Arc<dyn Function>> = vec![
            Arc::new(MockFunction) as Arc<dyn Function>,
            Arc::new(MockFunction),
            Arc::new(MockFunction),
        ];
        let filtered = funcs.into_iter().filter(|_| true);
        let mut it = WrappingFunctionIterator::new(filtered);
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_iterator_with_partial_filter() {
        let funcs: Vec<Arc<dyn Function>> = vec![
            Arc::new(MockFunction) as Arc<dyn Function>,
            Arc::new(MockFunction),
            Arc::new(MockFunction),
        ];
        let filtered = funcs.into_iter().filter(|_| true).take(2);
        let mut it = WrappingFunctionIterator::new(filtered);
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert_eq!(it.next(), None);
    }
}

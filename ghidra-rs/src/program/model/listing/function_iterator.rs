use crate::program::model::listing::Function;
use std::sync::Arc;

/// Iterator that returns functions.
///
/// This trait mirrors Ghidra's `FunctionIterator`, which combines the behavior of both
/// Iterator and Iterable in Java. Implementations should provide efficient iteration
/// over Function elements.
pub trait FunctionIterator: Iterator<Item = Arc<dyn Function>> {}

/// Empty function iterator with no items.
#[derive(Debug, Clone, Copy)]
pub struct EmptyFunctionIterator;

impl Iterator for EmptyFunctionIterator {
    type Item = Arc<dyn Function>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl FunctionIterator for EmptyFunctionIterator {}

/// List-based function iterator.
///
/// Wraps a vector of Function items and iterates over them by consuming ownership.
pub struct ListFunctionIterator {
    iter: std::vec::IntoIter<Arc<dyn Function>>,
}

impl ListFunctionIterator {
    /// Creates a new iterator over the supplied function items.
    pub fn new(items: Vec<Arc<dyn Function>>) -> Self {
        Self {
            iter: items.into_iter(),
        }
    }
}

impl Iterator for ListFunctionIterator {
    type Item = Arc<dyn Function>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl FunctionIterator for ListFunctionIterator {}

/// Creates an empty function iterator.
pub fn empty() -> Box<dyn FunctionIterator> {
    Box::new(EmptyFunctionIterator)
}

/// Creates a function iterator from a vector of function items.
pub fn of(items: Vec<Arc<dyn Function>>) -> Box<dyn FunctionIterator> {
    Box::new(ListFunctionIterator::new(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::{
        FunctionSignature, FunctionTag, FunctionUpdateType, Parameter, Program, Variable,
    };
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
    use crate::program::seam_stubs::{PrototypeModel, StackFrame, VariableFilter, VariableStorage};
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockFunction;

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }

        fn set_comment(&mut self, _comment: Option<&str>) {}

        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }

        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }

        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}

        fn get_entry_point(&self) -> Address {
            mock_address(0x100)
        }

        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!("not needed for this smoke test")
        }

        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            String::new()
        }

        fn get_signature_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_signature_source(&mut self, _signature_source: SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_stack_purge_size(&self) -> i32 {
            0
        }

        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            Vec::new()
        }

        fn add_tag(&mut self, _name: &str) -> bool {
            true
        }

        fn remove_tag(&mut self, _name: &str) {}

        fn set_stack_purge_size(&mut self, _purge_size: i32) {}

        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }

        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }

        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            Ok(())
        }

        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            Ok(())
        }

        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            None
        }

        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}

        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn Parameter>, InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_parameter_count(&self) -> i32 {
            0
        }

        fn get_auto_parameter_count(&self) -> i32 {
            0
        }

        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }

        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }

        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }

        fn remove_variable(&mut self, _var: &dyn Variable) {}

        fn set_body(
            &mut self,
            _new_body: &dyn AddressSetView,
        ) -> Result<(), OverlappingFunctionException> {
            Ok(())
        }

        fn has_var_args(&self) -> bool {
            false
        }

        fn set_var_args(&mut self, _has_var_args: bool) {}

        fn is_inline(&self) -> bool {
            false
        }

        fn set_inline(&mut self, _is_inline: bool) {}

        fn has_no_return(&self) -> bool {
            false
        }

        fn set_no_return(&mut self, _has_no_return: bool) {}

        fn has_custom_variable_storage(&self) -> bool {
            false
        }

        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}

        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
        }

        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }

        fn set_thunked_function(
            &mut self,
            _thunked_function: Option<Arc<dyn Function>>,
        ) -> Result<(), String> {
            Ok(())
        }

        fn is_external(&self) -> bool {
            false
        }

        fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
            None
        }

        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }

        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }

        fn promote_local_user_labels_to_global(&mut self) {}

        fn is_deleted(&self) -> bool {
            false
        }
    }

    #[test]
    fn empty_iterator_returns_none() {
        let mut iterator = EmptyFunctionIterator;
        assert!(iterator.next().is_none());
    }

    #[test]
    fn empty_from_factory_returns_none() {
        let mut iterator = empty();
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_iterator_yields_items() {
        let items: Vec<Arc<dyn Function>> =
            vec![Arc::new(MockFunction), Arc::new(MockFunction)];
        let mut iterator = ListFunctionIterator::new(items);

        assert!(iterator.next().is_some());
        assert!(iterator.next().is_some());
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_from_factory_yields_items() {
        let items: Vec<Arc<dyn Function>> =
            vec![Arc::new(MockFunction), Arc::new(MockFunction)];
        let mut iterator = of(items);

        assert!(iterator.next().is_some());
        assert!(iterator.next().is_some());
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_iterator_empty_list() {
        let items: Vec<Arc<dyn Function>> = vec![];
        let mut iterator = ListFunctionIterator::new(items);

        assert!(iterator.next().is_none());
    }
}

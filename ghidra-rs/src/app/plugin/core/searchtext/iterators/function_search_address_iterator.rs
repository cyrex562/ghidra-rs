use crate::program::model::address::{Address, AddressIterator};
use crate::program::model::listing::FunctionIterator;
use std::cell::RefCell;
use std::sync::Arc;

/// Wrapper that converts a FunctionIterator to an AddressIterator.
///
/// Iterates through functions and yields each function's entry point address.
///
/// Port of `ghidra.app.plugin.core.searchtext.iterators.FunctionSearchAddressIterator`.
pub struct FunctionSearchAddressIterator {
    function_iterator: RefCell<Box<dyn FunctionIterator>>,
    cached_next: RefCell<Option<Option<Arc<dyn crate::program::model::listing::Function>>>>,
}

impl FunctionSearchAddressIterator {
    /// Creates a new iterator that wraps the given function iterator.
    pub fn new(function_iterator: Box<dyn FunctionIterator>) -> Self {
        Self {
            function_iterator: RefCell::new(function_iterator),
            cached_next: RefCell::new(None),
        }
    }

    fn ensure_cached(&self) {
        if self.cached_next.borrow().is_none() {
            let next = self.function_iterator.borrow_mut().next();
            *self.cached_next.borrow_mut() = Some(next);
        }
    }
}

impl AddressIterator for FunctionSearchAddressIterator {
    fn has_next(&self) -> bool {
        self.ensure_cached();
        self.cached_next
            .borrow()
            .as_ref()
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    fn next_address(&mut self) -> Option<Address> {
        self.ensure_cached();
        self.cached_next
            .borrow_mut()
            .take()
            .flatten()
            .map(|function| function.get_entry_point())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct TestFunctionIterator {
        functions: Vec<Arc<dyn crate::program::model::listing::Function>>,
        index: usize,
    }

    impl TestFunctionIterator {
        fn new(functions: Vec<Arc<dyn crate::program::model::listing::Function>>) -> Self {
            Self { functions, index: 0 }
        }
    }

    impl Iterator for TestFunctionIterator {
        type Item = Arc<dyn crate::program::model::listing::Function>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index < self.functions.len() {
                let func = self.functions[self.index].clone();
                self.index += 1;
                Some(func)
            } else {
                None
            }
        }
    }

    impl FunctionIterator for TestFunctionIterator {}

    fn test_address(offset: i64) -> Address {
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            1,
        );
        Address::new(space, offset)
    }

    struct MockFunction {
        entry_point: Address,
    }

    impl crate::program::model::symbol::Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!("not needed for this test")
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
    }

    impl crate::program::model::listing::Function for MockFunction {
        fn get_name(&self) -> String {
            "test_func".to_string()
        }

        fn set_name(
            &mut self,
            _name: &str,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl crate::program::model::listing::Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock".to_string()
                }
                fn get_language_id(&self) -> String {
                    "mock:LE:64:default".to_string()
                }
            }
            Arc::new(MockProgram)
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
            self.entry_point.clone()
        }

        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!("not needed for this test")
        }

        fn set_return(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::seam_stubs::VariableStorage>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_signature_formal(
            &self,
            _formal_signature: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            struct MockSignature;
            impl crate::program::model::listing::FunctionSignature for MockSignature {
                fn get_name(&self) -> String {
                    String::new()
                }

                fn get_prototype_string_with_calling_convention(
                    &self,
                    _include_calling_convention: bool,
                ) -> String {
                    String::new()
                }

                fn get_arguments(
                    &self,
                ) -> Vec<Box<dyn crate::program::model::data::parameter_definition::ParameterDefinition>>
                {
                    Vec::new()
                }

                fn get_return_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
                    unimplemented!()
                }

                fn get_comment(&self) -> Option<String> {
                    None
                }

                fn has_var_args(&self) -> bool {
                    false
                }

                fn has_no_return(&self) -> bool {
                    false
                }

                fn get_calling_convention(
                    &self,
                ) -> Option<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
                    None
                }

                fn get_calling_convention_name(&self) -> String {
                    String::new()
                }

                fn is_equivalent_signature(
                    &self,
                    _signature: &dyn crate::program::model::listing::FunctionSignature,
                ) -> bool {
                    false
                }
            }
            Box::new(MockSignature)
        }

        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            "void test_func(void)".to_string()
        }

        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType {
            crate::program::model::symbol::SourceType::UserDefined
        }

        fn set_signature_source(&mut self, _signature_source: crate::program::model::symbol::SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            struct MockStackFrame;
            impl crate::program::seam_stubs::StackFrame for MockStackFrame {
                fn get_function(&self) -> Option<Box<dyn crate::program::model::listing::Function>> {
                    None
                }
                fn get_frame_size(&self) -> i32 {
                    0
                }
                fn get_local_size(&self) -> i32 {
                    0
                }
                fn get_parameter_size(&self) -> i32 {
                    0
                }
                fn get_parameter_offset(&self) -> i32 {
                    0
                }
                fn is_parameter_offset(&self, _offset: i32) -> bool {
                    false
                }
                fn set_local_size(&mut self, _size: i32) {}
                fn set_return_address_offset(&mut self, _offset: i32) {}
                fn get_return_address_offset(&self) -> i32 {
                    0
                }
                fn get_variable_containing(
                    &self,
                    _offset: i32,
                ) -> Option<Box<dyn crate::program::model::listing::Variable>> {
                    None
                }
                fn create_variable(
                    &mut self,
                    _name: &str,
                    _offset: i32,
                    _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
                    _source: crate::program::model::symbol::SourceType,
                ) -> Result<
                    Box<dyn crate::program::model::listing::Variable>,
                    crate::program::model::listing::CreateStackVariableError,
                > {
                    unimplemented!()
                }
                fn clear_variable(&mut self, _offset: i32) {}
                fn get_stack_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
                    vec![]
                }
                fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
                    vec![]
                }
                fn get_locals(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
                    vec![]
                }
                fn grows_negative(&self) -> bool {
                    true
                }
            }
            Box::new(MockStackFrame)
        }

        fn get_stack_purge_size(&self) -> i32 {
            0
        }

        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
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
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not needed for this test")
        }

        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not needed for this test")
        }

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn crate::program::model::listing::Variable>>,
            _new_params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            None
        }

        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}

        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException> {
            unimplemented!("not needed for this test")
        }

        fn get_parameter_count(&self) -> i32 {
            0
        }

        fn get_auto_parameter_count(&self) -> i32 {
            0
        }

        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            Vec::new()
        }

        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            Vec::new()
        }

        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }

        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }

        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }

        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }

        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Variable>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not needed for this test")
        }

        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {}

        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
        ) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
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

        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
        }

        fn set_calling_convention(&mut self, _name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn crate::program::model::listing::Function>> {
            None
        }

        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }

        fn set_thunked_function(
            &mut self,
            _thunked_function: Option<Arc<dyn crate::program::model::listing::Function>>,
        ) -> Result<(), String> {
            Ok(())
        }

        fn is_external(&self) -> bool {
            false
        }

        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }

        fn get_calling_functions(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn crate::program::model::listing::Function>> {
            Vec::new()
        }

        fn get_called_functions(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn crate::program::model::listing::Function>> {
            Vec::new()
        }

        fn promote_local_user_labels_to_global(&mut self) {}

        fn is_deleted(&self) -> bool {
            false
        }
    }

    #[test]
    fn empty_function_iterator_has_no_next() {
        let functions: Vec<Arc<dyn crate::program::model::listing::Function>> = vec![];
        let test_iter = TestFunctionIterator::new(functions);
        let iter = FunctionSearchAddressIterator::new(Box::new(test_iter));
        assert!(!iter.has_next());
    }

    #[test]
    fn iterator_with_functions_has_next() {
        let addr1 = test_address(0x1000);
        let func1 = Arc::new(MockFunction { entry_point: addr1 });
        let functions = vec![func1];
        let test_iter = TestFunctionIterator::new(functions);
        let iter = FunctionSearchAddressIterator::new(Box::new(test_iter));
        assert!(iter.has_next());
    }

    #[test]
    fn iterator_returns_entry_points() {
        let addr1 = test_address(0x1000);
        let addr2 = test_address(0x2000);
        let addr3 = test_address(0x3000);

        let func1 = Arc::new(MockFunction { entry_point: addr1.clone() });
        let func2 = Arc::new(MockFunction { entry_point: addr2.clone() });
        let func3 = Arc::new(MockFunction { entry_point: addr3.clone() });

        let functions = vec![func1, func2, func3];
        let test_iter = TestFunctionIterator::new(functions);
        let mut iter = FunctionSearchAddressIterator::new(Box::new(test_iter));

        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr1));

        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr2));

        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr3));

        assert!(!iter.has_next());
        assert_eq!(iter.next_address(), None);
    }

    #[test]
    fn multiple_next_calls_when_empty() {
        let functions: Vec<Arc<dyn crate::program::model::listing::Function>> = vec![];
        let test_iter = TestFunctionIterator::new(functions);
        let mut iter = FunctionSearchAddressIterator::new(Box::new(test_iter));
        assert_eq!(iter.next_address(), None);
        assert_eq!(iter.next_address(), None);
        assert_eq!(iter.next_address(), None);
    }
}

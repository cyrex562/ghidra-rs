use crate::program::model::listing::Function;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Computes hashes for functions and counts common bits between function hashes.
///
/// Ported from `ghidra.app.plugin.match.FunctionHasher`.
pub trait FunctionHasher: Send + Sync {
    /// Computes a 64-bit hash for the given function.
    ///
    /// # Arguments
    ///
    /// * `function` - The function to hash.
    /// * `monitor` - A task monitor for cancellation checking.
    ///
    /// # Errors
    ///
    /// Returns `CancelledException` if the operation is cancelled via the monitor.
    fn hash(&self, function: &dyn Function, monitor: &dyn TaskMonitor) -> Result<i64, CancelledException>;

    /// Counts the number of common bit positions between hashes of two functions.
    ///
    /// # Arguments
    ///
    /// * `func_a` - The first function.
    /// * `func_b` - The second function.
    /// * `monitor` - A task monitor.
    ///
    /// # Returns
    ///
    /// The count of common bits in the hashes of the two functions.
    fn common_bit_count(
        &self,
        func_a: &dyn Function,
        func_b: &dyn Function,
        monitor: &dyn TaskMonitor,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHasher;

    impl FunctionHasher for TestHasher {
        fn hash(&self, _function: &dyn Function, _monitor: &dyn TaskMonitor) -> Result<i64, CancelledException> {
            Ok(0x1234567890ABCDEF)
        }

        fn common_bit_count(
            &self,
            _func_a: &dyn Function,
            _func_b: &dyn Function,
            _monitor: &dyn TaskMonitor,
        ) -> i32 {
            32
        }
    }

    #[test]
    fn trait_is_implementable() {
        let _: &dyn FunctionHasher = &TestHasher;
    }

    #[test]
    fn hash_returns_result() {
        let hasher = TestHasher;
        let mock_function: &dyn Function = &MockFunction;
        let mock_monitor: &dyn TaskMonitor = &MockMonitor;

        let result = hasher.hash(mock_function, mock_monitor);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x1234567890ABCDEF);
    }

    #[test]
    fn common_bit_count_returns_count() {
        let hasher = TestHasher;
        let mock_function_a: &dyn Function = &MockFunction;
        let mock_function_b: &dyn Function = &MockFunction;
        let mock_monitor: &dyn TaskMonitor = &MockMonitor;

        let count = hasher.common_bit_count(mock_function_a, mock_function_b, mock_monitor);
        assert_eq!(count, 32);
    }

    use std::sync::Arc;
    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::{Address, AddressSetView};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function::{
        FunctionEditError, FunctionUpdateType, SetFunctionNameError,
        UNKNOWN_CALLING_CONVENTION_STRING,
    };
    use crate::program::model::listing::{FunctionSignature, FunctionTag, Parameter, Program, Variable};
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
    use crate::program::seam_stubs::{PrototypeModel, StackFrame, VariableFilter, VariableStorage};
    use crate::util::exception::InvalidInputException;

    fn mock_address(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
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
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock".to_string()
                }
                fn get_language_id(&self) -> String {
                    "mock:LE:32:default".to_string()
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
            "void mock(void)".to_string()
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

        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
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

        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
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
            UNKNOWN_CALLING_CONVENTION_STRING.to_string()
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

    struct MockMonitor;
    impl TaskMonitor for MockMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn set_show_progress_value(&self, _show: bool) {}

        fn set_message(&self, _message: &str) {}

        fn get_message(&self) -> String {
            String::new()
        }

        fn set_progress(&self, _value: i64) {}

        fn initialize(&self, _max: i64) {}

        fn set_maximum(&self, _max: i64) {}

        fn get_maximum(&self) -> i64 {
            0
        }

        fn set_indeterminate(&self, _indeterminate: bool) {}

        fn is_indeterminate(&self) -> bool {
            false
        }

        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Ok(())
        }

        fn increment_progress(&self, _amount: i64) {}

        fn get_progress(&self) -> i64 {
            0
        }

        fn cancel(&self) {}

        fn add_cancelled_listener(
            &self,
            _listener: Box<dyn crate::util::task::CancelledListener>,
        ) {}

        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}

        fn set_cancel_enabled(&self, _enabled: bool) {}

        fn is_cancel_enabled(&self) -> bool {
            true
        }

        fn clear_cancelled(&self) {}
    }
}

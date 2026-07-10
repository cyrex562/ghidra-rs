use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::{Function, Program};

/// A command to set the stack purge size of a function.
pub struct SetFunctionPurgeCommand {
    entry_point: Address,
    purge_size: i32,
}

impl SetFunctionPurgeCommand {
    /// Creates a new command that will set the given purge size on the given function.
    ///
    /// # Arguments
    ///
    /// * `function` - The function on which to set the purge size.
    /// * `new_purge` - The new stack purge size.
    pub fn new(function: &dyn Function, new_purge: i32) -> Self {
        SetFunctionPurgeCommand {
            entry_point: function.get_entry_point(),
            purge_size: new_purge,
        }
    }
}

impl Command<dyn Program + 'static> for SetFunctionPurgeCommand {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        if let Some(listing) = program.get_listing() {
            if let Some(function) = listing.get_function_at(&self.entry_point) {
                let func_ptr = function.as_ref() as *const dyn Function as *mut dyn Function;
                unsafe {
                    (*func_ptr).set_stack_purge_size(self.purge_size);
                }
                return true;
            }
        }
        false
    }

    fn status_msg(&self) -> Option<String> {
        None
    }

    fn name(&self) -> String {
        "Set Function Purge".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::AddressSetView;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function::{
        FunctionEditError, FunctionUpdateType, SetFunctionNameError,
    };
    use crate::program::model::listing::{FunctionSignature, FunctionTag, Parameter, Variable};
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType};
    use crate::program::seam_stubs::{
        PrototypeModel, StackFrame, VariableFilter, VariableStorage,
    };
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;

    #[allow(dead_code)]
    struct MockFunction {
        purge_size: i32,
        entry_point: Address,
    }

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "test_func".to_string()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            Ok(())
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            vec![]
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            vec![]
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}
        fn get_entry_point(&self) -> Address {
            self.entry_point
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
            unimplemented!()
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
            unimplemented!()
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
            unimplemented!()
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            vec![]
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            true
        }
        fn remove_tag(&mut self, _name: &str) {}
        fn set_stack_purge_size(&mut self, purge_size: i32) {
            self.purge_size = purge_size;
        }
        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
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
            unimplemented!()
        }
        fn get_parameter_count(&self) -> i32 {
            0
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            vec![]
        }
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Parameter>> {
            vec![]
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!()
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
            vec![]
        }
        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }
        fn promote_local_user_labels_to_global(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
    }
    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
    }

    #[test]
    fn test_set_function_purge_size() {
        let mock_func = MockFunction {
            purge_size: 0,
            entry_point: Address::from(0x1000),
        };

        let mut cmd = SetFunctionPurgeCommand::new(&mock_func, 8);
        assert_eq!(cmd.purge_size, 8);
        assert_eq!(cmd.entry_point, Address::from(0x1000));
    }

    #[test]
    fn test_command_name() {
        let mock_func = MockFunction {
            purge_size: 0,
            entry_point: Address::from(0x1000),
        };

        let cmd = SetFunctionPurgeCommand::new(&mock_func, 8);
        assert_eq!(cmd.name(), "Set Function Purge");
    }

    #[test]
    fn test_command_status_msg() {
        let mock_func = MockFunction {
            purge_size: 0,
            entry_point: Address::from(0x1000),
        };

        let cmd = SetFunctionPurgeCommand::new(&mock_func, 8);
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn test_apply_to_with_no_listing() {
        let mock_func = MockFunction {
            purge_size: 0,
            entry_point: Address::from(0x1000),
        };

        let mut cmd = SetFunctionPurgeCommand::new(&mock_func, 8);
        let mut program = MockProgram;

        assert!(!cmd.apply_to(&mut program));
    }
}

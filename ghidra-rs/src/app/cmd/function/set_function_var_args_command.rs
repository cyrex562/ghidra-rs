use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::{Function, Program};

/// A command to set whether or not a function has VarArgs.
pub struct SetFunctionVarArgsCommand {
    entry_point: Address,
    has_var_args: bool,
}

impl SetFunctionVarArgsCommand {
    /// Creates a new command that will set whether or not there are VarArgs on the given
    /// function.
    ///
    /// # Arguments
    ///
    /// * `function` - The function on which to set whether or not there are VarArgs.
    /// * `has_var_args` - True if you want to set this function to have VarArgs.
    pub fn new(function: &dyn Function, has_var_args: bool) -> Self {
        SetFunctionVarArgsCommand {
            entry_point: function.get_entry_point(),
            has_var_args,
        }
    }
}

impl Command<dyn Program + 'static> for SetFunctionVarArgsCommand {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        if let Some(listing) = program.get_listing() {
            if let Some(function) = listing.get_function_at(&self.entry_point) {
                let func_ptr = function.as_ref() as *const dyn Function as *mut dyn Function;
                unsafe {
                    (*func_ptr).set_var_args(self.has_var_args);
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
        "Set Function VarArgs".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::{AddressIterator, AddressSetView};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::function::{
        FunctionEditError, FunctionUpdateType, SetFunctionNameError,
    };
    use crate::program::model::listing::instruction::Instruction;
    use crate::program::model::listing::program_fragment::ProgramFragment;
    use crate::program::model::listing::program_module::ProgramModule;
    use crate::program::model::listing::{
        CreateFunctionError, FunctionSignature, FunctionTag, Parameter, Variable,
    };
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::ProcessorContextView;
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType};
    use crate::program::model::util::PropertyMap;
    use crate::program::seam_stubs::{
        CodeUnitComments, CodeUnitIterator, CommentHistory, CommentType, DataIterator,
        FunctionIterator, InstructionIterator, InstructionSet, MemBuffer, PrototypeModel, StackFrame,
        VariableFilter, VariableStorage,
    };
    use crate::program::util::CodeUnitInsertionException;
    use crate::util::exception::{CancelledException, DuplicateNameException, InvalidInputException};
    use crate::util::task::TaskMonitor;

    struct MockFunction {
        var_args: bool,
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
            struct P;
            impl crate::framework::model::DomainObject for P {}
            impl Program for P {
                fn get_name(&self) -> String {
                    "mock".to_string()
                }
                fn get_language_id(&self) -> String {
                    "mock:LE:32:default".to_string()
                }
            }
            Arc::new(P)
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
            self.var_args
        }
        fn set_var_args(&mut self, has_var_args: bool) {
            self.var_args = has_var_args;
        }
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

    struct MockListing {
        function: Option<Arc<dyn Function>>,
    }

    impl crate::program::model::listing::Listing for MockListing {
        fn get_code_unit_at(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_containing(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_iterator(
            &self,
            _property: &str,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_comment_code_unit_iterator(
            &self,
            _comment_type: CommentType,
            _addr_set: &dyn AddressSetView,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_comment_address_iterator(
            &self,
            _comment_type: CommentType,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            unimplemented!()
        }
        fn get_any_comment_address_iterator(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            unimplemented!()
        }
        fn get_comment(&self, _comment_type: CommentType, _address: &Address) -> Option<String> {
            None
        }
        fn get_all_comments(&self, _address: &Address) -> Box<dyn CodeUnitComments> {
            struct MockComments;
            impl CodeUnitComments for MockComments {}
            Box::new(MockComments)
        }
        fn set_comment(
            &mut self,
            _address: &Address,
            _comment_type: CommentType,
            _comment: Option<String>,
        ) {
        }
        fn get_code_units(&self, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_code_units_from(&self, _addr: &Address, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_code_units_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_instruction_at(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_containing(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_after(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_before(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instructions(&self, _forward: bool) -> Box<dyn InstructionIterator> {
            unimplemented!()
        }
        fn get_instructions_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!()
        }
        fn get_instructions_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!()
        }
        fn get_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_containing(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_after(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_before(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data(&self, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_data_from(&self, _addr: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_data_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_defined_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_containing(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_after(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_before(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data(&self, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_defined_data_from(&self, _addr: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_defined_data_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_undefined_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_after(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_first_undefined_data(
            &self,
            _set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_before(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_ranges(
            &self,
            _set: &dyn AddressSetView,
            _initialized_memory_only: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn AddressSetView>, CancelledException> {
            unimplemented!()
        }
        fn get_defined_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_defined_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_user_defined_properties(&self) -> Vec<String> {
            vec![]
        }
        fn remove_user_defined_property(&mut self, _property_name: &str) {}
        fn get_property_map(&self, _property_name: &str) -> Option<Box<dyn PropertyMap>> {
            None
        }
        fn create_instruction(
            &mut self,
            _addr: Address,
            _prototype: Arc<dyn InstructionPrototype>,
            _mem_buf: &dyn MemBuffer,
            _context: &dyn ProcessorContextView,
            _length: i32,
        ) -> Result<Arc<dyn Instruction>, CodeUnitInsertionException> {
            unimplemented!()
        }
        fn add_instructions(
            &mut self,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Result<Box<dyn AddressSetView>, CodeUnitInsertionException> {
            unimplemented!()
        }
        fn create_data_sized(
            &mut self,
            _addr: Address,
            _data_type: Box<dyn DataType>,
            _length: i32,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!()
        }
        fn create_data(
            &mut self,
            _addr: Address,
            _data_type: Box<dyn DataType>,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!()
        }
        fn clear_code_units(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _clear_context: bool,
        ) {
        }
        fn clear_code_units_with_monitor(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _clear_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn is_undefined(&self, _start: &Address, _end: &Address) -> bool {
            true
        }
        fn clear_comments(&mut self, _start_addr: &Address, _end_addr: &Address) {}
        fn clear_properties(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn clear_all(&mut self, _clear_context: bool, _monitor: &dyn TaskMonitor) {}
        fn get_fragment(
            &self,
            _tree_name: &str,
            _addr: &Address,
        ) -> Option<Arc<dyn ProgramFragment>> {
            None
        }
        fn get_module(&self, _tree_name: &str, _name: &str) -> Option<Arc<dyn ProgramModule>> {
            None
        }
        fn get_fragment_by_name(
            &self,
            _tree_name: &str,
            _name: &str,
        ) -> Option<Arc<dyn ProgramFragment>> {
            None
        }
        fn create_root_module(
            &mut self,
            _tree_name: &str,
        ) -> Result<Arc<dyn ProgramModule>, DuplicateNameException> {
            unimplemented!()
        }
        fn get_root_module(&self, _tree_name: &str) -> Option<Arc<dyn ProgramModule>> {
            None
        }
        fn get_root_module_by_id(&self, _tree_id: i64) -> Option<Arc<dyn ProgramModule>> {
            None
        }
        fn get_default_root_module(&self) -> Arc<dyn ProgramModule> {
            unimplemented!()
        }
        fn get_tree_names(&self) -> Vec<String> {
            vec![]
        }
        fn remove_tree(&mut self, _tree_name: &str) -> bool {
            false
        }
        fn rename_tree(
            &mut self,
            _old_name: &str,
            _new_name: &str,
        ) -> Result<(), DuplicateNameException> {
            Ok(())
        }
        fn get_num_code_units(&self) -> i64 {
            0
        }
        fn get_num_defined_data(&self) -> i64 {
            0
        }
        fn get_num_instructions(&self) -> i64 {
            0
        }
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            struct MockDataTypeManager;
            impl DataTypeManager for MockDataTypeManager {}
            Box::new(MockDataTypeManager)
        }
        fn create_function(
            &mut self,
            _name: &str,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!()
        }
        fn create_function_in_namespace(
            &mut self,
            _name: &str,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!()
        }
        fn remove_function(&mut self, _entry_point: &Address) {}
        fn get_function_at(&self, entry_point: &Address) -> Option<Arc<dyn Function>> {
            match &self.function {
                Some(func) if func.get_entry_point() == *entry_point => Some(func.clone()),
                _ => None,
            }
        }
        fn get_global_functions(&self, _name: &str) -> Vec<Arc<dyn Function>> {
            vec![]
        }
        fn get_functions_by_name(
            &self,
            _namespace: Option<&str>,
            _name: &str,
        ) -> Vec<Arc<dyn Function>> {
            vec![]
        }
        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_external_functions(&self) -> Box<dyn FunctionIterator> {
            unimplemented!()
        }
        fn get_functions(&self, _forward: bool) -> Box<dyn FunctionIterator> {
            unimplemented!()
        }
        fn get_functions_from(&self, _start: &Address, _forward: bool) -> Box<dyn FunctionIterator> {
            unimplemented!()
        }
        fn get_functions_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            unimplemented!()
        }
        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }
        fn get_comment_history(
            &self,
            _addr: &Address,
            _comment_type: CommentType,
        ) -> Vec<Box<dyn CommentHistory>> {
            vec![]
        }
        fn get_comment_address_count(&self) -> i64 {
            0
        }
    }

    struct MockProgram {
        listing: MockListing,
    }

    impl crate::framework::model::DomainObject for MockProgram {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }

        fn get_listing(&mut self) -> Option<&mut dyn crate::program::model::listing::Listing> {
            Some(&mut self.listing as &mut dyn crate::program::model::listing::Listing)
        }
    }

    #[test]
    fn command_name_is_correct() {
        let entry_point = Address::new(0x1000);
        let mock_func = Arc::new(MockFunction {
            var_args: false,
            entry_point,
        });
        let cmd = SetFunctionVarArgsCommand::new(mock_func.as_ref(), false);
        assert_eq!(cmd.name(), "Set Function VarArgs");
    }

    #[test]
    fn command_status_msg_is_none() {
        let entry_point = Address::new(0x1000);
        let mock_func = Arc::new(MockFunction {
            var_args: false,
            entry_point,
        });
        let cmd = SetFunctionVarArgsCommand::new(mock_func.as_ref(), false);
        assert_eq!(cmd.status_msg(), None);
    }
}

use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::{Function, Program};
use crate::program::model::symbol::SourceType;

/// A command to set the name of a function.
pub struct SetFunctionNameCmd {
    entry: Address,
    name: Option<String>,
    msg: Option<String>,
    source: SourceType,
}

impl SetFunctionNameCmd {
    /// Constructs a new command for setting the name of a function.
    ///
    /// # Arguments
    ///
    /// * `entry` - the address of the function to be renamed.
    /// * `new_name` - the new name for the function.
    /// * `source` - the source of this function name
    pub fn new(entry: Address, new_name: String, source: SourceType) -> Self {
        let name = if new_name.is_empty() { None } else { Some(new_name) };
        SetFunctionNameCmd {
            entry,
            name,
            msg: None,
            source,
        }
    }
}

impl Command<dyn Program + 'static> for SetFunctionNameCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        if let Some(listing) = program.get_listing() {
            if let Some(function) = listing.get_function_at(&self.entry) {
                let func_ptr = function.as_ref() as *const dyn Function as *mut dyn Function;
                let name_str = self.name.as_deref().unwrap_or("");
                match unsafe { (*func_ptr).set_name(name_str, self.source) } {
                    Ok(_) => true,
                    Err(e) => {
                        self.msg = Some(e.to_string());
                        false
                    }
                }
            } else {
                true
            }
        } else {
            true
        }
    }

    fn status_msg(&self) -> Option<String> {
        self.msg.clone()
    }

    fn name(&self) -> String {
        "Rename Function".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockFunction {
        entry_point: Address,
        name_value: String,
        last_source: Option<SourceType>,
    }

    impl crate::program::model::symbol::Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!()
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn has_var_args(&self) -> bool {
            false
        }

        fn set_var_args(&mut self, _has_var_args: bool) {}

        fn get_name(&self) -> String {
            self.name_value.clone()
        }

        fn set_name(
            &mut self,
            name: &str,
            source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            self.name_value = name.to_string();
            self.last_source = Some(source);
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn Program> {
            struct MockProgram;
            impl Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock_program".to_string()
                }

                fn get_language_id(&self) -> String {
                    "x86".to_string()
                }

                fn get_listing(&mut self) -> Option<&mut dyn crate::program::model::listing::Listing> {
                    None
                }
            }
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

        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _return_type: Option<Box<dyn crate::program::model::data::data_type::DataType>>,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn get_signature(&self) -> Arc<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!()
        }

        fn has_custom_variable_storage(&self) -> bool {
            false
        }

        fn get_local_variables(&self) -> Vec<Arc<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_parameters(&self) -> Vec<Arc<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }

        fn get_body(&self) -> Arc<dyn crate::program::model::address::AddressSetView> {
            unimplemented!()
        }

        fn add_local_variable(
            &mut self,
            _var: Arc<dyn crate::program::model::listing::Variable>,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn get_stack_depth(&self) -> i32 {
            0
        }

        fn set_stack_depth(&mut self, _depth: i32) {}

        fn get_stack_purge_size(&self) -> Option<i32> {
            None
        }

        fn set_stack_purge_size(&mut self, _purge_size: Option<i32>) {}

        fn has_no_return(&self) -> bool {
            false
        }

        fn set_no_return(&mut self, _no_return: bool) {}

        fn is_external(&self) -> bool {
            false
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn get_thunked_function(&self) -> Option<Arc<dyn Function>> {
            None
        }

        fn set_thunked_function(
            &mut self,
            _thunked_function: Option<Arc<dyn Function>>,
        ) -> Result<(), String> {
            Ok(())
        }

        fn set_inline_flag(&mut self, _inline: bool) {}

        fn is_inline(&self) -> bool {
            false
        }

        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
        }

        fn set_calling_convention_name(&mut self, _convention_name: &str) -> Result<(), String> {
            Ok(())
        }

        fn get_type(&self) -> crate::program::model::symbol::NamespaceType {
            crate::program::model::symbol::NamespaceType::Function
        }
    }

    struct MockListing {
        function: Option<Arc<dyn Function>>,
    }

    impl crate::program::model::listing::Listing for MockListing {
        fn get_code_unit_at(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_containing(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_after(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_before(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_iterator(
            &self,
            _property: &str,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_comment_code_unit_iterator_by_ordinal(
            &self,
            _ordinal: i32,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_comment_code_unit_iterator(
            &self,
            _comment_type: crate::program::seam_stubs::CommentType,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_comment_code_unit_iterator_from(
            &self,
            _comment_type: crate::program::seam_stubs::CommentType,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_code_units(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_code_units_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_code_units_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_instruction_at(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }

        fn get_instruction_containing(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }

        fn get_instruction_after(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }

        fn get_instruction_before(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }

        fn get_instructions(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!()
        }

        fn get_instructions_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!()
        }

        fn get_instructions_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!()
        }

        fn get_data_at(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_data_containing(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_data_after(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_data_before(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_data(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!()
        }

        fn get_data_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!()
        }

        fn get_data_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!()
        }

        fn get_defined_data_at(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_defined_data_containing(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_defined_data_after(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_defined_data_before(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_defined_data(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!()
        }

        fn get_defined_data_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!()
        }

        fn get_defined_data_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!()
        }

        fn get_undefined_data_at(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_undefined_data_containing(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_undefined_data_after(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_undefined_data_before(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn get_undefined_data(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!()
        }

        fn get_undefined_data_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!()
        }

        fn get_undefined_data_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!()
        }

        fn get_function_at(&self, entry_point: &Address) -> Option<Arc<dyn Function>> {
            if self.function.is_some() {
                let func = self.function.as_ref().unwrap();
                if func.get_entry_point() == *entry_point {
                    self.function.clone()
                } else {
                    None
                }
            } else {
                None
            }
        }

        fn get_global_functions(&self, _name: &str) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn get_functions_by_name(&self, _namespace: Option<&str>, _name: &str) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_external_functions(&self) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!()
        }

        fn get_functions(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!()
        }

        fn get_functions_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!()
        }

        fn get_functions_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!()
        }

        fn create_function(
            &mut self,
            _name: Option<&str>,
            _entry: &Address,
            _body: Arc<dyn crate::program::model::address::AddressSetView>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!()
        }

        fn remove_function(&mut self, _entry_point: &Address) {}

        fn create_module(
            &mut self,
            _parent_module: Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>>,
            _module_name: &str,
        ) -> Arc<dyn crate::program::model::listing::program_module::ProgramModule> {
            unimplemented!()
        }

        fn get_root_module(&self) -> Arc<dyn crate::program::model::listing::program_module::ProgramModule> {
            unimplemented!()
        }

        fn get_module(&self, _tree_name: &str) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }

        fn get_module_tree(&self, _tree_name: &str) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }

        fn get_tree_names(&self) -> Vec<String> {
            vec![]
        }

        fn create_root_module(&mut self, _module_name: &str) {
        }

        fn remove_tree(&mut self, _tree_name: &str) {
        }

        fn add_tree_change_listener(
            &mut self,
            _listener: Box<dyn crate::program::seam_stubs::TreeChangeListener>,
        ) {
        }

        fn remove_tree_change_listener(
            &mut self,
            _listener: Box<dyn crate::program::seam_stubs::TreeChangeListener>,
        ) {
        }

        fn is_in_delimited_set(
            &self,
            _addr: &Address,
            _property: &str,
        ) -> bool {
            false
        }

        fn get_data_type_manager(&self) -> Arc<dyn crate::program::model::data::data_type_manager::DataTypeManager> {
            unimplemented!()
        }

        fn get_property_map(&self, _property_name: &str) -> Option<Arc<dyn crate::program::model::util::PropertyMap>> {
            None
        }

        fn get_property_names(&self) -> Vec<String> {
            vec![]
        }

        fn create_property(&mut self, _property_name: &str, _value_type: i32) {
        }

        fn copy_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _len: i64,
            _monitor: Option<Arc<dyn crate::util::task::TaskMonitor>>,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }

        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _len: i64,
            _monitor: Option<Arc<dyn crate::util::task::TaskMonitor>>,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }

        fn clear_address_range(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _clear_context: bool,
            _monitor: Option<Arc<dyn crate::util::task::TaskMonitor>>,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }

        fn append_address_range(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
        ) -> Result<(), String> {
            Ok(())
        }

        fn delete_address_range(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _monitor: Option<Arc<dyn crate::util::task::TaskMonitor>>,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }

        fn insert_address_range(
            &mut self,
            _addr: &Address,
            _size: i64,
            _monitor: Option<Arc<dyn crate::util::task::TaskMonitor>>,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }

        fn get_address(&self, offset: i32) -> Address {
            Address::from(offset as u64)
        }

        fn get_address_from_string(&self, _addr_str: &str) -> Result<Address, String> {
            Err("Unimplemented".to_string())
        }

        fn set_program_context(&mut self, _new_context: Arc<dyn crate::program::model::lang::ProcessorContextView>) {
        }

        fn get_program_context(&self) -> Arc<dyn crate::program::model::lang::ProcessorContextView> {
            unimplemented!()
        }
    }

    struct MockProgram {
        listing: Option<MockListing>,
    }

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

        fn get_listing(&mut self) -> Option<&mut dyn crate::program::model::listing::Listing> {
            self.listing.as_mut().map(|l| l as &mut dyn crate::program::model::listing::Listing)
        }
    }

    #[test]
    fn test_set_function_name_cmd_empty_name_converted_to_none() {
        let addr = Address::from(0x1000);
        let cmd = SetFunctionNameCmd::new(addr, "".to_string(), SourceType::UserDefined);
        assert_eq!(cmd.name, None);
    }

    #[test]
    fn test_set_function_name_cmd_name_preserved() {
        let addr = Address::from(0x1000);
        let cmd = SetFunctionNameCmd::new(addr, "my_function".to_string(), SourceType::UserDefined);
        assert_eq!(cmd.name, Some("my_function".to_string()));
    }

    #[test]
    fn test_set_function_name_cmd_name() {
        let addr = Address::from(0x1000);
        let cmd = SetFunctionNameCmd::new(addr, "test".to_string(), SourceType::UserDefined);
        assert_eq!(cmd.name(), "Rename Function");
    }

    #[test]
    fn test_set_function_name_cmd_status_msg_initially_none() {
        let addr = Address::from(0x1000);
        let cmd = SetFunctionNameCmd::new(addr, "test".to_string(), SourceType::UserDefined);
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn test_set_function_name_cmd_apply_no_listing() {
        let addr = Address::from(0x1000);
        let mut cmd = SetFunctionNameCmd::new(addr, "test".to_string(), SourceType::UserDefined);
        let mut program = MockProgram { listing: None };
        let result = cmd.apply_to(&mut program);
        assert!(result);
    }

    #[test]
    fn test_set_function_name_cmd_apply_no_function() {
        let addr = Address::from(0x1000);
        let mut cmd = SetFunctionNameCmd::new(addr, "new_name".to_string(), SourceType::UserDefined);

        let listing = MockListing { function: None };
        let mut program = MockProgram { listing: Some(listing) };

        let result = cmd.apply_to(&mut program);
        assert!(result);
    }
}

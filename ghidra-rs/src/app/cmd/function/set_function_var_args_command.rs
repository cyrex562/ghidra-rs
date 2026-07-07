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
    use crate::program::seam_stubs::FunctionIterator;

    struct MockFunction {
        var_args: bool,
        entry_point: Address,
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
            self.var_args
        }

        fn set_var_args(&mut self, has_var_args: bool) {
            self.var_args = has_var_args;
        }

        fn get_name(&self) -> String {
            "test_func".to_string()
        }

        fn set_name(&mut self, _name: &str, _source: crate::program::model::symbol::SourceType) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
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
            self.entry_point
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
            unimplemented!()
        }

        fn set_return(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::seam_stubs::VariableStorage>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!()
        }

        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
        ) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            Ok(())
        }

        fn is_inline(&self) -> bool {
            false
        }

        fn set_inline(&mut self, _is_inline: bool) {}

        fn has_no_return(&self) -> bool {
            false
        }

        fn set_no_return(&mut self, _has_no_return: bool) {}

        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
        }

        fn set_calling_convention(&mut self, _calling_convention_name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
    }

    struct MockListing {
        function: Option<Arc<dyn Function>>,
    }

    impl crate::program::model::listing::Listing for MockListing {
        fn get_function_at(&self, _entry_point: &Address) -> Option<Arc<dyn Function>> {
            self.function.clone()
        }

        fn remove_function(&mut self, _entry_point: &Address) {}

        fn create_function(
            &mut self,
            _entry_point: &Address,
            _name: &str,
        ) -> Result<Arc<dyn Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!()
        }

        fn create_function_in_namespace(
            &mut self,
            _entry_point: &Address,
            _name: &str,
            _namespace: Option<Arc<dyn crate::program::model::symbol::Namespace>>,
        ) -> Result<Arc<dyn Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!()
        }

        fn get_global_functions(&self, _name: &str) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }

        fn get_functions_by_name(
            &self,
            _namespace: Option<&str>,
            _name: &str,
        ) -> Vec<Arc<dyn Function>> {
            Vec::new()
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

        fn get_functions_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            unimplemented!()
        }

        fn get_functions_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            unimplemented!()
        }

        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }

        fn get_code_unit_at(&self, _addr: &Address) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_containing(&self, _addr: &Address) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
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

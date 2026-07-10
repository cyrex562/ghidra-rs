use crate::program::model::address::Address;
use crate::program::model::listing::Function;

/// Represents a function that simply passes control to a destination function.
///
/// A thunk function corresponds to a fragment of code which simply passes control
/// to a destination function. All Function behaviors are mapped through to the current
/// destination function.
///
/// Port of `ghidra.program.model.listing.ThunkFunction`.
pub trait ThunkFunction: Function {
    /// Set the destination function which corresponds to this thunk.
    fn set_destination_function(&mut self, function: &dyn Function);

    /// Returns the current destination function entry point address.
    ///
    /// A function should exist at the specified address although there is no guarantee.
    /// If the address is within the EXTERNAL space, this is a place-holder for an external
    /// library function.
    fn get_destination_function_entry_point(&self) -> Address;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::framework::model::DomainObject;
    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::{AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::{
        FunctionSignature, FunctionTag, FunctionUpdateType, Parameter, Program, Variable,
    };
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
    use crate::program::seam_stubs::{PrototypeModel, StackFrame, VariableFilter, VariableStorage};
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;

    macro_rules! impl_mock_function {
        ($t:ty) => {
            impl Namespace for $t {
                fn get_symbol(&self) -> Arc<dyn Symbol> {
                    unimplemented!("not needed for this smoke test")
                }

                fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
                    None
                }
            }

            impl Function for $t {
                fn get_name(&self) -> String {
                    "mock".to_string()
                }

                fn set_name(
                    &mut self,
                    _name: &str,
                    _source: SourceType,
                ) -> Result<(), SetFunctionNameError> {
                    Ok(())
                }

                fn set_call_fixup(&mut self, _name: Option<&str>) {}

                fn get_call_fixup(&self) -> Option<String> {
                    None
                }

                fn get_program(&self) -> Arc<dyn Program> {
                    struct MockProgram;
                    impl DomainObject for MockProgram {}
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
                    self.entry_point.clone()
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
        };
    }

    struct MockFunction {
        entry_point: Address,
    }

    impl_mock_function!(MockFunction);

    struct MockThunkFunction {
        entry_point: Address,
        destination_entry_point: Address,
        destination: Option<Box<dyn Function>>,
    }

    impl MockThunkFunction {
        fn new(entry_point: Address, destination_entry_point: Address) -> Self {
            Self {
                entry_point,
                destination_entry_point,
                destination: None,
            }
        }
    }

    impl_mock_function!(MockThunkFunction);

    impl ThunkFunction for MockThunkFunction {
        fn set_destination_function(&mut self, _function: &dyn Function) {
            self.destination = Some(Box::new(MockFunction {
                entry_point: self.destination_entry_point.clone(),
            }));
        }

        fn get_destination_function_entry_point(&self) -> Address {
            self.destination_entry_point.clone()
        }
    }

    fn create_test_address(offset: u64) -> Address {
        Address::new(
            AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1),
            offset as i64,
        )
    }

    #[test]
    fn get_destination_function_entry_point_returns_set_address() {
        let entry = create_test_address(0x1000);
        let dest = create_test_address(0x2000);
        let thunk = MockThunkFunction::new(entry, dest.clone());
        assert_eq!(thunk.get_destination_function_entry_point(), dest);
    }

    #[test]
    fn set_destination_function_stores_destination() {
        let entry = create_test_address(0x1000);
        let dest = create_test_address(0x2000);
        let mut thunk = MockThunkFunction::new(entry, dest.clone());
        let destination = MockFunction {
            entry_point: dest,
        };
        thunk.set_destination_function(&destination);
        assert!(thunk.destination.is_some());
    }

    #[test]
    fn thunk_preserves_own_entry_point() {
        let entry = create_test_address(0x1000);
        let dest = create_test_address(0x2000);
        let thunk = MockThunkFunction::new(entry.clone(), dest);
        assert_eq!(thunk.get_entry_point(), entry);
    }

    #[test]
    fn thunk_different_entry_and_destination() {
        let entry = create_test_address(0x5000);
        let dest = create_test_address(0x6000);
        let thunk = MockThunkFunction::new(entry, dest);
        assert_ne!(thunk.get_entry_point(), thunk.get_destination_function_entry_point());
    }
}

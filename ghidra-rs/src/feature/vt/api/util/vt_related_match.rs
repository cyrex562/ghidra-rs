use std::sync::Arc;

use crate::feature::vt::gui::provider::related_matches::vt_related_match_type::VtRelatedMatchType;
use crate::program::model::address::Address;
use crate::program::model::listing::Function;

/// Describes a match related to a primary match by way of a caller/callee/target relationship
/// between their source and destination functions.
///
/// Port of `ghidra.feature.vt.api.util.VTRelatedMatch`.
pub trait VTRelatedMatch: Send + Sync {
    /// Returns the classification of how this related match correlates to the primary match.
    fn get_correlation(&self) -> VtRelatedMatchType;

    /// Returns the source address of this related match.
    fn get_source_address(&self) -> Address;

    /// Returns the source function of this related match.
    fn get_source_function(&self) -> Arc<dyn Function>;

    /// Returns the destination address of this related match.
    fn get_destination_address(&self) -> Address;

    /// Returns the destination function of this related match.
    fn get_destination_function(&self) -> Arc<dyn Function>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
    use crate::feature::vt::gui::provider::related_matches::vt_related_match_correlation_type::VtRelatedMatchCorrelationType;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::function::{
        FunctionEditError, FunctionUpdateType, SetFunctionNameError,
    };
    use crate::program::model::listing::{FunctionSignature, FunctionTag, Parameter, Program, StackFrame, Variable, VariableFilter};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::symbol::{ExternalLocation, Namespace, Symbol, SourceType};
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;

    struct MockFunction {
        name: &'static str,
    }

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not exercised by this test")
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            self.name.to_string()
        }

        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            unimplemented!("not exercised by this test")
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this test")
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
            unimplemented!("not exercised by this test")
        }

        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!("not exercised by this test")
        }

        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!("not exercised by this test")
        }

        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!("not exercised by this test")
        }

        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!("not exercised by this test")
        }

        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            unimplemented!("not exercised by this test")
        }

        fn get_signature_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_signature_source(&mut self, _signature_source: SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!("not exercised by this test")
        }

        fn get_stack_purge_size(&self) -> i32 {
            0
        }

        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            Vec::new()
        }

        fn add_tag(&mut self, _name: &str) -> bool {
            false
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
            unimplemented!("not exercised by this test")
        }

        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not exercised by this test")
        }

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!("not exercised by this test")
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
            unimplemented!("not exercised by this test")
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
            unimplemented!("not exercised by this test")
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
            unimplemented!("not exercised by this test")
        }

        fn remove_variable(&mut self, _var: &dyn Variable) {}

        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
        ) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            unimplemented!("not exercised by this test")
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
            String::new()
        }

        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            unimplemented!("not exercised by this test")
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

        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            unimplemented!("not exercised by this test")
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

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    struct MockRelatedMatch {
        correlation: VtRelatedMatchType,
        source_address: Address,
        source_function: Arc<dyn Function>,
        destination_address: Address,
        destination_function: Arc<dyn Function>,
    }

    impl VTRelatedMatch for MockRelatedMatch {
        fn get_correlation(&self) -> VtRelatedMatchType {
            self.correlation
        }

        fn get_source_address(&self) -> Address {
            self.source_address.clone()
        }

        fn get_source_function(&self) -> Arc<dyn Function> {
            self.source_function.clone()
        }

        fn get_destination_address(&self) -> Address {
            self.destination_address.clone()
        }

        fn get_destination_function(&self) -> Arc<dyn Function> {
            self.destination_function.clone()
        }
    }

    fn mock_related_match() -> MockRelatedMatch {
        let correlation = VtRelatedMatchType::find_match_type(
            VtRelatedMatchCorrelationType::Caller,
            VtRelatedMatchCorrelationType::Caller,
            VtAssociationStatus::Accepted,
        )
        .expect("CallerMatchesCallerAccepted must exist");

        MockRelatedMatch {
            correlation,
            source_address: mock_address(0x1000),
            source_function: Arc::new(MockFunction { name: "source_fn" }),
            destination_address: mock_address(0x2000),
            destination_function: Arc::new(MockFunction { name: "destination_fn" }),
        }
    }

    #[test]
    fn get_correlation_returns_assigned_type() {
        let related_match = mock_related_match();
        assert_eq!(
            related_match.get_correlation(),
            VtRelatedMatchType::CallerMatchesCallerAccepted
        );
    }

    #[test]
    fn get_source_address_and_function_match_construction() {
        let related_match = mock_related_match();
        assert_eq!(related_match.get_source_address(), mock_address(0x1000));
        assert_eq!(
            Function::get_name(related_match.get_source_function().as_ref()),
            "source_fn"
        );
    }

    #[test]
    fn get_destination_address_and_function_match_construction() {
        let related_match = mock_related_match();
        assert_eq!(related_match.get_destination_address(), mock_address(0x2000));
        assert_eq!(
            Function::get_name(related_match.get_destination_function().as_ref()),
            "destination_fn"
        );
    }

    #[test]
    fn usable_as_trait_object() {
        let related_match: Box<dyn VTRelatedMatch> = Box::new(mock_related_match());
        assert_eq!(
            related_match.get_correlation(),
            VtRelatedMatchType::CallerMatchesCallerAccepted
        );
    }
}

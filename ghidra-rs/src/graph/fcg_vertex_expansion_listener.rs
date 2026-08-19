use super::seam_stubs::FcgVertex;

/// A listener to know when a vertex has been told to expand.
pub trait FcgVertexExpansionListener: Send + Sync {
    /// Show or hide those vertices that are on incoming edges to v.
    fn toggle_incoming_vertices(&self, v: &dyn FcgVertex);

    /// Show or hide those vertices that are on outgoing edges to v.
    fn toggle_outgoing_vertices(&self, v: &dyn FcgVertex);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Function;
    use crate::program::model::symbol::Namespace;
    use crate::graph::seam_stubs::FcgLevel;
    use crate::graph::fcg_direction::FcgDirection;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockFunction;

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
            "mock".to_string()
        }
        fn set_name(&mut self, _name: &str, _source: crate::program::model::symbol::SourceType) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            Ok(())
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
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
            mock_address(0x100)
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
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!()
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            String::new()
        }
        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType {
            unimplemented!()
        }
        fn set_signature_source(&mut self, _signature_source: crate::program::model::symbol::SourceType) {}
        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!()
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
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
        fn add_parameter(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
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
        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            None
        }
        fn get_parameter_count(&self) -> i32 {
            0
        }
        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Variable>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }
        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {}
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }
        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException> {
            unimplemented!()
        }
        fn has_custom_variable_storage(&self) -> bool {
            false
        }
        fn set_custom_variable_storage(&mut self, _custom_storage: bool) {}
        fn is_external(&self) -> bool {
            false
        }
        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            Ok(())
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }
        fn is_thunk(&self) -> bool {
            false
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
        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            String::from("unknown")
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
        fn get_calling_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }
        fn get_called_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }
        fn set_body(&mut self, _new_body: &dyn crate::program::model::address::AddressSetView) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            Ok(())
        }
        fn promote_local_user_labels_to_global(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
    }

    struct MockVertex;
    impl FcgVertex for MockVertex {
        fn clone_vertex(&self, _new_listener: &dyn FcgVertexExpansionListener) -> Box<dyn FcgVertex> {
            Box::new(MockVertex)
        }
        fn get_function(&self) -> Arc<dyn Function> {
            Arc::new(MockFunction)
        }
        fn get_address(&self) -> Address {
            mock_address(0x100)
        }
        fn get_options(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_level(&self) -> FcgLevel {
            FcgLevel::new(0, FcgDirection::InAndOut)
        }
        fn get_degree(&self) -> i32 {
            0
        }
        fn get_direction(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn set_hovered(&self, _hovered: bool) {}
        fn get_incoming_toggle_button(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_outgoing_toggle_button(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn set_has_incoming_references(&self, _has_incoming: bool) {}
        fn set_has_outgoing_references(&self, _has_outgoing: bool) {}
        fn set_too_many_incoming_references(&self, _too_many: bool) {}
        fn set_too_many_outgoing_references(&self, _too_many: bool) {}
        fn has_too_many_incoming_references(&self) -> bool {
            false
        }
        fn has_too_many_outgoing_references(&self) -> bool {
            false
        }
        fn is_incoming_expanded(&self) -> bool {
            false
        }
        fn is_outgoing_expanded(&self) -> bool {
            false
        }
        fn is_expanded(&self) -> bool {
            false
        }
        fn can_expand(&self) -> bool {
            false
        }
        fn can_expand_incoming_references(&self) -> bool {
            false
        }
        fn can_expand_outgoing_references(&self) -> bool {
            false
        }
        fn set_incoming_expanded(&self, _set_expanded: bool) {}
        fn set_outgoing_expanded(&self, _set_expanded: bool) {}
        fn to_string(&self) -> String {
            "MockVertex".to_string()
        }
        fn hash_code(&self) -> i32 {
            42
        }
        fn equals(&self, _obj: &dyn std::any::Any) -> bool {
            true
        }
        fn dispose(&self) {}
    }

    struct MockListener;

    impl FcgVertexExpansionListener for MockListener {
        fn toggle_incoming_vertices(&self, _v: &dyn FcgVertex) {}

        fn toggle_outgoing_vertices(&self, _v: &dyn FcgVertex) {}
    }

    #[test]
    fn test_listener_implements_trait() {
        let listener = MockListener;
        let vertex = MockVertex;

        listener.toggle_incoming_vertices(&vertex);
        listener.toggle_outgoing_vertices(&vertex);
    }

    #[test]
    fn test_listener_as_trait_object() {
        let listener: Box<dyn FcgVertexExpansionListener> = Box::new(MockListener);
        let vertex = MockVertex;

        listener.toggle_incoming_vertices(&vertex);
        listener.toggle_outgoing_vertices(&vertex);
    }
}

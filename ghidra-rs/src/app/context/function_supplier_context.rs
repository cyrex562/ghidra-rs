use std::sync::Arc;

use crate::docking::action_context::ActionContext;
use crate::program::model::listing::Function;

/// A "mix-in" trait that specific implementers of `ActionContext` may also implement if
/// they can supply functions in their action context. Actions that want to work on functions
/// can look for this trait, which can be used in a variety of contexts.
///
/// Port of `ghidra.app.context.FunctionSupplierContext`.
pub trait FunctionSupplierContext: ActionContext {
    /// Returns true if this context can supply one or more functions.
    fn has_functions(&self) -> bool;

    /// Returns a collection of functions that this context object can supply.
    fn get_functions(&self) -> Vec<Arc<dyn Function>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::Arc;

    use crate::docking::seam_stubs::{ActionContextProvider, Component, ComponentProvider, MouseEvent};

    #[derive(Default)]
    struct MockFunctionSupplierContext {
        functions: Vec<Arc<dyn Function>>,
    }

    impl ActionContext for MockFunctionSupplierContext {
        fn component_provider(&self) -> Option<Arc<dyn ComponentProvider>> {
            None
        }

        fn context_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            None
        }

        fn set_context_object(&mut self, _context_object: Option<Arc<dyn Any + Send + Sync>>) {}

        fn set_event_click_modifiers(&mut self, _modifiers: i32) {}

        fn event_click_modifiers(&self) -> i32 {
            0
        }

        fn has_any_event_click_modifiers(&self, _modifiers_mask: i32) -> bool {
            false
        }

        fn set_source_object(&mut self, _source_object: Option<Arc<dyn Any + Send + Sync>>) {}

        fn source_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            None
        }

        fn set_context_provider(&mut self, _provider: Option<Arc<dyn ActionContextProvider>>) {}

        fn context_provider(&self) -> Option<Arc<dyn ActionContextProvider>> {
            None
        }

        fn set_mouse_event(&mut self, _event: Option<Arc<dyn MouseEvent>>) {}

        fn mouse_event(&self) -> Option<Arc<dyn MouseEvent>> {
            None
        }

        fn source_component(&self) -> Option<Arc<dyn Component>> {
            None
        }

        fn set_source_component(&mut self, _component: Option<Arc<dyn Component>>) {}
    }

    impl FunctionSupplierContext for MockFunctionSupplierContext {
        fn has_functions(&self) -> bool {
            !self.functions.is_empty()
        }

        fn get_functions(&self) -> Vec<Arc<dyn Function>> {
            self.functions.clone()
        }
    }

    #[test]
    fn has_functions_returns_false_for_empty_context() {
        let ctx = MockFunctionSupplierContext::default();
        assert!(!ctx.has_functions());
    }

    #[test]
    fn has_functions_returns_true_when_functions_present() {
        let mut ctx = MockFunctionSupplierContext::default();
        ctx.functions = vec![create_mock_function()];
        assert!(ctx.has_functions());
    }

    #[test]
    fn get_functions_returns_empty_when_no_functions() {
        let ctx = MockFunctionSupplierContext::default();
        assert_eq!(ctx.get_functions().len(), 0);
    }

    #[test]
    fn get_functions_returns_all_functions() {
        let mut ctx = MockFunctionSupplierContext::default();
        ctx.functions = vec![create_mock_function(), create_mock_function(), create_mock_function()];
        let functions = ctx.get_functions();
        assert_eq!(functions.len(), 3);
    }

    #[test]
    fn get_functions_preserves_order() {
        let mut ctx = MockFunctionSupplierContext::default();
        let func1 = create_mock_function();
        let func2 = create_mock_function();
        ctx.functions = vec![func1.clone(), func2.clone()];
        let functions = ctx.get_functions();
        assert_eq!(functions.len(), 2);
    }

    fn create_mock_function() -> Arc<dyn Function> {
        Arc::new(MinimalMockFunction)
    }

    struct MinimalMockFunction;

    use crate::program::model::address::Address;

    impl crate::program::model::symbol::Namespace for MinimalMockFunction {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }

        fn get_name_space_type(&self) -> crate::program::model::symbol::NamespaceType {
            crate::program::model::symbol::NamespaceType::Function
        }

        fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }

        fn get_parent_namespace(
            &self,
        ) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }

        fn get_external_namespace(
            &self,
        ) -> Option<Arc<dyn crate::program::model::symbol::ExternalNamespace>> {
            None
        }

        fn is_external(&self) -> bool {
            false
        }

        fn get_id(&self) -> u64 {
            0
        }
    }

    impl Function for MinimalMockFunction {
        fn get_entry_point(&self) -> Address {
            Address::default()
        }

        fn get_body(&self) -> crate::program::model::address::AddressSetView {
            panic!("not used in test")
        }

        fn set_body(
            &mut self,
            _new_body: crate::program::model::address::AddressSetView,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn contains(&self, _addr: Address) -> bool {
            false
        }

        fn get_function_manager(
            &self,
        ) -> Option<Arc<dyn crate::program::model::listing::FunctionManager>> {
            None
        }

        fn get_program(&self) -> Option<Arc<dyn crate::program::model::listing::Program>> {
            None
        }

        fn get_parameters(
            &self,
        ) -> Vec<Arc<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }

        fn set_parameters(
            &mut self,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _parameters: Vec<Arc<dyn crate::program::model::listing::Parameter>>,
            _calling_convention: String,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn get_return_type(&self) -> Option<Arc<dyn crate::program::model::data::DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _return_type: Arc<dyn crate::program::model::data::DataType>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn get_local_variables(
            &self,
        ) -> Vec<Arc<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn add_local_variable(
            &mut self,
            _variable: Arc<dyn crate::program::model::listing::Variable>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn remove_local_variable(
            &mut self,
            _variable_offset: i32,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn get_stack_frame(
            &self,
        ) -> Option<Arc<dyn crate::program::seam_stubs::StackFrame>> {
            None
        }

        fn get_calling_convention(&self) -> String {
            "unknown".to_string()
        }

        fn set_calling_convention(&mut self, _convention: String) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn get_external_location(&self) -> Option<Arc<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }

        fn set_external_location(&mut self, _external_location: Option<Arc<dyn crate::program::model::symbol::ExternalLocation>>) {
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn get_thunked_function(
            &self,
        ) -> Option<Arc<dyn crate::program::model::listing::Function>> {
            None
        }

        fn add_tag(
            &mut self,
            _tag_name: String,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn remove_tag(
            &mut self,
            _tag_name: String,
        ) -> Result<bool, Box<dyn std::error::Error>> {
            Ok(false)
        }

        fn get_tags(&self) -> Vec<Arc<dyn crate::program::model::listing::FunctionTag>> {
            vec![]
        }

        fn has_tag(&self, _tag_name: &str) -> bool {
            false
        }

        fn remove(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn get_comment(&self) -> String {
            String::new()
        }

        fn set_comment(&mut self, _comment: String) {}

        fn get_return_storage(
            &self,
        ) -> Option<Arc<dyn crate::program::seam_stubs::VariableStorage>> {
            None
        }

        fn set_return_storage(
            &mut self,
            _storage: Arc<dyn crate::program::seam_stubs::VariableStorage>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn get_repeat_pattern(&self) -> Option<u8> {
            None
        }

        fn set_repeat_pattern(&mut self, _pattern: Option<u8>) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn is_inline(&self) -> bool {
            false
        }

        fn is_no_return(&self) -> bool {
            false
        }

        fn has_custom_variable_storage(&self) -> bool {
            false
        }

        fn set_custom_variable_storage(
            &mut self,
            _custom_storage: bool,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn get_prototype_model(
            &self,
        ) -> Option<Arc<dyn crate::program::seam_stubs::PrototypeModel>> {
            None
        }

        fn set_prototype_model(
            &mut self,
            _model: Option<Arc<dyn crate::program::seam_stubs::PrototypeModel>>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn update_function(
            &mut self,
            _calling_convention: String,
            _parameters: Vec<Arc<dyn crate::program::model::listing::Parameter>>,
            _return_type: Arc<dyn crate::program::model::data::DataType>,
            _force_custom_storage: bool,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn is_variable_length_stack_frame(&self) -> bool {
            false
        }

        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType {
            crate::program::model::symbol::SourceType::User
        }

        fn set_signature_source(
            &mut self,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }
}

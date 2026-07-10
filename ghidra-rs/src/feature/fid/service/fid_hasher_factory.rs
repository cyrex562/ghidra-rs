use std::sync::Arc;

use crate::generic::cache::Factory;
use crate::program::model::listing::Function;

use super::super::hash::FidHasher;
use super::super::hash::FidHashQuad;

/// A factory for caching FID function hashes. Greatly speeds up processing by memoizing hash
/// values for functions which are used repeatedly in different contexts.
///
/// Port of `ghidra.feature.fid.service.FidHasherFactory`.
pub struct FidHasherFactory {
    hasher: Arc<dyn FidHasher>,
}

impl FidHasherFactory {
    /// Creates a new FidHasherFactory with the given hasher.
    pub fn new(hasher: Arc<dyn FidHasher>) -> Self {
        Self { hasher }
    }
}

impl Factory<Arc<dyn Function>, Option<Arc<dyn FidHashQuad>>> for FidHasherFactory {
    fn get(&self, func: Arc<dyn Function>) -> Option<Arc<dyn FidHashQuad>> {
        match self.hasher.hash(&*func) {
            Ok(maybe_quad) => maybe_quad,
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function::{
        FunctionEditError, FunctionUpdateType, SetFunctionNameError,
        UNKNOWN_CALLING_CONVENTION_STRING,
    };
    use crate::program::model::listing::{FunctionSignature, FunctionTag, Parameter, Program, Variable};
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
    use crate::program::seam_stubs::{PrototypeModel, StackFrame, VariableFilter, VariableStorage};
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockHasher {
        return_quad: bool,
        called: AtomicBool,
    }

    impl FidHasher for MockHasher {
        fn hash(
            &self,
            _func: &dyn Function,
        ) -> Result<Option<Arc<dyn FidHashQuad>>, crate::program::model::mem::MemoryAccessException>
        {
            self.called.store(true, Ordering::SeqCst);
            if self.return_quad {
                Ok(Some(Arc::new(MockQuad)))
            } else {
                Ok(None)
            }
        }
    }

    struct MockQuad;
    impl FidHashQuad for MockQuad {
        fn code_unit_size(&self) -> i16 {
            10
        }

        fn full_hash(&self) -> i64 {
            0x1234_5678_9ABC_DEF0_u64 as i64
        }

        fn specific_hash_additional_size(&self) -> i8 {
            3
        }

        fn specific_hash(&self) -> i64 {
            0xDEAD_BEEF_CAFE_1234_u64 as i64
        }
    }

    struct FailingHasher;
    impl FidHasher for FailingHasher {
        fn hash(
            &self,
            _func: &dyn Function,
        ) -> Result<Option<Arc<dyn FidHashQuad>>, crate::program::model::mem::MemoryAccessException>
        {
            Err(crate::program::model::mem::MemoryAccessException::new(
                "test failure",
            ))
        }
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
            mock_address(0x1000)
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

    #[test]
    fn factory_returns_quad_when_hasher_succeeds() {
        let hasher = Arc::new(MockHasher {
            return_quad: true,
            called: AtomicBool::new(false),
        });
        let factory = FidHasherFactory::new(hasher.clone());
        let func = Arc::new(MockFunction) as Arc<dyn Function>;

        let result = factory.get(func);

        assert!(result.is_some());
        assert!(hasher.called.load(Ordering::SeqCst));
    }

    #[test]
    fn factory_returns_none_when_hasher_returns_none() {
        let hasher = Arc::new(MockHasher {
            return_quad: false,
            called: AtomicBool::new(false),
        });
        let factory = FidHasherFactory::new(hasher.clone());
        let func = Arc::new(MockFunction) as Arc<dyn Function>;

        let result = factory.get(func);

        assert!(result.is_none());
        assert!(hasher.called.load(Ordering::SeqCst));
    }

    #[test]
    fn factory_returns_none_on_memory_access_exception() {
        let hasher = Arc::new(FailingHasher);
        let factory = FidHasherFactory::new(hasher);
        let func = Arc::new(MockFunction) as Arc<dyn Function>;

        let result = factory.get(func);

        assert!(result.is_none());
    }

    #[test]
    fn factory_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FidHasherFactory>();
    }

    #[test]
    fn factory_trait_object() {
        let hasher = Arc::new(MockHasher {
            return_quad: true,
            called: AtomicBool::new(false),
        });
        let factory: Box<dyn Factory<Arc<dyn Function>, Option<Arc<dyn FidHashQuad>>>> =
            Box::new(FidHasherFactory::new(hasher));
        let func = Arc::new(MockFunction) as Arc<dyn Function>;

        let result = factory.get(func);

        assert!(result.is_some());
    }
}

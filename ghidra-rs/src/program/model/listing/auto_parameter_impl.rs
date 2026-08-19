//! Port of `ghidra.program.model.listing.AutoParameterImpl`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends ParameterImpl` to represent a hidden, calling-convention-injected
//! parameter (e.g. `this`, `__return_storage_ptr__`) that carries a direct reference back to its
//! owning [`Function`] and rejects every mutation. Following the same `*_impl_*`-prefix,
//! `stored_*`-accessor convention as
//! [`ParameterImpl`](crate::program::model::listing::parameter_impl::ParameterImpl) and
//! [`VariableImpl`](crate::program::model::listing::variable_impl::VariableImpl): the private
//! `function` field is exposed via a required
//! [`stored_function`](AutoParameterImpl::stored_function) accessor, and each `Variable`/
//! `Parameter` method `AutoParameterImpl` overrides is exposed as a defaulted
//! `auto_parameter_impl_*` method. A concrete type implementing `AutoParameterImpl` (on top of
//! `ParameterImpl`/`VariableImpl`/`Parameter`/`Variable`) is expected to delegate
//! `get_function`/`set_data_type_with_storage`/`set_data_type`/`set_comment`/`set_name` to these
//! five methods instead of their `parameter_impl_*`/`variable_impl_*` counterparts, exactly as
//! `MockParameterImpl` delegates to `ParameterImpl` in the sibling module.
//!
//! The two-part constructor validation (`getAutoName(storage.getAutoParameterType())`, evaluated
//! as part of the Java `super(...)` call, followed by the `isForcedIndirect() ||
//! !isAutoStorage()` check in the constructor body) is ported as the free functions
//! [`auto_parameter_name`] and [`check_auto_storage`], mirroring how
//! [`VariableImpl`](crate::program::model::listing::variable_impl::VariableImpl)'s `init_fields`
//! ports its own constructor-time validation as a free function a concrete implementor's
//! constructor is expected to call, since a trait cannot construct "a new `Self`" generically.
//! Both report their Java `IllegalArgumentException` via [`InvalidInputException`], mirroring the
//! same substitution `VariableImpl::check_usage`/`check_program` already make (there is no ported
//! analogue of the unchecked `IllegalArgumentException`).
//!
//! `VariableStorage.isForcedIndirect()`/`isAutoStorage()` are already covered by the
//! [`VariableStorage`](crate::program::model::listing::variable_storage::VariableStorage) trait (grown
//! for `ParameterImpl`), so no further growth is needed here.

use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::parameter_impl::ParameterImpl;
use crate::program::model::listing::variable::SetVariableNameError;
use crate::program::model::listing::{AutoParameterType, Function};
use crate::program::model::symbol::SourceType;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::util::exception::InvalidInputException;

/// Stands in for the private static `AutoParameterImpl.getAutoName(AutoParameterType)`: the
/// display name assigned to an auto-parameter, or an error if `storage` does not correspond to
/// an auto-parameter at all (`autoParamType == null`).
pub fn auto_parameter_name(
    auto_param_type: Option<AutoParameterType>,
) -> Result<String, InvalidInputException> {
    match auto_param_type {
        Some(t) => Ok(t.display_name().to_string()),
        None => Err(InvalidInputException::with_message(
            "storage does not correspond to an auto-parameter",
        )),
    }
}

/// Stands in for the `if (storage.isForcedIndirect() || !storage.isAutoStorage())` guard in the
/// `AutoParameterImpl` constructor body.
pub fn check_auto_storage(storage: &dyn VariableStorage) -> Result<(), InvalidInputException> {
    if storage.is_forced_indirect() || !storage.is_auto_storage() {
        Err(InvalidInputException::with_message(
            "Improper auto storage specified",
        ))
    } else {
        Ok(())
    }
}

/// Field-backed default implementation of the `Variable`/`Parameter` overrides `AutoParameterImpl`
/// gives real bodies to, layered on top of [`ParameterImpl`].
///
/// Port of `ghidra.program.model.listing.AutoParameterImpl`. See the module docs for the
/// `stored_*` accessor / `auto_parameter_impl_*` method-naming convention.
pub trait AutoParameterImpl: ParameterImpl {
    /// Backing storage for the `function` field.
    fn stored_function(&self) -> Box<dyn Function>;

    /// Default body for [`Variable::get_function`](crate::program::model::listing::Variable::get_function).
    ///
    /// Port of `AutoParameterImpl.getFunction`.
    fn auto_parameter_impl_get_function(&self) -> Option<Box<dyn Function>> {
        Some(self.stored_function())
    }

    /// Default body for
    /// [`Variable::set_data_type_with_storage`](crate::program::model::listing::Variable::set_data_type_with_storage):
    /// always rejected.
    ///
    /// Port of `AutoParameterImpl.setDataType(DataType, VariableStorage, boolean, SourceType)`.
    fn auto_parameter_impl_set_data_type_with_storage(
        &mut self,
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        let _ = (data_type, storage, force, source);
        Err(InvalidInputException::with_message(
            "Auto-parameter may not be modified",
        ))
    }

    /// Default body for
    /// [`Variable::set_data_type`](crate::program::model::listing::Variable::set_data_type):
    /// always rejected.
    ///
    /// Port of `AutoParameterImpl.setDataType(DataType, SourceType)`.
    fn auto_parameter_impl_set_data_type(
        &mut self,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        let _ = (data_type, source);
        Err(InvalidInputException::with_message(
            "Auto-parameter may not be modified",
        ))
    }

    /// Default body for
    /// [`Variable::set_comment`](crate::program::model::listing::Variable::set_comment): silently
    /// ignored.
    ///
    /// Port of `AutoParameterImpl.setComment`.
    fn auto_parameter_impl_set_comment(&mut self, comment: Option<String>) {
        let _ = comment;
    }

    /// Default body for
    /// [`Variable::set_name`](crate::program::model::listing::Variable::set_name): always
    /// rejected.
    ///
    /// Port of `AutoParameterImpl.setName`.
    fn auto_parameter_impl_set_name(
        &mut self,
        name: &str,
        source: SourceType,
    ) -> Result<(), SetVariableNameError> {
        let _ = (name, source);
        Err(SetVariableNameError::InvalidInput(
            InvalidInputException::with_message("Auto-parameter may not be modified"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;
    use std::sync::Arc;

    use crate::program::model::address::Address;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::variable::UnsupportedOperationError;
    use crate::program::model::listing::variable_impl::VariableImpl;
    use crate::program::model::listing::{Parameter, Program, Variable};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::Symbol;
    use crate::program::seam_stubs::PlaceholderVariableStorage;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockDataType {
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            format!("mock{}", self.length)
        }
        fn get_length(&self) -> i32 {
            self.length
        }
    }

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

    /// [`VariableStorage`] reporting itself as valid auto-storage for
    /// [`AutoParameterType::ReturnStoragePtr`], mirroring the storage a real
    /// `__return_storage_ptr__` auto-parameter would carry.
    #[derive(Clone)]
    struct AutoStorage;
    impl VariableStorage for AutoStorage {
        fn is_auto_storage(&self) -> bool {
            true
        }
        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            Some(AutoParameterType::ReturnStoragePtr)
        }
        fn with_varnodes(&self, _varnodes: Vec<Varnode>) -> Box<dyn VariableStorage> {
            Box::new(AutoStorage)
        }
    }

    struct MockFunction {
        program: Arc<dyn Program>,
    }

    impl crate::program::model::symbol::Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
    }

    /// Only [`Function::get_program`] is exercised by this module's tests; every other method
    /// (required by the large [`Function`] trait) is unreachable and left `unimplemented!()`,
    /// mirroring the sibling smoke-test mock in `function.rs`.
    impl crate::program::model::listing::Function for MockFunction {
        fn get_name(&self) -> String {
            unimplemented!("not needed for this smoke test")
        }
        fn set_name(
            &mut self,
            _name: &str,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {
            unimplemented!("not needed for this smoke test")
        }
        fn get_call_fixup(&self) -> Option<String> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_comment(&self) -> Option<String> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_comment(&mut self, _comment: Option<&str>) {
            unimplemented!("not needed for this smoke test")
        }
        fn get_repeatable_comment(&self) -> Option<String> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {
            unimplemented!("not needed for this smoke test")
        }
        fn get_entry_point(&self) -> Address {
            unimplemented!("not needed for this smoke test")
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!("not needed for this smoke test")
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
            unimplemented!("not needed for this smoke test")
        }
        fn get_signature_formal(
            &self,
            _formal_signature: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            unimplemented!("not needed for this smoke test")
        }
        fn get_signature_source(&self) -> SourceType {
            unimplemented!("not needed for this smoke test")
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {
            unimplemented!("not needed for this smoke test")
        }
        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_stack_purge_size(&self) -> i32 {
            unimplemented!("not needed for this smoke test")
        }
        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
            unimplemented!("not needed for this smoke test")
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn remove_tag(&mut self, _name: &str) {
            unimplemented!("not needed for this smoke test")
        }
        fn set_stack_purge_size(&mut self, _purge_size: i32) {
            unimplemented!("not needed for this smoke test")
        }
        fn is_stack_purge_size_valid(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, crate::program::model::listing::function::FunctionEditError>
        {
            unimplemented!("not needed for this smoke test")
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, crate::program::model::listing::function::FunctionEditError>
        {
            unimplemented!("not needed for this smoke test")
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            unimplemented!("not needed for this smoke test")
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {
            unimplemented!("not needed for this smoke test")
        }
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn Parameter>, InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parameter_count(&self) -> i32 {
            unimplemented!("not needed for this smoke test")
        }
        fn get_auto_parameter_count(&self) -> i32 {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Parameter>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            unimplemented!("not needed for this smoke test")
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, crate::program::model::listing::function::FunctionEditError>
        {
            unimplemented!("not needed for this smoke test")
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {
            unimplemented!("not needed for this smoke test")
        }
        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
        ) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn has_var_args(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn set_var_args(&mut self, _has_var_args: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn is_inline(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn set_inline(&mut self, _is_inline: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn has_no_return(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn set_no_return(&mut self, _has_no_return: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn has_custom_variable_storage(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn get_calling_convention(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_calling_convention_name(&self) -> String {
            unimplemented!("not needed for this smoke test")
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_thunk(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn get_thunked_function(
            &self,
            _recursive: bool,
        ) -> Option<Arc<dyn crate::program::model::listing::Function>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_thunked_function(
            &mut self,
            _thunked_function: Option<Arc<dyn crate::program::model::listing::Function>>,
        ) -> Result<(), String> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_external(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn get_external_location(
            &self,
        ) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_calling_functions(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn crate::program::model::listing::Function>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_called_functions(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn crate::program::model::listing::Function>> {
            unimplemented!("not needed for this smoke test")
        }
        fn promote_local_user_labels_to_global(&mut self) {
            unimplemented!("not needed for this smoke test")
        }
        fn is_deleted(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
    }

    /// Minimal `AutoParameterImpl`/`ParameterImpl`/`VariableImpl`/`Parameter`/`Variable`
    /// implementor backed by plain struct fields, mirroring `MockParameterImpl` in the sibling
    /// `parameter_impl` module. Every method this port gives a real algorithm to just delegates
    /// to its `auto_parameter_impl_*`/`parameter_impl_*`/`variable_impl_*` counterpart.
    struct MockAutoParameterImpl {
        name: Option<String>,
        data_type: MockDataType,
        comment: Option<String>,
        source_type: SourceType,
        storage: Option<Box<dyn VariableStorage>>,
        program: Arc<dyn Program>,
        ordinal: i32,
        function: Arc<dyn crate::program::model::listing::Function>,
    }

    impl MockAutoParameterImpl {
        /// Mirrors the `AutoParameterImpl` constructor: validates `storage` via
        /// [`auto_parameter_name`]/[`check_auto_storage`] before building the value.
        fn try_new(
            data_type: MockDataType,
            ordinal: i32,
            storage: Box<dyn VariableStorage>,
            function: Arc<dyn crate::program::model::listing::Function>,
        ) -> Result<Self, InvalidInputException> {
            let name = auto_parameter_name(storage.get_auto_parameter_type())?;
            check_auto_storage(storage.as_ref())?;
            Ok(MockAutoParameterImpl {
                name: Some(name),
                data_type,
                comment: None,
                source_type: SourceType::Analysis,
                storage: Some(storage),
                program: function.get_program(),
                ordinal,
                function,
            })
        }
    }

    impl VariableImpl for MockAutoParameterImpl {
        fn has_default_name(&self) -> bool {
            self.parameter_impl_has_default_name()
        }
        fn stored_name(&self) -> Option<String> {
            self.name.clone()
        }
        fn set_stored_name(&mut self, name: Option<String>) {
            self.name = name;
        }
        fn stored_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.data_type)
        }
        fn set_stored_data_type(&mut self, data_type: Box<dyn DataType>) {
            self.data_type = MockDataType {
                length: data_type.get_length(),
            };
        }
        fn stored_comment(&self) -> Option<String> {
            self.comment.clone()
        }
        fn set_stored_comment(&mut self, comment: Option<String>) {
            self.comment = comment;
        }
        fn stored_source_type(&self) -> SourceType {
            self.source_type
        }
        fn set_stored_source_type(&mut self, source_type: SourceType) {
            self.source_type = source_type;
        }
        fn stored_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            self.storage
                .as_ref()
                .map(|s| s.with_varnodes(s.get_varnodes()))
        }
        fn set_stored_variable_storage(&mut self, storage: Option<Box<dyn VariableStorage>>) {
            self.storage = storage;
        }
    }

    impl ParameterImpl for MockAutoParameterImpl {
        fn stored_ordinal(&self) -> i32 {
            self.ordinal
        }
    }

    impl AutoParameterImpl for MockAutoParameterImpl {
        fn stored_function(&self) -> Box<dyn crate::program::model::listing::Function> {
            // `dyn Function` has no `Clone`, so rebuild a fresh `MockFunction` sharing the same
            // underlying `program` rather than trying to hand back `self.function` itself.
            Box::new(MockFunction {
                program: self.function.get_program(),
            })
        }
    }

    impl Variable for MockAutoParameterImpl {
        fn get_data_type(&self) -> Box<dyn DataType> {
            self.parameter_impl_get_data_type()
        }
        fn set_data_type_with_storage(
            &mut self,
            data_type: Box<dyn DataType>,
            storage: Box<dyn VariableStorage>,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.auto_parameter_impl_set_data_type_with_storage(data_type, storage, force, source)
        }
        fn set_data_type(
            &mut self,
            data_type: Box<dyn DataType>,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.auto_parameter_impl_set_data_type(data_type, source)
        }
        fn set_data_type_aligned(
            &mut self,
            data_type: Box<dyn DataType>,
            align: bool,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_impl_set_data_type_aligned(data_type, align, force, source)
        }
        fn get_name(&self) -> Option<String> {
            self.variable_impl_get_name()
        }
        fn get_length(&self) -> i32 {
            self.variable_impl_get_length()
        }
        fn is_valid(&self) -> bool {
            self.variable_impl_is_valid()
        }
        fn get_function(&self) -> Option<Box<dyn crate::program::model::listing::Function>> {
            self.auto_parameter_impl_get_function()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_source(&self) -> SourceType {
            self.variable_impl_get_source()
        }
        fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetVariableNameError> {
            self.auto_parameter_impl_set_name(name, source)
        }
        fn get_comment(&self) -> Option<String> {
            self.variable_impl_get_comment()
        }
        fn set_comment(&mut self, comment: Option<String>) {
            self.auto_parameter_impl_set_comment(comment)
        }
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            self.variable_impl_get_variable_storage()
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            self.variable_impl_get_first_storage_varnode()
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            self.variable_impl_get_last_storage_varnode()
        }
        fn is_stack_variable(&self) -> bool {
            self.variable_impl_is_stack_variable()
        }
        fn has_stack_storage(&self) -> bool {
            self.variable_impl_has_stack_storage()
        }
        fn is_register_variable(&self) -> bool {
            self.variable_impl_is_register_variable()
        }
        fn get_register(&self) -> Option<RegisterRef> {
            self.variable_impl_get_register()
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            self.variable_impl_get_registers()
        }
        fn get_min_address(&self) -> Option<Address> {
            self.variable_impl_get_min_address()
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            self.variable_impl_get_stack_offset()
        }
        fn is_memory_variable(&self) -> bool {
            self.variable_impl_is_memory_variable()
        }
        fn is_unique_variable(&self) -> bool {
            self.variable_impl_is_unique_variable()
        }
        fn is_compound_variable(&self) -> bool {
            self.variable_impl_is_compound_variable()
        }
        fn has_assigned_storage(&self) -> bool {
            self.variable_impl_has_assigned_storage()
        }
        fn get_first_use_offset(&self) -> i32 {
            self.parameter_impl_get_first_use_offset()
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.variable_impl_is_equivalent(variable)
        }
        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.variable_impl_compare_to(other)
        }
        fn is_parameter(&self) -> bool {
            true
        }
        fn is_auto_parameter(&self) -> bool {
            self.parameter_impl_is_auto_parameter()
        }
        fn parameter_ordinal(&self) -> Option<i32> {
            Some(self.stored_ordinal())
        }
    }

    impl Parameter for MockAutoParameterImpl {
        fn get_ordinal(&self) -> i32 {
            self.parameter_impl_get_ordinal()
        }
        fn is_auto_parameter(&self) -> bool {
            self.parameter_impl_is_auto_parameter()
        }
        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            self.parameter_impl_get_auto_parameter_type()
        }
        fn is_forced_indirect(&self) -> bool {
            self.parameter_impl_is_forced_indirect()
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            self.parameter_impl_get_formal_data_type()
        }
    }

    fn mock_function() -> Arc<dyn crate::program::model::listing::Function> {
        Arc::new(MockFunction {
            program: Arc::new(MockProgram),
        })
    }

    #[test]
    fn constructor_rejects_non_auto_storage() {
        let result = MockAutoParameterImpl::try_new(
            MockDataType { length: 4 },
            -1,
            Box::new(PlaceholderVariableStorage),
            mock_function(),
        );
        match result {
            Err(err) => assert_eq!(
                err,
                InvalidInputException::with_message(
                    "storage does not correspond to an auto-parameter"
                )
            ),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn constructor_accepts_auto_storage_and_derives_name() {
        let param = MockAutoParameterImpl::try_new(
            MockDataType { length: 4 },
            -1,
            Box::new(AutoStorage),
            mock_function(),
        )
        .unwrap();
        assert_eq!(param.get_name(), Some("__return_storage_ptr__".to_string()));
        assert_eq!(Parameter::get_ordinal(&param), -1);
    }

    #[test]
    fn get_function_returns_stored_function() {
        let param = MockAutoParameterImpl::try_new(
            MockDataType { length: 4 },
            -1,
            Box::new(AutoStorage),
            mock_function(),
        )
        .unwrap();
        let function = Variable::get_function(&param).expect("auto-parameter always has a function");
        assert_eq!(Program::get_name(function.get_program().as_ref()), "mock");
    }

    #[test]
    fn mutation_methods_are_all_rejected() {
        let mut param = MockAutoParameterImpl::try_new(
            MockDataType { length: 4 },
            -1,
            Box::new(AutoStorage),
            mock_function(),
        )
        .unwrap();

        assert!(param
            .set_data_type(Box::new(MockDataType { length: 8 }), SourceType::UserDefined)
            .is_err());
        assert!(param
            .set_data_type_with_storage(
                Box::new(MockDataType { length: 8 }),
                Box::new(AutoStorage),
                true,
                SourceType::UserDefined,
            )
            .is_err());
        assert!(matches!(
            param.set_name("renamed", SourceType::UserDefined),
            Err(SetVariableNameError::InvalidInput(_))
        ));

        // setComment is silently ignored rather than erroring, matching the Java override.
        param.set_comment(Some("a comment".to_string()));
        assert_eq!(param.get_comment(), None);

        // None of the rejected calls actually mutated the parameter.
        assert_eq!(param.get_data_type().get_length(), 4);
        assert_eq!(param.get_name(), Some("__return_storage_ptr__".to_string()));
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let param: Box<dyn AutoParameterImpl> = Box::new(
            MockAutoParameterImpl::try_new(
                MockDataType { length: 4 },
                -1,
                Box::new(AutoStorage),
                mock_function(),
            )
            .unwrap(),
        );
        assert!(param.auto_parameter_impl_get_function().is_some());
    }
}

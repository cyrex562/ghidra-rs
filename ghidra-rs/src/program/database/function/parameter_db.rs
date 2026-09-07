//! Port of `ghidra.program.database.function.ParameterDB`, mirroring [`VariableDb`]/
//! [`LocalVariableDb`](crate::program::database::function::LocalVariableDb)'s shape: `pub trait
//! ParameterDb: VariableDb + Parameter`, matching how
//! [`ParameterImpl`](crate::program::model::listing::parameter_impl::ParameterImpl) is declared as
//! `VariableImpl + Parameter`.
//!
//! `ParameterDB extends VariableDB implements Parameter`. Its `autoParamCount` field (mutated only
//! by the package-private `setOrdinal(int, int)`) is exposed as required accessors
//! ([`ParameterDb::auto_param_count`]/[`ParameterDb::set_auto_param_count`]), mirroring
//! [`VariableDb`]'s own `cached_storage`/`set_cached_storage` shape for its analogous field.
//!
//! Every `ParameterDB` method gets a real default here:
//! [`get_first_use_offset`](ParameterDb::parameter_db_get_first_use_offset) (a constant `0`),
//! [`get_ordinal`](ParameterDb::parameter_db_get_ordinal)/[`set_ordinal`](ParameterDb::parameter_db_set_ordinal)
//! (pure `symbol`/`auto_param_count` arithmetic, no `functionMgr` notification in the Java body),
//! [`get_formal_data_type`](ParameterDb::parameter_db_get_formal_data_type) (`super.getDataType()`,
//! i.e. [`VariableDb::variable_db_get_data_type`]),
//! [`is_forced_indirect`](ParameterDb::parameter_db_is_forced_indirect), and
//! [`get_data_type`](ParameterDb::parameter_db_get_data_type) (the forced-indirect pointer-wrapping
//! algorithm). `isAutoParameter()`/`getAutoParameterType()` are not re-exposed here since they are
//! already defaulted on [`Parameter`] itself (`false`/`None`) with exactly the values `ParameterDB`
//! hard-codes, so a concrete implementor's `impl Parameter for Foo` needs no override for them.
//!
//! `setDynamicStorage(VariableStorage)` overrides [`VariableDb::variable_db_set_dynamic_storage`]'s
//! panicking default with a real one-line body
//! ([`ParameterDb::parameter_db_set_dynamic_storage`]). Rust cannot let a subtrait override a
//! supertrait's default method directly (the default belongs to [`VariableDb`], not
//! [`ParameterDb`]), so -- mirroring
//! [`ParameterImpl::parameter_impl_has_default_name`](crate::program::model::listing::parameter_impl::ParameterImpl::parameter_impl_has_default_name)'s
//! identical situation with [`VariableImpl::has_default_name`](crate::program::model::listing::variable_impl::VariableImpl::has_default_name) --
//! this is exposed under its own `parameter_db_*` name, and a concrete implementor's `impl
//! VariableDb for Foo` is expected to wire `variable_db_set_dynamic_storage` to call it directly
//! (see the test mock below).
//!
//! The package-private constructor and the `autoParamCount` field's zero-initialization are left
//! out, matching [`VariableDb`]'s own omission of `VariableDB`'s constructor.

use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::listing::Parameter;

use super::VariableDb;

/// Database implementation of a [`Parameter`].
///
/// Port of `ghidra.program.database.function.ParameterDB`.
pub trait ParameterDb: VariableDb + Parameter {
    /// Backing storage for the `autoParamCount` field.
    fn auto_param_count(&self) -> i32;

    /// Update the backing storage for the `autoParamCount` field.
    fn set_auto_param_count(&self, count: i32);

    /// Default body for [`crate::program::model::listing::Variable::get_first_use_offset`]. Port
    /// of `ParameterDB.getFirstUseOffset()`.
    fn parameter_db_get_first_use_offset(&self) -> i32 {
        0
    }

    /// Default body for [`Parameter::get_ordinal`]. Port of `ParameterDB.getOrdinal()`.
    fn parameter_db_get_ordinal(&self) -> i32 {
        self.symbol().variable_ordinal() + self.auto_param_count()
    }

    /// Default body for the package-private `ParameterDB.setOrdinal(int, int)`.
    fn parameter_db_set_ordinal(&self, ordinal: i32, auto_param_count: i32) {
        self.set_auto_param_count(auto_param_count);
        let symbol_ordinal = ordinal - auto_param_count;
        if self.symbol().variable_ordinal() != symbol_ordinal {
            self.symbol().set_variable_ordinal(symbol_ordinal);
        }
    }

    /// Alternate body for [`VariableDb::variable_db_set_dynamic_storage`], standing in for
    /// `ParameterDB.setDynamicStorage(VariableStorage)`'s override of the `VariableDB` default
    /// (see module docs for why a concrete implementor must wire this manually).
    fn parameter_db_set_dynamic_storage(&self, storage: Box<dyn VariableStorage>) {
        self.set_cached_storage(Some(storage));
    }

    /// Default body for [`Parameter::get_formal_data_type`]. Port of
    /// `ParameterDB.getFormalDataType()` (`super.getDataType()`).
    fn parameter_db_get_formal_data_type(&self) -> Box<dyn DataType> {
        self.variable_db_get_data_type()
    }

    /// Default body for [`Parameter::is_forced_indirect`]. Port of
    /// `ParameterDB.isForcedIndirect()`.
    fn parameter_db_is_forced_indirect(&self) -> bool {
        self.variable_db_get_variable_storage().is_forced_indirect()
    }

    /// Default body for [`crate::program::model::listing::Variable::get_data_type`]. Port of
    /// `ParameterDB.getDataType()`: wraps the formal data type in a pointer sized to this
    /// parameter's storage when [`Parameter::is_forced_indirect`] is set.
    fn parameter_db_get_data_type(&self) -> Box<dyn DataType> {
        let dt = self.parameter_db_get_formal_data_type();
        if !self.parameter_db_is_forced_indirect() {
            return dt;
        }
        let ptr_size = self.variable_db_get_variable_storage().size();
        match self.variable_db_get_program().get_data_type_manager() {
            Some(dtm) => {
                let ptr = if ptr_size != dtm.get_data_organization().get_pointer_size() {
                    dtm.get_pointer_with_size(dt.as_ref(), ptr_size)
                } else {
                    dtm.get_pointer(dt.as_ref())
                };
                Box::new(PointerAsDataType(ptr))
            }
            // No data type manager available to mint a real pointer type; return the formal
            // (un-wrapped) type rather than fabricating a placeholder pointer, matching this
            // port's general practice of degrading gracefully when a manager is unavailable (see
            // e.g. `VariableUtilities::get_auto_data_type`'s `dt_mgr` handling).
            None => dt,
        }
    }
}

/// Adapter exposing a [`Box<dyn Pointer>`] as a [`Box<dyn DataType>`] by delegating every
/// [`DataType`] method to the wrapped pointer. Mirrors
/// [`variable_utilities::PointerAsDataType`](crate::program::model::listing::variable_utilities)
/// (duplicated locally since that adapter is private to its module); see that module's
/// `StructureAsDataType` doc for why this delegation is needed (Rust does not support coercing
/// `Box<dyn Sub>` to `Box<dyn Super>` for arbitrary supertraits).
struct PointerAsDataType(Box<dyn Pointer>);

impl DataType for PointerAsDataType {
    fn get_name(&self) -> String {
        DataType::get_name(self.0.as_ref())
    }

    fn get_length(&self) -> i32 {
        DataType::get_length(self.0.as_ref())
    }

    fn is_pointer(&self) -> bool {
        true
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        DataType::is_equivalent(self.0.as_ref(), dt)
    }

    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        DataType::clone_data_type(self.0.as_ref(), dtm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicI32, Ordering as AtomicOrdering};
    use std::sync::Mutex;

    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::database::function::FunctionDb;
    use crate::program::database::function::FunctionManagerDb;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::listing::variable_storage::UnassignedStorage;
    use crate::program::model::listing::{
        AutoParameterType, Function, FunctionSignature, FunctionTag, Program, StackFrame, Variable,
        VariableFilter,
    };
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol, SymbolType};
    use crate::program::seam_stubs::{VariableSymbolDb, VarnodeListStorage};
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;

    #[derive(Clone)]
    struct MockDataType {
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.length == dt.get_length()
        }
        fn get_name(&self) -> String {
            "int".to_string()
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
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

    struct MockSymbol {
        name: Mutex<String>,
        data_type: MockDataType,
        storage: Mutex<Option<Vec<Varnode>>>,
        comment: Mutex<Option<String>>,
        first_use_offset: AtomicI32,
        ordinal: AtomicI32,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            ram_space().address(0)
        }
        fn get_name(&self) -> &str {
            Box::leak(self.name.lock().unwrap().clone().into_boxed_str())
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Parameter
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    impl VariableSymbolDb for MockSymbol {
        fn variable_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.data_type.clone())
        }
        fn variable_storage(&self) -> Box<dyn VariableStorage> {
            match self.storage.lock().unwrap().clone() {
                Some(varnodes) => Box::new(VarnodeListStorage(varnodes)),
                None => Box::new(UnassignedStorage),
            }
        }
        fn set_variable_storage_and_data_type(
            &self,
            storage: Box<dyn VariableStorage>,
            _data_type: Box<dyn DataType>,
        ) {
            *self.storage.lock().unwrap() = Some(storage.get_varnodes());
        }
        fn variable_first_use_offset(&self) -> i32 {
            self.first_use_offset.load(AtomicOrdering::SeqCst)
        }
        fn set_variable_first_use_offset(&self, first_use_offset: i32) {
            self.first_use_offset.store(first_use_offset, AtomicOrdering::SeqCst);
        }
        fn variable_ordinal(&self) -> i32 {
            self.ordinal.load(AtomicOrdering::SeqCst)
        }
        fn set_variable_ordinal(&self, ordinal: i32) {
            self.ordinal.store(ordinal, AtomicOrdering::SeqCst);
        }
        fn variable_symbol_comment(&self) -> Option<String> {
            self.comment.lock().unwrap().clone()
        }
        fn set_variable_symbol_comment(&self, comment: Option<String>) {
            *self.comment.lock().unwrap() = comment;
        }
        fn rename(&self, name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            *self.name.lock().unwrap() = name.to_string();
            Ok(())
        }
    }

    /// Minimal no-op [`FunctionDb`], sufficient to satisfy the trait bound; `custom_storage`
    /// toggles [`crate::program::model::listing::Function::has_custom_variable_storage`] for the
    /// dynamic-storage-vs-custom-storage tests.
    struct MockFunctionDb {
        state: DbObjectState,
        custom_storage: bool,
    }

    impl Namespace for MockFunctionDb {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunctionDb {
        fn get_name(&self) -> String {
            "mock_func".to_string()
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
            ram_space().address(0)
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn set_return_type(
            &mut self,
            _dt: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_return(
            &mut self,
            _dt: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            String::new()
        }
        fn get_signature_source(&self) -> SourceType {
            SourceType::Default
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {}
        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!("not exercised by this smoke test")
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
            unimplemented!("not exercised by this smoke test")
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::function::FunctionUpdateType,
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
            _update_type: crate::program::model::listing::function::FunctionUpdateType,
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
            unimplemented!("not exercised by this smoke test")
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
        fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
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
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {}
        fn set_body(
            &mut self,
            _new_body: &dyn AddressSetView,
        ) -> Result<(), crate::program::database::OverlappingFunctionException> {
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
            self.custom_storage
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}
        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::model::lang::PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            String::new()
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
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
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

    impl DbObject for MockFunctionDb {
        fn state(&self) -> &DbObjectState {
            &self.state
        }
        fn refresh(&self, _record: Option<&crate::framework::db::DBRecord>) -> bool {
            true
        }
    }

    impl FunctionDb for MockFunctionDb {
        fn set_validation_enabled(&mut self, _enabled: bool) {}
        fn function_manager(&self) -> Arc<dyn FunctionManagerDb> {
            unimplemented!("not exercised by this smoke test")
        }
        fn do_delete_variable(&mut self, _symbol: &dyn VariableSymbolDb) {}
        fn get_variable(&self, _symbol: &dyn VariableSymbolDb) -> Option<Box<dyn Variable>> {
            None
        }
        fn set_return_storage_and_data_type(
            &mut self,
            _storage: Option<Box<dyn VariableStorage>>,
            _data_type: Box<dyn DataType>,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn get_return_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4 })
        }
        fn get_return_storage(&self, _has_custom_storage: bool) -> Box<dyn VariableStorage> {
            Box::new(UnassignedStorage)
        }
        fn deserialize_storage(&self, _serialized: Option<&str>) -> Box<dyn VariableStorage> {
            Box::new(UnassignedStorage)
        }
        fn get_stored_signature_source(&self) -> SourceType {
            SourceType::Default
        }
        fn set_local_size(&mut self, _size: i32) {}
        fn get_return_address_offset(&self) -> i32 {
            0
        }
        fn set_return_address_offset(&mut self, _offset: i32) {}
        fn create_class_struct_if_needed(&mut self) {}
        fn data_type_changed(&mut self, _var: &dyn Variable) {}
        fn function_changed(&mut self, _change_type: Option<crate::program::util::FunctionChangeType>) {}
        fn invalidate_frame(&mut self) {}
        fn update_parameters_and_return(&mut self) {}
    }

    struct MockParameterDb {
        symbol: Arc<MockSymbol>,
        function: Arc<MockFunctionDb>,
        cache: RefCell<Option<Box<dyn VariableStorage>>>,
        auto_param_count: RefCell<i32>,
    }

    impl VariableDb for MockParameterDb {
        fn symbol(&self) -> Arc<dyn VariableSymbolDb> {
            self.symbol.clone()
        }
        fn function(&self) -> Arc<dyn FunctionDb> {
            self.function.clone()
        }
        fn cached_storage(&self) -> Option<Box<dyn VariableStorage>> {
            self.cache.borrow().as_ref().map(|s| s.with_varnodes(s.get_varnodes()))
        }
        fn set_cached_storage(&self, storage: Option<Box<dyn VariableStorage>>) {
            *self.cache.borrow_mut() = storage;
        }
        fn variable_db_set_comment(&self, comment: Option<String>) {
            self.symbol.set_variable_symbol_comment(comment);
        }
        fn variable_db_get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn variable_db_set_dynamic_storage(&self, storage: Box<dyn VariableStorage>) {
            // `ParameterDB` overrides `setDynamicStorage`; wire the `ParameterDb` alternate body
            // in manually (see the module docs for why this can't be a supertrait default).
            self.parameter_db_set_dynamic_storage(storage);
        }
        fn variable_db_set_data_type_with_storage(
            &self,
            data_type: Box<dyn DataType>,
            new_storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_db_set_storage_and_data_type(new_storage, data_type);
            Ok(())
        }
        fn variable_db_set_data_type_aligned(
            &self,
            data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            let storage = self.variable_db_get_variable_storage();
            self.variable_db_set_storage_and_data_type(storage, data_type);
            Ok(())
        }
    }

    impl ParameterDb for MockParameterDb {
        fn auto_param_count(&self) -> i32 {
            *self.auto_param_count.borrow()
        }
        fn set_auto_param_count(&self, count: i32) {
            *self.auto_param_count.borrow_mut() = count;
        }
    }

    impl Variable for MockParameterDb {
        fn get_data_type(&self) -> Box<dyn DataType> {
            self.parameter_db_get_data_type()
        }
        fn set_data_type_with_storage(
            &mut self,
            data_type: Box<dyn DataType>,
            storage: Box<dyn VariableStorage>,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_db_set_data_type_with_storage(data_type, storage, force, source)
        }
        fn set_data_type(
            &mut self,
            data_type: Box<dyn DataType>,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_db_set_data_type(data_type, source)
        }
        fn set_data_type_aligned(
            &mut self,
            data_type: Box<dyn DataType>,
            align_stack: bool,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_db_set_data_type_aligned(data_type, align_stack, force, source)
        }
        fn get_name(&self) -> Option<String> {
            self.variable_db_get_name()
        }
        fn get_length(&self) -> i32 {
            self.variable_db_get_length()
        }
        fn is_valid(&self) -> bool {
            self.variable_db_is_valid()
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            self.variable_db_get_function()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.variable_db_get_program()
        }
        fn get_source(&self) -> SourceType {
            self.variable_db_get_source()
        }
        fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetVariableNameError> {
            self.variable_db_set_name(name, source)
        }
        fn get_comment(&self) -> Option<String> {
            self.variable_db_get_comment()
        }
        fn set_comment(&mut self, comment: Option<String>) {
            self.variable_db_set_comment(comment)
        }
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            Some(self.variable_db_get_variable_storage())
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            self.variable_db_get_first_storage_varnode()
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            self.variable_db_get_last_storage_varnode()
        }
        fn is_stack_variable(&self) -> bool {
            self.variable_db_is_stack_variable()
        }
        fn has_stack_storage(&self) -> bool {
            self.variable_db_has_stack_storage()
        }
        fn is_register_variable(&self) -> bool {
            self.variable_db_is_register_variable()
        }
        fn get_register(&self) -> Option<RegisterRef> {
            self.variable_db_get_register()
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            self.variable_db_get_registers()
        }
        fn get_min_address(&self) -> Option<Address> {
            self.variable_db_get_min_address()
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            self.variable_db_get_stack_offset()
        }
        fn is_memory_variable(&self) -> bool {
            self.variable_db_is_memory_variable()
        }
        fn is_unique_variable(&self) -> bool {
            self.variable_db_is_unique_variable()
        }
        fn is_compound_variable(&self) -> bool {
            self.variable_db_is_compound_variable()
        }
        fn has_assigned_storage(&self) -> bool {
            self.variable_db_has_assigned_storage()
        }
        fn get_first_use_offset(&self) -> i32 {
            self.parameter_db_get_first_use_offset()
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            self.variable_db_get_symbol()
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.variable_db_is_equivalent(variable)
        }
        fn compare_to(&self, other: &dyn Variable) -> std::cmp::Ordering {
            self.variable_db_compare_to(other)
        }
        fn is_parameter(&self) -> bool {
            true
        }
        fn parameter_ordinal(&self) -> Option<i32> {
            Some(self.get_ordinal())
        }
    }

    impl Parameter for MockParameterDb {
        fn get_ordinal(&self) -> i32 {
            self.parameter_db_get_ordinal()
        }
        fn is_auto_parameter(&self) -> bool {
            false
        }
        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            None
        }
        fn is_forced_indirect(&self) -> bool {
            self.parameter_db_is_forced_indirect()
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            self.parameter_db_get_formal_data_type()
        }
    }

    fn mock_param(storage: Option<Box<dyn VariableStorage>>, custom_storage: bool) -> MockParameterDb {
        MockParameterDb {
            symbol: Arc::new(MockSymbol {
                name: Mutex::new("param_1".to_string()),
                data_type: MockDataType { length: 4 },
                storage: Mutex::new(storage.map(|s| s.get_varnodes())),
                comment: Mutex::new(None),
                first_use_offset: AtomicI32::new(0),
                ordinal: AtomicI32::new(0),
            }),
            function: Arc::new(MockFunctionDb { state: DbObjectState::new(1), custom_storage }),
            cache: RefCell::new(None),
            auto_param_count: RefCell::new(0),
        }
    }

    fn register_storage(size: i32) -> Box<dyn VariableStorage> {
        Box::new(VarnodeListStorage(vec![Varnode::new(register_space().address(0x10), size)]))
    }

    #[test]
    fn get_first_use_offset_is_always_zero() {
        let var = mock_param(Some(register_storage(4)), false);
        assert_eq!(Variable::get_first_use_offset(&var), 0);
    }

    #[test]
    fn get_ordinal_adds_auto_param_count_to_symbol_ordinal() {
        let var = mock_param(Some(register_storage(4)), false);
        var.symbol.set_variable_ordinal(2);
        assert_eq!(Parameter::get_ordinal(&var), 2);

        var.parameter_db_set_ordinal(5, 3);
        assert_eq!(var.auto_param_count(), 3);
        assert_eq!(var.symbol.variable_ordinal(), 2); // 5 - 3
        assert_eq!(Parameter::get_ordinal(&var), 5);
    }

    #[test]
    fn set_dynamic_storage_bypasses_symbol_and_updates_cache_only() {
        let var = mock_param(None, false);
        VariableDb::variable_db_set_dynamic_storage(&var, register_storage(4));
        assert!(var.variable_db_get_variable_storage().is_register_storage());
        // The symbol itself was never touched.
        assert!(var.symbol.variable_storage().is_unassigned_storage());
    }

    #[test]
    fn get_data_type_returns_formal_type_when_not_forced_indirect() {
        let var = mock_param(Some(register_storage(4)), false);
        assert_eq!(var.get_data_type().get_length(), 4);
        assert!(!var.is_forced_indirect());
    }

    #[test]
    fn is_equivalent_uses_parameter_ordinal_from_variable_trait() {
        let a = mock_param(Some(register_storage(4)), false);
        a.symbol.set_variable_ordinal(0);
        let b = mock_param(Some(register_storage(4)), false);
        b.symbol.set_variable_ordinal(0);
        assert!(Variable::is_equivalent(&a, &b));

        let c = mock_param(Some(register_storage(4)), false);
        c.symbol.set_variable_ordinal(1);
        assert!(!Variable::is_equivalent(&a, &c));
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let var: Box<dyn Parameter> = Box::new(mock_param(Some(register_storage(4)), false));
        assert_eq!(var.get_ordinal(), 0);
        assert!(!Parameter::is_auto_parameter(var.as_ref()));
    }
}

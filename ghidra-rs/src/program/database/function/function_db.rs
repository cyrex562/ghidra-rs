//! Port of `ghidra.program.database.function.FunctionDB` as a trait (cycle cut-point).
//!
//! The Java class holds a `final FunctionManagerDB manager` field set at construction and is
//! itself constructed *by* `FunctionManagerDB` (`FunctionManagerDB.getFunction`/`createFunction`
//! build `new FunctionDB(this, addrMap, rec)`). That mutual construction is what makes this class
//! a cycle cut-point, mirroring the same `ExternalManagerDB`/`ExternalLocationDB` relationship
//! captured by [`ExternalManagerDb`](crate::program::database::external::ExternalManagerDb) and
//! [`ExternalLocationDb`](crate::program::database::external::ExternalLocationDb).
//!
//! `FunctionDB implements Function`; this trait models that relationship by extending the
//! already-ported [`Function`] interface rather than re-declaring its methods -- every public
//! `Function` method `FunctionDB` overrides (name, comment, signature, parameters, thunk state,
//! calling convention, tags, ...) is already a required or defaulted method there. `FunctionDB
//! extends DbObject`, similarly modeled by extending the already-ported [`DbObject`] trait, whose
//! [`DbObject::get_key`] stands in for `FunctionDB.getID()` (`return key;`) directly.
//!
//! What this trait adds on top of `Function + DbObject` is `FunctionDB`'s own extra
//! public/package-private API, used by sibling classes in the `ghidra.program.database.function`
//! package (`FunctionVariables`, `ReturnParameterDB`, `ParameterDB`, `VariableDB`,
//! `ThunkFunctionAdapter`) that are not yet ported:
//! - [`set_validation_enabled`](FunctionDb::set_validation_enabled) (public `setValidationEnabled`)
//! - [`function_manager`](FunctionDb::function_manager) (package-private `getFunctionManager()`)
//! - [`do_delete_variable`](FunctionDb::do_delete_variable)/[`get_variable`](FunctionDb::get_variable)
//!   (public `doDeleteVariable(VariableSymbolDB)`/`getVariable(VariableSymbolDB)`)
//! - the DB-record-backed return-type/storage accessors (`setReturnStorageAndDataType`,
//!   `getReturnDataType`, `getReturnStorage`, `deserializeStorage`) and stack-frame-backed
//!   accessors (`setLocalSize`, `getReturnAddressOffset`, `setReturnAddressOffset`)
//! - the change-notification plumbing (`functionChanged`, `invalidateFrame`,
//!   `updateParametersAndReturn`, `dataTypeChanged`) and `createClassStructIfNeeded`
//!
//! All of the above are modeled as *required* methods rather than defaulted: each one either
//! mutates the underlying `DBRecord`/`FunctionManagerDB` state directly in Java (no algorithm to
//! reproduce, just a field write routed through not-yet-ported adapters) or depends on
//! `FunctionManagerDB` methods (`functionChanged`, `getCallFixupMap`, `setFunctionBody`,
//! `getThunkedFunction`, `setThunkedFunction`) that
//! [`FunctionManagerDb`](crate::program::database::function::FunctionManagerDb)'s own module docs
//! explicitly deferred as "used only by the not-yet-ported sibling `FunctionDB`". Reintroducing
//! them here as required methods on `FunctionDb` -- rather than growing `FunctionManagerDb` to
//! supply them -- lets a concrete implementor satisfy them trivially in its own method body,
//! mirroring the same choice [`ExternalLocationDb::ext_manager_create_function`] makes for
//! `ExternalManagerDB.createFunction(ExternalLocation)`.
//!
//! Two package-private helpers *are* pure algorithms over already-ported/required state, and are
//! kept as default methods: [`get_stored_signature_source`](FunctionDb::get_stored_signature_source)
//! is required (raw flag-bits decode with no portable algorithm behind it), but
//! [`update_signature_source_after_variable_change`](FunctionDb::update_signature_source_after_variable_change)
//! and [`get_inferred_signature_source`](FunctionDb::get_inferred_signature_source) are provided as
//! default methods built on top of it plus the already-required [`Function::get_return_type`]/
//! [`Function::get_parameters`].
//!
//! Left out of this port:
//! - The constructor and private `init()`/`refresh(DBRecord)` (the latter is `DbObject::refresh`,
//!   a required method on the already-ported [`DbObject`] supertrait; a concrete implementor
//!   supplies it directly).
//! - `equals`/`hashCode`/`toString`: Rust has no `Object` identity contract to satisfy, and
//!   `toString` (`getName(true)`) is already available to any caller via
//!   `Namespace::get_name_with_path(true)` (`Function: Namespace`), so no `Display` impl is added
//!   here.
//! - Private helpers with no external callers: `getFunctionThunkAddresses(long, boolean)` (the
//!   recursive worker behind the already-ported public
//!   [`Function::get_function_thunk_addresses`]), `adjustThunkThisParameter` (all three
//!   overloads), the private `ThunkVariableFilter` inner class, and `getRealCallingConventionName`
//!   (worker behind `getPrototypeString`, itself already a required [`Function`] method).
//! - `startUpdate()`/`endUpdate()`: a private reentrancy-tracking pair used only to defer this
//!   object's own `refresh()` while one of its own mutating methods is on the call stack. This is
//!   an implementation detail of how a concrete `FunctionDb` implementor should guard its
//!   [`DbObject::refresh`] body, not API another type needs to call.

use std::sync::Arc;

use crate::program::database::db_object::DbObject;
use crate::program::database::function::FunctionManagerDb;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::undefined::is_undefined;
use crate::program::model::listing::{Function, Variable};
use crate::program::model::symbol::SourceType;
use crate::program::seam_stubs::VariableStorage;
use crate::program::util::FunctionChangeType;

/// Database implementation of a Function.
///
/// Port of `ghidra.program.database.function.FunctionDB` (cycle cut-point; see the module docs
/// for what was ported, added, and omitted).
pub trait FunctionDb: Function + DbObject {
    /// Enable or disable variable-storage validation performed while editing this function's
    /// variables.
    ///
    /// Stands in for `FunctionDB.setValidationEnabled(boolean)`.
    fn set_validation_enabled(&mut self, enabled: bool);

    /// Accessor for the owning `FunctionManagerDB`, standing in for the `manager` field
    /// (package-private `getFunctionManager()`).
    fn function_manager(&self) -> Arc<dyn FunctionManagerDb>;

    /// Callback to remove a variable just prior to removal of its underlying symbol.
    ///
    /// Stands in for `FunctionDB.doDeleteVariable(VariableSymbolDB)`.
    fn do_delete_variable(&mut self, symbol: &dyn crate::program::seam_stubs::VariableSymbolDb);

    /// Returns the `Variable` for the given variable symbol.
    ///
    /// Stands in for `FunctionDB.getVariable(VariableSymbolDB)`.
    fn get_variable(
        &self,
        symbol: &dyn crate::program::seam_stubs::VariableSymbolDb,
    ) -> Option<Box<dyn Variable>>;

    /// Persist the resolved return data type id and, if custom storage is enabled, the serialized
    /// return storage.
    ///
    /// Stands in for `FunctionDB.setReturnStorageAndDataType(VariableStorage, DataType)`.
    ///
    /// # Errors
    /// Returns `Err` on a database IO failure.
    fn set_return_storage_and_data_type(
        &mut self,
        storage: Option<Box<dyn VariableStorage>>,
        data_type: Box<dyn DataType>,
    ) -> std::io::Result<()>;

    /// Returns the raw stored return data type, without factoring in whether this function is a
    /// thunk (`getReturn()` handles thunk delegation before ever reaching this method in Java).
    ///
    /// Stands in for `FunctionDB.getReturnDataType()`.
    fn get_return_data_type(&self) -> Box<dyn DataType>;

    /// Returns the raw stored return storage, or `VariableStorage.UNASSIGNED_STORAGE` if
    /// `has_custom_storage` is `false`.
    ///
    /// Stands in for `FunctionDB.getReturnStorage(boolean)`.
    fn get_return_storage(&self, has_custom_storage: bool) -> Box<dyn VariableStorage>;

    /// Deserializes a `VariableStorage` serialization string produced by
    /// `VariableStorage.getSerializationString()`, returning `VariableStorage.BAD_STORAGE` if the
    /// string cannot be parsed, or `VariableStorage.UNASSIGNED_STORAGE` if `serialized` is `None`.
    ///
    /// Stands in for `FunctionDB.deserializeStorage(String)`.
    fn deserialize_storage(&self, serialized: Option<&str>) -> Box<dyn VariableStorage>;

    /// Returns the raw stored signature source flag bits, without factoring in whether this
    /// function is a thunk (`getSignatureSource()` handles thunk delegation before ever reaching
    /// this method in Java).
    ///
    /// Stands in for `FunctionDB.getStoredSignatureSource()`.
    fn get_stored_signature_source(&self) -> SourceType;

    /// Sets this function's stack frame local size.
    ///
    /// Stands in for package-private `FunctionDB.setLocalSize(int)`.
    ///
    /// # Panics
    /// Implementations should panic if `size` is negative, standing in for the Java method's
    /// `IllegalArgumentException`.
    fn set_local_size(&mut self, size: i32);

    /// Returns this function's stack frame return address offset.
    ///
    /// Stands in for package-private `FunctionDB.getReturnAddressOffset()`.
    fn get_return_address_offset(&self) -> i32;

    /// Sets this function's stack frame return address offset.
    ///
    /// Stands in for package-private `FunctionDB.setReturnAddressOffset(int)`.
    fn set_return_address_offset(&mut self, offset: i32);

    /// If this function's calling convention is `__thiscall` and it resides within a
    /// `GhidraClass` namespace, resolves (creating if needed) the class structure used for its
    /// `this`-pointer auto-parameter.
    ///
    /// Stands in for package-private `FunctionDB.createClassStructIfNeeded()`.
    fn create_class_struct_if_needed(&mut self);

    /// Notification that `var`'s data type changed; propagates a
    /// [`FunctionChangeType::ParametersChanged`] notification if `var` is a parameter, else an
    /// unspecified function-changed notification.
    ///
    /// Stands in for package-private `FunctionDB.dataTypeChanged(VariableDB)`.
    fn data_type_changed(&mut self, var: &dyn Variable);

    /// Routes a function-changed notification (of the given specific type, or unspecified) to
    /// this function's owning manager.
    ///
    /// Stands in for package-private `FunctionDB.functionChanged(FunctionChangeType)`.
    fn function_changed(&mut self, change_type: Option<FunctionChangeType>);

    /// Invalidates this function's cached stack frame.
    ///
    /// Stands in for package-private `FunctionDB.invalidateFrame()`.
    fn invalidate_frame(&mut self);

    /// If this function's variables have already been lazily loaded, recomputes dynamic
    /// parameter/return storage for the current calling convention.
    ///
    /// Stands in for package-private `FunctionDB.updateParametersAndReturn()`.
    fn update_parameters_and_return(&mut self);

    /// If `variable_source_type` has a strictly higher priority than this function's currently
    /// stored signature source, promotes the signature source to `variable_source_type`. No-op if
    /// `variable_data_type` is an undefined data type.
    ///
    /// Stands in for package-private
    /// `FunctionDB.updateSignatureSourceAfterVariableChange(SourceType, DataType)`.
    fn update_signature_source_after_variable_change(
        &mut self,
        variable_source_type: SourceType,
        variable_data_type: Box<dyn DataType>,
    ) {
        if is_undefined(variable_data_type) {
            return;
        }
        if variable_source_type.is_higher_priority_than(&self.get_stored_signature_source()) {
            self.set_signature_source(variable_source_type);
        }
    }

    /// Computes the inferred signature source for use during upgrade, based on whether the return
    /// type and parameter data types are undefined.
    ///
    /// Stands in for package-private `FunctionDB.getInferredSignatureSource()`.
    fn get_inferred_signature_source(&self) -> SourceType {
        let is_return_undefined = match self.get_return_type() {
            Some(dt) => is_undefined(dt),
            None => true,
        };
        let mut result = if is_return_undefined {
            SourceType::Default
        } else {
            SourceType::Analysis
        };

        for parameter in self.get_parameters() {
            if is_undefined(parameter.get_data_type()) {
                continue;
            }
            let param_source = parameter.get_source();
            if param_source.is_higher_or_equal_priority_than(&SourceType::Imported) {
                result = param_source;
            } else {
                result = SourceType::Analysis;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::db_object::DbObjectState;
    use crate::program::database::function::function_manager_db::FunctionManagerDb;
    use crate::program::database::manager_db::ManagerDB;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::database::OverlappingFunctionException;
    use crate::program::model::listing::function::{
        FunctionEditError, SetFunctionNameError, UNKNOWN_CALLING_CONVENTION_STRING,
    };
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::listing::{
        CreateFunctionError, FunctionIterator, FunctionSignature, FunctionTag, FunctionTagManager,
        FunctionUpdateType, Parameter, Program,
    };
    use crate::program::model::symbol::{ExternalLocation, Namespace};
    use crate::program::seam_stubs::{StackFrame, VariableFilter, VariableSymbolDb};
    use crate::program::util::function_change_record::FunctionChangeType as FCT;
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Mutex;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockFunctionManagerDb;

    impl ManagerDB for MockFunctionManagerDb {
        fn invalidate_cache(&mut self, _all: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn delete_address_range(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::program::model::listing::FunctionManager for MockFunctionManagerDb {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_calling_convention_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn create_function(
            &mut self,
            _name: Option<&str>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_function_in_namespace(
            &mut self,
            _name: Option<&str>,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_thunk_function(
            &mut self,
            _name: Option<&str>,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _thunked_function: Arc<dyn Function>,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, OverlappingFunctionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_function_count(&self) -> usize {
            0
        }
        fn remove_function(&mut self, _entry_point: &Address) -> bool {
            false
        }
        fn get_function_at(&self, _entry_point: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_referenced_function(&self, _address: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_functions(&self, _forward: bool) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_functions_from(&self, _start: &Address, _forward: bool) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_functions_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_functions_no_stubs(&self, _forward: bool) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_functions_no_stubs_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_functions_no_stubs_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_external_functions(&self) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }
        fn get_functions_overlapping(&self, _set: &dyn AddressSetView) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_referenced_variable(
            &self,
            _instr_addr: &Address,
            _storage_addr: &Address,
            _size: i32,
            _is_read: bool,
        ) -> Option<Box<dyn Variable>> {
            None
        }
        fn get_function(&self, _key: i64) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_function_tag_manager(&self) -> Arc<dyn FunctionTagManager> {
            struct MockTagManager;
            impl FunctionTagManager for MockTagManager {
                fn get_function_tag_by_name(&self, _name: &str) -> Option<&dyn FunctionTag> {
                    None
                }
                fn get_function_tag_by_id(&self, _id: i64) -> Option<&dyn FunctionTag> {
                    None
                }
                fn get_all_function_tags(&self) -> Vec<&dyn FunctionTag> {
                    Vec::new()
                }
                fn is_tag_assigned(&self, _name: &str) -> bool {
                    false
                }
                fn create_function_tag(&mut self, _name: &str, _comment: &str) -> &dyn FunctionTag {
                    unimplemented!("not needed for this smoke test")
                }
                fn get_use_count(&self, _tag: &dyn FunctionTag) -> usize {
                    0
                }
            }
            Arc::new(MockTagManager)
        }
    }

    impl FunctionManagerDb for MockFunctionManagerDb {
        fn create_external_function(
            &mut self,
            _ext_space_addr: Address,
            _name: &str,
            _name_space: Arc<dyn Namespace>,
            _original_import_name: Option<&str>,
            _external_program_address: Option<Address>,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }
        fn function_tags_changed(&mut self) {}
        fn function_namespace_changed(&mut self, _key: i64) {}
        fn do_remove_function(&mut self, _key: i64) -> bool {
            false
        }
        fn init_signature_source(
            &mut self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::program::database::function::function_manager_db::SignatureUpgradeError>
        {
            Ok(())
        }
        fn remove_explicit_this_parameters(
            &mut self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::program::database::function::function_manager_db::SignatureUpgradeError>
        {
            Ok(())
        }
        fn replace_data_types(&mut self, _data_type_replacement_map: &std::collections::HashMap<i64, i64>) {}
        fn is_thunk(&self, _key: i64) -> bool {
            false
        }
        fn get_thunked_function_id(&self, _function_id: i64) -> i64 {
            -1
        }
        fn get_thunk_function_ids(&self, _referenced_function_id: i64) -> Vec<i64> {
            Vec::new()
        }
        fn set_language(
            &mut self,
            _translator: &dyn crate::program::util::language_translator::LanguageTranslator,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
    }

    /// A minimal in-memory `FunctionDB`, exercising object-safety and both the required extra API
    /// surface (beyond `Function + DbObject`) and the default `update_signature_source_after_*`/
    /// `get_inferred_signature_source` algorithms this trait adds.
    struct MockFunctionDb {
        state: DbObjectState,
        name: String,
        deleted: bool,
        return_type: Option<TestDataType>,
        parameters: Vec<TestParam>,
        signature_source: SourceType,
        manager: Arc<dyn FunctionManagerDb>,
        local_size: AtomicI32,
        return_address_offset: AtomicI32,
        frame_invalidations: AtomicI32,
        changed_log: Mutex<Vec<Option<FCT>>>,
    }

    #[derive(Clone)]
    struct TestParam {
        data_type: TestDataType,
        source: SourceType,
    }

    #[derive(Clone)]
    struct TestDataType {
        undefined: bool,
        name: String,
    }

    impl DataType for TestDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn is_undefined_type(&self) -> bool {
            self.undefined
        }
    }

    fn defined_dt(name: &str) -> TestDataType {
        TestDataType {
            undefined: false,
            name: name.to_string(),
        }
    }

    fn undefined_dt() -> TestDataType {
        TestDataType {
            undefined: true,
            name: "undefined".to_string(),
        }
    }

    impl Variable for TestParam {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.data_type.clone())
        }
        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn set_data_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn set_data_type_aligned(
            &mut self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_name(&self) -> Option<String> {
            None
        }
        fn get_length(&self) -> i32 {
            self.data_type.get_length()
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_source(&self) -> SourceType {
            self.source
        }
        fn set_name(
            &mut self,
            _name: &str,
            _source: SourceType,
        ) -> Result<(), SetVariableNameError> {
            Ok(())
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn get_first_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
            None
        }
        fn is_stack_variable(&self) -> bool {
            false
        }
        fn has_stack_storage(&self) -> bool {
            false
        }
        fn is_register_variable(&self) -> bool {
            false
        }
        fn get_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<crate::program::model::lang::RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_stack_offset(
            &self,
        ) -> Result<i32, UnsupportedOperationError> {
            Err(UnsupportedOperationError(
                "not a simple stack variable".to_string(),
            ))
        }
        fn is_memory_variable(&self) -> bool {
            false
        }
        fn is_unique_variable(&self) -> bool {
            false
        }
        fn is_compound_variable(&self) -> bool {
            false
        }
        fn has_assigned_storage(&self) -> bool {
            false
        }
        fn get_first_use_offset(&self) -> i32 {
            0
        }
        fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }
        fn is_equivalent(&self, _variable: &dyn Variable) -> bool {
            false
        }
        fn compare_to(&self, _other: &dyn Variable) -> std::cmp::Ordering {
            std::cmp::Ordering::Equal
        }
        fn is_parameter(&self) -> bool {
            true
        }
    }

    impl Parameter for TestParam {
        fn get_ordinal(&self) -> i32 {
            0
        }
        fn is_auto_parameter(&self) -> bool {
            false
        }
        fn get_auto_parameter_type(&self) -> Option<crate::program::model::listing::AutoParameterType> {
            None
        }
        fn is_forced_indirect(&self) -> bool {
            false
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.data_type.clone())
        }
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    impl Namespace for MockFunctionDb {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunctionDb {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn set_name(
            &mut self,
            name: &str,
            _source: SourceType,
        ) -> Result<(), SetFunctionNameError> {
            self.name = name.to_string();
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
            mock_address(0x1000)
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            self.return_type
                .clone()
                .map(|dt| Box::new(dt) as Box<dyn DataType>)
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
            self.signature_source
        }
        fn set_signature_source(&mut self, signature_source: SourceType) {
            self.signature_source = signature_source;
        }
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
        fn get_parameter(&self, ordinal: i32) -> Option<Box<dyn Parameter>> {
            self.parameters
                .get(ordinal as usize)
                .map(|p| Box::new(p.clone()) as Box<dyn Parameter>)
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
            self.parameters.len() as i32
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            self.parameters
                .iter()
                .cloned()
                .map(|p| Box::new(p) as Box<dyn Parameter>)
                .collect()
        }
        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            Function::get_parameters(self)
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
            self.deleted
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
            self.manager.clone()
        }

        fn do_delete_variable(&mut self, _symbol: &dyn VariableSymbolDb) {}

        fn get_variable(&self, _symbol: &dyn VariableSymbolDb) -> Option<Box<dyn Variable>> {
            None
        }

        fn set_return_storage_and_data_type(
            &mut self,
            _storage: Option<Box<dyn VariableStorage>>,
            data_type: Box<dyn DataType>,
        ) -> std::io::Result<()> {
            self.return_type = Some(TestDataType {
                undefined: data_type.is_undefined_type(),
                name: data_type.get_name(),
            });
            Ok(())
        }

        fn get_return_data_type(&self) -> Box<dyn DataType> {
            self.return_type
                .clone()
                .map(|dt| Box::new(dt) as Box<dyn DataType>)
                .unwrap_or_else(|| Box::new(undefined_dt()))
        }

        fn get_return_storage(&self, _has_custom_storage: bool) -> Box<dyn VariableStorage> {
            Box::new(crate::program::seam_stubs::PlaceholderVariableStorage)
        }

        fn deserialize_storage(&self, _serialized: Option<&str>) -> Box<dyn VariableStorage> {
            Box::new(crate::program::seam_stubs::PlaceholderVariableStorage)
        }

        fn get_stored_signature_source(&self) -> SourceType {
            self.signature_source
        }

        fn set_local_size(&mut self, size: i32) {
            assert!(size >= 0, "invalid local size: {size}");
            self.local_size.store(size, Ordering::SeqCst);
        }

        fn get_return_address_offset(&self) -> i32 {
            self.return_address_offset.load(Ordering::SeqCst)
        }

        fn set_return_address_offset(&mut self, offset: i32) {
            self.return_address_offset.store(offset, Ordering::SeqCst);
        }

        fn create_class_struct_if_needed(&mut self) {}

        fn data_type_changed(&mut self, var: &dyn Variable) {
            let change_type = if var.is_parameter() {
                Some(FCT::ParametersChanged)
            } else {
                None
            };
            self.function_changed(change_type);
        }

        fn function_changed(&mut self, change_type: Option<FCT>) {
            self.changed_log.lock().unwrap().push(change_type);
        }

        fn invalidate_frame(&mut self) {
            self.frame_invalidations.fetch_add(1, Ordering::SeqCst);
        }

        fn update_parameters_and_return(&mut self) {}
    }

    fn function(name: &str) -> MockFunctionDb {
        MockFunctionDb {
            state: DbObjectState::new(42),
            name: name.to_string(),
            deleted: false,
            return_type: None,
            parameters: Vec::new(),
            signature_source: SourceType::Default,
            manager: Arc::new(MockFunctionManagerDb),
            local_size: AtomicI32::new(0),
            return_address_offset: AtomicI32::new(0),
            frame_invalidations: AtomicI32::new(0),
            changed_log: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn get_key_stands_in_for_get_id() {
        let f = function("main");
        assert_eq!(DbObject::get_key(&f), 42);
    }

    #[test]
    fn get_inferred_signature_source_defaults_to_default_with_no_state() {
        let f = function("FUN_00001000");
        assert_eq!(f.get_inferred_signature_source(), SourceType::Default);
    }

    #[test]
    fn get_inferred_signature_source_reflects_defined_return_and_params() {
        let mut f = function("main");
        f.return_type = Some(defined_dt("int"));
        f.parameters.push(TestParam {
            data_type: defined_dt("int"),
            source: SourceType::UserDefined,
        });
        assert_eq!(f.get_inferred_signature_source(), SourceType::UserDefined);
    }

    #[test]
    fn get_inferred_signature_source_skips_undefined_params() {
        let mut f = function("main");
        f.return_type = Some(defined_dt("int"));
        f.parameters.push(TestParam {
            data_type: undefined_dt(),
            source: SourceType::UserDefined,
        });
        assert_eq!(f.get_inferred_signature_source(), SourceType::Analysis);
    }

    #[test]
    fn update_signature_source_after_variable_change_promotes_higher_priority() {
        let mut f = function("main");
        f.signature_source = SourceType::Analysis;
        f.update_signature_source_after_variable_change(
            SourceType::UserDefined,
            Box::new(defined_dt("int")),
        );
        assert_eq!(f.get_signature_source(), SourceType::UserDefined);
    }

    #[test]
    fn update_signature_source_after_variable_change_ignores_undefined_data_type() {
        let mut f = function("main");
        f.signature_source = SourceType::Analysis;
        f.update_signature_source_after_variable_change(
            SourceType::UserDefined,
            Box::new(undefined_dt()),
        );
        assert_eq!(f.get_signature_source(), SourceType::Analysis);
    }

    #[test]
    fn update_signature_source_after_variable_change_ignores_lower_priority() {
        let mut f = function("main");
        f.signature_source = SourceType::UserDefined;
        f.update_signature_source_after_variable_change(
            SourceType::Analysis,
            Box::new(defined_dt("int")),
        );
        assert_eq!(f.get_signature_source(), SourceType::UserDefined);
    }

    #[test]
    fn set_and_get_return_address_offset_and_local_size() {
        let mut f = function("main");
        f.set_local_size(16);
        f.set_return_address_offset(8);
        assert_eq!(f.local_size.load(Ordering::SeqCst), 16);
        assert_eq!(f.get_return_address_offset(), 8);
    }

    #[test]
    #[should_panic(expected = "invalid local size")]
    fn set_local_size_rejects_negative() {
        let mut f = function("main");
        f.set_local_size(-1);
    }

    #[test]
    fn data_type_changed_and_function_changed_route_to_change_log() {
        let mut f = function("main");
        let param = TestParam {
            data_type: defined_dt("int"),
            source: SourceType::UserDefined,
        };
        f.data_type_changed(&param);
        f.function_changed(Some(FCT::InlineChanged));
        let log = f.changed_log.lock().unwrap();
        assert_eq!(
            log.as_slice(),
            &[Some(FCT::ParametersChanged), Some(FCT::InlineChanged)]
        );
    }

    #[test]
    fn invalidate_frame_increments_counter() {
        let mut f = function("main");
        f.invalidate_frame();
        f.invalidate_frame();
        assert_eq!(f.frame_invalidations.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let f: Box<dyn FunctionDb> = Box::new(function("main"));
        assert_eq!(Function::get_name(f.as_ref()), "main");
        assert_eq!(DbObject::get_key(f.as_ref()), 42);
        assert!(!Function::is_deleted(f.as_ref()));
    }
}

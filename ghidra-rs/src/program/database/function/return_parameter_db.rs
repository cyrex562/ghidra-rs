//! Port of `ghidra.program.database.function.ReturnParameterDB`.
//!
//! `ReturnParameterDB extends ParameterDB`, but constructs its superclass with a `null` symbol
//! (`super(function, null)`) and overrides nearly every `Variable`/`Parameter` method that would
//! otherwise touch that symbol: `getName`/`setName`, `getComment`/`setComment`, `getOrdinal`/
//! `setOrdinal`, all three `setDataType` overloads, `getFormalDataType`, `getDataType`,
//! `isForcedIndirect`, `getSource`, `hasAssignedStorage`, `getVariableStorage`, and
//! `setStorageAndDataType`. Since so little of [`VariableDb`](crate::program::database::function::VariableDb)/
//! [`ParameterDb`](crate::program::database::function::ParameterDb)'s symbol-shaped machinery
//! survives unused, this is ported as its own standalone `pub trait ReturnParameterDb: Parameter`
//! (not composing either) with two plain fields exposed as required accessors
//! ([`ReturnParameterDb::stored_data_type`]/[`ReturnParameterDb::stored_storage`], mirroring
//! `dataType`/`storage`) plus [`ReturnParameterDb::function`] for the owning `FunctionDB`.
//!
//! The handful of `Variable` methods `ReturnParameterDB` does *not* override
//! (`isValid`/`getProgram`/`getLength`/`getFunction`/`isEquivalent`/`compareTo`/
//! `getFirstUseOffset`, all inherited unchanged from `VariableDB`/`ParameterDB`) are re-derived
//! here as their own `return_parameter_db_*` defaults operating on
//! [`ReturnParameterDb::stored_storage`]/[`ReturnParameterDb::stored_data_type`] directly, rather
//! than reused from [`VariableDb`]'s defaults (which are keyed on a real symbol this type never
//! has) -- duplicated locally the same way
//! [`VariableDb::variable_db_compare_to`](crate::program::database::function::VariableDb::variable_db_compare_to)
//! already duplicates [`VariableUtilities::compare`](crate::program::model::listing::variable_utilities::VariableUtilities::compare)
//! rather than fighting a `&dyn Variable` reborrow it cannot make.
//!
//! Left as required methods, for the same `&mut self`-through-a-shared-`Arc<dyn FunctionDb>`
//! friction [`VariableDb`]'s own module docs describe:
//! [`set_storage_and_data_type`](ReturnParameterDb::return_parameter_db_set_storage_and_data_type)
//! (calls `FunctionDb::set_return_storage_and_data_type`),
//! [`set_data_type_with_storage`](ReturnParameterDb::return_parameter_db_set_data_type_with_storage),
//! and [`set_data_type_aligned`](ReturnParameterDb::return_parameter_db_set_data_type_aligned)
//! (both additionally call `FunctionDb::update_parameters_and_return`/
//! `update_signature_source_after_variable_change`/`Function::function_changed`, all `&mut self`).
//! [`get_function`](ReturnParameterDb::return_parameter_db_get_function) is required too, for the
//! same `Box<dyn Function>`-from-`Arc<dyn FunctionDb>` reason
//! [`VariableDb::variable_db_get_function`](crate::program::database::function::VariableDb::variable_db_get_function)
//! documents.
//!
//! `setName`/`setComment` get real (non-required) defaults despite being unconditional
//! `UnsupportedOperationException`s in Java: since they always panic regardless of any manager
//! access, there is no `&mut`-reachability problem to solve, just a direct translation of "always
//! throws". The package-private, `final` `setOrdinal(int, int)` is left out entirely: it has no
//! caller outside `FunctionManagerDB`/`FunctionDB` (neither ported), and is not part of the public
//! [`Parameter`] surface this trait needs to satisfy.
//!
//! One known, documented gap: `getDataType()`'s `storage ==
//! DynamicVariableStorage.INDIRECT_VOID_STORAGE` identity check has no Rust equivalent yet --
//! [`DynamicVariableStorage`](crate::program::model::lang::DynamicVariableStorage)'s own module
//! docs already flag that singleton as unmodeled construction-time plumbing. This port always
//! falls through to the general forced-indirect pointer-wrapping path
//! ([`return_parameter_db_get_data_type`](ReturnParameterDb::return_parameter_db_get_data_type)),
//! which is correct for every case except a return value specifically marked with that exact
//! sentinel storage.

use std::cmp::Ordering;
use std::io;
use std::sync::Arc;

use crate::program::database::function::FunctionDb;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::data::undefined::is_undefined;
use crate::program::model::listing::parameter::{RETURN_NAME, RETURN_ORDINAL};
use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::listing::{Function, Parameter, Program, Variable};
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::SourceType;
use crate::util::exception::InvalidInputException;

/// Database implementation of a function's return [`Parameter`].
///
/// Port of `ghidra.program.database.function.ReturnParameterDB`. See the module docs for the
/// default-vs-required split, the duplicated (not composed) `VariableDB`-inherited logic, and the
/// one documented gap (`INDIRECT_VOID_STORAGE`).
pub trait ReturnParameterDb: Parameter {
    /// Backing storage for the `function` field.
    fn function(&self) -> Arc<dyn FunctionDb>;

    /// Backing storage for the `dataType` field.
    fn stored_data_type(&self) -> Box<dyn DataType>;

    /// Update the backing storage for the `dataType` field.
    fn set_stored_data_type(&self, data_type: Box<dyn DataType>);

    /// Backing storage for the `storage` field.
    fn stored_storage(&self) -> Box<dyn VariableStorage>;

    /// Update the backing storage for the `storage` field.
    fn set_stored_storage(&self, storage: Box<dyn VariableStorage>);

    /// Default body for [`Variable::is_valid`]. Port of the inherited, `final`
    /// `VariableDB.isValid()`, with `isVoidAllowed()` hard-coded `true` (`ReturnParameterDB`'s
    /// override).
    fn return_parameter_db_is_valid(&self) -> bool {
        let storage = self.stored_storage();
        let dt = self.get_data_type();
        if dt.is_void_type() {
            return storage.is_void_storage();
        }
        if dt.get_length() <= 0 || !storage.is_valid() {
            return false;
        }
        storage.size() >= dt.get_length()
    }

    /// Default body for [`Variable::get_program`]. Port of the inherited `VariableDB.getProgram()`.
    fn return_parameter_db_get_program(&self) -> Arc<dyn Program> {
        self.function().get_program()
    }

    /// Default body for [`Variable::get_length`]. Port of the inherited `VariableDB.getLength()`.
    fn return_parameter_db_get_length(&self) -> i32 {
        self.get_data_type().get_length()
    }

    /// Default body for [`Variable::get_first_use_offset`]. Port of the inherited
    /// `ParameterDB.getFirstUseOffset()`.
    fn return_parameter_db_get_first_use_offset(&self) -> i32 {
        0
    }

    /// Required body for [`Variable::get_function`]. See the module docs (same reasoning as
    /// [`VariableDb::variable_db_get_function`](crate::program::database::function::VariableDb::variable_db_get_function)).
    fn return_parameter_db_get_function(&self) -> Option<Box<dyn Function>>;

    /// Default body for [`Variable::get_name`]. Port of `ReturnParameterDB.getName()`.
    fn return_parameter_db_get_name(&self) -> String {
        RETURN_NAME.to_string()
    }

    /// Default body for [`Variable::set_name`]. Port of `ReturnParameterDB.setName(String,
    /// SourceType)`: unconditionally throws `UnsupportedOperationException` in Java, which does
    /// not fit this method's checked `Result` error type, so this panics instead.
    ///
    /// # Panics
    /// Always.
    fn return_parameter_db_set_name(&self, _name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
        panic!("setName is not supported for the return parameter");
    }

    /// Default body for [`Variable::get_comment`]. Port of `ReturnParameterDB.getComment()`.
    fn return_parameter_db_get_comment(&self) -> Option<String> {
        None
    }

    /// Default body for [`Variable::set_comment`]. Port of `ReturnParameterDB.setComment(String)`;
    /// see [`ReturnParameterDb::return_parameter_db_set_name`] for why this panics.
    ///
    /// # Panics
    /// Always.
    fn return_parameter_db_set_comment(&self, _comment: Option<String>) {
        panic!("setComment is not supported for the return parameter");
    }

    /// Default body for [`Parameter::get_ordinal`]. Port of the `final`
    /// `ReturnParameterDB.getOrdinal()`.
    fn return_parameter_db_get_ordinal(&self) -> i32 {
        RETURN_ORDINAL
    }

    /// Default body for [`Parameter::get_formal_data_type`]. Port of
    /// `ReturnParameterDB.getFormalDataType()`.
    fn return_parameter_db_get_formal_data_type(&self) -> Box<dyn DataType> {
        self.stored_data_type()
    }

    /// Default body for [`Parameter::is_forced_indirect`]. Port of
    /// `ReturnParameterDB.isForcedIndirect()`.
    fn return_parameter_db_is_forced_indirect(&self) -> bool {
        self.stored_storage().is_forced_indirect()
    }

    /// Default body for [`Variable::get_data_type`]. Port of `ReturnParameterDB.getDataType()`.
    /// See the module docs for the one documented gap (`INDIRECT_VOID_STORAGE`).
    fn return_parameter_db_get_data_type(&self) -> Box<dyn DataType> {
        let dt = self.return_parameter_db_get_formal_data_type();
        if !self.return_parameter_db_is_forced_indirect() {
            return dt;
        }
        let ptr_size = self.stored_storage().size();
        match self.return_parameter_db_get_program().get_data_type_manager() {
            Some(dtm) => {
                let ptr = if ptr_size != dtm.get_data_organization().get_pointer_size() {
                    dtm.get_pointer_with_size(dt.as_ref(), ptr_size)
                } else {
                    dtm.get_pointer(dt.as_ref())
                };
                Box::new(PointerAsDataType(ptr))
            }
            None => dt,
        }
    }

    /// Default body for [`Variable::get_source`]. Port of `ReturnParameterDB.getSource()`.
    fn return_parameter_db_get_source(&self) -> SourceType {
        let dt = self.stored_data_type();
        if is_undefined(dt) {
            SourceType::Default
        } else {
            self.function().get_signature_source()
        }
    }

    /// Default body for [`Variable::has_assigned_storage`]. Port of
    /// `ReturnParameterDB.hasAssignedStorage()`.
    fn return_parameter_db_has_assigned_storage(&self) -> bool {
        self.function().has_custom_variable_storage() && !self.stored_storage().is_unassigned_storage()
    }

    /// Default body for [`Variable::get_variable_storage`] (returning the storage directly, as
    /// with [`VariableDb::variable_db_get_variable_storage`](crate::program::database::function::VariableDb::variable_db_get_variable_storage)).
    /// Port of `ReturnParameterDB.getVariableStorage()`.
    fn return_parameter_db_get_variable_storage(&self) -> Box<dyn VariableStorage> {
        self.stored_storage()
    }

    /// Default body for [`Variable::get_first_storage_varnode`]. Port of the inherited
    /// `VariableDB.getFirstStorageVarnode()`.
    fn return_parameter_db_get_first_storage_varnode(&self) -> Option<Varnode> {
        self.stored_storage().get_first_varnode()
    }

    /// Default body for [`Variable::get_last_storage_varnode`]. Port of the inherited
    /// `VariableDB.getLastStorageVarnode()`.
    fn return_parameter_db_get_last_storage_varnode(&self) -> Option<Varnode> {
        self.stored_storage().get_last_varnode()
    }

    /// Default body for [`Variable::is_stack_variable`]. Port of the inherited
    /// `VariableDB.isStackVariable()`.
    fn return_parameter_db_is_stack_variable(&self) -> bool {
        self.stored_storage().is_stack_storage()
    }

    /// Default body for [`Variable::has_stack_storage`]. Port of the inherited
    /// `VariableDB.hasStackStorage()`.
    fn return_parameter_db_has_stack_storage(&self) -> bool {
        self.stored_storage().has_stack_storage()
    }

    /// Default body for [`Variable::is_register_variable`]. Port of the inherited
    /// `VariableDB.isRegisterVariable()`.
    fn return_parameter_db_is_register_variable(&self) -> bool {
        self.stored_storage().is_register_storage()
    }

    /// Default body for [`Variable::get_register`]. Port of the inherited
    /// `VariableDB.getRegister()`.
    fn return_parameter_db_get_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
        self.stored_storage().get_register()
    }

    /// Default body for [`Variable::get_registers`]. Port of the inherited
    /// `VariableDB.getRegisters()`.
    fn return_parameter_db_get_registers(&self) -> Option<Vec<crate::program::model::lang::RegisterRef>> {
        self.stored_storage().get_registers()
    }

    /// Default body for [`Variable::get_min_address`]. Port of the inherited
    /// `VariableDB.getMinAddress()`.
    fn return_parameter_db_get_min_address(&self) -> Option<crate::program::model::address::Address> {
        self.stored_storage().get_min_address()
    }

    /// Default body for [`Variable::get_stack_offset`]. Port of the inherited
    /// `VariableDB.getStackOffset()`.
    fn return_parameter_db_get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
        Ok(self.stored_storage().get_stack_offset())
    }

    /// Default body for [`Variable::is_memory_variable`]. Port of the inherited
    /// `VariableDB.isMemoryVariable()`.
    fn return_parameter_db_is_memory_variable(&self) -> bool {
        self.stored_storage().is_memory_storage()
    }

    /// Default body for [`Variable::is_unique_variable`]. Port of the inherited
    /// `VariableDB.isUniqueVariable()`.
    fn return_parameter_db_is_unique_variable(&self) -> bool {
        self.stored_storage().is_hash_storage()
    }

    /// Default body for [`Variable::is_compound_variable`]. Port of the inherited
    /// `VariableDB.isCompoundVariable()`.
    fn return_parameter_db_is_compound_variable(&self) -> bool {
        self.stored_storage().is_compound_storage()
    }

    /// Required body for the package-private `VariableDB.setStorageAndDataType(VariableStorage,
    /// DataType)`, overridden by `ReturnParameterDB`:
    /// ```java
    /// void setStorageAndDataType(VariableStorage newStorage, DataType dt) {
    ///     if (!function.hasCustomVariableStorage()) {
    ///         newStorage = VariableStorage.UNASSIGNED_STORAGE;
    ///     }
    ///     try {
    ///         function.setReturnStorageAndDataType(newStorage, dt);
    ///         storage = newStorage;
    ///         dataType = dt;
    ///     }
    ///     catch (IOException e) {
    ///         function.getFunctionManager().dbError(e);
    ///     }
    /// }
    /// ```
    /// Left required: `FunctionDb::set_return_storage_and_data_type` is `&mut self`, unreachable
    /// from a `&self` default through the shared `Arc<dyn FunctionDb>` [`ReturnParameterDb::function`]
    /// returns.
    fn return_parameter_db_set_storage_and_data_type(
        &self,
        new_storage: Box<dyn VariableStorage>,
        data_type: Box<dyn DataType>,
    ) -> io::Result<()>;

    /// Required body for [`Variable::set_data_type_with_storage`]. Port of
    /// `ReturnParameterDB.setDataType(DataType, VariableStorage, boolean, SourceType)`. Left
    /// required for the same reason as
    /// [`ReturnParameterDb::return_parameter_db_set_storage_and_data_type`] (also reaches
    /// `FunctionDb::update_parameters_and_return`/`Function::function_changed`, likewise `&mut
    /// self`).
    fn return_parameter_db_set_data_type_with_storage(
        &self,
        data_type: Box<dyn DataType>,
        new_storage: Box<dyn VariableStorage>,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException>;

    /// Required body for [`Variable::set_data_type_aligned`]. Port of
    /// `ReturnParameterDB.setDataType(DataType, boolean, boolean, SourceType)`. Left required for
    /// the same reason as
    /// [`ReturnParameterDb::return_parameter_db_set_data_type_with_storage`].
    fn return_parameter_db_set_data_type_aligned(
        &self,
        data_type: Box<dyn DataType>,
        align_stack: bool,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException>;

    /// Default body for [`Variable::set_data_type`]. Port of `ReturnParameterDB.setDataType(DataType,
    /// SourceType)`, a pure forward to the `alignStack` overload.
    fn return_parameter_db_set_data_type(
        &self,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.return_parameter_db_set_data_type_aligned(data_type, true, false, source)
    }

    /// Default body for [`Variable::is_equivalent`]. Port of the inherited
    /// `VariableDB.isEquivalent(Variable)`, duplicated locally (see the module docs for why this
    /// isn't reused from [`VariableDb::variable_db_is_equivalent`](crate::program::database::function::VariableDb::variable_db_is_equivalent)).
    fn return_parameter_db_is_equivalent(&self, other: &dyn Variable) -> bool {
        if other.is_parameter() != self.is_parameter() {
            return false;
        }
        if let (Some(mine), Some(theirs)) = (self.parameter_ordinal(), other.parameter_ordinal()) {
            if mine != theirs {
                return false;
            }
        }
        let other_function = other.get_function();
        let self_has_custom = self.function().has_custom_variable_storage();
        let other_has_custom = other_function.as_ref().map(|f| f.has_custom_variable_storage()).unwrap_or(true);
        if self_has_custom || other_has_custom {
            let mine = self.stored_storage();
            let storage_eq = match other.get_variable_storage() {
                Some(theirs) => mine.storage_equals(theirs.as_ref()),
                None => false,
            };
            if !storage_eq {
                return false;
            }
        }
        if self.get_first_use_offset() != other.get_first_use_offset() {
            return false;
        }
        crate::program::model::data::parameter_definition_impl::is_same_or_equivalent_data_type(
            self.get_data_type().as_ref(),
            other.get_data_type().as_ref(),
        )
    }

    /// Default body for [`Variable::compare_to`]. Port of the inherited
    /// `VariableDB.compareTo(Variable)`, duplicated locally (see the module docs).
    fn return_parameter_db_compare_to(&self, other: &dyn Variable) -> Ordering {
        if let (Some(o1), Some(o2)) = (self.parameter_ordinal(), other.parameter_ordinal()) {
            return o1.cmp(&o2);
        }
        let fu1 = self.get_first_use_offset();
        let fu2 = other.get_first_use_offset();
        if fu1 != fu2 {
            if fu1 == 0 {
                return Ordering::Less;
            }
            if fu2 == 0 {
                return Ordering::Greater;
            }
            return fu1.cmp(&fu2);
        }
        Ordering::Equal
    }
}

/// Adapter exposing a [`Box<dyn Pointer>`] as a [`Box<dyn DataType>`]. Duplicated locally from
/// [`crate::program::database::function::parameter_db`]'s identical private adapter (itself a
/// duplicate of `variable_utilities`'s -- see that module's `StructureAsDataType` doc for why this
/// delegation is needed).
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

    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::database::function::FunctionManagerDb;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::variable_storage::UnassignedStorage;
    use crate::program::model::listing::{
        AutoParameterType, FunctionSignature, FunctionTag, StackFrame, VariableFilter,
    };
    use crate::program::seam_stubs::{VariableSymbolDb, VarnodeListStorage};
    use crate::program::model::symbol::{ExternalLocation, Namespace, Symbol, SymbolType};
    use crate::util::task::TaskMonitor;

    #[derive(Clone)]
    struct MockDataType {
        length: i32,
        void_type: bool,
    }

    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_void_type(&self) -> bool {
            self.void_type
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.length == dt.get_length() && self.void_type == dt.is_void_type()
        }
        fn get_name(&self) -> String {
            if self.void_type { "void".to_string() } else { "int".to_string() }
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

    /// Minimal no-op [`FunctionDb`]; `custom_storage` toggles
    /// `Function::has_custom_variable_storage` for the has-assigned-storage tests.
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
            SourceType::Analysis
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
        fn get_calling_convention(&self) -> Option<Arc<crate::program::model::lang::PrototypeModel>> {
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
            Box::new(MockDataType { length: 4, void_type: false })
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

    struct MockReturnParameterDb {
        function: Arc<MockFunctionDb>,
        data_type: RefCell<Box<dyn DataType>>,
        storage: RefCell<Box<dyn VariableStorage>>,
    }

    impl ReturnParameterDb for MockReturnParameterDb {
        fn function(&self) -> Arc<dyn FunctionDb> {
            self.function.clone()
        }
        fn stored_data_type(&self) -> Box<dyn DataType> {
            let dt = self.data_type.borrow();
            Box::new(MockDataType {
                length: dt.get_length(),
                void_type: dt.is_void_type(),
            })
        }
        fn set_stored_data_type(&self, data_type: Box<dyn DataType>) {
            *self.data_type.borrow_mut() = data_type;
        }
        fn stored_storage(&self) -> Box<dyn VariableStorage> {
            let s = self.storage.borrow();
            // Preserve sentinel identity (bad/unassigned/void storage carries no varnodes, so a
            // generic `with_varnodes` rebuild would silently turn it into a merely-empty,
            // non-sentinel `VarnodeListStorage`); see `VariableDb`'s identical `duplicate_storage`
            // helper for the same fix.
            if s.is_void_storage() {
                Box::new(crate::program::model::listing::variable_storage::VoidStorage)
            } else if s.is_unassigned_storage() {
                Box::new(UnassignedStorage)
            } else if s.is_bad_storage() {
                Box::new(crate::program::model::listing::variable_storage::BadStorage)
            } else {
                s.with_varnodes(s.get_varnodes())
            }
        }
        fn set_stored_storage(&self, storage: Box<dyn VariableStorage>) {
            *self.storage.borrow_mut() = storage;
        }
        fn return_parameter_db_get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn return_parameter_db_set_storage_and_data_type(
            &self,
            new_storage: Box<dyn VariableStorage>,
            data_type: Box<dyn DataType>,
        ) -> io::Result<()> {
            self.set_stored_storage(new_storage);
            self.set_stored_data_type(data_type);
            Ok(())
        }
        fn return_parameter_db_set_data_type_with_storage(
            &self,
            data_type: Box<dyn DataType>,
            new_storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.return_parameter_db_set_storage_and_data_type(new_storage, data_type).unwrap();
            Ok(())
        }
        fn return_parameter_db_set_data_type_aligned(
            &self,
            data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            let storage = self.stored_storage();
            self.return_parameter_db_set_storage_and_data_type(storage, data_type).unwrap();
            Ok(())
        }
    }

    impl Variable for MockReturnParameterDb {
        fn get_data_type(&self) -> Box<dyn DataType> {
            self.return_parameter_db_get_data_type()
        }
        fn set_data_type_with_storage(
            &mut self,
            data_type: Box<dyn DataType>,
            storage: Box<dyn VariableStorage>,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.return_parameter_db_set_data_type_with_storage(data_type, storage, force, source)
        }
        fn set_data_type(
            &mut self,
            data_type: Box<dyn DataType>,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.return_parameter_db_set_data_type(data_type, source)
        }
        fn set_data_type_aligned(
            &mut self,
            data_type: Box<dyn DataType>,
            align_stack: bool,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.return_parameter_db_set_data_type_aligned(data_type, align_stack, force, source)
        }
        fn get_name(&self) -> Option<String> {
            Some(self.return_parameter_db_get_name())
        }
        fn get_length(&self) -> i32 {
            self.return_parameter_db_get_length()
        }
        fn is_valid(&self) -> bool {
            self.return_parameter_db_is_valid()
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            self.return_parameter_db_get_function()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.return_parameter_db_get_program()
        }
        fn get_source(&self) -> SourceType {
            self.return_parameter_db_get_source()
        }
        fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetVariableNameError> {
            self.return_parameter_db_set_name(name, source)
        }
        fn get_comment(&self) -> Option<String> {
            self.return_parameter_db_get_comment()
        }
        fn set_comment(&mut self, comment: Option<String>) {
            self.return_parameter_db_set_comment(comment)
        }
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            Some(self.return_parameter_db_get_variable_storage())
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            self.return_parameter_db_get_first_storage_varnode()
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            self.return_parameter_db_get_last_storage_varnode()
        }
        fn is_stack_variable(&self) -> bool {
            self.return_parameter_db_is_stack_variable()
        }
        fn has_stack_storage(&self) -> bool {
            self.return_parameter_db_has_stack_storage()
        }
        fn is_register_variable(&self) -> bool {
            self.return_parameter_db_is_register_variable()
        }
        fn get_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
            self.return_parameter_db_get_register()
        }
        fn get_registers(&self) -> Option<Vec<crate::program::model::lang::RegisterRef>> {
            self.return_parameter_db_get_registers()
        }
        fn get_min_address(&self) -> Option<Address> {
            self.return_parameter_db_get_min_address()
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            self.return_parameter_db_get_stack_offset()
        }
        fn is_memory_variable(&self) -> bool {
            self.return_parameter_db_is_memory_variable()
        }
        fn is_unique_variable(&self) -> bool {
            self.return_parameter_db_is_unique_variable()
        }
        fn is_compound_variable(&self) -> bool {
            self.return_parameter_db_is_compound_variable()
        }
        fn has_assigned_storage(&self) -> bool {
            self.return_parameter_db_has_assigned_storage()
        }
        fn get_first_use_offset(&self) -> i32 {
            self.return_parameter_db_get_first_use_offset()
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.return_parameter_db_is_equivalent(variable)
        }
        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.return_parameter_db_compare_to(other)
        }
        fn is_parameter(&self) -> bool {
            true
        }
        fn parameter_ordinal(&self) -> Option<i32> {
            Some(self.get_ordinal())
        }
    }

    impl Parameter for MockReturnParameterDb {
        fn get_ordinal(&self) -> i32 {
            self.return_parameter_db_get_ordinal()
        }
        fn is_auto_parameter(&self) -> bool {
            false
        }
        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            None
        }
        fn is_forced_indirect(&self) -> bool {
            self.return_parameter_db_is_forced_indirect()
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            self.return_parameter_db_get_formal_data_type()
        }
    }

    fn register_storage(size: i32) -> Box<dyn VariableStorage> {
        Box::new(VarnodeListStorage(vec![Varnode::new(register_space().address(0x10), size)]))
    }

    fn mock_return(custom_storage: bool, dt: MockDataType, storage: Box<dyn VariableStorage>) -> MockReturnParameterDb {
        MockReturnParameterDb {
            function: Arc::new(MockFunctionDb { state: DbObjectState::new(1), custom_storage }),
            data_type: RefCell::new(Box::new(dt)),
            storage: RefCell::new(storage),
        }
    }

    #[test]
    fn name_is_always_the_return_name_constant() {
        let ret = mock_return(false, MockDataType { length: 4, void_type: false }, register_storage(4));
        assert_eq!(Variable::get_name(&ret), Some(RETURN_NAME.to_string()));
        assert_eq!(Parameter::get_ordinal(&ret), RETURN_ORDINAL);
        assert_eq!(ret.get_first_use_offset(), 0);
        assert!(ret.get_comment().is_none());
    }

    #[test]
    #[should_panic(expected = "setName is not supported")]
    fn set_name_panics() {
        let mut ret = mock_return(false, MockDataType { length: 4, void_type: false }, register_storage(4));
        let _ = Variable::set_name(&mut ret, "x", SourceType::UserDefined);
    }

    #[test]
    fn is_valid_allows_void_storage_for_void_type() {
        let ret = mock_return(false, MockDataType { length: 0, void_type: true }, Box::new(crate::program::model::listing::variable_storage::VoidStorage));
        assert!(ret.is_valid());
    }

    #[test]
    fn has_assigned_storage_requires_custom_storage_and_non_unassigned() {
        let with_custom = mock_return(true, MockDataType { length: 4, void_type: false }, register_storage(4));
        assert!(with_custom.has_assigned_storage());

        let without_custom = mock_return(false, MockDataType { length: 4, void_type: false }, register_storage(4));
        assert!(!without_custom.has_assigned_storage());
    }

    #[test]
    fn set_storage_and_data_type_updates_both_fields() {
        let ret = mock_return(true, MockDataType { length: 4, void_type: false }, register_storage(4));
        ret.return_parameter_db_set_storage_and_data_type(
            register_storage(8),
            Box::new(MockDataType { length: 8, void_type: false }),
        ).unwrap();
        assert_eq!(ret.stored_storage().size(), 8);
        assert_eq!(ret.stored_data_type().get_length(), 8);
    }

    #[test]
    fn get_source_reports_default_for_undefined_data_type() {
        let ret = mock_return(false, MockDataType { length: 1, void_type: false }, register_storage(1));
        // MockDataType doesn't implement is_undefined_type as true, so this exercises the
        // "defined" branch (delegates to function.get_signature_source()).
        assert_eq!(ret.return_parameter_db_get_source(), SourceType::Analysis);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let ret: Box<dyn Parameter> = Box::new(mock_return(
            false,
            MockDataType { length: 4, void_type: false },
            register_storage(4),
        ));
        assert_eq!(ret.get_ordinal(), RETURN_ORDINAL);
        assert!(!Parameter::is_auto_parameter(ret.as_ref()));
    }
}

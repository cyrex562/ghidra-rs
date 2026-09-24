//! Port of `ghidra.program.database.function.FunctionVariables`.
//!
//! **This is a partial port.** `FunctionVariables` is `FunctionDB`'s internal bookkeeping for a
//! function's full variable set (parameters, locals, auto-parameters, and the return "parameter").
//! Unlike `FunctionDB`/`VariableDB`/`ParameterDB`/etc., it is not itself a dependency-cycle
//! cut-point -- every method takes the owning `FunctionDB function` as a plain parameter rather
//! than storing it, so this is ported as an ordinary concrete `struct` (not a trait) holding
//! already-ported trait objects: [`Box<dyn ReturnParameterDb>`], `Option<Vec<Box<dyn
//! AutoParameterImpl>>>`, `Vec<Box<dyn ParameterDb>>`, and `Vec<Box<dyn VariableDb>>`, mirroring
//! the Java fields `returnParam`, `autoParams`, `params`, and `locals` exactly (the Java field
//! types are the general `ParameterDB`/`VariableDB`/`AutoParameterImpl` types, not
//! `LocalVariableDB` specifically, which this port matches).
//!
//! ## What's ported (real logic, unit-tested)
//! - The struct's read-only query surface: [`FunctionVariables::get_return_param`],
//!   [`FunctionVariables::get_auto_param_count`], [`FunctionVariables::get_parameter_count`],
//!   [`FunctionVariables::get_local_variables`], [`FunctionVariables::get_variables`],
//!   [`FunctionVariables::get_parameters`], [`FunctionVariables::get_parameter`], and
//!   [`FunctionVariables::renumber_parameter_ordinals`] (the last reuses the already-real
//!   [`ParameterDb::parameter_db_set_ordinal`] default). [`FunctionVariables::set_validation_enabled`]
//!   is a plain field setter (Java's `setValidataionEnabled` name typo is not reproduced).
//! - A handful of `private static` pure helpers with no `FunctionDB`/symbol-table dependency,
//!   ported as free functions: [`is_bad_variable`], [`find_explicit_this_parameter`],
//!   [`find_explicit_return_storage_ptr_parameter`], [`remove_explicit_this_parameter`],
//!   [`remove_explicit_return_storage_ptr_parameter`], and [`check_for_parameter_name_conflict`].
//!   These are exactly the pieces `updateFunction`/`setCustomVariableStorage` (see below) will
//!   need once those land, so porting them now -- independently, with their own tests -- is not
//!   wasted work even though nothing in this port calls them yet.
//!
//! ## What's NOT ported, and why
//! Every method below either constructs a brand-new database symbol/variable (needing
//! `SymbolManager.createVariableSymbol` plumbing and a concrete `VariableSymbolDB`/
//! `LocalVariableImpl`, **neither of which exists in this port yet** -- both are still `TODO` in
//! `PORT_MANIFEST.tsv`), or requires stable object identity across the `symbolMap`/`locals`/
//! `params` lists (Java's `==` reference-equality lookups), which has no direct Rust equivalent
//! for `Box<dyn Trait>` values without a concrete identity story this port hasn't settled on yet:
//! - The real constructor (`FunctionVariables(FunctionDB, boolean)`), `loadSymbolBasedVariables`,
//!   and `loadReturn`: all three walk `function.getSymbol()`'s child symbols via
//!   `SymbolTable.getChildren`, downcast each to `VariableSymbolDB`, and key a `symbolMap` by that
//!   symbol's object identity. [`FunctionVariables::new`] is a plain field constructor standing in
//!   for these -- it does no symbol-table loading and expects a caller to supply already-built
//!   `params`/`locals`/`auto_params`/`return_param` once the loading logic above is ported.
//! - `updateParametersAndReturn`: reachable once `PrototypeModel::get_storage_locations` (already
//!   ported) and `VariableUtilities::get_auto_data_type` (already ported) are wired up, but its
//!   `AutoParameterImpl` construction path goes through the real `AutoParameterImpl` constructor,
//!   which validates storage via `Function`/`FunctionDb` state this struct doesn't have a way to
//!   thread through yet without a concrete implementor to test against.
//! - `addLocalVariable`, `insertParameter`, `updateFunction`, `removeParameter`, `moveParameter`,
//!   `setCustomVariableStorage`, `doDeleteVariable`, `removeVariable(Variable)`, and
//!   `purgeBadVariables`: all call `SymbolManager.createVariableSymbol`/`Symbol.delete()` (DB
//!   writes) and/or `BookmarkManager.setBookmark`, none of which this port threads through a
//!   `FunctionVariables`-level API yet.
//! - `getResolvedVariable`: its final step constructs `new LocalVariableImpl(...)`, and
//!   `LocalVariableImpl` is still `TODO` in `PORT_MANIFEST.tsv`. The pure parts of its algorithm
//!   (formal-data-type extraction for `Parameter`s, [`VariableUtilities::check_data_type`]/
//!   [`VariableUtilities::resize_storage`], both already ported) have no isolated caller yet
//!   without the final construction step, so they are not split out on their own.
//! - `revertIndirectParameter`'s `create = true` branch constructs `new ParameterImpl(...)`, but
//!   [`crate::program::model::listing::parameter_impl::ParameterImpl`] is itself a trait (a
//!   dependency-cycle cut-point, not a concrete constructible type) in this port, so there is no
//!   portable way to "create a new one" generically. Its `create = false` branch (mutate an
//!   existing `Variable` in place via `Variable::set_data_type_with_storage`) has no caller left
//!   once `updateFunction`/`setCustomVariableStorage` are excluded, so it is not ported standalone
//!   either.
//! - The instance-method overload `removeExplicitThisParameter(FunctionDB)` (as opposed to the
//!   ported static `removeExplicitThisParameter(List, String)` overload): it calls
//!   `removeParameter(int)`, not ported (see above).
//!
//! `PORT_MANIFEST.tsv` intentionally still lists this class as `TODO`; flipping it to `DONE` would
//! misrepresent the very large gap above.

use std::collections::HashSet;

use crate::program::database::function::{ParameterDb, ReturnParameterDb, VariableDb};
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::compiler_spec::CALLING_CONVENTION_THISCALL;
use crate::program::model::listing::auto_parameter_impl::AutoParameterImpl;
use crate::program::model::listing::function::{RETURN_PTR_PARAM_NAME, THIS_PARAM_NAME};
use crate::program::model::listing::{Parameter, Variable, VariableFilter};
use crate::program::model::symbol::SymbolUtilities;
use crate::util::exception::DuplicateNameException;

/// A function's full variable set: parameters (including auto-parameters), locals, and the return
/// "parameter". Port of `ghidra.program.database.function.FunctionVariables` (see the module docs
/// for the large list of methods intentionally not yet ported).
pub struct FunctionVariables {
    return_param: Box<dyn ReturnParameterDb>,
    auto_params: Option<Vec<Box<dyn AutoParameterImpl>>>,
    params: Vec<Box<dyn ParameterDb>>,
    locals: Vec<Box<dyn VariableDb>>,
    found_bad_variables: bool,
    validate_enabled: bool,
}

impl FunctionVariables {
    /// Builds a `FunctionVariables` from already-resolved parameter/local/auto-parameter/return
    /// state. Stands in for the real `FunctionVariables(FunctionDB, boolean)` constructor, which
    /// additionally performs the symbol-table loading described in the module docs; this
    /// constructor leaves that loading to the caller. `found_bad_variables` always starts `false`
    /// and `validate_enabled` always starts `true`, matching the Java field initializers.
    pub fn new(
        return_param: Box<dyn ReturnParameterDb>,
        params: Vec<Box<dyn ParameterDb>>,
        locals: Vec<Box<dyn VariableDb>>,
        auto_params: Option<Vec<Box<dyn AutoParameterImpl>>>,
    ) -> Self {
        FunctionVariables {
            return_param,
            auto_params,
            params,
            locals,
            found_bad_variables: false,
            validate_enabled: true,
        }
    }

    /// Port of `FunctionVariables.getReturnParam()`.
    pub fn get_return_param(&self) -> &dyn ReturnParameterDb {
        self.return_param.as_ref()
    }

    /// Port of `FunctionVariables.getAutoParamCount()`.
    pub fn get_auto_param_count(&self) -> i32 {
        self.auto_params.as_ref().map_or(0, |v| v.len() as i32)
    }

    /// Port of `FunctionVariables.getParameterCount()`.
    pub fn get_parameter_count(&self) -> i32 {
        self.params.len() as i32 + self.get_auto_param_count()
    }

    /// Port of `FunctionVariables.getLocalVariables(VariableFilter)`.
    pub fn get_local_variables(&self, filter: Option<&dyn VariableFilter>) -> Vec<&dyn Variable> {
        self.locals
            .iter()
            .map(|v| v.as_ref() as &dyn Variable)
            .filter(|v| filter.map_or(true, |f| f.matches(*v)))
            .collect()
    }

    /// Port of `FunctionVariables.getVariables(VariableFilter)`: auto-parameters first, then
    /// parameters, then locals, matching the Java iteration order exactly.
    pub fn get_variables(&self, filter: Option<&dyn VariableFilter>) -> Vec<&dyn Variable> {
        let mut result: Vec<&dyn Variable> = Vec::new();
        if let Some(auto_params) = &self.auto_params {
            result.extend(
                auto_params
                    .iter()
                    .map(|p| p.as_ref() as &dyn Variable)
                    .filter(|v| filter.map_or(true, |f| f.matches(*v))),
            );
        }
        result.extend(
            self.params
                .iter()
                .map(|p| p.as_ref() as &dyn Variable)
                .filter(|v| filter.map_or(true, |f| f.matches(*v))),
        );
        result.extend(
            self.locals
                .iter()
                .map(|v| v.as_ref() as &dyn Variable)
                .filter(|v| filter.map_or(true, |f| f.matches(*v))),
        );
        result
    }

    /// Port of `FunctionVariables.getParameters(VariableFilter)`: auto-parameters first, then
    /// parameters, matching the Java iteration order.
    pub fn get_parameters(&self, filter: Option<&dyn VariableFilter>) -> Vec<&dyn Parameter> {
        let mut result: Vec<&dyn Parameter> = Vec::new();
        if let Some(auto_params) = &self.auto_params {
            result.extend(
                auto_params
                    .iter()
                    .map(|p| p.as_ref() as &dyn Parameter)
                    .filter(|p| filter.map_or(true, |f| f.matches(*p))),
            );
        }
        result.extend(
            self.params
                .iter()
                .map(|p| p.as_ref() as &dyn Parameter)
                .filter(|p| filter.map_or(true, |f| f.matches(*p))),
        );
        result
    }

    /// Port of `FunctionVariables.getParameter(int)`. Unlike the Java version (which would throw
    /// an unchecked `IndexOutOfBoundsException` for a negative `ordinal` after subtracting the
    /// auto-parameter count), this returns `None` for any negative `ordinal`.
    pub fn get_parameter(&self, ordinal: i32) -> Option<&dyn Parameter> {
        if ordinal < 0 {
            return None;
        }
        let mut ordinal = ordinal as usize;
        if let Some(auto_params) = &self.auto_params {
            if ordinal < auto_params.len() {
                return Some(auto_params[ordinal].as_ref() as &dyn Parameter);
            }
            ordinal -= auto_params.len();
        }
        self.params.get(ordinal).map(|p| p.as_ref() as &dyn Parameter)
    }

    /// Port of the private `FunctionVariables.renumberParameterOrdinals()`, reusing the already-real
    /// [`ParameterDb::parameter_db_set_ordinal`] default for the actual ordinal/symbol update.
    pub fn renumber_parameter_ordinals(&self) {
        let auto_param_count = self.get_auto_param_count();
        let mut ordinal = auto_param_count;
        for param in &self.params {
            param.parameter_db_set_ordinal(ordinal, auto_param_count);
            ordinal += 1;
        }
    }

    /// Port of `FunctionVariables.setValidataionEnabled(boolean)` (Java's own misspelling is not
    /// reproduced in this method's name).
    pub fn set_validation_enabled(&mut self, enabled: bool) {
        self.validate_enabled = enabled;
    }

    /// Accessor for the `validateEnabled` field. Java exposes no public getter for this field
    /// (only the setter above); added here purely for observability/testability.
    pub fn is_validation_enabled(&self) -> bool {
        self.validate_enabled
    }

    /// Accessor for the `foundBadVariables` field. Java exposes no public getter for this field
    /// either; added purely for observability/testability. Currently always `false` after
    /// [`FunctionVariables::new`], since the only method that sets it true
    /// (`loadSymbolBasedVariables`) is not yet ported.
    pub fn found_bad_variables(&self) -> bool {
        self.found_bad_variables
    }
}

/// Port of the private static `FunctionVariables.isBadVariable(VariableSymbolDB)`: a variable
/// symbol is "bad" if its address no longer decodes (`Address.NO_ADDRESS`) or its storage is
/// otherwise invalid.
pub fn is_bad_variable(var_sym: &dyn crate::program::seam_stubs::VariableSymbolDb) -> bool {
    use crate::program::model::address::special_address::SpecialAddress;

    var_sym.get_address() == SpecialAddress::no_address() || var_sym.variable_storage().is_bad_storage()
}

/// Port of the private static `FunctionVariables.findExplicitThisParameter(List)`: the index of
/// the first parameter named `"this"` whose data type is a pointer, or `None` if there is none.
pub fn find_explicit_this_parameter(params: &[Box<dyn Variable>]) -> Option<usize> {
    params
        .iter()
        .position(|p| p.get_name().as_deref() == Some(THIS_PARAM_NAME) && p.get_data_type().as_pointer().is_some())
}

/// Port of the private static `FunctionVariables.findExplicitReturnStoragePtrParameter(List)`: the
/// index of the first parameter named [`RETURN_PTR_PARAM_NAME`] whose data type is a pointer, or
/// `None` if there is none.
pub fn find_explicit_return_storage_ptr_parameter(params: &[Box<dyn Variable>]) -> Option<usize> {
    params.iter().position(|p| {
        p.get_name().as_deref() == Some(RETURN_PTR_PARAM_NAME) && p.get_data_type().as_pointer().is_some()
    })
}

/// Port of the private static `FunctionVariables.removeExplicitThisParameter(List, String)`:
/// removes an explicit `this` parameter (see [`find_explicit_this_parameter`]) from `params` if
/// `calling_convention_name` is `__thiscall`, returning `true` if a parameter was removed.
pub fn remove_explicit_this_parameter(
    params: &mut Vec<Box<dyn Variable>>,
    calling_convention_name: Option<&str>,
) -> bool {
    if calling_convention_name != Some(CALLING_CONVENTION_THISCALL) {
        return false;
    }
    match find_explicit_this_parameter(params) {
        Some(index) => {
            params.remove(index);
            true
        }
        None => false,
    }
}

/// Port of the private static `FunctionVariables.removeExplicitReturnStoragePtrParameter(List)`:
/// removes an explicit return-storage-pointer parameter (see
/// [`find_explicit_return_storage_ptr_parameter`]) from `params` if present, returning the
/// pointer's pointee data type.
pub fn remove_explicit_return_storage_ptr_parameter(
    params: &mut Vec<Box<dyn Variable>>,
) -> Option<Box<dyn DataType>> {
    let index = find_explicit_return_storage_ptr_parameter(params)?;
    let removed = params.remove(index);
    removed.get_data_type().as_pointer().and_then(|ptr| ptr.get_data_type())
}

/// Port of the private `FunctionVariables.checkForParameterNameConflict(Variable, List, Set)`.
/// `index` identifies `params[index]`'s position within `params`, standing in for Java's
/// reference-identity self-skip (`if (param == chkParam) continue;`) -- every real call site
/// invokes this with `param` being `params.get(i)` for the very `i` being iterated, so an
/// index-based skip is exactly equivalent.
///
/// # Errors
/// Returns `Err` if `params[index]`'s name collides with another entry in `params`, or with a
/// name in `non_param_names` (other symbols within the function).
pub fn check_for_parameter_name_conflict(
    params: &[Box<dyn Variable>],
    index: usize,
    non_param_names: &HashSet<String>,
    symbol_utilities: &dyn SymbolUtilities,
) -> Result<(), DuplicateNameException> {
    let name = match params[index].get_name() {
        Some(n) if !n.is_empty() && !symbol_utilities.is_default_parameter_name(Some(&n)) => n,
        _ => return Ok(()),
    };

    for (i, chk_param) in params.iter().enumerate() {
        if i == index {
            continue;
        }
        if chk_param.get_name().as_deref() == Some(name.as_str()) {
            return Err(DuplicateNameException(format!("Duplicate parameter name '{name}'")));
        }
    }

    if non_param_names.contains(&name) {
        return Err(DuplicateNameException(format!(
            "Parameter name conflicts with a symbol within function named '{name}'"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::cmp::Ordering;
    use std::sync::Arc;

    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::database::function::function_manager_db::FunctionManagerDb;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::pointer::Pointer;
    use crate::program::model::lang::{PrototypeModel, RegisterRef};
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::parameter_impl::ParameterImpl;
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::listing::variable_impl::VariableImpl;
    use crate::program::model::listing::variable_storage::{UnassignedStorage, VariableStorage};
    use crate::program::model::listing::{
        AutoParameterType, Function, FunctionSignature, FunctionTag, Program,
    };
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{ExternalLocation, Namespace, Symbol, SymbolType};
    use crate::program::model::symbol::SourceType;
    use crate::program::seam_stubs::VariableSymbolDb;
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
    }

    /// A pointer `DataType` standing in for `Pointer`, used to test the `Pointer`-detecting
    /// helpers ([`find_explicit_this_parameter`], [`find_explicit_return_storage_ptr_parameter`],
    /// [`remove_explicit_return_storage_ptr_parameter`]) without a real pointer type.
    struct MockPointerDataType {
        pointee_length: i32,
    }
    impl DataType for MockPointerDataType {
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            Some(self)
        }
    }
    impl Pointer for MockPointerDataType {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            Some(Box::new(MockDataType { length: self.pointee_length }))
        }
        fn new_pointer(&self, _data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            unimplemented!("not exercised by this smoke test")
        }
        fn typedef_builder(
            &self,
        ) -> Box<dyn crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder> {
            unimplemented!("not exercised by this smoke test")
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
    fn mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram)
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    // ---------------------------------------------------------------------------------------
    // Group 1: pure free-function helpers, tested against a plain `Box<dyn Variable>` mock.
    // ---------------------------------------------------------------------------------------

    #[derive(Clone)]
    struct MockVariable {
        name: Option<String>,
        is_pointer: bool,
        pointee_length: i32,
    }

    impl MockVariable {
        fn named(name: &str) -> Self {
            MockVariable { name: Some(name.to_string()), is_pointer: false, pointee_length: 0 }
        }
        fn pointer_named(name: &str, pointee_length: i32) -> Self {
            MockVariable { name: Some(name.to_string()), is_pointer: true, pointee_length }
        }
    }

    impl Variable for MockVariable {
        fn get_data_type(&self) -> Box<dyn DataType> {
            if self.is_pointer {
                Box::new(MockPointerDataType { pointee_length: self.pointee_length })
            } else {
                Box::new(MockDataType { length: 4 })
            }
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
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            4
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            mock_program()
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn set_name(&mut self, name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            self.name = Some(name.to_string());
            Ok(())
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
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
        fn get_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            Err(UnsupportedOperationError("not a stack variable".to_string()))
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
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name()
        }
        fn compare_to(&self, _other: &dyn Variable) -> Ordering {
            Ordering::Equal
        }
    }

    fn boxed(vars: Vec<MockVariable>) -> Vec<Box<dyn Variable>> {
        vars.into_iter().map(|v| Box::new(v) as Box<dyn Variable>).collect()
    }

    struct MockVariableSymbolDb {
        address: Address,
        bad_storage: bool,
    }
    impl Symbol for MockVariableSymbolDb {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            "var_sym"
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::LocalVar
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
    impl VariableSymbolDb for MockVariableSymbolDb {
        fn variable_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4 })
        }
        fn variable_storage(&self) -> Box<dyn VariableStorage> {
            if self.bad_storage {
                Box::new(crate::program::model::listing::variable_storage::BadStorage)
            } else {
                Box::new(UnassignedStorage)
            }
        }
        fn set_variable_storage_and_data_type(&self, _storage: Box<dyn VariableStorage>, _data_type: Box<dyn DataType>) {}
        fn variable_first_use_offset(&self) -> i32 {
            0
        }
        fn set_variable_first_use_offset(&self, _first_use_offset: i32) {}
        fn variable_ordinal(&self) -> i32 {
            0
        }
        fn set_variable_ordinal(&self, _ordinal: i32) {}
        fn variable_symbol_comment(&self) -> Option<String> {
            None
        }
        fn set_variable_symbol_comment(&self, _comment: Option<String>) {}
        fn rename(&self, _name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            Ok(())
        }
    }

    #[test]
    fn is_bad_variable_detects_no_address_sentinel() {
        use crate::program::model::address::special_address::SpecialAddress;
        let sym = MockVariableSymbolDb {
            address: SpecialAddress::no_address(),
            bad_storage: false,
        };
        assert!(is_bad_variable(&sym));
    }

    #[test]
    fn is_bad_variable_detects_bad_storage() {
        let sym = MockVariableSymbolDb {
            address: mock_address(0x100),
            bad_storage: true,
        };
        assert!(is_bad_variable(&sym));
    }

    #[test]
    fn is_bad_variable_false_for_normal_variable() {
        let sym = MockVariableSymbolDb {
            address: mock_address(0x100),
            bad_storage: false,
        };
        assert!(!is_bad_variable(&sym));
    }

    #[test]
    fn find_explicit_this_parameter_requires_name_and_pointer_type() {
        let params = boxed(vec![
            MockVariable::named("param_1"),
            MockVariable::pointer_named("this", 4),
            MockVariable::named("param_2"),
        ]);
        assert_eq!(find_explicit_this_parameter(&params), Some(1));

        // Named "this" but not a pointer: not a match.
        let params = boxed(vec![MockVariable::named("this")]);
        assert_eq!(find_explicit_this_parameter(&params), None);
    }

    #[test]
    fn find_explicit_return_storage_ptr_parameter_requires_name_and_pointer_type() {
        let params = boxed(vec![
            MockVariable::pointer_named("__return_storage_ptr__", 8),
            MockVariable::named("param_1"),
        ]);
        assert_eq!(find_explicit_return_storage_ptr_parameter(&params), Some(0));
        assert_eq!(find_explicit_this_parameter(&params), None);
    }

    #[test]
    fn remove_explicit_this_parameter_only_for_thiscall() {
        let mut params = boxed(vec![MockVariable::pointer_named("this", 4), MockVariable::named("param_1")]);
        assert!(!remove_explicit_this_parameter(&mut params, Some("__cdecl")));
        assert_eq!(params.len(), 2);

        assert!(remove_explicit_this_parameter(&mut params, Some(CALLING_CONVENTION_THISCALL)));
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].get_name(), Some("param_1".to_string()));

        // No explicit 'this' parameter present: no-op.
        assert!(!remove_explicit_this_parameter(&mut params, Some(CALLING_CONVENTION_THISCALL)));
    }

    #[test]
    fn remove_explicit_return_storage_ptr_parameter_returns_pointee_type() {
        let mut params = boxed(vec![
            MockVariable::named("param_1"),
            MockVariable::pointer_named("__return_storage_ptr__", 8),
        ]);
        let dt = remove_explicit_return_storage_ptr_parameter(&mut params).unwrap();
        assert_eq!(dt.get_length(), 8);
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].get_name(), Some("param_1".to_string()));

        // No explicit return-storage-pointer parameter present.
        assert!(remove_explicit_return_storage_ptr_parameter(&mut params).is_none());
    }

    struct TestSymbolUtilities;
    impl SymbolUtilities for TestSymbolUtilities {}

    #[test]
    fn check_for_parameter_name_conflict_detects_duplicate_within_params() {
        let params = boxed(vec![MockVariable::named("foo"), MockVariable::named("foo")]);
        let non_param_names = HashSet::new();
        let err = check_for_parameter_name_conflict(&params, 0, &non_param_names, &TestSymbolUtilities)
            .unwrap_err();
        assert!(err.0.contains("Duplicate parameter name"));

        // The reverse direction (index 1 checked against index 0) is symmetric.
        let err = check_for_parameter_name_conflict(&params, 1, &non_param_names, &TestSymbolUtilities)
            .unwrap_err();
        assert!(err.0.contains("Duplicate parameter name"));
    }

    #[test]
    fn check_for_parameter_name_conflict_detects_non_param_symbol_collision() {
        let params = boxed(vec![MockVariable::named("foo")]);
        let mut non_param_names = HashSet::new();
        non_param_names.insert("foo".to_string());
        let err = check_for_parameter_name_conflict(&params, 0, &non_param_names, &TestSymbolUtilities)
            .unwrap_err();
        assert!(err.0.contains("conflicts with a symbol"));
    }

    #[test]
    fn check_for_parameter_name_conflict_ignores_default_and_empty_names() {
        let params = boxed(vec![MockVariable::named("param_1"), MockVariable::named("param_1")]);
        // "param_1" is a default parameter name (matches `DEFAULT_PARAM_PREFIX` + digits), so the
        // early-return in the Java source (and this port) skips the conflict check entirely.
        assert!(check_for_parameter_name_conflict(&params, 0, &HashSet::new(), &TestSymbolUtilities).is_ok());

        let params = boxed(vec![MockVariable { name: None, is_pointer: false, pointee_length: 0 }]);
        assert!(check_for_parameter_name_conflict(&params, 0, &HashSet::new(), &TestSymbolUtilities).is_ok());
    }

    #[test]
    fn check_for_parameter_name_conflict_skips_self_by_index() {
        // A single named parameter never conflicts with itself.
        let params = boxed(vec![MockVariable::named("real_name")]);
        assert!(check_for_parameter_name_conflict(&params, 0, &HashSet::new(), &TestSymbolUtilities).is_ok());
    }

    // ---------------------------------------------------------------------------------------
    // Group 2: `FunctionVariables` struct methods, tested against minimal `VariableDb`/
    // `ParameterDb`/`AutoParameterImpl`/`ReturnParameterDb` mocks.
    // ---------------------------------------------------------------------------------------

    struct MockFunctionDb {
        state: DbObjectState,
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
            mock_program()
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
            mock_address(0)
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
        fn get_stack_frame(&self) -> Box<dyn crate::program::model::listing::StackFrame> {
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
            false
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}
        fn get_calling_convention(&self) -> Option<Arc<PrototypeModel>> {
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
    impl crate::program::database::function::FunctionDb for MockFunctionDb {
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

    fn mock_function_db() -> Arc<MockFunctionDb> {
        Arc::new(MockFunctionDb { state: DbObjectState::new(1) })
    }

    /// Minimal [`VariableDb`] used for the `locals` list: only `get_name`/`is_parameter` are
    /// exercised by this module's tests, so everything else is a cheap placeholder.
    struct MockVariableDbLocal {
        name: String,
        function: Arc<MockFunctionDb>,
    }
    impl VariableDb for MockVariableDbLocal {
        fn symbol(&self) -> Arc<dyn VariableSymbolDb> {
            unimplemented!("not exercised by this smoke test")
        }
        fn function(&self) -> Arc<dyn crate::program::database::function::FunctionDb> {
            self.function.clone()
        }
        fn cached_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn set_cached_storage(&self, _storage: Option<Box<dyn VariableStorage>>) {}
        fn variable_db_set_comment(&self, _comment: Option<String>) {}
        fn variable_db_get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn variable_db_set_data_type_with_storage(
            &self,
            _data_type: Box<dyn DataType>,
            _new_storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn variable_db_set_data_type_aligned(
            &self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
    }
    impl Variable for MockVariableDbLocal {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4 })
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
            Some(self.name.clone())
        }
        fn get_length(&self) -> i32 {
            4
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            mock_program()
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn set_name(&mut self, name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            self.name = name.to_string();
            Ok(())
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
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
        fn get_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            Err(UnsupportedOperationError("not a stack variable".to_string()))
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
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name()
        }
        fn compare_to(&self, _other: &dyn Variable) -> Ordering {
            Ordering::Equal
        }
        fn is_parameter(&self) -> bool {
            false
        }
    }

    struct MockOrdinalSymbol {
        ordinal: std::sync::atomic::AtomicI32,
    }
    impl Symbol for MockOrdinalSymbol {
        fn get_address(&self) -> Address {
            mock_address(0)
        }
        fn get_name(&self) -> &str {
            "param"
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
    impl VariableSymbolDb for MockOrdinalSymbol {
        fn variable_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4 })
        }
        fn variable_storage(&self) -> Box<dyn VariableStorage> {
            Box::new(UnassignedStorage)
        }
        fn set_variable_storage_and_data_type(&self, _storage: Box<dyn VariableStorage>, _data_type: Box<dyn DataType>) {}
        fn variable_first_use_offset(&self) -> i32 {
            0
        }
        fn set_variable_first_use_offset(&self, _first_use_offset: i32) {}
        fn variable_ordinal(&self) -> i32 {
            self.ordinal.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn set_variable_ordinal(&self, ordinal: i32) {
            self.ordinal.store(ordinal, std::sync::atomic::Ordering::SeqCst);
        }
        fn variable_symbol_comment(&self) -> Option<String> {
            None
        }
        fn set_variable_symbol_comment(&self, _comment: Option<String>) {}
        fn rename(&self, _name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            Ok(())
        }
    }

    /// Minimal [`ParameterDb`] used for the `params` list. `get_ordinal` delegates to the real
    /// [`ParameterDb::parameter_db_get_ordinal`] default (backed by a real [`MockOrdinalSymbol`]),
    /// since [`renumber_parameter_ordinals`](FunctionVariables::renumber_parameter_ordinals) is
    /// exercised against it; everything else is a cheap placeholder.
    struct MockParameterDbParam {
        name: String,
        symbol: Arc<MockOrdinalSymbol>,
        function: Arc<MockFunctionDb>,
        auto_param_count: Cell<i32>,
    }
    impl VariableDb for MockParameterDbParam {
        fn symbol(&self) -> Arc<dyn VariableSymbolDb> {
            self.symbol.clone()
        }
        fn function(&self) -> Arc<dyn crate::program::database::function::FunctionDb> {
            self.function.clone()
        }
        fn cached_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn set_cached_storage(&self, _storage: Option<Box<dyn VariableStorage>>) {}
        fn variable_db_set_comment(&self, _comment: Option<String>) {}
        fn variable_db_get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn variable_db_set_data_type_with_storage(
            &self,
            _data_type: Box<dyn DataType>,
            _new_storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn variable_db_set_data_type_aligned(
            &self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
    }
    impl ParameterDb for MockParameterDbParam {
        fn auto_param_count(&self) -> i32 {
            self.auto_param_count.get()
        }
        fn set_auto_param_count(&self, count: i32) {
            self.auto_param_count.set(count);
        }
    }
    impl Variable for MockParameterDbParam {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4 })
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
            Some(self.name.clone())
        }
        fn get_length(&self) -> i32 {
            4
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            mock_program()
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn set_name(&mut self, name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            self.name = name.to_string();
            Ok(())
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
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
        fn get_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            Err(UnsupportedOperationError("not a stack variable".to_string()))
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
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            Some(self.symbol.clone())
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name()
        }
        fn compare_to(&self, _other: &dyn Variable) -> Ordering {
            Ordering::Equal
        }
        fn is_parameter(&self) -> bool {
            true
        }
    }
    impl Parameter for MockParameterDbParam {
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
            false
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            self.get_data_type()
        }
    }

    fn mock_param(name: &str, ordinal: i32) -> Box<dyn ParameterDb> {
        Box::new(MockParameterDbParam {
            name: name.to_string(),
            symbol: Arc::new(MockOrdinalSymbol { ordinal: std::sync::atomic::AtomicI32::new(ordinal) }),
            function: mock_function_db(),
            auto_param_count: Cell::new(0),
        })
    }

    fn mock_local(name: &str) -> Box<dyn VariableDb> {
        Box::new(MockVariableDbLocal { name: name.to_string(), function: mock_function_db() })
    }

    /// Minimal `AutoParameterImpl` used for the `auto_params` list.
    struct MockAutoParam {
        name: String,
    }
    impl VariableImpl for MockAutoParam {
        fn stored_name(&self) -> Option<String> {
            Some(self.name.clone())
        }
        fn set_stored_name(&mut self, name: Option<String>) {
            self.name = name.unwrap_or_default();
        }
        fn stored_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4 })
        }
        fn set_stored_data_type(&mut self, _data_type: Box<dyn DataType>) {}
        fn stored_comment(&self) -> Option<String> {
            None
        }
        fn set_stored_comment(&mut self, _comment: Option<String>) {}
        fn stored_source_type(&self) -> SourceType {
            SourceType::Analysis
        }
        fn set_stored_source_type(&mut self, _source_type: SourceType) {}
        fn stored_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn set_stored_variable_storage(&mut self, _storage: Option<Box<dyn VariableStorage>>) {}
    }
    impl ParameterImpl for MockAutoParam {
        fn stored_ordinal(&self) -> i32 {
            0
        }
    }
    impl crate::program::model::listing::auto_parameter_impl::AutoParameterImpl for MockAutoParam {
        fn stored_function(&self) -> Box<dyn Function> {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl Variable for MockAutoParam {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4 })
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
            Some(self.name.clone())
        }
        fn get_length(&self) -> i32 {
            4
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            mock_program()
        }
        fn get_source(&self) -> SourceType {
            SourceType::Analysis
        }
        fn set_name(&mut self, name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            self.name = name.to_string();
            Ok(())
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            None
        }
        fn is_stack_variable(&self) -> bool {
            false
        }
        fn has_stack_storage(&self) -> bool {
            false
        }
        fn is_register_variable(&self) -> bool {
            true
        }
        fn get_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            Err(UnsupportedOperationError("not a stack variable".to_string()))
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
            true
        }
        fn get_first_use_offset(&self) -> i32 {
            0
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name()
        }
        fn compare_to(&self, _other: &dyn Variable) -> Ordering {
            Ordering::Equal
        }
        fn is_parameter(&self) -> bool {
            true
        }
    }
    impl Parameter for MockAutoParam {
        fn get_ordinal(&self) -> i32 {
            0
        }
        fn is_auto_parameter(&self) -> bool {
            true
        }
        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            Some(AutoParameterType::This)
        }
        fn is_forced_indirect(&self) -> bool {
            false
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            self.get_data_type()
        }
    }

    fn mock_auto_param(
        name: &str,
    ) -> Box<dyn crate::program::model::listing::auto_parameter_impl::AutoParameterImpl> {
        Box::new(MockAutoParam { name: name.to_string() })
    }

    /// Minimal [`ReturnParameterDb`] for [`FunctionVariables::get_return_param`].
    struct MockReturnParam {
        name: &'static str,
    }
    impl ReturnParameterDb for MockReturnParam {
        fn function(&self) -> Arc<dyn crate::program::database::function::FunctionDb> {
            mock_function_db()
        }
        fn stored_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4 })
        }
        fn set_stored_data_type(&self, _data_type: Box<dyn DataType>) {}
        fn stored_storage(&self) -> Box<dyn VariableStorage> {
            Box::new(UnassignedStorage)
        }
        fn set_stored_storage(&self, _storage: Box<dyn VariableStorage>) {}
        fn return_parameter_db_get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn return_parameter_db_set_storage_and_data_type(
            &self,
            _new_storage: Box<dyn VariableStorage>,
            _data_type: Box<dyn DataType>,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn return_parameter_db_set_data_type_with_storage(
            &self,
            _data_type: Box<dyn DataType>,
            _new_storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn return_parameter_db_set_data_type_aligned(
            &self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
    }
    impl Variable for MockReturnParam {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4 })
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
            Some(self.name.to_string())
        }
        fn get_length(&self) -> i32 {
            4
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            mock_program()
        }
        fn get_source(&self) -> SourceType {
            SourceType::Default
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            panic!("setName is not supported for the return parameter")
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            Some(self.stored_storage())
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
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
        fn get_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            Err(UnsupportedOperationError("not a stack variable".to_string()))
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
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name()
        }
        fn compare_to(&self, _other: &dyn Variable) -> Ordering {
            Ordering::Equal
        }
        fn is_parameter(&self) -> bool {
            true
        }
    }
    impl Parameter for MockReturnParam {
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
            false
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            self.get_data_type()
        }
    }

    fn function_variables_fixture(with_auto_param: bool) -> FunctionVariables {
        let auto_params = if with_auto_param {
            Some(vec![mock_auto_param("this")])
        } else {
            None
        };
        FunctionVariables::new(
            Box::new(MockReturnParam { name: "<RETURN>" }),
            vec![mock_param("param_1", 0), mock_param("param_2", 1)],
            vec![mock_local("local_1"), mock_local("local_2")],
            auto_params,
        )
    }

    #[test]
    fn get_return_param_returns_stored_return_param() {
        let fv = function_variables_fixture(false);
        assert_eq!(fv.get_return_param().get_name(), Some("<RETURN>".to_string()));
    }

    #[test]
    fn auto_param_and_parameter_counts() {
        let fv = function_variables_fixture(false);
        assert_eq!(fv.get_auto_param_count(), 0);
        assert_eq!(fv.get_parameter_count(), 2);

        let fv = function_variables_fixture(true);
        assert_eq!(fv.get_auto_param_count(), 1);
        assert_eq!(fv.get_parameter_count(), 3);
    }

    #[test]
    fn get_local_variables_returns_only_locals() {
        let fv = function_variables_fixture(true);
        let names: Vec<_> = fv.get_local_variables(None).iter().map(|v| v.get_name().unwrap()).collect();
        assert_eq!(names, vec!["local_1", "local_2"]);
    }

    #[test]
    fn get_variables_orders_auto_params_then_params_then_locals() {
        let fv = function_variables_fixture(true);
        let names: Vec<_> = fv.get_variables(None).iter().map(|v| v.get_name().unwrap()).collect();
        assert_eq!(names, vec!["this", "param_1", "param_2", "local_1", "local_2"]);
    }

    #[test]
    fn get_parameters_orders_auto_params_then_params_and_excludes_locals() {
        let fv = function_variables_fixture(true);
        let names: Vec<_> = fv.get_parameters(None).iter().map(|p| p.get_name().unwrap()).collect();
        assert_eq!(names, vec!["this", "param_1", "param_2"]);
    }

    struct NameFilter(&'static str);
    impl VariableFilter for NameFilter {
        fn matches(&self, variable: &dyn Variable) -> bool {
            variable.get_name().as_deref() == Some(self.0)
        }
    }

    #[test]
    fn filters_are_applied_across_all_three_query_methods() {
        let fv = function_variables_fixture(true);
        let filter = NameFilter("param_2");
        assert_eq!(fv.get_variables(Some(&filter)).len(), 1);
        assert_eq!(fv.get_parameters(Some(&filter)).len(), 1);
        assert_eq!(fv.get_local_variables(Some(&NameFilter("local_1"))).len(), 1);
    }

    #[test]
    fn get_parameter_indexes_auto_params_before_params() {
        let fv = function_variables_fixture(true);
        assert_eq!(fv.get_parameter(0).unwrap().get_name(), Some("this".to_string()));
        assert_eq!(fv.get_parameter(1).unwrap().get_name(), Some("param_1".to_string()));
        assert_eq!(fv.get_parameter(2).unwrap().get_name(), Some("param_2".to_string()));
        assert!(fv.get_parameter(3).is_none());
        assert!(fv.get_parameter(-1).is_none());
    }

    #[test]
    fn renumber_parameter_ordinals_accounts_for_auto_param_count() {
        let fv = function_variables_fixture(true);
        fv.renumber_parameter_ordinals();
        // One auto-parameter, so the two real parameters should land at ordinals 1 and 2.
        let ordinals: Vec<_> = fv.get_parameters(None).iter().skip(1).map(|p| p.get_ordinal()).collect();
        assert_eq!(ordinals, vec![1, 2]);
    }

    #[test]
    fn set_validation_enabled_updates_accessor() {
        let mut fv = function_variables_fixture(false);
        assert!(fv.is_validation_enabled());
        fv.set_validation_enabled(false);
        assert!(!fv.is_validation_enabled());
    }

    #[test]
    fn found_bad_variables_starts_false() {
        let fv = function_variables_fixture(false);
        assert!(!fv.found_bad_variables());
    }
}

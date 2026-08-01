//! Port of `ghidra.program.model.pcode.HighFunctionDBUtil`.
//!
//! `HighFunctionDBUtil` provides various methods for updating the state of a function contained
//! within a program database. It is important to note that the decompiler result state (e.g.
//! `HighFunction`, `HighParam`, `HighLocal`, etc.) is not altered by any of these methods. A new
//! decompiler result will need to be generated to reflect any changes made to the database. Care
//! must be taken when making incremental changes to multiple elements (e.g. `Variable`s).
//!
//! The Java class is a bag of unrelated static utility methods with heterogeneous first
//! parameters (`HighFunction`, `HighSymbol`, `Function`, `Symbol`, `Program`, `AddressFactory`),
//! so this port models it as a dyn-object-safe trait whose methods each take their Java
//! counterpart's first argument as an explicit parameter (rather than forcing an artificial
//! `Self` receiver relationship onto one of them). [`HighFunctionDb`] is the zero-sized concrete
//! implementor, mirroring calling the Java static methods via `HighFunctionDBUtil.foo(...)`.
//!
//! This type was selected as a dependency-cycle cut-point; several of the core types it
//! references (`HighSymbol`, `LocalSymbolMap`, `DynamicEntry`, `DataTypeSymbol`,
//! `UnionFacetSymbol`, and the DB-backed `ParameterImpl`/`ReturnParameterImpl`/`LocalVariableImpl`
//! trio) are not yet ported; minimal placeholders for them live in
//! [`crate::program::seam_stubs`] (see `STUBS.tsv`). `HighFunction` and `HighVariable` themselves
//! have since been ported as traits (see
//! [`high_function`](crate::program::model::pcode::high_function::HighFunction) and
//! [`high_variable`](crate::program::model::pcode::high_variable::HighVariable)). A handful of
//! sub-steps that need mutable `SymbolTable`/`Listing`/`ReferenceManager` access via a `Program`
//! reached only as a shared `Arc<dyn Program>` (through `Function::get_program`/
//! `Variable::get_program`) cannot be represented with this crate's current ownership
//! conventions; those are documented as best-effort no-ops at their call sites below.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressFactory};
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::function::{FunctionEditError, UNKNOWN_CALLING_CONVENTION_STRING};
use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
use crate::program::model::listing::{
    Function, FunctionSignature, FunctionUpdateType, Parameter, Program, Variable,
};
use crate::program::model::pcode::{OpCode, PcodeOp, Varnode};
use crate::program::model::symbol::{SourceType, Symbol, SymbolUtilities};
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::seam_stubs::{self, DataTypeSymbol, HighSymbol};
use crate::util::exception::{AssertException, DuplicateNameException, InvalidInputException};

/// Category for auto generated prototypes. Port of `HighFunctionDBUtil.AUTO_CAT`.
pub const AUTO_CAT: &str = "/auto_proto";

/// Governs how a return parameter is committed to the database. Port of
/// `HighFunctionDBUtil.ReturnCommitOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReturnCommitOption {
    /// Keep the function's existing return parameter.
    NoCommit,
    /// Commit the return parameter as defined by the `HighFunction`.
    Commit,
    /// Commit the return parameter as defined by the `HighFunction`, unless it is `void`, in
    /// which case keep the existing function return parameter.
    CommitNoVoid,
}

/// Error produced by [`HighFunctionDBUtil::update_db_variable`] and
/// [`HighFunctionDBUtil::write_union_facet`].
///
/// Combines the two checked exceptions declared on the corresponding Java methods.
#[derive(thiserror::Error, Debug)]
pub enum UpdateDbVariableError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

impl From<SetVariableNameError> for UpdateDbVariableError {
    fn from(err: SetVariableNameError) -> Self {
        match err {
            SetVariableNameError::Duplicate(e) => UpdateDbVariableError::Duplicate(e),
            SetVariableNameError::InvalidInput(e) => UpdateDbVariableError::InvalidInput(e),
        }
    }
}

impl From<FunctionEditError> for UpdateDbVariableError {
    fn from(err: FunctionEditError) -> Self {
        match err {
            FunctionEditError::Duplicate(e) => UpdateDbVariableError::Duplicate(e),
            FunctionEditError::InvalidInput(e) => UpdateDbVariableError::InvalidInput(e),
        }
    }
}

/// Provides various methods for updating the state of a function contained within a program
/// database. Port of `ghidra.program.model.pcode.HighFunctionDBUtil`.
pub trait HighFunctionDBUtil {
    /// Commit all parameters, including optional return, associated with `high_function` to the
    /// underlying database. `use_data_types` is true if the `HighFunction`'s parameter data-types
    /// should be committed. `return_commit` controls optional commit of the return parameter.
    /// `source` is the signature source type to set.
    ///
    /// # Errors
    /// Returns `Err` if commit of parameters caused a conflict with another local
    /// variable/label, or if specified storage is invalid.
    fn commit_params_to_database(
        &self,
        high_function: &dyn HighFunction,
        use_data_types: bool,
        return_commit: ReturnCommitOption,
        source: SourceType,
    ) -> Result<(), FunctionEditError> {
        commit_params_to_database_impl(high_function, use_data_types, return_commit, source)
    }

    /// Commit local variables from the decompiler's model of the function to the database. This
    /// does NOT include formal function parameters.
    fn commit_local_names_to_database(&self, high_function: &dyn HighFunction, source: SourceType) {
        commit_local_names_to_database_impl(high_function, source)
    }

    /// Returns the database `Variable` corresponding to `high_symbol`, or `None`.
    fn get_function_variable(&self, high_symbol: Option<&dyn HighSymbol>) -> Option<Box<dyn Variable>> {
        get_function_variable_impl(high_symbol)
    }

    /// Rename and/or retype the variable described by `high_symbol` in the database. All
    /// parameters may be flushed to the database if typed parameter inconsistency is detected.
    /// `name` of `None` retains the current variable name; `data_type` of `None` retains the
    /// current variable data type (a specified data type must be fixed-length).
    ///
    /// # Errors
    /// Returns `Err` if a suitable data type was not specified, storage could not be resized, an
    /// invalid name was specified, or the name conflicts with another variable/label.
    fn update_db_variable(
        &self,
        high_symbol: &dyn HighSymbol,
        name: Option<&str>,
        data_type: Option<Box<dyn DataType>>,
        source: SourceType,
    ) -> Result<(), UpdateDbVariableError> {
        update_db_variable_impl(high_symbol, name, data_type, source)
    }

    /// Commit an overriding prototype for a particular call site to the database. The override
    /// only applies to the function(s) containing the actual call site; calls to the same
    /// function from other sites are unaffected. Used typically either for indirect calls or for
    /// calls to a function with a variable number of parameters.
    ///
    /// # Errors
    /// Returns `Err` if there are problems committing the override symbol.
    fn write_override(
        &self,
        function: &mut dyn Function,
        callsite: Address,
        sig: &dyn FunctionSignature,
    ) -> Result<(), InvalidInputException> {
        write_override_impl(function, callsite, sig)
    }

    /// Read a call prototype override which corresponds to the specified override code symbol.
    /// Returns `None` if the associated function signature data-type could not be found.
    fn read_override(&self, sym: &dyn Symbol) -> Option<Box<dyn DataTypeSymbol>> {
        read_override_impl(sym)
    }

    /// If there is a call to a function at `addr`, and the function takes variable arguments,
    /// returns the index of the first variable argument. Returns -1 otherwise.
    fn get_first_var_arg(&self, program: &mut dyn Program, addr: Address) -> i32 {
        get_first_var_arg_impl(program, addr)
    }

    /// Get the `Address` referred to by a spacebase reference. Address-of references are encoded
    /// in the p-code syntax tree as `vn = PTRSUB(<spacebase>, #const)`; this decodes the
    /// reference and returns the `Address`, or `None` if not of the correct form.
    fn get_spacebase_reference_address(
        &self,
        addr_factory: &dyn AddressFactory,
        op: Option<&PcodeOp>,
    ) -> Option<Address> {
        get_spacebase_reference_address_impl(addr_factory, op)
    }

    /// Write a union facet to the database (`UnionFacetSymbol`). Parameters provide the pieces
    /// for building the dynamic local variable. This clears out any preexisting union facet with
    /// the same dynamic hash and first-use offset. The new facet can optionally be "address
    /// based", meaning that all reads/writes of the union at the address are controlled by this
    /// single facet.
    ///
    /// # Errors
    /// Returns `Err` if the local variable cannot be created, or the (auto-generated) name is
    /// used elsewhere.
    #[allow(clippy::too_many_arguments)]
    fn write_union_facet(
        &self,
        function: &mut dyn Function,
        dt: Box<dyn DataType>,
        field_num: i32,
        addr: Address,
        hash: i64,
        is_addr: bool,
        source: SourceType,
    ) -> Result<(), UpdateDbVariableError> {
        write_union_facet_impl(function, dt, field_num, addr, hash, is_addr, source)
    }
}

/// Concrete, zero-sized implementor of [`HighFunctionDBUtil`], mirroring calling the Java static
/// methods via `HighFunctionDBUtil.foo(...)`.
pub struct HighFunctionDb;

impl HighFunctionDBUtil for HighFunctionDb {}

/// Wraps a `Box<dyn Parameter>` so it can be handed out as a `Box<dyn Variable>` (`Parameter`
/// extends `Variable` in Java; this crate has no trait-object upcasting, so this delegates each
/// `Variable` method instead). Not a port of any specific Java class.
struct ParamAsVariable(Box<dyn Parameter>);

impl Variable for ParamAsVariable {
    fn get_data_type(&self) -> Box<dyn DataType> {
        self.0.get_data_type()
    }

    fn set_data_type_with_storage(
        &mut self,
        data_type: Box<dyn DataType>,
        storage: Box<dyn crate::program::seam_stubs::VariableStorage>,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.0.set_data_type_with_storage(data_type, storage, force, source)
    }

    fn set_data_type(
        &mut self,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.0.set_data_type(data_type, source)
    }

    fn set_data_type_aligned(
        &mut self,
        data_type: Box<dyn DataType>,
        align_stack: bool,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.0.set_data_type_aligned(data_type, align_stack, force, source)
    }

    fn get_name(&self) -> Option<String> {
        self.0.get_name()
    }

    fn get_length(&self) -> i32 {
        self.0.get_length()
    }

    fn is_valid(&self) -> bool {
        self.0.is_valid()
    }

    fn get_function(&self) -> Option<Box<dyn Function>> {
        self.0.get_function()
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.0.get_program()
    }

    fn get_source(&self) -> SourceType {
        self.0.get_source()
    }

    fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetVariableNameError> {
        self.0.set_name(name, source)
    }

    fn get_comment(&self) -> Option<String> {
        self.0.get_comment()
    }

    fn set_comment(&mut self, comment: Option<String>) {
        self.0.set_comment(comment)
    }

    fn get_variable_storage(&self) -> Option<Box<dyn crate::program::seam_stubs::VariableStorage>> {
        self.0.get_variable_storage()
    }

    fn get_first_storage_varnode(&self) -> Option<Varnode> {
        self.0.get_first_storage_varnode()
    }

    fn get_last_storage_varnode(&self) -> Option<Varnode> {
        self.0.get_last_storage_varnode()
    }

    fn is_stack_variable(&self) -> bool {
        self.0.is_stack_variable()
    }

    fn has_stack_storage(&self) -> bool {
        self.0.has_stack_storage()
    }

    fn is_register_variable(&self) -> bool {
        self.0.is_register_variable()
    }

    fn get_register(&self) -> Option<RegisterRef> {
        self.0.get_register()
    }

    fn get_registers(&self) -> Option<Vec<RegisterRef>> {
        self.0.get_registers()
    }

    fn get_min_address(&self) -> Option<Address> {
        self.0.get_min_address()
    }

    fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
        self.0.get_stack_offset()
    }

    fn is_memory_variable(&self) -> bool {
        self.0.is_memory_variable()
    }

    fn is_unique_variable(&self) -> bool {
        self.0.is_unique_variable()
    }

    fn is_compound_variable(&self) -> bool {
        self.0.is_compound_variable()
    }

    fn has_assigned_storage(&self) -> bool {
        self.0.has_assigned_storage()
    }

    fn get_first_use_offset(&self) -> i32 {
        self.0.get_first_use_offset()
    }

    fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
        self.0.get_symbol()
    }

    fn is_equivalent(&self, variable: &dyn Variable) -> bool {
        self.0.is_equivalent(variable)
    }

    fn compare_to(&self, other: &dyn Variable) -> Ordering {
        self.0.compare_to(other)
    }

    fn is_parameter(&self) -> bool {
        true
    }

    fn is_auto_parameter(&self) -> bool {
        Parameter::is_auto_parameter(self.0.as_ref())
    }
}

/// Return the appropriate model name for committing to the database with the given
/// `HighFunction`. Generally this just returns the model name attached to the `HighFunction`, but
/// if the "unknown" model is associated with the function, or if the model doesn't exist, the
/// decompiler was using the "default" model internally, so this is the more appropriate model to
/// commit. It's possible for this routine to return `None`, if the architecture has no default
/// model.
fn get_prototype_model_for_commit(high_function: &dyn HighFunction) -> Option<String> {
    let mut model_name = high_function
        .get_function_prototype()
        .and_then(|prototype| prototype.get_model_name());

    if let Some(name) = &model_name {
        if name == UNKNOWN_CALLING_CONVENTION_STRING {
            model_name = None;
        } else if high_function
            .get_compiler_spec()
            .get_calling_convention(name)
            .is_none()
        {
            model_name = None;
        }
    }

    if model_name.is_none() {
        // Currently the decompiler uses the default convention to model an unknown convention.
        model_name = high_function
            .get_compiler_spec()
            .get_default_calling_convention()
            .and_then(|model| model.get_name());
    }

    model_name
}

fn commit_params_to_database_impl(
    high_function: &dyn HighFunction,
    use_data_types: bool,
    return_commit: ReturnCommitOption,
    source: SourceType,
) -> Result<(), FunctionEditError> {
    let mut function = high_function.get_function();

    let model_name = get_prototype_model_for_commit(high_function);
    let has_var_args = high_function
        .get_function_prototype()
        .map(|proto| proto.is_var_arg())
        .unwrap_or(false);

    let return_param = get_return_parameter(high_function, use_data_types, return_commit)?;
    let params = get_parameters(high_function, use_data_types);

    let update_result = function.update_function(
        model_name.as_deref(),
        Some(return_param),
        params,
        FunctionUpdateType::DynamicStorageAllParams,
        true,
        source,
    );

    if let Err(FunctionEditError::Duplicate(_)) = update_result {
        let params_retry = get_parameters(high_function, use_data_types);
        let return_param_retry = get_return_parameter(high_function, use_data_types, return_commit)?;
        for param in &params_retry {
            change_conflicting_symbol_names(
                param.get_name().as_deref().unwrap_or(""),
                Some(return_param_retry.as_ref()),
                function.as_mut(),
            );
        }
        function.update_function(
            model_name.as_deref(),
            None,
            params_retry,
            FunctionUpdateType::DynamicStorageAllParams,
            true,
            source,
        )?;
    } else {
        update_result?;
    }

    // Try again if dynamic storage assignment does not match the decompiler's -- force into
    // custom storage mode.
    let params_check = get_parameters(high_function, use_data_types);
    let function_params = function.get_parameters();
    let mut custom_storage_required = !variable_storage_matches(&params_check, &function_params);
    let return_param_check = get_return_parameter(high_function, use_data_types, return_commit)?;
    if return_commit != ReturnCommitOption::NoCommit {
        let current_return = function.get_return();
        custom_storage_required |= !storage_option_equals(
            return_param_check.get_variable_storage().as_deref(),
            current_return.get_variable_storage().as_deref(),
        );
    }
    if custom_storage_required {
        function.update_function(
            model_name.as_deref(),
            Some(return_param_check),
            params_check,
            FunctionUpdateType::CustomStorage,
            true,
            source,
        )?;
    }

    if function.has_var_args() != has_var_args {
        function.set_var_args(has_var_args);
    }

    Ok(())
}

fn commit_local_names_to_database_impl(high_function: &dyn HighFunction, source: SourceType) {
    let mut function = high_function.get_function();
    clear_obsolete_dynamic_locals_from_database(high_function, function.as_mut());

    for sym in high_function.get_local_symbol_map().get_symbols() {
        if sym.is_parameter() || sym.is_global() {
            continue;
        }
        // Errors are logged and skipped in the real Java method (`Msg.error`); this port simply
        // ignores them for the same reason (best-effort local-name commit).
        let _ = update_db_variable_impl(sym.as_ref(), None, None, source);
    }
}

fn get_return_parameter(
    high_function: &dyn HighFunction,
    use_data_types: bool,
    return_commit: ReturnCommitOption,
) -> Result<Box<dyn Variable>, InvalidInputException> {
    let function = high_function.get_function();
    if return_commit == ReturnCommitOption::NoCommit {
        return Ok(Box::new(ParamAsVariable(function.get_return())));
    }

    let program = function.get_program();
    let prototype = high_function.get_function_prototype();
    let mut return_storage = prototype
        .as_ref()
        .map(|proto| proto.get_return_storage())
        .unwrap_or_else(|| Box::new(seam_stubs::PlaceholderVariableStorage));
    let return_dt = prototype.as_ref().and_then(|proto| proto.get_return_type());

    if use_data_types && return_commit == ReturnCommitOption::CommitNoVoid {
        if let Some(dt) = &return_dt {
            if dt.is_void_type() {
                return Ok(Box::new(ParamAsVariable(function.get_return()))); // retain current return
            }
        }
    }

    let return_dt: Box<dyn DataType> = match return_dt {
        None => {
            return_storage = Box::new(seam_stubs::PlaceholderVariableStorage);
            Box::new(seam_stubs::PlaceholderDataType)
        }
        Some(dt) if !use_data_types => {
            let undefined = seam_stubs::undefined_data_type(dt.get_length());
            match program.get_data_type_manager() {
                Some(dtm) => undefined.clone_data_type(dtm.as_ref()),
                None => undefined,
            }
        }
        Some(dt) => dt,
    };

    Ok(Box::new(seam_stubs::DatabaseVariableImpl::new(
        None,
        0,
        return_dt,
        return_storage,
        program,
    )))
}

fn get_parameters(high_function: &dyn HighFunction, use_data_types: bool) -> Vec<Box<dyn Variable>> {
    let function = high_function.get_function();
    let program = function.get_program();
    let symbol_map = high_function.get_local_symbol_map();
    let param_count = symbol_map.get_num_params().max(0);
    let mut params: Vec<Box<dyn Variable>> = Vec::with_capacity(param_count as usize);
    for i in 0..param_count {
        let param = symbol_map.get_param_symbol(i);
        let name = param.get_name();
        let data_type: Box<dyn DataType> = if use_data_types {
            param.get_data_type()
        } else {
            let undefined = seam_stubs::undefined_data_type(param.get_size());
            match program.get_data_type_manager() {
                Some(dtm) => undefined.clone_data_type(dtm.as_ref()),
                None => undefined,
            }
        };
        params.push(Box::new(seam_stubs::DatabaseVariableImpl::new(
            Some(name),
            0,
            data_type,
            param.get_storage(),
            program.clone(),
        )));
    }
    params
}

/// Simplified stand-in for `VariableUtilities.storageMatches(List<Variable>, Variable[])`: true
/// if both lists have the same length and each pair's storage compares equal via
/// [`crate::program::seam_stubs::VariableStorage::storage_equals`].
fn variable_storage_matches(a: &[Box<dyn Variable>], b: &[Box<dyn Parameter>]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| {
        storage_option_equals(
            x.get_variable_storage().as_deref(),
            y.get_variable_storage().as_deref(),
        )
    })
}

fn storage_option_equals(
    a: Option<&dyn crate::program::seam_stubs::VariableStorage>,
    b: Option<&dyn crate::program::seam_stubs::VariableStorage>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.storage_equals(b),
        _ => false,
    }
}

/// Simplified stand-in for `HighFunctionDBUtil.changeConflictingSymbolNames`: locating (and, on
/// conflict, renaming) the symbol at `name`'s storage requires mutable `SymbolTable` access via
/// `Program`, which `Function::get_program` cannot provide here (it hands back a shared
/// `Arc<dyn Program>`); real conflict resolution is deferred until that access path is ported.
fn change_conflicting_symbol_names(
    name: &str,
    ignore_variable: Option<&dyn Variable>,
    function: &mut dyn Function,
) {
    let _ = (name, ignore_variable, function);
}

/// Low-level routine for clearing any variables in the database which conflict with `dt`/`storage`
/// and returning one of them for re-use. The returned variable still exists within the function
/// at the same first-use-offset.
fn create_local_variable(
    function: &mut dyn Function,
    dt: Box<dyn DataType>,
    storage: Box<dyn crate::program::seam_stubs::VariableStorage>,
    pc_addr: Option<Address>,
    source: SourceType,
) -> Result<Box<dyn Variable>, InvalidInputException> {
    let program = function.get_program();
    let first_use_offset = pc_addr
        .as_ref()
        .map(|addr| addr.subtract(&function.get_entry_point()) as i32)
        .unwrap_or(0);
    let var: Box<dyn Variable> = Box::new(seam_stubs::DatabaseVariableImpl::new(
        None,
        first_use_offset,
        dt,
        storage,
        program,
    ));
    let var = match function.add_local_variable(var, source) {
        Ok(var) => var,
        Err(FunctionEditError::Duplicate(e)) => {
            panic!(
                "{}",
                AssertException::with_message(format!("Unexpected exception with default name: {e}"))
            );
        }
        Err(FunctionEditError::InvalidInput(e)) => return Err(e),
    };
    // NOTE: registering a write reference for a register-backed variable at `pc_addr` requires
    // mutable `ReferenceManager` access via `Program`, unreachable here for the same reason as
    // `change_conflicting_symbol_names` above; deferred until that access path is ported.
    Ok(var)
}

fn clear_obsolete_dynamic_locals_from_database(high_function: &dyn HighFunction, function: &mut dyn Function) {
    for var in function.get_local_variables() {
        if var.is_unique_variable() && !is_valid_unique_variable(high_function, var.as_ref()) {
            function.remove_variable(var.as_ref());
        }
    }
}

fn is_valid_unique_variable(high_function: &dyn HighFunction, var: &dyn Variable) -> bool {
    if !var.is_unique_variable() {
        return false;
    }
    let Some(hash) = var.get_first_storage_varnode().map(|vn| vn.get_offset()) else {
        return false;
    };
    for symbol in high_function.get_local_symbol_map().get_symbols() {
        // Note: assumes there is only one hash method used for unique locals.
        if symbol.get_dynamic_hash() == Some(hash) && symbol.get_high_variable().is_some() {
            return true; // Hash successfully attached to a variable.
        }
    }
    false
}

/// Given a particular seed `Variable`, find the set of local variables that are intended to be
/// merged containing that seed. The result will contain at least the seed variable.
fn gather_merge_set(function: &mut dyn Function, seed: Box<dyn Variable>) -> Vec<Box<dyn Variable>> {
    let mut name_map: std::collections::HashMap<String, Box<dyn Variable>> =
        std::collections::HashMap::new();
    for var in function.get_all_variables() {
        if let Some(name) = var.get_name() {
            name_map.insert(name, var);
        }
    }

    let seed_name = seed.get_name().unwrap_or_default();
    let base_name = match seed_name.rfind('$') {
        Some(pos) => seed_name[..pos].to_string(),
        None => seed_name.clone(),
    };
    let seed_data_type = seed.get_data_type();

    let mut current = name_map.remove(&base_name);
    let mut index = 0i32;
    let mut saw_seed = false;
    let mut merge_vec: Vec<Box<dyn Variable>> = Vec::new();
    loop {
        let Some(var) = current.take() else { break };
        if !var.get_data_type().is_equivalent(seed_data_type.as_ref()) {
            break;
        }
        if index != 0 && var.is_parameter() {
            break;
        }
        if index != 0 && var.has_stack_storage() {
            break;
        }
        if var.get_name() == Some(seed_name.clone()) {
            saw_seed = true;
        }
        merge_vec.push(var);
        index += 1;
        let new_name = format!("{base_name}${index}");
        current = name_map.remove(&new_name);
    }

    if !saw_seed {
        vec![seed]
    } else {
        merge_vec
    }
}

fn get_local_variable(
    function: &dyn Function,
    storage: &dyn crate::program::seam_stubs::VariableStorage,
    pc_addr: Option<&Address>,
) -> Option<Box<dyn Variable>> {
    if storage.is_hash_storage() {
        let hash_val = storage.get_first_varnode().map(|vn| vn.get_offset())?;
        return function.get_local_variables().into_iter().find(|var| {
            var.is_unique_variable()
                && var.get_first_storage_varnode().map(|vn| vn.get_offset()) == Some(hash_val)
        });
    }

    let first_use_offset = pc_addr
        .map(|addr| addr.subtract(&function.get_entry_point()) as i32)
        .unwrap_or(0);

    function.get_local_variables().into_iter().find(|other_var| {
        if other_var.get_first_use_offset() != first_use_offset {
            return false;
        }
        match other_var.get_variable_storage() {
            Some(other_storage) => other_storage.intersects(storage) && other_storage.storage_equals(storage),
            None => false,
        }
    })
}

/// Low-level routine for clearing any variables in the database which conflict with this
/// variable and returning one of them for re-use. The returned variable still exists within the
/// function at the same first-use-offset.
fn clear_conflicting_local_variables(
    function: &mut dyn Function,
    storage: &dyn crate::program::seam_stubs::VariableStorage,
    pc_addr: Option<&Address>,
) -> Option<Box<dyn Variable>> {
    if storage.is_hash_storage() {
        let hash_val = storage.get_first_varnode().map(|vn| vn.get_offset())?;
        return function.get_local_variables().into_iter().find(|var| {
            var.is_unique_variable()
                && var.get_first_storage_varnode().map(|vn| vn.get_offset()) == Some(hash_val)
        });
    }

    let first_use_offset = pc_addr
        .map(|addr| addr.subtract(&function.get_entry_point()) as i32)
        .unwrap_or(0);

    let mut matching_variable: Option<Box<dyn Variable>> = None;
    for other_var in function.get_local_variables() {
        if other_var.get_first_use_offset() != first_use_offset {
            continue;
        }
        let Some(other_storage) = other_var.get_variable_storage() else {
            continue;
        };
        if !other_storage.intersects(storage) {
            continue;
        }
        if matching_variable.is_none() && other_storage.storage_equals(storage) {
            matching_variable = Some(other_var);
            continue;
        }
        function.remove_variable(other_var.as_ref());
    }
    matching_variable
}

/// Get the database parameter which corresponds to `param`, where we anticipate that the
/// parameter will be modified to match the symbol. The entire prototype is committed to the
/// database if necessary.
fn get_database_parameter(param: &dyn HighSymbol) -> Result<Box<dyn Parameter>, InvalidInputException> {
    let high_function = param.get_high_function();
    let function = high_function.get_function();

    let slot = param.get_category_index();
    let mut parameters = function.get_parameters();
    if slot >= 0
        && (slot as usize) < parameters.len()
        && Parameter::is_auto_parameter(parameters[slot as usize].as_ref())
    {
        return Err(InvalidInputException(format!(
            "Cannot modify auto-parameter: {}",
            parameters[slot as usize].get_name().unwrap_or_default()
        )));
    }

    let param_storage = param.get_storage();
    let needs_commit = slot < 0
        || slot as usize >= parameters.len()
        || !storage_option_equals(
            parameters[slot as usize].get_variable_storage().as_deref(),
            Some(param_storage.as_ref()),
        );

    if needs_commit {
        match commit_params_to_database_impl(
            high_function.as_ref(),
            true,
            ReturnCommitOption::NoCommit,
            SourceType::Analysis,
        ) {
            Ok(()) => {}
            Err(FunctionEditError::Duplicate(e)) => {
                panic!("{}", AssertException::with_message(format!("Unexpected exception: {e}")));
            }
            Err(FunctionEditError::InvalidInput(e)) => return Err(e),
        }
        parameters = function.get_parameters();
        let still_bad = slot < 0
            || slot as usize >= parameters.len()
            || !storage_option_equals(
                parameters[slot as usize].get_variable_storage().as_deref(),
                Some(param_storage.as_ref()),
            );
        if still_bad {
            return Err(InvalidInputException(format!(
                "Parameter commit failed for function at {}",
                function.get_entry_point()
            )));
        }
    }

    Ok(parameters.remove(slot as usize))
}

fn get_function_variable_impl(high_symbol: Option<&dyn HighSymbol>) -> Option<Box<dyn Variable>> {
    let high_symbol = high_symbol?;
    let high_function = high_symbol.get_high_function();
    let function = high_function.get_function();
    let high_var = high_symbol.get_high_variable();

    if high_symbol.is_parameter() {
        let slot = high_var.as_ref().and_then(|v| v.as_param_slot()).unwrap_or(0);
        return function
            .get_parameter(slot)
            .map(|p| Box::new(ParamAsVariable(p)) as Box<dyn Variable>);
    }

    if high_symbol.is_global() {
        return None;
    }

    let storage = high_symbol.get_storage();
    let pc_addr = high_symbol.get_pc_address();
    let local_variable = get_local_variable(function.as_ref(), storage.as_ref(), pc_addr.as_ref());

    // Java recomputes a dynamic-storage `DynamicEntry` here (`storage`/`pcAddr` are reassigned)
    // but never reads the updated values before returning; that apparent dead branch is mirrored
    // faithfully (as a no-op) rather than "fixed".
    if !storage.is_hash_storage() {
        if let Some(hv) = &high_var {
            if hv.requires_dynamic_storage() {
                let _ = seam_stubs::DynamicEntry::build(&hv.get_representative());
            }
        }
    }

    local_variable
}

fn update_db_variable_impl(
    high_symbol: &dyn HighSymbol,
    name: Option<&str>,
    data_type: Option<Box<dyn DataType>>,
    source: SourceType,
) -> Result<(), UpdateDbVariableError> {
    let high_function = high_symbol.get_high_function();
    let mut function = high_function.get_function();
    let program = function.get_program();

    let mut resized = false;
    let data_type: Option<Box<dyn DataType>> = match data_type {
        Some(dt) => {
            let dt = match program.get_data_type_manager() {
                Some(dtm) => dt.clone_data_type(dtm.as_ref()),
                None => dt,
            };
            if dt.get_length() <= 0 {
                return Err(InvalidInputException(format!(
                    "Data type is not fixed-length: {}",
                    dt.get_name()
                ))
                .into());
            }
            resized = dt.get_length() != high_symbol.get_size();
            Some(dt)
        }
        None => None,
    };

    let is_rename = name.is_some();

    if high_symbol.is_parameter() {
        let mut db_param = get_database_parameter(high_symbol)?;
        let storage = high_symbol.get_storage();
        if let Some(dt) = data_type {
            if resized && function.has_custom_variable_storage() {
                let new_storage = seam_stubs::resize_storage(storage, dt.as_ref(), true, function.as_ref());
                db_param.set_data_type_with_storage(dt, new_storage, false, source)?;
            } else {
                db_param.set_data_type(dt, source)?;
            }
        }
        if let Some(name) = name {
            if db_param.get_name().as_deref() != Some(name) {
                db_param.set_name(name, source)?;
            }
        }
        return Ok(());
    }

    if !high_symbol.is_global() {
        let mut storage = high_symbol.get_storage();
        let mut pc_addr = high_symbol.get_pc_address();
        let tmp_high = high_symbol.get_high_variable();
        let mut var_list: Option<Vec<Box<dyn Variable>>> = None;

        if !storage.is_hash_storage() && tmp_high.as_ref().is_some_and(|v| v.requires_dynamic_storage()) {
            let entry = seam_stubs::DynamicEntry::build(&tmp_high.as_ref().unwrap().get_representative());
            storage = entry.get_storage();
            pc_addr = entry.get_pc_address();
        } else if let Some(var) =
            clear_conflicting_local_variables(function.as_mut(), storage.as_ref(), pc_addr.as_ref())
        {
            var_list = Some(if !resized {
                gather_merge_set(function.as_mut(), var)
            } else {
                vec![var]
            });
        }

        let uses_hash_storage = storage.is_hash_storage();
        let data_type = match data_type {
            Some(dt) => dt,
            None => match &var_list {
                Some(list) => list[0].get_data_type(),
                None => {
                    let undefined = seam_stubs::undefined_data_type(high_symbol.get_size());
                    match program.get_data_type_manager() {
                        Some(dtm) => undefined.clone_data_type(dtm.as_ref()),
                        None => undefined,
                    }
                }
            },
        };

        if resized && uses_hash_storage {
            return Err(InvalidInputException(format!(
                "Variable size ({}) may not be changed: type '{}' length is {}",
                high_symbol.get_size(),
                data_type.get_name(),
                data_type.get_length()
            ))
            .into());
        }
        let storage = if resized {
            seam_stubs::resize_storage(storage, data_type.as_ref(), true, function.as_ref())
        } else {
            storage
        };

        let mut var_list = match var_list {
            None => {
                let var = create_local_variable(function.as_mut(), data_type, storage, pc_addr, source)?;
                vec![var]
            }
            Some(mut list) if resized => {
                list[0].set_data_type_with_storage(data_type, storage, true, source)?;
                list
            }
            Some(mut list) => {
                let data_type_shared: Arc<dyn DataType> = Arc::from(data_type);
                for var in list.iter_mut() {
                    var.set_data_type(seam_stubs::share_data_type(&data_type_shared), source)?;
                }
                list
            }
        };

        let final_name = name.map(|s| s.to_string()).unwrap_or_else(|| high_symbol.get_name());
        let mut index = 0i32;
        let mut cur_name = final_name.clone();
        let mut duplicate: Option<(usize, DuplicateNameException)> = None;
        for (i, var) in var_list.iter_mut().enumerate() {
            match var.set_name(&cur_name, source) {
                Ok(()) => {}
                Err(SetVariableNameError::Duplicate(e)) => {
                    duplicate = Some((i, e));
                    break;
                }
                Err(SetVariableNameError::InvalidInput(e)) => return Err(e.into()),
            }
            index += 1;
            cur_name = format!("{final_name}${index}");
        }
        if let Some((rename_index, e)) = duplicate {
            if is_rename {
                return Err(e.into());
            }
            // Assign a default name on conflict, mirroring the Java fallback
            // (`renameVar.setName(null, SourceType.DEFAULT)`); this crate's `Variable::set_name`
            // has no null/default-name sentinel, so an empty name is used as a best-effort stand
            // in.
            if let Some(var) = var_list.get_mut(rename_index) {
                if let Err(e1) = var.set_name("", SourceType::Default) {
                    panic!(
                        "{}",
                        AssertException::with_message(format!("Unexpected exception with default name: {e1}"))
                    );
                }
            }
        }
        return Ok(());
    }

    // A global symbol.
    let storage = high_symbol.get_storage();
    if !storage.is_memory_storage() {
        panic!("Database supports global memory variables only");
    }

    let name = match name {
        Some(name) => Some(name.to_string()),
        None => {
            let symbol_name = high_symbol.get_name();
            if crate::program::model::symbol::DefaultSymbolUtilities
                .is_dynamic_symbol_pattern(&symbol_name, true)
            {
                None
            } else {
                Some(symbol_name)
            }
        }
    };

    if let Some(dt) = &data_type {
        set_global_data_type(high_symbol, dt.as_ref())?;
    }

    if let Some(name) = &name {
        match set_global_name(high_symbol, name, source) {
            Ok(()) => {}
            Err(UpdateDbVariableError::Duplicate(e)) => {
                if is_rename {
                    return Err(UpdateDbVariableError::Duplicate(e));
                }
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Simplified stand-in for `HighFunctionDBUtil.setGlobalName`: creating/renaming the label at
/// `global`'s storage address requires mutable `SymbolTable` access via `Program`, unreachable
/// here for the same reason documented on [`change_conflicting_symbol_names`]; the memory-storage
/// guard is preserved, but persisting the rename is deferred until that access path is ported.
fn set_global_name(
    global: &dyn HighSymbol,
    name: &str,
    source: SourceType,
) -> Result<(), UpdateDbVariableError> {
    let storage = global.get_storage();
    if !storage.is_memory_storage() {
        return Ok(()); // Unsupported global (register?).
    }
    let _ = (name, source);
    Ok(())
}

/// Simplified stand-in for `HighFunctionDBUtil.setGlobalDataType`: persisting the data type at
/// `global`'s storage address requires mutable `Listing` access via `Program`, unreachable here
/// for the same reason documented on [`change_conflicting_symbol_names`]; the memory-storage
/// guard is preserved, but persisting the data type is deferred until that access path is ported.
fn set_global_data_type(global: &dyn HighSymbol, dt: &dyn DataType) -> Result<(), InvalidInputException> {
    let storage = global.get_storage();
    if !storage.is_memory_storage() {
        return Ok(());
    }
    let _ = dt;
    Ok(())
}

fn write_override_impl(
    function: &mut dyn Function,
    callsite: Address,
    sig: &dyn FunctionSignature,
) -> Result<(), InvalidInputException> {
    let space = crate::program::model::pcode::high_function::find_create_override_space(function)
        .ok_or_else(|| InvalidInputException("Could not create \"override\" namespace".to_string()))?;
    seam_stubs::write_data_type_symbol_override(space.as_ref(), callsite, sig);
    Ok(())
}

fn read_override_impl(sym: &dyn Symbol) -> Option<Box<dyn DataTypeSymbol>> {
    // NOTE: without the real `DataTypeSymbol`/`FunctionSignature` downcast machinery, the Java
    // `dt instanceof FunctionSignature` guard cannot be checked here; `read_data_type_symbol`
    // always returns `None` until the real DB-backed type is ported, so this is unreachable for
    // now, but the shape is kept faithful for when it is.
    seam_stubs::read_data_type_symbol(AUTO_CAT, sym)
}

fn get_first_var_arg_impl(program: &mut dyn Program, addr: Address) -> i32 {
    let Some(reference_manager) = program.get_reference_manager() else {
        return -1;
    };
    for reference in reference_manager.get_references_from(addr) {
        if reference.is_primary() && reference.reference_type().is_call() {
            let call_dest_addr = reference.to_address();
            let func = program
                .get_function_manager()
                .and_then(|fm| fm.get_function_at(&call_dest_addr));
            if let Some(func) = func {
                if func.has_var_args() {
                    return func.get_parameter_count();
                }
            }
            break;
        }
    }
    -1
}

fn get_spacebase_reference_address_impl(
    addr_factory: &dyn AddressFactory,
    op: Option<&PcodeOp>,
) -> Option<Address> {
    let op = op?;
    if op.opcode != OpCode::PtrSub {
        return None;
    }
    let vnode = op.inputs.first()?;
    let cnode = op.inputs.get(1)?;
    if vnode.is_register() {
        let stack_space = addr_factory.get_stack_space()?;
        Some(stack_space.address(cnode.get_offset()))
    } else {
        let space = addr_factory.get_default_address_space()?;
        // NOTE: the real Java method special-cases `SegmentedAddressSpace` here to decode a
        // "full" segment:offset encoding; this crate's `AddressSpace` cannot currently be
        // downcast to `SegmentedAddressSpace` (the latter wraps rather than extends it), so that
        // branch is elided pending that wiring and only the flat-offset form is produced.
        Some(space.address(cnode.get_offset()))
    }
}

fn write_union_facet_impl(
    function: &mut dyn Function,
    dt: Box<dyn DataType>,
    field_num: i32,
    addr: Address,
    hash: i64,
    is_addr: bool,
    source: SourceType,
) -> Result<(), UpdateDbVariableError> {
    let first_use_offset = addr.subtract(&function.get_entry_point()) as i32;

    let mut local_variables: Vec<Option<Box<dyn Variable>>> = Vec::new();
    for var in function.get_local_variables() {
        if !var.is_unique_variable() {
            continue;
        }
        let name = var.get_name().unwrap_or_default();
        if name.starts_with(seam_stubs::union_facet_symbol::BASENAME) {
            if seam_stubs::union_facet_symbol::is_union_type(var.get_data_type().as_ref()) {
                local_variables.push(Some(var));
            } else {
                function.remove_variable(var.as_ref());
                local_variables.push(None);
            }
        } else {
            local_variables.push(None);
        }
    }

    let mut symbol_name = seam_stubs::union_facet_symbol::build_symbol_name(field_num, &addr, is_addr);
    let mut preexisting_index: Option<usize> = None;
    let mut name_collision = false;
    let mut to_remove: Vec<usize> = Vec::new();

    for (i, slot) in local_variables.iter().enumerate() {
        let Some(var) = slot else { continue };
        if is_addr && var.get_first_use_offset() == first_use_offset {
            if preexisting_index.is_none() {
                preexisting_index = Some(i);
            } else {
                to_remove.push(i);
            }
        } else if !is_addr
            && var.get_first_use_offset() == first_use_offset
            && var.get_first_storage_varnode().map(|vn| vn.get_offset()) == Some(hash)
        {
            preexisting_index = Some(i);
        } else if var.get_name().is_some_and(|n| n.starts_with(&symbol_name)) {
            name_collision = true;
        }
    }

    for i in to_remove {
        if let Some(var) = local_variables[i].take() {
            function.remove_variable(var.as_ref()); // Address-based facets override all other facets at the same address.
        }
    }

    // NOTE: unwrapping a `PartialUnion`'s parent, or a `Pointer`'s pointee type when `is_addr`
    // (as the real Java method does before persisting), needs downcast support this crate's
    // `DataType` trait does not expose yet; `dt` is used as given.
    if name_collision {
        symbol_name = format!("{symbol_name}_{hash:x}");
    }

    if let Some(i) = preexisting_index {
        if let Some(var) = local_variables[i].as_mut() {
            if var.get_name().as_deref() != Some(symbol_name.as_str()) {
                var.set_name(&symbol_name, source)?;
            }
            if !var.get_data_type().is_equivalent(dt.as_ref()) {
                var.set_data_type(dt, source)?;
            }
        }
        return Ok(());
    }

    let program = function.get_program();
    let storage: Box<dyn crate::program::seam_stubs::VariableStorage> =
        Box::new(seam_stubs::HashVariableStorage(hash));
    let var = seam_stubs::DatabaseVariableImpl::new(Some(symbol_name), first_use_offset, dt, storage, program);
    let _ = function.add_local_variable(Box::new(var), SourceType::UserDefined);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::SequenceNumber;

    fn mock_address(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    struct MockAddressFactory {
        stack: Arc<AddressSpace>,
        default: Arc<AddressSpace>,
    }

    impl AddressFactory for MockAddressFactory {
        fn get_address(&self, _addr_string: &str) -> Option<Address> {
            None
        }

        fn get_all_addresses_case(&self, _addr_string: &str, _case_sensitive: bool) -> Vec<Address> {
            Vec::new()
        }

        fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
            Some(self.default.clone())
        }

        fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            vec![self.default.clone(), self.stack.clone()]
        }

        fn get_address_space_by_name(&self, _name: &str) -> Option<Arc<AddressSpace>> {
            None
        }

        fn get_address_space_by_id(&self, _id: i32) -> Option<Arc<AddressSpace>> {
            None
        }

        fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            self.get_address_spaces()
        }

        fn get_num_address_spaces(&self) -> usize {
            2
        }

        fn is_valid_address(&self, _address: &Address) -> bool {
            true
        }

        fn get_index(&self, _address: &Address) -> i64 {
            0
        }

        fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
            space.clone()
        }

        fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
            self.get_address_spaces()
        }

        fn address(&self, _space_id: i32, _offset: i64) -> Option<Address> {
            None
        }

        fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
            Some(self.stack.clone())
        }

        fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }

        fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }

        fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }

        fn get_constant_address(&self, _offset: i64) -> Option<Address> {
            None
        }

        fn get_address_set_range(
            &self,
            _min: &Address,
            _max: &Address,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }

        fn get_address_set(&self) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }

        fn old_get_address_from_long(&self, _value: i64) -> Option<Address> {
            None
        }

        fn has_multiple_memory_spaces(&self) -> bool {
            true
        }
    }

    /// Proves [`HighFunctionDBUtil`] is dyn-object-safe (usable as `Box<dyn HighFunctionDBUtil>`)
    /// and that [`HighFunctionDb::get_spacebase_reference_address`] correctly decodes a
    /// `PTRSUB(<register>, #const)` stack reference into the stack space's address for the given
    /// constant offset -- real behavior, not a trivially-true assertion.
    #[test]
    fn get_spacebase_reference_address_decodes_stack_ptrsub() {
        let register_space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        let stack_space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 2);
        let ram_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 3);
        let factory = MockAddressFactory {
            stack: stack_space.clone(),
            default: ram_space.clone(),
        };

        let reg_vn = Varnode::new(mock_address(&register_space, 0x20), 4);
        let const_vn = Varnode::new(mock_address(&ram_space, 0x8), 4);
        let op = PcodeOp::new(
            OpCode::PtrSub,
            SequenceNumber::new(mock_address(&ram_space, 0x1000), 0),
            vec![reg_vn, const_vn.clone()],
            None,
        );

        let util: Box<dyn HighFunctionDBUtil> = Box::new(HighFunctionDb);
        let addr = util
            .get_spacebase_reference_address(&factory, Some(&op))
            .expect("stack PTRSUB should decode to an address");
        assert_eq!(addr, stack_space.address(0x8));

        // A non-PTRSUB op decodes to nothing.
        let other_op = PcodeOp::new(
            OpCode::Copy,
            SequenceNumber::new(mock_address(&ram_space, 0x1000), 0),
            vec![const_vn.clone()],
            None,
        );
        assert_eq!(util.get_spacebase_reference_address(&factory, Some(&other_op)), None);
        assert_eq!(util.get_spacebase_reference_address(&factory, None), None);
    }
}

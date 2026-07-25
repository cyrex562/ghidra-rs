//! Port of `ghidra.program.model.listing.VariableUtilities`.
//!
//! The Java class is a `private`-constructor static-method utility (it cannot be instantiated).
//! It was selected as a dependency-cycle cut-point, so it is ported here as a Rust trait with
//! default-implemented methods instead of free functions: callers depend on `&dyn
//! VariableUtilities` (a trait-object seam) rather than importing this module's concrete
//! machinery directly, which is what breaks the cycle. A bare `impl VariableUtilities for Foo
//! {}` is enough to use every method, since every method has a real default implementation.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::structure::Structure;
use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::{AutoParameterType, Function, Parameter, Variable, VariableSizeException};
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::{Namespace, NamespaceType};
use crate::program::seam_stubs::VariableStorage;
use crate::util::exception::InvalidInputException;

/// Assumed pointer size, in bytes, used when no [`DataTypeManager`] is available to ask for a
/// language-appropriate pointer size. Stands in for the common case where
/// `program.getDefaultPointerSize()` would have been consulted; not a port of any specific Java
/// constant.
const DEFAULT_POINTER_SIZE: i32 = 4;

/// Callback used by [`VariableUtilities::check_variable_conflict_with_handler`] to resolve
/// variable storage conflicts (e.g. by removing the conflicting variables).
///
/// Port of `ghidra.program.model.listing.VariableUtilities.VariableConflictHandler`.
pub trait VariableConflictHandler {
    /// Attempt to resolve the given conflicts (e.g. by deleting them). Returns `true` if the
    /// conflicts were resolved.
    fn resolve_conflicts(&self, conflicts: &[&dyn Variable]) -> bool;
}

/// Static helper methods for working with [`Variable`]s, their precedence/ordering, and their
/// storage.
///
/// Port of `ghidra.program.model.listing.VariableUtilities`.
pub trait VariableUtilities {
    /// Get a precedence value for the specified variable. This value can be used to assist with
    /// `LocalVariable::compare_to`.
    fn get_precedence(&self, var: &dyn Variable) -> i32 {
        let mut precedence = if var.is_memory_variable() {
            15
        } else if var.is_register_variable() {
            13
        } else if var.is_stack_variable() {
            14
        } else if var.is_unique_variable() {
            16
        } else if var.is_compound_variable() {
            11
        } else {
            0
        };
        if var.is_parameter() {
            precedence -= 10;
        }
        precedence
    }

    /// Compare storage varnodes for two lists of variables. No check is done to ensure that
    /// storage is considered good/valid (i.e., BAD_STORAGE, UNASSIGNED_STORAGE and VOID_STORAGE
    /// all have an empty varnode list and would be considered a match).
    ///
    /// Returns `true` if the exact sequence of variable storage varnodes matches across the two
    /// lists of variables.
    fn storage_matches(&self, vars: &[&dyn Variable], other_vars: &[&dyn Variable]) -> bool {
        if vars.len() != other_vars.len() {
            return false;
        }
        vars.iter().zip(other_vars.iter()).all(|(v, other)| {
            variable_varnodes(*v) == variable_varnodes(*other)
        })
    }

    /// Compare two variables without using the instance specific `compare_to` method.
    ///
    /// Returns [`Ordering::Less`] if `v1 < v2`, [`Ordering::Equal`] if equal, and
    /// [`Ordering::Greater`] if `v1 > v2`.
    fn compare(&self, v1: &dyn Variable, v2: &dyn Variable) -> Ordering {
        if let (Some(o1), Some(o2)) = (v1.parameter_ordinal(), v2.parameter_ordinal()) {
            // All dynamic/unmapped variables should be parameters.
            return o1.cmp(&o2);
        }
        let precedence_diff = self.get_precedence(v1) - self.get_precedence(v2);
        if precedence_diff != 0 {
            return precedence_diff.cmp(&0);
        }

        if v1.is_stack_variable() && v2.is_stack_variable() {
            if let (Ok(o1), Ok(o2)) = (v1.get_stack_offset(), v2.get_stack_offset()) {
                // For some reason we like to reverse the natural order of stack variable
                // addresses.
                let diff = o2 - o1;
                if diff != 0 {
                    return diff.cmp(&0);
                }
            }
        }

        let fu1 = v1.get_first_use_offset();
        let fu2 = v2.get_first_use_offset();
        if fu1 != fu2 {
            // give precedence to 0 first-use-offset
            if fu1 == 0 {
                return Ordering::Less;
            }
            if fu2 == 0 {
                return Ordering::Greater;
            }
            return fu1.cmp(&fu2);
        }

        compare_varnode_lists(&variable_varnodes(v1), &variable_varnodes(v2))
    }

    /// Determine the appropriate data type for an automatic parameter.
    ///
    /// `function` is the function whose auto param datatype is to be determined, `return_data_type`
    /// is the function's formal return datatype, and `storage` is the variable storage for an
    /// auto-parameter (its `get_auto_parameter_type()` should return `Some`).
    fn get_auto_data_type(
        &self,
        function: &dyn Function,
        return_data_type: &dyn DataType,
        storage: &dyn VariableStorage,
    ) -> Box<dyn DataType> {
        let dt_mgr = function.get_program().get_data_type_manager();
        match storage.get_auto_parameter_type() {
            Some(AutoParameterType::This) => {
                let base: Box<dyn DataType> =
                    match self.find_or_create_class_struct_for_function(function) {
                        Some(s) => Box::new(StructureAsDataType(s)),
                        None => Box::new(FallbackVoidDataType),
                    };
                make_pointer(dt_mgr.as_deref(), base, Some(storage.size()))
            }
            Some(AutoParameterType::ReturnStoragePtr) => {
                let base = match dt_mgr.as_deref() {
                    Some(mgr) => return_data_type.clone_data_type(mgr),
                    None => crate::program::seam_stubs::undefined_data_type(
                        return_data_type.get_length(),
                    ),
                };
                make_pointer(dt_mgr.as_deref(), base, Some(storage.size()))
            }
            None => crate::program::seam_stubs::undefined_data_type(storage.size()),
        }
    }

    /// Perform variable storage checks using the specified datatype (no function context).
    ///
    /// # Errors
    /// Returns `Err` if the specified storage is not suitable for the datatype.
    fn check_storage(
        &self,
        storage: Box<dyn VariableStorage>,
        data_type: &dyn DataType,
        allow_size_mismatch: bool,
    ) -> Result<(), InvalidInputException> {
        self.check_storage_for_function(None, storage, data_type, allow_size_mismatch)?;
        Ok(())
    }

    /// Perform variable storage checks using the specified datatype.
    ///
    /// If `function` is specified and the variable storage size does not match the data-type
    /// size, an attempt will be made to resize the specified storage.
    ///
    /// Returns the original storage or resized storage with the correct size.
    ///
    /// # Errors
    /// Returns `Err` if specified storage is not suitable for the datatype.
    fn check_storage_for_function(
        &self,
        function: Option<&dyn Function>,
        storage: Box<dyn VariableStorage>,
        data_type: &dyn DataType,
        allow_size_mismatch: bool,
    ) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
        if !storage.is_valid() {
            // allow BAD and UNASSIGNED to pass thru
            return Ok(storage);
        }

        let base = data_type.typedef_base_data_type();
        let base_is_void = base.as_deref().map_or(data_type.is_void_type(), DataType::is_void_type);
        let base_is_composite = base
            .as_deref()
            .map_or(data_type.is_structure() || data_type.is_union(), |b| {
                b.is_structure() || b.is_union()
            });

        let storage_size = storage.size();
        let dt_len = data_type.get_length();

        if base_is_void {
            return Ok(Box::new(crate::program::seam_stubs::PlaceholderVariableStorage));
        }
        if storage.is_unique_storage() || storage.is_constant_storage() {
            return Err(InvalidInputException::with_message(format!(
                "Invalid storage address specified: {}",
                storage_repr(storage.as_ref())
            )));
        }
        if dt_len == 0 && base_is_composite {
            return Ok(Box::new(crate::program::seam_stubs::PlaceholderVariableStorage));
        }
        if !allow_size_mismatch && storage_size != dt_len {
            if data_type.is_floating_point() {
                // do not constrain or attempt resize of float storage
                return Ok(storage);
            }
            if let Some(function) = function {
                return self.resize_storage(storage, data_type, true, function);
            }
            if dt_len < storage_size && storage.is_register_storage() {
                if let Some(reg) = storage.get_register() {
                    let shrunk = shrink_register(&reg, storage_size - dt_len);
                    return Ok(storage.with_varnodes(vec![shrunk]));
                }
            }
            return Err(InvalidInputException::with_message(format!(
                "Storage size does not match data type size: {}",
                dt_len
            )));
        }
        Ok(storage)
    }

    /// Check the specified datatype for use as a return, parameter or variable type. It may not
    /// be suitable for other uses. Function definition datatypes and unsized/zero-element arrays
    /// will be mutated into a default pointer datatype.
    ///
    /// `void_ok` is true if checking a return datatype and void is allowed, else false.
    /// `default_size` is the `Undefined` datatype size to be used if `data_type` is `None`; a
    /// value less than 1 results in the DEFAULT data type being returned (i.e. "undefined").
    ///
    /// # Errors
    /// Returns `Err` if an unacceptable datatype was specified.
    fn check_data_type(
        &self,
        data_type: Option<Box<dyn DataType>>,
        void_ok: bool,
        default_size: i32,
        dt_mgr: Option<&dyn DataTypeManager>,
    ) -> Result<Box<dyn DataType>, InvalidInputException> {
        let mut dt: Box<dyn DataType> = match data_type {
            Some(dt) => dt,
            None => crate::program::seam_stubs::undefined_data_type(default_size),
        };

        if dt.is_bit_field_type() {
            return Err(InvalidInputException::with_message("Bitfield not permitted"));
        }
        if dt.is_dynamic_type() || dt.is_factory_type() {
            return Err(InvalidInputException::with_message(format!(
                "Dynamic and Factory data types are not permitted: {}",
                dt.get_name()
            )));
        }

        let base = if dt.is_typedef() {
            dt.typedef_base_data_type()
        } else {
            None
        };
        let target_is_function_def = base
            .as_deref()
            .map_or(dt.is_function_definition_type(), DataType::is_function_definition_type);
        let target_is_array = base.as_deref().map_or(dt.is_array(), DataType::is_array);
        let target_is_void = base.as_deref().map_or(dt.is_void_type(), DataType::is_void_type);

        if target_is_function_def {
            dt = make_pointer(dt_mgr, dt, None);
        } else if target_is_array {
            let array_holder = base.unwrap_or(dt);
            match array_holder.into_array() {
                Some(arr) => {
                    if arr.get_num_elements() == 0 {
                        dt = make_pointer(dt_mgr, arr.get_data_type(), None);
                    } else {
                        dt = Box::new(ArrayAsDataType(arr));
                    }
                }
                None => {
                    // Downcast unavailable for this implementor; fall back to a same-sized
                    // undefined type rather than losing the data type entirely.
                    dt = crate::program::seam_stubs::undefined_data_type(default_size.max(1));
                }
            }
        }

        // A clone is done to ensure that any effects of the data organization are properly
        // reflected in the sizing of the datatype. Skipped when no data type manager is
        // available (matches the `dtMgr == null` case, which yields an unmanaged clone in Java;
        // here we simply keep the already-computed value).
        if let Some(mgr) = dt_mgr {
            dt = dt.clone_data_type(mgr);
        }

        if target_is_void {
            if !void_ok {
                return Err(InvalidInputException::with_message(
                    "The void type is not permitted - allowed for function return use only",
                ));
            }
            return Ok(dt);
        }

        if dt.get_length() <= 0 {
            return Err(InvalidInputException::with_message(format!(
                "Unsupported data type length ({}): {}",
                dt.get_length(),
                dt.get_name()
            )));
        }
        Ok(dt)
    }

    /// Check the specified datatype for use as a return, parameter or variable type, resolving
    /// the [`DataTypeManager`] from `program`. See [`VariableUtilities::check_data_type`].
    ///
    /// # Errors
    /// Returns `Err` if an unacceptable datatype was specified.
    fn check_data_type_for_program(
        &self,
        data_type: Option<Box<dyn DataType>>,
        void_ok: bool,
        default_size: i32,
        program: &dyn crate::program::model::listing::Program,
    ) -> Result<Box<dyn DataType>, InvalidInputException> {
        let dt_mgr = program.get_data_type_manager();
        self.check_data_type(data_type, void_ok, default_size, dt_mgr.as_deref())
    }

    /// Check the specified datatype for use as a return, parameter or variable type, using the
    /// DEFAULT undefined data type when `data_type` is `None`. See
    /// [`VariableUtilities::check_data_type`].
    ///
    /// # Errors
    /// Returns `Err` if an unacceptable datatype was specified.
    fn check_data_type_simple(
        &self,
        data_type: Option<Box<dyn DataType>>,
        void_ok: bool,
        dt_mgr: Option<&dyn DataTypeManager>,
    ) -> Result<Box<dyn DataType>, InvalidInputException> {
        self.check_data_type(data_type, void_ok, -1, dt_mgr)
    }

    /// Resize variable storage to the desired `data_type` size. This method has limited ability
    /// to grow storage if the current storage does not have a stack component or if other space
    /// constraints are exceeded.
    ///
    /// `align_stack`, if false, means no attempt is made to align stack usage for big-endian.
    /// `function` is the function which corresponds to the resized variable storage.
    ///
    /// # Errors
    /// Returns `Err` if unable to resize storage to the specified size.
    fn resize_storage(
        &self,
        cur_storage: Box<dyn VariableStorage>,
        data_type: &dyn DataType,
        align_stack: bool,
        function: &dyn Function,
    ) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
        let base = data_type.typedef_base_data_type();
        let effective: &dyn DataType = base.as_deref().unwrap_or(data_type);

        if effective.is_void_type() {
            return Ok(Box::new(crate::program::seam_stubs::PlaceholderVariableStorage));
        }
        if effective.is_floating_point() {
            // do not constrain or attempt resize of float storage
            return Ok(cur_storage);
        }
        if !cur_storage.is_valid() {
            return Ok(cur_storage);
        }

        let new_size = effective.get_length();
        let cur_size = cur_storage.size();
        if cur_size == new_size {
            return Ok(cur_storage);
        }
        if cur_size == 0 || cur_storage.is_unique_storage() || cur_storage.is_hash_storage() {
            return Err(InvalidInputException::with_message(format!(
                "Storage can't be resized: {}",
                storage_repr(cur_storage.as_ref())
            )));
        }

        if new_size > cur_size {
            expand_storage(cur_storage, new_size, effective, align_stack, function)
        } else {
            shrink_storage(cur_storage, new_size, effective, align_stack, function)
        }
    }

    /// Check for a variable storage conflict and optionally remove conflicting variables.
    ///
    /// `var` is the existing function variable or `None` for a new variable. If
    /// `delete_conflicting_variables` is true, the function's conflicting variables may be
    /// deleted.
    ///
    /// # Errors
    /// Returns `Err` if `delete_conflicting_variables` is false and another variable conflicts.
    fn check_variable_conflict(
        &self,
        function: &mut dyn Function,
        var: Option<&dyn Variable>,
        new_storage: &dyn VariableStorage,
        delete_conflicting_variables: bool,
    ) -> Result<(), VariableSizeException> {
        if !new_storage.is_valid() {
            return Ok(());
        }
        let all_vars = function.get_all_variables();
        let mut conflicts: Vec<&dyn Variable> = Vec::new();
        for other_var in &all_vars {
            let other_var: &dyn Variable = other_var.as_ref();
            if variables_share_identity(other_var, var) {
                // skip variable being modified
                continue;
            }
            if let Some(v) = var {
                if other_var.get_first_use_offset() != v.get_first_use_offset() {
                    // other than parameters we will have a hard time identifying local variable
                    // conflicts due to differences in scope (i.e., first-use)
                    continue;
                }
            }
            let intersects = other_var
                .get_variable_storage()
                .map(|s| s.intersects(new_storage))
                .unwrap_or(false);
            if intersects {
                if delete_conflicting_variables {
                    function.remove_variable(other_var);
                } else {
                    conflicts.push(other_var);
                }
            }
        }

        if !conflicts.is_empty() {
            return generate_conflict_exception(var, new_storage, &conflicts, 4);
        }
        Ok(())
    }

    /// Check for a variable storage conflict amongst an explicit list of existing variables
    /// (which may contain `None` entries), invoking `conflict_handler` to attempt resolution.
    ///
    /// # Errors
    /// Returns `Err` if another variable conflicts and `conflict_handler` does not resolve it.
    fn check_variable_conflict_with_handler(
        &self,
        existing_variables: &[Option<&dyn Variable>],
        var: Option<&dyn Variable>,
        new_storage: &dyn VariableStorage,
        conflict_handler: Option<&dyn VariableConflictHandler>,
    ) -> Result<(), VariableSizeException> {
        if !new_storage.is_valid() {
            return Ok(());
        }
        let mut conflicts: Vec<&dyn Variable> = Vec::new();
        for other_var in existing_variables.iter().flatten() {
            let other_var = *other_var;
            if variables_share_identity(other_var, var) {
                continue;
            }
            if let Some(v) = var {
                if other_var.get_first_use_offset() != v.get_first_use_offset() {
                    continue;
                }
            }
            let intersects = other_var
                .get_variable_storage()
                .map(|s| s.intersects(new_storage))
                .unwrap_or(false);
            if intersects {
                conflicts.push(other_var);
            }
        }

        if !conflicts.is_empty() {
            let resolved = conflict_handler
                .map(|h| h.resolve_conflicts(&conflicts))
                .unwrap_or(false);
            if !resolved {
                return generate_conflict_exception(var, new_storage, &conflicts, 4);
            }
        }
        Ok(())
    }

    /// Determine the minimum stack offset for parameters.
    ///
    /// Returns the stack parameter offset, or `None` if it could not be determined.
    fn get_base_stack_param_offset(&self, function: &dyn Function) -> Option<i32> {
        let convention = function.get_calling_convention().or_else(|| {
            function
                .get_program()
                .get_compiler_spec()
                .and_then(|cs| cs.get_default_calling_convention())
        })?;
        match convention.get_stack_parameter_offset() {
            Some(val) => Some(val as i32),
            None => Some(convention.get_stackshift()),
        }
    }

    /// Generate a suitable 'this' parameter for the specified function.
    ///
    /// Returns the 'this' parameter, or `None` if the calling convention is not a 'thiscall' or
    /// some other error prevents it.
    #[deprecated(note = "should rely on auto-param instead - try not to use this method which may be eliminated")]
    fn get_this_parameter(
        &self,
        function: &dyn Function,
        convention: Option<&dyn crate::program::model::lang::PrototypeModel>,
    ) -> Option<Box<dyn Parameter>> {
        let convention = convention?;
        if convention.get_name().as_deref()
            != Some(crate::program::model::lang::compiler_spec::CALLING_CONVENTION_THISCALL)
        {
            return None;
        }

        let program = function.get_program();
        let dt_mgr = program.get_data_type_manager();
        let base: Box<dyn DataType> = match self.find_or_create_class_struct_for_function(function) {
            Some(s) => Box::new(StructureAsDataType(s)),
            None => Box::new(FallbackVoidDataType),
        };
        let this_dt = make_pointer(dt_mgr.as_deref(), base, None);
        let this_len = this_dt.get_length();

        let data_types: Vec<Arc<dyn DataType>> = vec![
            Arc::new(FallbackVoidDataType) as Arc<dyn DataType>,
            Arc::new(FallbackPointerDataType(this_len)) as Arc<dyn DataType>,
        ];
        let storages = convention.get_storage_locations(
            program.as_ref(),
            &data_types,
            true,
            function.has_var_args(),
        );
        let this_storage = storages.into_iter().nth(1)?;

        Some(Box::new(PlaceholderThisParameter {
            data_type_length: this_len,
            storage: this_storage,
        }))
    }

    /// Create an empty placeholder class structure whose category is derived from the class
    /// namespace's parent, and search for an existing match first.
    ///
    /// `class_namespace` should be a namespace whose `get_type()` is
    /// [`NamespaceType::Class`](crate::program::model::symbol::NamespaceType::Class), standing in
    /// for the Java `GhidraClass` type (a `Namespace` subtype the Java class hierarchy guarantees
    /// via `instanceof`, which is not something this port can check for an arbitrary `&dyn
    /// Namespace` beyond its reported type).
    ///
    /// The structure is created in the root category (this port does not resolve a program's
    /// preferred namespace category path, since [`DataTypeManager`] has no route back to
    /// [`Program`](crate::program::model::listing::Program) here). If a colliding data-type
    /// matching the class name and category already exists, `None` is returned.
    ///
    /// NOTE: The structure will not be added to the data type manager.
    fn find_or_create_class_struct(
        &self,
        class_namespace: &dyn Namespace,
        data_type_manager: &dyn DataTypeManager,
    ) -> Option<Box<dyn Structure>> {
        self.find_existing_class_struct(class_namespace, data_type_manager)
            .or_else(|| create_placeholder_class_struct(class_namespace, data_type_manager))
    }

    /// Find or create the structure data type which corresponds to `function`'s class namespace
    /// within the function's program.
    ///
    /// Returns `None` if the function is not part of a class, or if an unrelated data-type
    /// already exists with the class's name and category.
    fn find_or_create_class_struct_for_function(
        &self,
        function: &dyn Function,
    ) -> Option<Box<dyn Structure>> {
        let namespace = function.get_parent_namespace()?;
        if namespace.get_type() != NamespaceType::Class {
            return None;
        }
        let program = function.get_program();
        let dt_mgr = program.get_data_type_manager()?;
        self.find_or_create_class_struct(namespace.as_ref(), dt_mgr.as_ref())
    }

    /// Find the structure data type which corresponds to the specified class namespace within
    /// `data_type_manager`.
    ///
    /// The preferred structure utilizes a namespace-based category path, however the match
    /// criteria can be fuzzy and relies primarily on the class name.
    ///
    /// Returns `None` if not found.
    fn find_existing_class_struct(
        &self,
        class_namespace: &dyn Namespace,
        data_type_manager: &dyn DataTypeManager,
    ) -> Option<Box<dyn Structure>> {
        let pref_root = ROOT.clone();
        let parent = class_namespace.get_parent_namespace();
        let category = data_type_category_path(&pref_root, parent.as_deref());
        let name = class_namespace.get_name();
        lookup_structure(data_type_manager, &category, &name)
    }

    /// Find the structure data type which corresponds to `func`'s class namespace within the
    /// function's program.
    ///
    /// Returns `None` if not found, or if `func` is not contained within a class namespace.
    fn find_existing_class_struct_for_function(
        &self,
        func: &dyn Function,
    ) -> Option<Box<dyn Structure>> {
        let namespace = func.get_parent_namespace()?;
        if namespace.get_type() != NamespaceType::Class {
            return None;
        }
        let dt_mgr = func.get_program().get_data_type_manager()?;
        self.find_existing_class_struct(namespace.as_ref(), dt_mgr.as_ref())
    }

    /// Compare two arrays of variables for equivalence, per [`Self::equivalent_variables`].
    fn equivalent_variable_arrays(
        &self,
        vars1: Option<&[&dyn Variable]>,
        vars2: Option<&[&dyn Variable]>,
    ) -> bool {
        match (vars1, vars2) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .zip(b.iter())
                        .all(|(x, y)| self.equivalent_variables(*x, *y))
            }
            _ => false,
        }
    }

    /// Determine if `var2` is equivalent to `var1`: same name, equivalent data type, and equal
    /// comments.
    ///
    /// NOTE: unlike the Java original (which also requires `var1.equals(var2)`), object identity
    /// is not modeled for `&dyn Variable` in this port, so this check is based purely on
    /// name/data-type/comment.
    fn equivalent_variables(&self, var1: &dyn Variable, var2: &dyn Variable) -> bool {
        var1.get_name() == var2.get_name()
            && var1.get_data_type().is_equivalent(var2.get_data_type().as_ref())
            && var1.get_comment() == var2.get_comment()
    }
}

fn variable_varnodes(var: &dyn Variable) -> Vec<Varnode> {
    var.get_variable_storage()
        .map(|s| s.get_varnodes())
        .unwrap_or_default()
}

fn compare_varnode_lists(a: &[Varnode], b: &[Varnode]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        let key_x = (x.get_space_id(), x.get_offset(), x.get_size());
        let key_y = (y.get_space_id(), y.get_offset(), y.get_size());
        let ord = key_x.cmp(&key_y);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

/// Loose proxy for Java's `otherVar.equals(var)` identity check: `&dyn Variable` has no `Eq`
/// bound in this port, so two variables are treated as "the same" when their name and first-use
/// offset match. `b == None` never matches, mirroring `otherVar.equals(null) == false`.
fn variables_share_identity(a: &dyn Variable, b: Option<&dyn Variable>) -> bool {
    match b {
        Some(b) => a.get_name() == b.get_name() && a.get_first_use_offset() == b.get_first_use_offset(),
        None => false,
    }
}

fn storage_repr(storage: &dyn VariableStorage) -> String {
    let varnodes = storage.get_varnodes();
    if varnodes.is_empty() {
        return "<empty>".to_string();
    }
    varnodes
        .iter()
        .map(|vn| vn.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn append_variable_storage_details(var: Option<&dyn Variable>, storage: &dyn VariableStorage, msg: &mut String) {
    if let Some(var) = var {
        if let Some(name) = var.get_name() {
            msg.push_str(&name);
        }
        msg.push('{');
        msg.push_str(&storage_repr(storage));
        msg.push('}');
    } else {
        msg.push_str(&storage_repr(storage));
    }
}

fn generate_conflict_exception(
    var: Option<&dyn Variable>,
    new_storage: &dyn VariableStorage,
    conflicts: &[&dyn Variable],
    max_conflict_var_details: usize,
) -> Result<(), VariableSizeException> {
    let max_details = conflicts.len().min(max_conflict_var_details);

    let mut msg = String::from("Variable storage conflict between ");
    append_variable_storage_details(var, new_storage, &mut msg);
    msg.push_str(" and ");
    for (i, v) in conflicts.iter().take(max_details).enumerate() {
        if i != 0 {
            msg.push_str(", ");
        }
        if let Some(storage) = v.get_variable_storage() {
            append_variable_storage_details(Some(*v), storage.as_ref(), &mut msg);
        }
    }
    if max_details < conflicts.len() {
        msg.push_str(&format!(" ... {{{} more}}", conflicts.len() - max_details));
    }
    Err(VariableSizeException::with_force(msg, true))
}

fn make_pointer(
    dt_mgr: Option<&dyn DataTypeManager>,
    base: Box<dyn DataType>,
    size: Option<i32>,
) -> Box<dyn DataType> {
    if let Some(mgr) = dt_mgr {
        let ptr = match size {
            Some(sz) if sz > 0 => mgr.get_pointer_with_size(base.as_ref(), sz),
            _ => mgr.get_pointer(base.as_ref()),
        };
        Box::new(PointerAsDataType(ptr))
    } else {
        Box::new(FallbackPointerDataType(
            size.filter(|&s| s > 0).unwrap_or(DEFAULT_POINTER_SIZE),
        ))
    }
}

fn shrink_register(reg: &RegisterRef, size_reduction: i32) -> Varnode {
    let r = reg.borrow();
    if r.is_big_endian() {
        let addr = r
            .address()
            .add(size_reduction as i64)
            .unwrap_or_else(|_| r.address().clone());
        Varnode::new(addr, r.minimum_byte_size() - size_reduction)
    } else {
        Varnode::new(r.address().clone(), r.minimum_byte_size() - size_reduction)
    }
}

fn shrink_storage(
    cur_storage: Box<dyn VariableStorage>,
    new_size: i32,
    data_type: &dyn DataType,
    align_stack: bool,
    function: &dyn Function,
) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
    let mut new_list: Vec<Varnode> = Vec::new();
    let mut size = 0;
    for vn in cur_storage.get_varnodes() {
        size += vn.get_size();
        if size >= new_size {
            let shrunk = shrink_varnode(
                &vn,
                size - new_size,
                cur_storage.as_ref(),
                new_size,
                data_type,
                align_stack,
                function,
            )?;
            new_list.push(shrunk);
            break;
        }
        new_list.push(vn);
    }
    Ok(cur_storage.with_varnodes(new_list))
}

fn expand_storage(
    cur_storage: Box<dyn VariableStorage>,
    new_size: i32,
    data_type: &dyn DataType,
    align_stack: bool,
    function: &dyn Function,
) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
    let mut varnodes = cur_storage.get_varnodes();
    let Some(last) = varnodes.last().cloned() else {
        return Err(InvalidInputException::with_message(format!(
            "Storage can't be resized: {}",
            storage_repr(cur_storage.as_ref())
        )));
    };
    let last_index = varnodes.len() - 1;
    let expanded = expand_varnode(
        &last,
        new_size - cur_storage.size(),
        cur_storage.as_ref(),
        new_size,
        data_type,
        align_stack,
        function,
    )?;
    varnodes[last_index] = expanded;
    Ok(cur_storage.with_varnodes(varnodes))
}

fn is_complex_data_type(data_type: &dyn DataType) -> bool {
    data_type.is_structure() || data_type.is_union() || data_type.is_array()
}

fn language_is_big_endian(function: &dyn Function) -> bool {
    function
        .get_program()
        .get_compiler_spec()
        .map(|cs| cs.get_language().is_big_endian())
        .unwrap_or(false)
}

fn shrink_varnode(
    varnode: &Varnode,
    size_reduction: i32,
    cur_storage: &dyn VariableStorage,
    new_size: i32,
    data_type: &dyn DataType,
    align_stack: bool,
    function: &dyn Function,
) -> Result<Varnode, InvalidInputException> {
    let addr = varnode.get_address();
    if addr.is_stack_address() {
        return resize_stack_varnode(
            varnode,
            varnode.get_size() - size_reduction,
            cur_storage,
            new_size,
            data_type,
            align_stack,
            function,
        );
    }
    let is_register = varnode.is_register();
    let big_endian = language_is_big_endian(function);
    let complex_dt = is_complex_data_type(data_type);
    if big_endian && (is_register || !complex_dt) {
        let new_addr = varnode
            .get_address()
            .add(size_reduction as i64)
            .map_err(|_| InvalidInputException::with_message("address overflow while shrinking storage"))?;
        return Ok(Varnode::new(new_addr, varnode.get_size() - size_reduction));
    }
    Ok(Varnode::new(varnode.get_address().clone(), varnode.get_size() - size_reduction))
}

fn expand_varnode(
    varnode: &Varnode,
    size_increase: i32,
    cur_storage: &dyn VariableStorage,
    new_size: i32,
    data_type: &dyn DataType,
    align_stack: bool,
    function: &dyn Function,
) -> Result<Varnode, InvalidInputException> {
    let addr = varnode.get_address();
    if addr.is_stack_address() {
        return resize_stack_varnode(
            varnode,
            varnode.get_size() + size_increase,
            cur_storage,
            new_size,
            data_type,
            align_stack,
            function,
        );
    }

    let size = varnode.get_size() + size_increase;
    let big_endian = language_is_big_endian(function);
    let reg = function.get_program().get_register_at(varnode.get_address());
    let mut vn_addr = varnode.get_address().clone();

    if let Some(mut new_reg) = reg {
        loop {
            let too_small = new_reg.borrow().minimum_byte_size() < size;
            if !too_small {
                break;
            }
            let parent = new_reg.borrow().parent_register();
            match parent {
                Some(p) => new_reg = p,
                None => {
                    return Err(InvalidInputException::with_message(format!(
                        "Storage can't be expanded to {} bytes: {}",
                        new_size,
                        storage_repr(cur_storage)
                    )));
                }
            }
        }
        vn_addr = new_reg.borrow().address().clone();
        if big_endian {
            let msb = new_reg.borrow().minimum_byte_size();
            vn_addr = vn_addr
                .add((msb - size) as i64)
                .map_err(|_| InvalidInputException::with_message("address overflow while expanding storage"))?;
            return Ok(Varnode::new(vn_addr, size));
        }
    }

    let complex_dt = is_complex_data_type(data_type);
    if big_endian && !complex_dt {
        let new_addr = vn_addr
            .subtract_no_wrap(size_increase as i64)
            .map_err(|_| InvalidInputException::with_message("address underflow while expanding storage"))?;
        return Ok(Varnode::new(new_addr, size));
    }
    Ok(Varnode::new(vn_addr, size))
}

struct StackAttributes {
    stack_align: i32,
    bias: i32,
    right_justify: bool,
}

fn get_stack_attributes(function: &dyn Function) -> StackAttributes {
    let compiler_spec = function.get_program().get_compiler_spec();
    let right_justify = compiler_spec
        .as_ref()
        .map(|cs| cs.is_stack_right_justified())
        .unwrap_or(false);
    let convention = function.get_calling_convention().or_else(|| {
        compiler_spec
            .as_ref()
            .and_then(|cs| cs.get_default_calling_convention())
    });

    let mut stack_align = convention
        .as_ref()
        .map(|c| c.get_stack_parameter_alignment())
        .unwrap_or(1);
    if stack_align < 1 {
        stack_align = 1;
    }

    let mut bias = 0;
    if let Some(c) = &convention {
        if let Some(stack_base) = c.get_stack_parameter_offset() {
            bias = (stack_base % stack_align as i64) as i32;
            if bias < 0 {
                bias += stack_align;
            }
        }
    }

    StackAttributes {
        stack_align,
        bias,
        right_justify,
    }
}

fn resize_stack_varnode(
    varnode: &Varnode,
    new_varnode_size: i32,
    _cur_storage: &dyn VariableStorage,
    _new_size: i32,
    data_type: &dyn DataType,
    align: bool,
    function: &dyn Function,
) -> Result<Varnode, InvalidInputException> {
    let complex_dt = is_complex_data_type(data_type);
    let attrs = get_stack_attributes(function);

    let cur_addr = varnode.get_address();
    let stack_offset = cur_addr.offset() as i32;
    let mut new_stack_offset = stack_offset;

    if attrs.right_justify && align {
        // complex data-type: always left align
        // simple data-type: right align within minimum number of aligned cells
        let mut stack_align = attrs.stack_align;
        if (stack_offset + varnode.get_size() - attrs.bias) % stack_align != 0 {
            stack_align = 1; // was not aligned to start with
        }

        let mut new_align = (new_stack_offset - attrs.bias) % stack_align;
        if new_align < 0 {
            new_align += stack_align;
        }
        new_stack_offset -= new_align; // left-alignment of start offset
        if !complex_dt {
            // right-align non-complex data
            let cell_excess = new_varnode_size % stack_align;
            if cell_excess != 0 {
                new_stack_offset += stack_align - cell_excess;
            }
        }
    }

    let new_end_stack_offset = new_stack_offset + new_varnode_size - 1;
    if new_stack_offset < 0 && new_end_stack_offset >= 0 {
        return Err(InvalidInputException::with_message(
            "Data type does not fit within variable stack constraints",
        ));
    }

    let new_addr = Address::new(cur_addr.space().clone(), new_stack_offset as i64);
    Ok(Varnode::new(new_addr, new_varnode_size))
}

/// Stands in for `ghidra.program.database.data.DataTypeUtilities.getDataTypeCategoryPath`,
/// built directly from [`Namespace::get_path_list`] rather than a separate ported utility class.
fn data_type_category_path(root: &CategoryPath, namespace: Option<&dyn Namespace>) -> CategoryPath {
    let Some(namespace) = namespace else {
        return root.clone();
    };
    let segments = namespace.get_path_list(false);
    if segments.is_empty() {
        return root.clone();
    }
    let refs: Vec<&str> = segments.iter().map(String::as_str).collect();
    root.extend(&refs)
}

fn lookup_structure(
    data_type_manager: &dyn DataTypeManager,
    category: &CategoryPath,
    name: &str,
) -> Option<Box<dyn Structure>> {
    let path = category.get_path_for_child(name).ok()?;
    let dt = data_type_manager.get_data_type(&path)?;
    if dt.is_structure() {
        Some(Box::new(DataTypeAsStructure(dt)))
    } else {
        None
    }
}

fn create_placeholder_class_struct(
    class_namespace: &dyn Namespace,
    data_type_manager: &dyn DataTypeManager,
) -> Option<Box<dyn Structure>> {
    let pref_root = ROOT.clone();

    let class_parent_namespace = class_namespace.get_parent_namespace();
    let mut category = data_type_category_path(&pref_root, class_parent_namespace.as_deref());
    let name = Namespace::get_name(class_namespace);

    if lookup_structure(data_type_manager, &category, &name).is_some() {
        // If a data-type already exists in the parent, try to create in the child.
        category = data_type_category_path(&pref_root, Some(class_namespace));
        if lookup_structure(data_type_manager, &category, &name).is_some() {
            // If this also already exists, don't create a placeholder.
            return None;
        }
    }

    Some(Box::new(PlaceholderClassStruct {
        name,
        category,
        description: "PlaceHolder Class Structure".to_string(),
    }))
}

/// Minimal empty structure standing in for `new StructureDataType(category, name, 0, dtMgr)`,
/// used only by [`create_placeholder_class_struct`]. Not a port of any specific Java class; every
/// [`DataType`]/[`Composite`]/[`Structure`] method not overridden here keeps its all-default
/// implementation (see those traits' `EmptyStructure`/`bare_impl_stays_object_safe` tests).
struct PlaceholderClassStruct {
    name: String,
    category: CategoryPath,
    description: String,
}

impl DataType for PlaceholderClassStruct {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_category_path(&self) -> CategoryPath {
        self.category.clone()
    }

    fn get_length(&self) -> i32 {
        0
    }

    fn is_structure(&self) -> bool {
        true
    }

    fn get_description(&self) -> String {
        self.description.clone()
    }
}

impl Composite for PlaceholderClassStruct {}
impl Structure for PlaceholderClassStruct {}

/// Adapter exposing a [`Box<dyn Structure>`] as a [`Box<dyn DataType>`] by delegating every
/// [`DataType`] method to the wrapped structure. Rust does not (portably) support coercing
/// `Box<dyn Sub>` to `Box<dyn Super>` for arbitrary supertraits, so this hand-written delegation
/// stands in for the automatic `Structure IS-A DataType` widening Java gets for free. Not a port
/// of any specific Java class.
struct StructureAsDataType(Box<dyn Structure>);

impl DataType for StructureAsDataType {
    fn get_name(&self) -> String {
        DataType::get_name(self.0.as_ref())
    }

    fn get_length(&self) -> i32 {
        DataType::get_length(self.0.as_ref())
    }

    fn is_structure(&self) -> bool {
        true
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        DataType::is_equivalent(self.0.as_ref(), dt)
    }

    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        Box::new(StructureAsDataType(self.0.clone_structure(dtm)))
    }

    fn get_category_path(&self) -> CategoryPath {
        DataType::get_category_path(self.0.as_ref())
    }
}

/// Adapter exposing a [`Box<dyn DataType>`] already known to be structure-shaped (i.e.
/// `is_structure()` is `true`) as a [`Box<dyn Structure>`], used by
/// [`lookup_structure`] once [`DataTypeManager::get_data_type`] hands back a plain
/// `Box<dyn DataType>`. [`Structure`]/[`Composite`]'s own component-editing methods keep their
/// all-default (empty) implementations here, since the callers of this adapter only need
/// identity (name/length/category), not the wrapped type's actual field layout. See
/// [`StructureAsDataType`] for the mirror-image adapter and why this delegation is needed.
struct DataTypeAsStructure(Box<dyn DataType>);

impl DataType for DataTypeAsStructure {
    fn get_name(&self) -> String {
        DataType::get_name(self.0.as_ref())
    }

    fn get_length(&self) -> i32 {
        DataType::get_length(self.0.as_ref())
    }

    fn is_structure(&self) -> bool {
        true
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        DataType::is_equivalent(self.0.as_ref(), dt)
    }

    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        DataType::clone_data_type(self.0.as_ref(), dtm)
    }

    fn get_category_path(&self) -> CategoryPath {
        DataType::get_category_path(self.0.as_ref())
    }
}

impl Composite for DataTypeAsStructure {}
impl Structure for DataTypeAsStructure {}

/// Adapter exposing a [`Box<dyn crate::program::model::data::array::Array>`] as a
/// [`Box<dyn DataType>`]. See [`StructureAsDataType`] for why this delegation is needed.
struct ArrayAsDataType(Box<dyn crate::program::model::data::array::Array>);

impl DataType for ArrayAsDataType {
    fn get_name(&self) -> String {
        DataType::get_name(self.0.as_ref())
    }

    fn get_length(&self) -> i32 {
        DataType::get_length(self.0.as_ref())
    }

    fn is_array(&self) -> bool {
        true
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        DataType::is_equivalent(self.0.as_ref(), dt)
    }

    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        DataType::clone_data_type(self.0.as_ref(), dtm)
    }
}

/// Adapter exposing a [`Box<dyn crate::program::model::data::pointer::Pointer>`] as a
/// [`Box<dyn DataType>`]. See [`StructureAsDataType`] for why this delegation is needed.
struct PointerAsDataType(Box<dyn crate::program::model::data::pointer::Pointer>);

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

/// Fallback pointer [`DataType`] used when no [`DataTypeManager`] is available to mint a real
/// one via `get_pointer`/`get_pointer_with_size`. Stands in for
/// `new PointerDataType(base, null)`; not a port of any specific Java class.
struct FallbackPointerDataType(i32);

impl DataType for FallbackPointerDataType {
    fn get_name(&self) -> String {
        "pointer".to_string()
    }

    fn get_length(&self) -> i32 {
        self.0
    }

    fn is_pointer(&self) -> bool {
        true
    }
}

/// Fallback `void` [`DataType`] used where `VoidDataType.dataType` would have been referenced in
/// Java before the real `VoidDataType` class is ported (see `is_void_data_type` in
/// `program::seam_stubs`). Not a port of any specific Java class.
struct FallbackVoidDataType;

impl DataType for FallbackVoidDataType {
    fn get_name(&self) -> String {
        "void".to_string()
    }

    fn get_length(&self) -> i32 {
        0
    }

    fn is_void_type(&self) -> bool {
        true
    }
}

/// Minimal [`Parameter`] implementation backing the deprecated
/// [`VariableUtilities::get_this_parameter`], standing in for `new ParameterImpl("this", 0, ...)`.
/// Not a port of any specific Java class.
struct PlaceholderThisParameter {
    data_type_length: i32,
    storage: Box<dyn VariableStorage>,
}

impl Variable for PlaceholderThisParameter {
    fn get_data_type(&self) -> Box<dyn DataType> {
        Box::new(FallbackPointerDataType(self.data_type_length))
    }

    fn set_data_type_with_storage(
        &mut self,
        _data_type: Box<dyn DataType>,
        _storage: Box<dyn VariableStorage>,
        _force: bool,
        _source: crate::program::model::symbol::SourceType,
    ) -> Result<(), InvalidInputException> {
        Err(InvalidInputException::with_message("this parameter is not mutable"))
    }

    fn set_data_type(
        &mut self,
        _data_type: Box<dyn DataType>,
        _source: crate::program::model::symbol::SourceType,
    ) -> Result<(), InvalidInputException> {
        Err(InvalidInputException::with_message("this parameter is not mutable"))
    }

    fn set_data_type_aligned(
        &mut self,
        _data_type: Box<dyn DataType>,
        _align_stack: bool,
        _force: bool,
        _source: crate::program::model::symbol::SourceType,
    ) -> Result<(), InvalidInputException> {
        Err(InvalidInputException::with_message("this parameter is not mutable"))
    }

    fn get_name(&self) -> Option<String> {
        Some(crate::program::model::listing::function::THIS_PARAM_NAME.to_string())
    }

    fn get_length(&self) -> i32 {
        self.data_type_length
    }

    fn is_valid(&self) -> bool {
        true
    }

    fn get_function(&self) -> Option<Box<dyn Function>> {
        None
    }

    fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
        struct EmptyProgram;
        impl crate::framework::model::DomainObject for EmptyProgram {}
        impl crate::program::model::listing::Program for EmptyProgram {
            fn get_name(&self) -> String {
                String::new()
            }
            fn get_language_id(&self) -> String {
                String::new()
            }
        }
        Arc::new(EmptyProgram)
    }

    fn get_source(&self) -> crate::program::model::symbol::SourceType {
        crate::program::model::symbol::SourceType::Analysis
    }

    fn set_name(
        &mut self,
        _name: &str,
        _source: crate::program::model::symbol::SourceType,
    ) -> Result<(), crate::program::model::listing::variable::SetVariableNameError> {
        Err(crate::util::exception::InvalidInputException::with_message("this parameter is not mutable").into())
    }

    fn get_comment(&self) -> Option<String> {
        None
    }

    fn set_comment(&mut self, _comment: Option<String>) {}

    fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
        Some(self.storage.with_varnodes(self.storage.get_varnodes()))
    }

    fn get_first_storage_varnode(&self) -> Option<Varnode> {
        self.storage.get_first_varnode()
    }

    fn get_last_storage_varnode(&self) -> Option<Varnode> {
        self.storage.get_varnodes().last().cloned()
    }

    fn is_stack_variable(&self) -> bool {
        false
    }

    fn has_stack_storage(&self) -> bool {
        false
    }

    fn is_register_variable(&self) -> bool {
        self.storage.is_register_storage()
    }

    fn get_register(&self) -> Option<RegisterRef> {
        self.storage.get_register()
    }

    fn get_registers(&self) -> Option<Vec<RegisterRef>> {
        self.storage.get_register().map(|r| vec![r])
    }

    fn get_min_address(&self) -> Option<Address> {
        self.storage.get_first_varnode().map(|vn| vn.get_address().clone())
    }

    fn get_stack_offset(
        &self,
    ) -> Result<i32, crate::program::model::listing::variable::UnsupportedOperationError> {
        Err(crate::program::model::listing::variable::UnsupportedOperationError(
            "not a simple stack variable".to_string(),
        ))
    }

    fn is_memory_variable(&self) -> bool {
        self.storage.is_memory_storage()
    }

    fn is_unique_variable(&self) -> bool {
        self.storage.is_unique_storage()
    }

    fn is_compound_variable(&self) -> bool {
        self.storage.get_varnodes().len() > 1
    }

    fn has_assigned_storage(&self) -> bool {
        true
    }

    fn get_first_use_offset(&self) -> i32 {
        0
    }

    fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
        None
    }

    fn is_equivalent(&self, variable: &dyn Variable) -> bool {
        self.get_name() == variable.get_name() && self.get_length() == variable.get_length()
    }

    fn compare_to(&self, other: &dyn Variable) -> Ordering {
        self.get_name().cmp(&other.get_name())
    }

    fn is_parameter(&self) -> bool {
        true
    }

    fn parameter_ordinal(&self) -> Option<i32> {
        Some(0)
    }
}

impl Parameter for PlaceholderThisParameter {
    fn get_ordinal(&self) -> i32 {
        0
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
        Variable::get_data_type(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::listing::Program;
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::program::seam_stubs::VarnodeListStorage;

    struct Impl;
    impl VariableUtilities for Impl {}

    struct MockDataType(i32);
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.0
        }

        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.0 == dt.get_length()
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

    fn mock_space() -> Arc<crate::program::model::address::AddressSpace> {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    struct MockVariable {
        name: Option<String>,
        storage: Option<Box<dyn VariableStorage>>,
        is_memory: bool,
        is_register: bool,
        is_stack: bool,
        is_unique: bool,
        is_compound: bool,
        is_param: bool,
        first_use: i32,
    }

    impl Default for MockVariable {
        fn default() -> Self {
            MockVariable {
                name: None,
                storage: None,
                is_memory: false,
                is_register: false,
                is_stack: false,
                is_unique: false,
                is_compound: false,
                is_param: false,
                first_use: 0,
            }
        }
    }

    impl Variable for MockVariable {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType(4))
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
            Arc::new(MockProgram)
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
            self.storage.as_ref().map(|s| s.with_varnodes(s.get_varnodes()))
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            None
        }
        fn is_stack_variable(&self) -> bool {
            self.is_stack
        }
        fn has_stack_storage(&self) -> bool {
            self.is_stack
        }
        fn is_register_variable(&self) -> bool {
            self.is_register
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
            if self.is_stack {
                Ok(self
                    .storage
                    .as_ref()
                    .and_then(|s| s.get_first_varnode())
                    .map(|vn| vn.get_address().offset() as i32)
                    .unwrap_or(0))
            } else {
                Err(UnsupportedOperationError("not a simple stack variable".to_string()))
            }
        }
        fn is_memory_variable(&self) -> bool {
            self.is_memory
        }
        fn is_unique_variable(&self) -> bool {
            self.is_unique
        }
        fn is_compound_variable(&self) -> bool {
            self.is_compound
        }
        fn has_assigned_storage(&self) -> bool {
            self.storage.is_some()
        }
        fn get_first_use_offset(&self) -> i32 {
            self.first_use
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name()
        }
        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.get_name().cmp(&other.get_name())
        }
        fn is_parameter(&self) -> bool {
            self.is_param
        }
    }

    #[test]
    fn get_precedence_ranks_memory_above_stack_above_register() {
        // Matches Java's MEMORY_PRECEDENCE(15) > STACK_PRECEDENCE(14) > REGISTER_PRECEDENCE(13).
        let util = Impl;
        let memory = MockVariable {
            is_memory: true,
            ..Default::default()
        };
        let register = MockVariable {
            is_register: true,
            ..Default::default()
        };
        let stack = MockVariable {
            is_stack: true,
            ..Default::default()
        };
        assert!(util.get_precedence(&memory) > util.get_precedence(&stack));
        assert!(util.get_precedence(&stack) > util.get_precedence(&register));
    }

    #[test]
    fn get_precedence_reduces_for_parameters() {
        let util = Impl;
        let local = MockVariable {
            is_memory: true,
            ..Default::default()
        };
        let param = MockVariable {
            is_memory: true,
            is_param: true,
            ..Default::default()
        };
        assert_eq!(util.get_precedence(&local) - util.get_precedence(&param), 10);
    }

    #[test]
    fn storage_matches_compares_varnode_sequences() {
        let util = Impl;
        let space = mock_space();
        let a = MockVariable {
            storage: Some(Box::new(VarnodeListStorage(vec![Varnode::new(
                Address::new(space.clone(), 0x100),
                4,
            )]))),
            ..Default::default()
        };
        let b = MockVariable {
            storage: Some(Box::new(VarnodeListStorage(vec![Varnode::new(
                Address::new(space.clone(), 0x100),
                4,
            )]))),
            ..Default::default()
        };
        let c = MockVariable {
            storage: Some(Box::new(VarnodeListStorage(vec![Varnode::new(
                Address::new(space, 0x200),
                4,
            )]))),
            ..Default::default()
        };
        let a_ref: &dyn Variable = &a;
        let b_ref: &dyn Variable = &b;
        let c_ref: &dyn Variable = &c;
        assert!(util.storage_matches(&[a_ref], &[b_ref]));
        assert!(!util.storage_matches(&[a_ref], &[c_ref]));
    }

    #[test]
    fn compare_orders_stack_before_memory() {
        // Higher precedence sorts later: STACK_PRECEDENCE(14) < MEMORY_PRECEDENCE(15).
        let util = Impl;
        let memory = MockVariable {
            is_memory: true,
            ..Default::default()
        };
        let stack = MockVariable {
            is_stack: true,
            ..Default::default()
        };
        assert_eq!(util.compare(&stack, &memory), Ordering::Less);
        assert_eq!(util.compare(&memory, &stack), Ordering::Greater);
    }

    #[test]
    fn compare_gives_precedence_to_zero_first_use_offset() {
        let util = Impl;
        let early = MockVariable {
            is_memory: true,
            first_use: 0,
            ..Default::default()
        };
        let late = MockVariable {
            is_memory: true,
            first_use: 4,
            ..Default::default()
        };
        assert_eq!(util.compare(&early, &late), Ordering::Less);
    }

    #[test]
    fn check_storage_passes_through_invalid_storage() {
        let util = Impl;
        let storage: Box<dyn VariableStorage> = Box::new(crate::program::seam_stubs::PlaceholderVariableStorage);
        let dt = MockDataType(4);
        assert!(util.check_storage(storage, &dt, false).is_ok());
    }

    #[test]
    fn check_storage_allows_matching_size() {
        let util = Impl;
        let space = mock_space();
        let storage: Box<dyn VariableStorage> =
            Box::new(VarnodeListStorage(vec![Varnode::new(Address::new(space, 0x8), 4)]));
        let dt = MockDataType(4);
        assert!(util.check_storage(storage, &dt, false).is_ok());
    }

    #[test]
    fn check_storage_rejects_size_mismatch_without_function() {
        let util = Impl;
        let space = mock_space();
        let storage: Box<dyn VariableStorage> =
            Box::new(VarnodeListStorage(vec![Varnode::new(Address::new(space, 0x8), 4)]));
        let dt = MockDataType(8);
        assert!(util.check_storage(storage, &dt, false).is_err());
    }

    #[test]
    fn check_storage_allows_size_mismatch_when_flagged() {
        let util = Impl;
        let space = mock_space();
        let storage: Box<dyn VariableStorage> =
            Box::new(VarnodeListStorage(vec![Varnode::new(Address::new(space, 0x8), 4)]));
        let dt = MockDataType(8);
        assert!(util.check_storage(storage, &dt, true).is_ok());
    }

    #[test]
    fn check_data_type_rejects_bit_field() {
        struct BitField;
        impl DataType for BitField {
            fn is_bit_field_type(&self) -> bool {
                true
            }
        }
        let util = Impl;
        let err = match util.check_data_type(Some(Box::new(BitField)), false, -1, None) {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        };
        assert!(err.0.contains("Bitfield"));
    }

    #[test]
    fn check_data_type_rejects_void_when_not_allowed() {
        let util = Impl;
        let err = match util.check_data_type(Some(Box::new(FallbackVoidDataType)), false, -1, None) {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        };
        assert!(err.0.contains("void"));
    }

    #[test]
    fn check_data_type_allows_void_when_permitted() {
        let util = Impl;
        let dt = util
            .check_data_type(Some(Box::new(FallbackVoidDataType)), true, -1, None)
            .unwrap();
        assert!(dt.is_void_type());
    }

    #[test]
    fn check_data_type_passes_through_ordinary_type() {
        let util = Impl;
        let dt = util
            .check_data_type(Some(Box::new(MockDataType(4))), false, -1, None)
            .unwrap();
        assert_eq!(dt.get_length(), 4);
    }

    #[test]
    fn equivalent_variables_compares_name_type_and_comment() {
        let util = Impl;
        let a = MockVariable {
            name: Some("local_1".to_string()),
            ..Default::default()
        };
        let b = MockVariable {
            name: Some("local_1".to_string()),
            ..Default::default()
        };
        let c = MockVariable {
            name: Some("local_2".to_string()),
            ..Default::default()
        };
        assert!(util.equivalent_variables(&a, &b));
        assert!(!util.equivalent_variables(&a, &c));
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let util: Box<dyn VariableUtilities> = Box::new(Impl);
        let a = MockVariable {
            is_memory: true,
            ..Default::default()
        };
        let b = MockVariable {
            is_stack: true,
            ..Default::default()
        };
        assert!(util.get_precedence(&a) > util.get_precedence(&b));
    }
}

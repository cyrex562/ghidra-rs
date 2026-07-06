use std::sync::Arc;

use thiserror::Error;

use crate::program::database::function::OverlappingFunctionException;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::{FunctionTag, Parameter, Program, Variable};
use crate::program::model::symbol::SourceType;
use crate::program::seam_stubs::{
    ExternalLocation, FunctionSignature, Namespace, NamespaceType, PrototypeModel, StackFrame,
    VariableFilter, VariableStorage,
};
use crate::util::exception::{DuplicateNameException, InvalidInputException};
use crate::util::task::TaskMonitor;

/// The default prefix for an unnamed parameter.
pub const DEFAULT_PARAM_PREFIX: &str = "param_";
/// Reserved parameter name assigned to the "this" pointer of a class method.
pub const THIS_PARAM_NAME: &str = "this";
/// Reserved parameter name assigned to an injected return-storage pointer parameter.
pub const RETURN_PTR_PARAM_NAME: &str = "__return_storage_ptr__";
/// Length of [`DEFAULT_PARAM_PREFIX`].
pub const DEFAULT_PARAM_PREFIX_LEN: i32 = DEFAULT_PARAM_PREFIX.len() as i32;
/// The default prefix for an unnamed local variable.
pub const DEFAULT_LOCAL_PREFIX: &str = "local_";
/// The default prefix for an unnamed local variable which reuses another variable's storage.
pub const DEFAULT_LOCAL_RESERVED_PREFIX: &str = "local_res";
/// The default prefix for an unnamed compiler-generated temporary variable.
pub const DEFAULT_LOCAL_TEMP_PREFIX: &str = "temp_";
/// Length of [`DEFAULT_LOCAL_PREFIX`].
pub const DEFAULT_LOCAL_PREFIX_LEN: i32 = DEFAULT_LOCAL_PREFIX.len() as i32;
/// Stands in for `CompilerSpec.CALLING_CONVENTION_unknown`.
pub const UNKNOWN_CALLING_CONVENTION_STRING: &str = "unknown";
/// Stands in for `CompilerSpec.CALLING_CONVENTION_default`.
pub const DEFAULT_CALLING_CONVENTION_STRING: &str = "default";
/// Function tag name used to mark a function as inline.
pub const INLINE: &str = "inline";
/// Function tag name used to mark a function as non-returning.
pub const NORETURN: &str = "noreturn";
/// Function tag name used to mark a function as a thunk.
pub const THUNK: &str = "thunk";
/// Default Stack depth for a function.
pub const UNKNOWN_STACK_DEPTH_CHANGE: i32 = i32::MAX;
/// Stack depth value indicating an invalid/unresolvable stack depth change.
pub const INVALID_STACK_DEPTH_CHANGE: i32 = i32::MAX - 1;

/// Governs how [`Function::replace_parameters`] and [`Function::update_function`] interpret the
/// supplied parameter list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionUpdateType {
    /// All parameters and return have been specified with their storage.
    CustomStorage,
    /// The formal signature parameters and return have been specified without storage. Storage
    /// will be computed. Any use of the reserved names 'this' and '__return_storage_ptr__' will
    /// be stripped before considering the injection of these parameters.
    DynamicStorageFormalParams,
    /// All parameters and return have been specified without storage. Storage will be computed.
    /// Any use of the reserved names 'this' and '__return_storage_ptr__' will be stripped before
    /// considering the injection of these parameters. In addition, if the calling convention is
    /// '__thiscall' if the 'this' parameter was not identified by name, the first parameter will
    /// be assumed the 'this' parameter if its name is a default name and it has the size of a
    /// pointer.
    DynamicStorageAllParams,
}

/// Error produced when [`Function::set_name`] fails.
///
/// Combines the two checked exceptions declared on the Java method
/// `Function.setName(String, SourceType)`.
#[derive(Error, Debug, PartialEq)]
pub enum SetFunctionNameError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// Error produced when adding, inserting, or replacing a function's parameters or local
/// variables fails.
///
/// Combines the two checked exceptions declared on the corresponding Java methods
/// (`addParameter`, `insertParameter`, `replaceParameters`, `updateFunction`,
/// `addLocalVariable`).
#[derive(Error, Debug, PartialEq)]
pub enum FunctionEditError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// Interface to define methods available on a function. Functions have a single entry point.
///
/// Port of `ghidra.program.model.listing.Function`.
pub trait Function: Namespace {
    /// The type of namespace this represents. Overrides the
    /// [`Namespace`](crate::program::seam_stubs::Namespace) default.
    fn get_type(&self) -> NamespaceType {
        NamespaceType::Function
    }

    /// Get the name of this function.
    fn get_name(&self) -> String;

    /// Set the name of this function.
    ///
    /// # Errors
    /// Returns `Err` if the name is used by some other symbol, or is not a valid function name.
    fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetFunctionNameError>;

    /// Set the named call-fixup for this function. `None` clears the current setting.
    fn set_call_fixup(&mut self, name: Option<&str>);

    /// Returns the current call-fixup name set on this instruction, or `None` if one has not
    /// been set.
    fn get_call_fixup(&self) -> Option<String>;

    /// Get the program containing this function.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Get the comment for this function.
    fn get_comment(&self) -> Option<String>;

    /// Returns the function (same as plate) comment as an array of strings where each item in
    /// the array is a line of text in the comment.
    fn get_comment_as_array(&self) -> Vec<String>;

    /// Set the comment for this function.
    fn set_comment(&mut self, comment: Option<&str>);

    /// Returns the repeatable comment for this function. A repeatable comment is a comment that
    /// will appear at locations that 'call' this function.
    fn get_repeatable_comment(&self) -> Option<String>;

    /// Returns the repeatable comment as an array of strings.
    fn get_repeatable_comment_as_array(&self) -> Vec<String>;

    /// Set the repeatable comment for this function.
    fn set_repeatable_comment(&mut self, comment: Option<&str>);

    /// Get the entry point for this function. Functions may only have ONE entry point.
    fn get_entry_point(&self) -> Address;

    /// Get the Function's return type. `None` indicates the function's return type has never
    /// been set.
    fn get_return_type(&self) -> Option<Box<dyn DataType>>;

    /// Set the function's return type.
    ///
    /// # Errors
    /// Returns `Err` if the data type is not a fixed length.
    fn set_return_type(
        &mut self,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<(), InvalidInputException>;

    /// Get the Function's return type/storage represented by a Parameter object. The parameter's
    /// ordinal value will be equal to `parameter::RETURN_ORDINAL`.
    fn get_return(&self) -> Box<dyn Parameter>;

    /// Set the return data-type and storage.
    ///
    /// NOTE: The storage and source are ignored if the function does not have custom storage
    /// enabled.
    ///
    /// # Errors
    /// Returns `Err` if the data type is not a fixed length or storage is improperly sized.
    fn set_return(
        &mut self,
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        source: SourceType,
    ) -> Result<(), InvalidInputException>;

    /// Get the function's effective signature. Equivalent to invoking
    /// `get_signature_formal(false)` where auto-params and forced-indirect types will be
    /// reflected in the signature if present.
    fn get_signature(&self) -> Box<dyn FunctionSignature> {
        self.get_signature_formal(false)
    }

    /// Get the function's signature.
    ///
    /// `formal_signature`, if true, keeps only original raw types and discards auto-params (e.g.
    /// this, `__return_storage_ptr__`, etc.) within the returned signature. If false, the
    /// effective signature is returned where forced indirect and auto-params are reflected in
    /// the signature. This option has no effect if the function has custom storage enabled.
    fn get_signature_formal(&self, formal_signature: bool) -> Box<dyn FunctionSignature>;

    /// Return a string representation of the function signature.
    ///
    /// `formal_signature` has the same meaning as in [`Function::get_signature_formal`].
    /// `include_calling_convention`, if true, includes the call convention declaration if known.
    fn get_prototype_string(&self, formal_signature: bool, include_calling_convention: bool)
        -> String;

    /// Returns the source type for the overall signature excluding function name and parameter
    /// names whose source is carried by the corresponding symbol.
    fn get_signature_source(&self) -> SourceType;

    /// Set the source type for the overall signature excluding function name and parameter names
    /// whose source is carried by the corresponding symbol.
    fn set_signature_source(&mut self, signature_source: SourceType);

    /// Get the stack frame for this function.
    ///
    /// NOTE: Use of the stack frame must be avoided during upgrade activity since the compiler
    /// spec may not be known (i.e., due to language upgrade process).
    fn get_stack_frame(&self) -> Box<dyn StackFrame>;

    /// Get the change in the stack pointer resulting from calling this function.
    fn get_stack_purge_size(&self) -> i32;

    /// Return all `FunctionTag` objects associated with this function.
    fn get_tags(&self) -> Vec<Box<dyn FunctionTag>>;

    /// Adds the tag with the given name to this function; if one does not exist, one is
    /// created. Returns true if the tag was successfully added.
    fn add_tag(&mut self, name: &str) -> bool;

    /// Removes the given tag from this function.
    fn remove_tag(&mut self, name: &str);

    /// Set the change in the stack pointer resulting from calling this function.
    fn set_stack_purge_size(&mut self, purge_size: i32);

    /// Check if stack purge size is valid.
    fn is_stack_purge_size_valid(&self) -> bool;

    /// Adds the given variable to the end of the parameters list. The variable storage
    /// specified for the new parameter will be ignored if custom storage mode is not enabled.
    ///
    /// # Errors
    /// Returns `Err` if another variable already exists in the function with that name, or the
    /// data type is not a fixed length or the variable name is invalid.
    #[deprecated(
        note = "discouraged due to the potential injection of auto-parameters; prefer update_function"
    )]
    fn add_parameter(
        &mut self,
        var: Box<dyn Variable>,
        source: SourceType,
    ) -> Result<Box<dyn Parameter>, FunctionEditError>;

    /// Inserts the given variable into the parameters list at `ordinal`. The variable storage
    /// specified for the new parameter will be ignored if custom storage mode is not enabled.
    ///
    /// # Errors
    /// Returns `Err` if another variable already exists in the function with that name, or the
    /// data type is not a fixed length or the variable name is invalid.
    #[deprecated(
        note = "discouraged due to the potential injection of auto-parameters; prefer update_function"
    )]
    fn insert_parameter(
        &mut self,
        ordinal: i32,
        var: Box<dyn Variable>,
        source: SourceType,
    ) -> Result<Box<dyn Parameter>, FunctionEditError>;

    /// Replace all current parameters with the given list of parameters.
    ///
    /// Corresponds to both the `List`- and vararg-based `replaceParameters` overloads in Java,
    /// which are functionally identical.
    ///
    /// # Errors
    /// Returns `Err` if another variable already exists in the function with that name, or a
    /// parameter data type is not a fixed length or variable name is invalid.
    fn replace_parameters(
        &mut self,
        params: Vec<Box<dyn Variable>>,
        update_type: FunctionUpdateType,
        force: bool,
        source: SourceType,
    ) -> Result<(), FunctionEditError>;

    /// Replace all current parameters with the given list of parameters and optionally change
    /// the calling convention and function return.
    ///
    /// Corresponds to both the `List`- and vararg-based `updateFunction` overloads in Java,
    /// which are functionally identical. `calling_convention` is the updated calling convention
    /// name, or `None` if no change is required. `return_value` is the return variable, or
    /// `None` if no change is required.
    ///
    /// # Errors
    /// Returns `Err` if another variable already exists in the function with that name, or a
    /// parameter data type is not a fixed length or variable name is invalid.
    fn update_function(
        &mut self,
        calling_convention: Option<&str>,
        return_value: Option<Box<dyn Variable>>,
        new_params: Vec<Box<dyn Variable>>,
        update_type: FunctionUpdateType,
        force: bool,
        source: SourceType,
    ) -> Result<(), FunctionEditError>;

    /// Returns the specified parameter including an auto-param at the specified ordinal, or
    /// `None` if ordinal is out of range.
    fn get_parameter(&self, ordinal: i32) -> Option<Box<dyn Parameter>>;

    /// Remove the specified parameter. Auto-parameters may not be removed but must be accounted
    /// for in the specified ordinal.
    #[deprecated(note = "discouraged; prefer update_function")]
    fn remove_parameter(&mut self, ordinal: i32);

    /// Move the parameter which occupies the `from_ordinal` position to the `to_ordinal`
    /// position. Parameters will be renumbered to reflect the new ordering. Auto-parameters may
    /// not be moved but must be accounted for in the specified ordinals.
    ///
    /// # Errors
    /// Returns `Err` if either ordinal is invalid.
    #[deprecated(note = "discouraged; prefer update_function")]
    fn move_parameter(
        &mut self,
        from_ordinal: i32,
        to_ordinal: i32,
    ) -> Result<Box<dyn Parameter>, InvalidInputException>;

    /// Gets the total number of parameters for this function. This number also includes any
    /// auto-parameters which may have been injected when dynamic parameter storage is used.
    fn get_parameter_count(&self) -> i32;

    /// Gets the number of auto-parameters for this function, also included in the total count
    /// provided by [`Function::get_parameter_count`]. This number will always be 0 when custom
    /// parameter storage is used.
    fn get_auto_parameter_count(&self) -> i32;

    /// Get all function parameters.
    fn get_parameters(&self) -> Vec<Box<dyn Parameter>>;

    /// Get all function parameters which satisfy the specified filter, or all parameters if
    /// `filter` is `None`.
    fn get_parameters_filtered(&self, filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>>;

    /// Get all local function variables.
    fn get_local_variables(&self) -> Vec<Box<dyn Variable>>;

    /// Get all local function variables which satisfy the specified filter, or all local
    /// variables if `filter` is `None`.
    fn get_local_variables_filtered(&self, filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>>;

    /// Get all function variables which satisfy the specified filter, or all variables if
    /// `filter` is `None`.
    fn get_variables_filtered(&self, filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>>;

    /// Returns all local and parameter variables.
    fn get_all_variables(&self) -> Vec<Box<dyn Variable>>;

    /// Adds a local variable to the function.
    ///
    /// # Errors
    /// Returns `Err` if another local variable or parameter already has that name, or there is
    /// an error or conflict when resolving the variable.
    fn add_local_variable(
        &mut self,
        var: Box<dyn Variable>,
        source: SourceType,
    ) -> Result<Box<dyn Variable>, FunctionEditError>;

    /// Removes the given variable from the function.
    fn remove_variable(&mut self, var: &dyn Variable);

    /// Set the new body for this function. The entry point must be contained in the new body.
    ///
    /// # Errors
    /// Returns `Err` if the address set overlaps that of another function.
    fn set_body(&mut self, new_body: &dyn AddressSetView) -> Result<(), OverlappingFunctionException>;

    /// Returns true if this function has a variable argument list (VarArgs).
    fn has_var_args(&self) -> bool;

    /// Set whether parameters can be passed as a VarArg (variable argument list), e.g.
    /// `printf(fmt, ...)`.
    fn set_var_args(&mut self, has_var_args: bool);

    /// Returns true if this is an inline function.
    fn is_inline(&self) -> bool;

    /// Sets whether or not this function is inline.
    fn set_inline(&mut self, is_inline: bool);

    /// Returns true if this function does not return.
    fn has_no_return(&self) -> bool;

    /// Set whether or not this function has a return.
    fn set_no_return(&mut self, has_no_return: bool);

    /// Returns true if function parameters utilize custom variable storage.
    fn has_custom_variable_storage(&self) -> bool;

    /// Set whether or not this function uses custom variable storage.
    fn set_custom_variable_storage(&mut self, has_custom_variable_storage: bool);

    /// Gets the calling convention prototype model for this function, or `None`.
    fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>>;

    /// Determine if this signature has an unknown or unrecognized calling convention name.
    fn has_unknown_calling_convention_name(&self) -> bool {
        self.get_calling_convention().is_none()
    }

    /// Gets the calling convention's name for this function: either
    /// [`DEFAULT_CALLING_CONVENTION_STRING`] if the calling convention has been set to the
    /// default for this function, or [`UNKNOWN_CALLING_CONVENTION_STRING`] if no calling
    /// convention is specified for this function.
    fn get_calling_convention_name(&self) -> String;

    /// Sets the calling convention for this function to the named calling convention. Only known
    /// calling convention names may be specified, which will always include those defined by the
    /// associated compiler spec, plus the reserved names [`UNKNOWN_CALLING_CONVENTION_STRING`]
    /// and [`DEFAULT_CALLING_CONVENTION_STRING`].
    ///
    /// # Errors
    /// Returns `Err` if the specified name is not a recognized calling convention name.
    fn set_calling_convention(&mut self, name: &str) -> Result<(), InvalidInputException>;

    /// Returns true if this function is a Thunk and has a referenced Thunked Function.
    fn is_thunk(&self) -> bool;

    /// If this function is a Thunk, this method returns the referenced function. If `recursive`
    /// is true and the thunked-function is a thunk itself, the returned thunked-function will be
    /// the final thunked-function which will never be a thunk. Returns `None` if this is not a
    /// Thunk function.
    fn get_thunked_function(&self, recursive: bool) -> Option<Arc<dyn Function>>;

    /// If this function is "Thunked", an array of Thunk Function entry points is returned. A
    /// non-recursive search is performed (i.e., first-hop only). Returns `None` if this is not a
    /// "Thunked" function.
    #[deprecated(note = "prefer get_function_thunk_addresses(recursive)")]
    fn get_function_thunk_addresses_first_hop(&self) -> Option<Vec<Address>> {
        self.get_function_thunk_addresses(false)
    }

    /// If this function is "Thunked", an array of Thunk Function entry points is returned. If
    /// `recursive` is true a recursive search is performed returning all effective thunks of
    /// this function, else only the first-hop (i.e., direct thunks) are returned. Returns `None`
    /// if this is not a "Thunked" function.
    fn get_function_thunk_addresses(&self, recursive: bool) -> Option<Vec<Address>>;

    /// Set the currently Thunked Function, or `None` to convert to a normal function.
    ///
    /// # Errors
    /// Returns `Err` if an attempt is made to thunk a function or another thunk which would
    /// result in a loop back to this function, if this function is an external function, or the
    /// specified function is from a different program instance (stands in for
    /// `IllegalArgumentException`/`UnsupportedOperationException`).
    fn set_thunked_function(&mut self, thunked_function: Option<Arc<dyn Function>>) -> Result<(), String>;

    /// Returns true if this function is external (i.e., entry point is in EXTERNAL address
    /// space).
    fn is_external(&self) -> bool;

    /// If this is an external function, returns the associated external location object.
    fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>>;

    /// Returns the set of functions that call this function.
    fn get_calling_functions(&self, monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>>;

    /// Returns the set of functions that this function calls.
    fn get_called_functions(&self, monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>>;

    /// Changes all local user-defined labels for this function to global symbols. If a global
    /// code symbol already exists with the same name at the symbol's address, the symbol will be
    /// removed.
    fn promote_local_user_labels_to_global(&mut self);

    /// Determine if this function object has been deleted. NOTE: the function could be deleted
    /// at any time due to asynchronous activity.
    fn is_deleted(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::symbol::Symbol;

    struct MockFunction {
        name: String,
        deleted: bool,
    }

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
            self.name.clone()
        }

        fn set_name(&mut self, name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            self.name = name.to_string();
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn Program> {
            struct MockProgram;
            impl Program for MockProgram {
                fn get_name(&self) -> &str {
                    "mock"
                }
                fn get_language_id(&self) -> &str {
                    "mock:LE:32:default"
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
            mock_address(0x100)
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
            struct MockSignature;
            impl FunctionSignature for MockSignature {}
            Box::new(MockSignature)
        }

        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            format!("void {}(void)", self.name)
        }

        fn get_signature_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_signature_source(&mut self, _signature_source: SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            struct MockStackFrame;
            impl StackFrame for MockStackFrame {}
            Box::new(MockStackFrame)
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
            self.deleted
        }
    }

    fn mock_address(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn get_type_defaults_to_function() {
        let f = MockFunction {
            name: "main".to_string(),
            deleted: false,
        };
        assert_eq!(Function::get_type(&f), NamespaceType::Function);
    }

    #[test]
    fn set_name_updates_name() {
        let mut f = MockFunction {
            name: "FUN_00000100".to_string(),
            deleted: false,
        };
        f.set_name("main", SourceType::UserDefined).unwrap();
        assert_eq!(Function::get_name(&f), "main");
    }

    #[test]
    fn has_unknown_calling_convention_name_defaults_true_without_model() {
        let f = MockFunction {
            name: "main".to_string(),
            deleted: false,
        };
        assert!(f.has_unknown_calling_convention_name());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let f: Box<dyn Function> = Box::new(MockFunction {
            name: "main".to_string(),
            deleted: false,
        });
        assert_eq!(f.get_entry_point(), mock_address(0x100));
        assert!(!f.is_deleted());
        assert_eq!(f.get_stack_purge_size(), 0);
    }
}

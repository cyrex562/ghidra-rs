//! Port of `ghidra.program.model.data.FunctionDefinitionDataType`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends GenericDataType implements FunctionDefinition`. `GenericDataType`
//! (itself extending the unported `DataTypeImpl`) contributes no interface beyond
//! [`DataType`] -- it only adds protected field storage (`name`, `categoryPath`) and a
//! `checkValidName`/`doSetName`/`doSetCategoryPath` helper family that this class never
//! overrides -- so, mirroring
//! [`CompositeDataTypeImpl`](crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl)'s
//! identical treatment of `GenericDataType`, this trait extends
//! [`FunctionDefinition`](crate::program::model::data::function_definition::FunctionDefinition)
//! directly (which already pulls in
//! [`FunctionSignature`](crate::program::model::listing::FunctionSignature) and [`DataType`]).
//!
//! Several Java methods here share a name with an already-provided default method on
//! [`DataType`] (`getMnemonic`, `getLength`, `getDescription`, `getRepresentation`,
//! `dataTypeReplaced`, `dataTypeDeleted`, `isEquivalent`) or are declared `abstract` (no default)
//! on [`FunctionSignature`]/[`FunctionDefinition`] (`getPrototypeString(boolean)`,
//! `getArguments`, `getReturnType`, `getComment`, `hasVarArgs`, `hasNoReturn`,
//! `getCallingConvention`, `getCallingConventionName`, `isEquivalentSignature`, `setArguments`,
//! `setReturnType`, `setComment`, `setVarArgs`, `setNoReturn`, `setGenericCallingConvention`,
//! `setCallingConvention`, `replaceArgument`). Rust does not allow a subtrait to provide a default
//! body for a method its supertrait already declares (whether that declaration has a default or
//! is abstract -- the call becomes ambiguous at every call site), so -- mirroring
//! [`ParameterDefinitionImpl`](crate::program::model::data::parameter_definition_impl::ParameterDefinitionImpl)'s
//! `parameter_definition_impl_*` convention -- those bodies are exposed here under distinct
//! `function_definition_data_type_impl_*` names. A concrete `impl FunctionDefinition`/`impl
//! DataType for ...` should delegate to these.
//!
//! Three Java methods override a supertrait default with *identical* behavior to the Rust default
//! already in place, so they are intentionally not re-declared here (matching the precedent set
//! by [`CompositeDataTypeImpl`]'s module documentation):
//!   - `getValue(MemBuffer, Settings, int)` always returns `null`, exactly
//!     [`DataType::get_value`]'s existing default (`None`).
//!   - `getPrototypeString()` (no-arg) just calls `getPrototypeString(false)`, exactly
//!     [`FunctionSignature::get_prototype_string`]'s existing default.
//!   - `dataTypeSizeChanged(DataType)` and `dataTypeNameChanged(DataType, String)` are both
//!     no-ops ("ignore -- no affect"), exactly [`DataType::data_type_size_changed`]'s and
//!     [`DataType::data_type_name_changed`]'s existing defaults.
//!
//! The private fields `returnType`, `params`, `comment`, `hasVarArgs`, `hasNoReturn`, and
//! `callingConventionName` have no home on a trait, so they are exposed via required accessor
//! methods ([`FunctionDefinitionDataType::stored_return_type`]/
//! [`FunctionDefinitionDataType::set_stored_return_type`], etc.) that implementors are expected to
//! back with real storage, mirroring [`ParameterDefinitionImpl`]'s accessor convention. The Java
//! constructors (which validate/copy an optional source `FunctionSignature` into those fields) are
//! not modeled as trait content, exactly as `GenericDataType`'s own constructor logic is left
//! unmodeled by [`CompositeDataTypeImpl`] -- a concrete implementor's own constructor is expected
//! to populate the backing fields directly.
//!
//! `toString()` delegates to `getPrototypeString(true)`; exposed here as
//! [`FunctionDefinitionDataType::function_definition_data_type_impl_to_string`] rather than a
//! `Display` impl, mirroring
//! [`ParameterDefinitionImpl::parameter_definition_impl_to_string`].
//!
//! `copy(DataTypeManager)`/`clone(DataTypeManager)` construct `new FunctionDefinitionDataType(...)`
//! directly, which requires calling a concrete constructor this trait has no way to name
//! generically (there is no `Self: Default`/factory bound); they are left unmodeled, same as
//! [`DataType::clone_data_type`]/[`DataType::copy_data_type`]'s own generic (placeholder-returning)
//! defaults, which a concrete implementor overrides directly instead.
//!
//! `isEquivalent(DataType)` needs an `instanceof FunctionDefinition` downcast from a bare `&dyn
//! DataType` to recover the other side's [`FunctionSignature`] accessors, which
//! [`DataType::is_function_definition_type`]'s own documentation notes is not yet available (no
//! `&dyn DataType` -> `&dyn FunctionDefinition` downcast exists in this crate yet); it is left
//! unmodeled, same as [`DataType::is_equivalent`]'s existing (`false`) default. The related
//! `isEquivalentSignature(FunctionSignature)` operates on an already-fully-accessorized
//! [`FunctionSignature`] trait object (no downcast needed) and so *is* modeled, as
//! [`FunctionDefinitionDataType::function_definition_data_type_impl_is_equivalent_signature`].
//!
//! `dataTypeReplaced`/`dataTypeDeleted` delegate to `DataTypeUtilities.checkValidReplacement` and
//! compare datatypes by Java reference identity (`==`). Neither `DataTypeUtilities` (a large,
//! unrelated static-utility class) nor a `DataTypeDB` marker it special-cases is ported yet, so
//! [`check_valid_replacement`] reimplements the two checks it delegates to directly off
//! already-ported [`DataType`] accessors (skipping the `instanceof DataTypeDB` early return --
//! every datatype is validated), and reference identity is approximated with
//! [`DataType::get_data_type_path`] equality, mirroring
//! [`CompositeDataTypeImpl::composite_impl_is_part_of`]'s identical approximation. Producing an
//! independent replacement copy for the return type and each matching parameter (Java shares one
//! `newDt` object reference across every assignment) requires [`DataType::clone_data_type`], which
//! needs a live `DataTypeManager`; when this function definition has none (`get_data_type_manager`
//! returns `None`), [`FunctionDefinitionDataType::function_definition_data_type_impl_data_type_replaced`]
//! performs no replacement, since there is no other way in the currently-ported [`DataType`]
//! surface to duplicate an owned `Box<dyn DataType>` from a borrowed `&dyn DataType`.
//!
//! `setArguments`/`replaceArgument` construct new `ParameterDefinitionImpl` instances directly
//! (`new ParameterDefinitionImpl(name, dataType, comment, ordinal)`), which -- like `copy`/`clone`
//! above -- names a concrete constructor generically unavailable here. Rather than leaving these
//! required methods unmodeled, [`BasicParameterDefinition`] (a private, directly-constructible
//! struct backed by real fields and implementing [`ParameterDefinition`] via
//! [`ParameterDefinitionImpl`]'s already-ported default bodies, mirroring
//! [`CompositeDataTypeImpl::composite_impl_create_component`]'s identical `BasicDataTypeComponent`
//! solution for the same "need a fresh concrete instance, have no factory" problem) stands in for
//! it; unlike the real constructor, it does not run the new parameter's data type through
//! `ParameterDefinitionImpl.validateDataType`.

use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::function_definition::FunctionDefinition;
use crate::program::model::data::generic_calling_convention::GenericCallingConvention;
use crate::program::model::data::parameter_definition::ParameterDefinition;
use crate::program::model::data::parameter_definition_impl::{
    is_same_or_equivalent_data_type, validate_data_type, ParameterDefinitionImpl,
};
use crate::program::model::lang::compiler_spec::{
    is_unknown_calling_convention, CALLING_CONVENTION_DEFAULT, CALLING_CONVENTION_UNKNOWN,
};
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::listing::function::{DEFAULT_PARAM_PREFIX, UNKNOWN_CALLING_CONVENTION_STRING};
use crate::program::model::listing::function_signature::{
    FunctionSignature, NORETURN_DISPLAY_STRING, VAR_ARGS_DISPLAY_STRING, VOID_PARAM_DISPLAY_STRING,
};
use crate::program::model::symbol::source_type::SourceType;
use crate::program::seam_stubs::{
    share_data_type, undefined_data_type, GenericCallingConvention as GenericCallingConventionPlaceholder,
    MemBuffer,
};
use crate::util::exception::InvalidInputException;

/// Definition of a function for things like function pointers.
///
/// Port of `ghidra.program.model.data.FunctionDefinitionDataType`. See the module-level
/// documentation for the conventions used to resolve name clashes with [`DataType`]/
/// [`FunctionSignature`]/[`FunctionDefinition`], for the required accessors standing in for
/// private fields, and for what was left required (rather than defaulted) or intentionally
/// omitted.
pub trait FunctionDefinitionDataType: FunctionDefinition {
    /// Backing storage for the private `returnType` field.
    fn stored_return_type(&self) -> Box<dyn DataType>;
    /// Mutator for the private `returnType` field's backing storage.
    fn set_stored_return_type(&mut self, return_type: Box<dyn DataType>);
    /// Backing storage for the private `params` field.
    fn stored_arguments(&self) -> Vec<Box<dyn ParameterDefinition>>;
    /// Mutator for the private `params` field's backing storage.
    fn set_stored_arguments(&mut self, arguments: Vec<Box<dyn ParameterDefinition>>);
    /// Backing storage for the private `comment` field.
    fn stored_comment(&self) -> Option<String>;
    /// Mutator for the private `comment` field's backing storage.
    fn set_stored_comment(&mut self, comment: Option<String>);
    /// Backing storage for the private `hasVarArgs` field.
    fn stored_has_var_args(&self) -> bool;
    /// Mutator for the private `hasVarArgs` field's backing storage.
    fn set_stored_has_var_args(&mut self, has_var_args: bool);
    /// Backing storage for the private `hasNoReturn` field.
    fn stored_has_no_return(&self) -> bool;
    /// Mutator for the private `hasNoReturn` field's backing storage.
    fn set_stored_has_no_return(&mut self, has_no_return: bool);
    /// Backing storage for the private `callingConventionName` field.
    fn stored_calling_convention_name(&self) -> String;
    /// Mutator for the private `callingConventionName` field's backing storage.
    fn set_stored_calling_convention_name(&mut self, calling_convention_name: String);

    /// Default body for [`FunctionDefinition::set_arguments`]. Builds a fresh
    /// [`BasicParameterDefinition`] per argument (renumbering ordinals to match position, exactly
    /// like the Java source), cloning each argument's data type against this function
    /// definition's own [`DataTypeManager`] when one is available (mirroring `dt.clone(
    /// getDataTypeManager())`); otherwise the data type is reused as-is.
    fn function_definition_data_type_impl_set_arguments(
        &mut self,
        args: Vec<Box<dyn ParameterDefinition>>,
    ) {
        let dtm = self.get_data_type_manager();
        let new_params = args
            .into_iter()
            .enumerate()
            .map(|(i, arg)| {
                let dt = arg.get_data_type();
                let dt = match &dtm {
                    Some(m) => dt.clone_data_type(m.as_ref()),
                    None => dt,
                };
                Box::new(BasicParameterDefinition {
                    ordinal: i as i32,
                    name: arg.get_name(),
                    data_type: Arc::from(dt),
                    comment: arg.get_comment(),
                }) as Box<dyn ParameterDefinition>
            })
            .collect();
        self.set_stored_arguments(new_params);
    }

    /// Default body for [`FunctionDefinition::set_return_type`].
    ///
    /// # Errors
    /// Returns `Err` if the specified data type is not an acceptable return type, mirroring the
    /// `IllegalArgumentException` thrown by `ParameterDefinitionImpl.validateDataType`.
    fn function_definition_data_type_impl_set_return_type(
        &mut self,
        data_type: Box<dyn DataType>,
    ) -> Result<(), String> {
        let dtm = self.get_data_type_manager();
        let validated = validate_data_type(Some(data_type), dtm.as_deref(), true)?;
        self.set_stored_return_type(validated);
        Ok(())
    }

    /// Default body for [`FunctionDefinition::set_comment`].
    fn function_definition_data_type_impl_set_comment(&mut self, comment: Option<String>) {
        self.set_stored_comment(comment);
    }

    /// Default body for [`FunctionDefinition::set_var_args`].
    fn function_definition_data_type_impl_set_var_args(&mut self, has_var_args: bool) {
        self.set_stored_has_var_args(has_var_args);
    }

    /// Default body for [`FunctionDefinition::set_no_return`].
    fn function_definition_data_type_impl_set_no_return(&mut self, has_no_return: bool) {
        self.set_stored_has_no_return(has_no_return);
    }

    /// Default body for [`FunctionDefinition::set_generic_calling_convention`].
    fn function_definition_data_type_impl_set_generic_calling_convention(
        &mut self,
        generic_calling_convention: &dyn GenericCallingConventionPlaceholder,
    ) {
        self.set_stored_calling_convention_name(generic_calling_convention.get_declaration_name());
    }

    /// Default body for [`FunctionDefinition::set_calling_convention`].
    ///
    /// # Errors
    /// Returns `Err` if `convention_name` is neither blank/"unknown"/"default", one of the
    /// [`GenericCallingConvention`] declaration names, nor a name known to this function
    /// definition's [`DataTypeManager`] (if any).
    fn function_definition_data_type_impl_set_calling_convention(
        &mut self,
        convention_name: Option<String>,
    ) -> Result<(), InvalidInputException> {
        if is_unknown_calling_convention(convention_name.as_deref()) {
            self.set_stored_calling_convention_name(CALLING_CONVENTION_UNKNOWN.to_string());
            return Ok(());
        }
        let name = convention_name.expect("checked non-blank above");
        if name == CALLING_CONVENTION_DEFAULT {
            self.set_stored_calling_convention_name(CALLING_CONVENTION_DEFAULT.to_string());
            return Ok(());
        }

        let generic = GenericCallingConvention::from_declaration_name(&name);
        let known_to_manager = self
            .get_data_type_manager()
            .map(|dtm| {
                dtm.get_known_calling_convention_names()
                    .iter()
                    .any(|known| known == &name)
            })
            .unwrap_or(false);
        if generic == GenericCallingConvention::Unknown && !known_to_manager {
            return Err(InvalidInputException::with_message(format!(
                "Unknown calling convention name: {name}"
            )));
        }

        self.set_stored_calling_convention_name(name);
        Ok(())
    }

    /// Default body for [`FunctionDefinition::get_calling_convention`].
    fn function_definition_data_type_impl_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
        let arch = self.get_data_type_manager()?.get_program_architecture()?;
        arch.get_compiler_spec()
            .get_calling_convention(&self.stored_calling_convention_name())
    }

    /// Default body for [`FunctionDefinition::get_calling_convention_name`].
    fn function_definition_data_type_impl_calling_convention_name(&self) -> String {
        self.stored_calling_convention_name()
    }

    /// Default body for [`DataType::get_mnemonic`].
    fn function_definition_data_type_impl_mnemonic(&self, _settings: &dyn Settings) -> String {
        self.function_definition_data_type_impl_prototype_string(false)
    }

    /// Default body for [`DataType::get_length`]. A function definition datatype has no fixed
    /// encoded length.
    fn function_definition_data_type_impl_length(&self) -> i32 {
        -1
    }

    /// Default body for [`DataType::get_description`].
    fn function_definition_data_type_impl_description(&self) -> String {
        format!(
            "Function:     {}",
            self.function_definition_data_type_impl_prototype_string(false)
        )
    }

    /// Default body for [`DataType::get_representation`].
    fn function_definition_data_type_impl_representation(
        &self,
        _buf: &dyn MemBuffer,
        _settings: &dyn Settings,
        _length: i32,
    ) -> String {
        self.function_definition_data_type_impl_prototype_string(false)
    }

    /// Default body for [`FunctionSignature::get_prototype_string_with_calling_convention`].
    ///
    /// Port of `FunctionDefinitionDataType.getPrototypeString(boolean)`. `param.getName()` is
    /// assumed to never be `None` in practice, since a real
    /// [`ParameterDefinitionImpl`]-backed parameter always substitutes `""` for an unassigned
    /// name (matching how `FunctionDefinitionDb`'s identical port treats the same call).
    fn function_definition_data_type_impl_prototype_string(
        &self,
        include_calling_convention: bool,
    ) -> String {
        let mut buf = String::new();
        if include_calling_convention && self.has_no_return() {
            buf.push_str(NORETURN_DISPLAY_STRING);
            buf.push(' ');
        }
        let return_type = self.get_return_type();
        buf.push_str(&return_type.get_display_name());
        buf.push(' ');
        if include_calling_convention {
            let calling_convention = self.get_calling_convention_name();
            if calling_convention != UNKNOWN_CALLING_CONVENTION_STRING {
                buf.push_str(&calling_convention);
                buf.push(' ');
            }
        }
        buf.push_str(&FunctionSignature::get_name(self));
        buf.push('(');

        let has_var_args = self.has_var_args();
        let args = self.get_arguments();
        let n = args.len();
        for (i, param) in args.iter().enumerate() {
            buf.push_str(&param.get_data_type().get_display_name());
            buf.push(' ');
            if let Some(name) = param.get_name() {
                buf.push_str(&name);
            }
            if i < n - 1 || has_var_args {
                buf.push_str(", ");
            }
        }
        if has_var_args {
            buf.push_str(VAR_ARGS_DISPLAY_STRING);
        } else if n == 0 {
            buf.push_str(VOID_PARAM_DISPLAY_STRING);
        }
        buf.push(')');

        buf
    }

    /// Default body for [`FunctionSignature::get_arguments`].
    fn function_definition_data_type_impl_get_arguments(&self) -> Vec<Box<dyn ParameterDefinition>> {
        self.stored_arguments()
    }

    /// Default body for [`FunctionSignature::get_return_type`].
    fn function_definition_data_type_impl_get_return_type(&self) -> Box<dyn DataType> {
        self.stored_return_type()
    }

    /// Default body for [`FunctionSignature::get_comment`].
    fn function_definition_data_type_impl_get_comment(&self) -> Option<String> {
        self.stored_comment()
    }

    /// Default body for [`FunctionSignature::has_var_args`].
    fn function_definition_data_type_impl_has_var_args(&self) -> bool {
        self.stored_has_var_args()
    }

    /// Default body for [`FunctionSignature::has_no_return`].
    fn function_definition_data_type_impl_has_no_return(&self) -> bool {
        self.stored_has_no_return()
    }

    /// Default body for `FunctionDefinitionDataType.toString()`.
    fn function_definition_data_type_impl_to_string(&self) -> String {
        self.function_definition_data_type_impl_prototype_string(true)
    }

    /// Default body for [`FunctionSignature::is_equivalent_signature`].
    fn function_definition_data_type_impl_is_equivalent_signature(
        &self,
        signature: &dyn FunctionSignature,
    ) -> bool {
        if FunctionSignature::get_name(self) != signature.get_name() {
            return false;
        }
        if self.stored_comment() != signature.get_comment() {
            return false;
        }
        if !is_same_or_equivalent_data_type(
            self.stored_return_type().as_ref(),
            signature.get_return_type().as_ref(),
        ) {
            return false;
        }
        if self.stored_has_var_args() != signature.has_var_args() {
            return false;
        }
        if self.stored_has_no_return() != signature.has_no_return() {
            return false;
        }
        if self.stored_calling_convention_name() != signature.get_calling_convention_name() {
            return false;
        }
        let other_args = signature.get_arguments();
        let self_args = self.stored_arguments();
        if other_args.len() != self_args.len() {
            return false;
        }
        other_args
            .iter()
            .zip(self_args.iter())
            .all(|(other, mine)| other.is_equivalent_parameter(mine.as_ref()))
    }

    /// Default body for [`DataType::data_type_replaced`]. See the module-level documentation for
    /// how this diverges from `FunctionDefinitionDataType.dataTypeReplaced`/
    /// `DataTypeUtilities.checkValidReplacement`.
    fn function_definition_data_type_impl_data_type_replaced(
        &mut self,
        old_dt: &dyn DataType,
        new_dt: &dyn DataType,
    ) {
        if check_valid_replacement(old_dt, new_dt).is_err() {
            return;
        }
        let Some(dtm) = self.get_data_type_manager() else {
            return;
        };
        let is_self_reference = new_dt.get_data_type_path() == self.get_data_type_path();
        let old_path = old_dt.get_data_type_path();
        let make_replacement = |dtm: &dyn DataTypeManager| -> Box<dyn DataType> {
            if is_self_reference {
                undefined_data_type(1)
            } else {
                new_dt.clone_data_type(dtm)
            }
        };

        if self.stored_return_type().get_data_type_path() == old_path {
            let replacement = make_replacement(dtm.as_ref());
            if self
                .function_definition_data_type_impl_set_return_type(replacement)
                .is_err()
            {
                self.function_definition_data_type_impl_data_type_deleted(old_dt);
                return;
            }
        }

        let mut params = self.stored_arguments();
        let mut failed = false;
        for param in params.iter_mut() {
            if param.get_data_type().get_data_type_path() == old_path {
                let replacement = make_replacement(dtm.as_ref());
                if param.set_data_type(replacement).is_err() {
                    failed = true;
                    break;
                }
            }
        }
        self.set_stored_arguments(params);
        if failed {
            self.function_definition_data_type_impl_data_type_deleted(old_dt);
        }
    }

    /// Default body for [`DataType::data_type_deleted`]. `DataType.DEFAULT` (the Java field this
    /// resets deleted fields to) is not ported yet; [`undefined_data_type`] stands in for it,
    /// mirroring its use elsewhere in this crate (e.g.
    /// [`VariableUtilities`](crate::program::model::listing::variable_utilities::VariableUtilities))
    /// as the placeholder for an unresolvable datatype -- notably with a length of `1`, unlike
    /// the zero-length [`PlaceholderDataType`](crate::program::seam_stubs::PlaceholderDataType),
    /// since a zero/negative length would fail this trait's own
    /// [`FunctionDefinitionDataType::function_definition_data_type_impl_set_return_type`]/
    /// [`ParameterDefinition::set_data_type`] validation.
    fn function_definition_data_type_impl_data_type_deleted(&mut self, dt: &dyn DataType) {
        let deleted_path = dt.get_data_type_path();
        if self.stored_return_type().get_data_type_path() == deleted_path {
            self.set_stored_return_type(undefined_data_type(1));
        }
        let mut params = self.stored_arguments();
        for param in params.iter_mut() {
            if param.get_data_type().get_data_type_path() == deleted_path {
                let _ = param.set_data_type(undefined_data_type(1));
            }
        }
        self.set_stored_arguments(params);
    }

    /// Default body for [`FunctionDefinition::replace_argument`]. Builds any newly-required
    /// filler arguments (when `ordinal` is beyond the current argument list) via
    /// [`BasicParameterDefinition`], exactly mirroring the Java source's
    /// `Function.DEFAULT_PARAM_PREFIX`-named, `DataType.DEFAULT`-typed gap fill (see
    /// [`FunctionDefinitionDataType::function_definition_data_type_impl_data_type_deleted`] for
    /// why [`undefined_data_type`] stands in for `DataType.DEFAULT`).
    fn function_definition_data_type_impl_replace_argument(
        &mut self,
        ordinal: i32,
        name: Option<String>,
        dt: Box<dyn DataType>,
        comment: Option<String>,
        source: SourceType,
    ) {
        let _ = source;
        let mut params = self.stored_arguments();
        let ordinal_index = ordinal.max(0) as usize;
        if params.len() <= ordinal_index {
            for i in params.len()..=ordinal_index {
                params.push(Box::new(BasicParameterDefinition {
                    ordinal: i as i32,
                    name: Some(format!("{DEFAULT_PARAM_PREFIX}{}", i + 1)),
                    data_type: Arc::from(undefined_data_type(1)),
                    comment: comment.clone(),
                }));
            }
        }
        params[ordinal_index] = Box::new(BasicParameterDefinition {
            ordinal,
            name,
            data_type: Arc::from(dt),
            comment,
        });
        self.set_stored_arguments(params);
    }
}

/// Stands in for `DataTypeUtilities.checkValidReplacement(DataType, DataType)`. See the
/// module-level documentation for why this reimplements the check directly rather than adding a
/// placeholder stub for `DataTypeUtilities`.
fn check_valid_replacement(old_dt: &dyn DataType, new_dt: &dyn DataType) -> Result<(), String> {
    check_valid_replacement_data_type(old_dt)?;
    check_valid_replacement_data_type(new_dt)?;
    check_for_invalid_function_definition_replacement(old_dt, new_dt)
}

/// Stands in for the private `DataTypeUtilities.checkValidReplacementDataType(DataType)`.
fn check_valid_replacement_data_type(data_type: &dyn DataType) -> Result<(), String> {
    if data_type.is_void_type() {
        return Err("Replacement data type may not be 'void' data type".to_string());
    }
    if data_type.is_default_data_type() {
        return Err("Replacement data type may not be 'default' undefined data type".to_string());
    }
    if data_type.is_bit_field_type() {
        return Err(format!(
            "Replacement data type may not be a bitfield: {}",
            data_type.get_name()
        ));
    }
    if data_type.is_factory_type() {
        return Err(format!(
            "Replacement data type may not be a Factory data type: {}",
            data_type.get_name()
        ));
    }
    if data_type.is_dynamic_type() {
        return Err(format!(
            "Replacement data type may not be a Dynamic data type: {}",
            data_type.get_name()
        ));
    }
    Ok(())
}

/// Stands in for the private `DataTypeUtilities.checkForInvalidFunctionDefinitionReplacement(DataType,
/// DataType)`.
fn check_for_invalid_function_definition_replacement(
    replaced_dt: &dyn DataType,
    replacement_dt: &dyn DataType,
) -> Result<(), String> {
    let is_function_definition = |dt: &dyn DataType| -> bool {
        if dt.is_typedef() {
            dt.typedef_base_data_type()
                .map(|base| base.is_function_definition_type())
                .unwrap_or(false)
        } else {
            dt.is_function_definition_type()
        }
    };
    let replaced_is_fd = is_function_definition(replaced_dt);
    let replacement_is_fd = is_function_definition(replacement_dt);
    if replaced_is_fd && !replacement_is_fd {
        return Err(format!(
            "Existing function definition \"{}\" may not be replaced with \"{}\"",
            replaced_dt.get_name(),
            replacement_dt.get_name()
        ));
    }
    if !replaced_is_fd && replacement_is_fd {
        return Err(format!(
            "Existing data type \"{}\" may not be replaced with function definition \"{}\"",
            replaced_dt.get_name(),
            replacement_dt.get_name()
        ));
    }
    Ok(())
}

/// Directly-constructible [`ParameterDefinition`] backed by real fields, standing in for `new
/// ParameterDefinitionImpl(name, dataType, comment, ordinal)` wherever
/// [`FunctionDefinitionDataType`]'s default method bodies need to build a fresh parameter (no
/// concrete `ParameterDefinitionImpl`-implementing struct is available generically). See the
/// module-level documentation. Not a port of any specific Java class.
struct BasicParameterDefinition {
    ordinal: i32,
    name: Option<String>,
    data_type: Arc<dyn DataType>,
    comment: Option<String>,
}

impl ParameterDefinitionImpl for BasicParameterDefinition {
    fn stored_ordinal(&self) -> i32 {
        self.ordinal
    }
    fn set_stored_ordinal(&mut self, ordinal: i32) {
        self.ordinal = ordinal;
    }
    fn stored_name(&self) -> Option<String> {
        self.name.clone()
    }
    fn set_stored_name(&mut self, name: Option<String>) {
        self.name = name;
    }
    fn stored_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }
    fn set_stored_data_type(&mut self, data_type: Box<dyn DataType>) {
        self.data_type = Arc::from(data_type);
    }
    fn stored_comment(&self) -> Option<String> {
        self.comment.clone()
    }
    fn set_stored_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }
}

impl ParameterDefinition for BasicParameterDefinition {
    fn get_ordinal(&self) -> i32 {
        self.parameter_definition_impl_get_ordinal()
    }
    fn get_data_type(&self) -> Box<dyn DataType> {
        self.parameter_definition_impl_get_data_type()
    }
    fn set_data_type(&mut self, data_type: Box<dyn DataType>) -> Result<(), String> {
        self.parameter_definition_impl_set_data_type(data_type)
    }
    fn get_name(&self) -> Option<String> {
        self.parameter_definition_impl_get_name()
    }
    fn get_length(&self) -> i32 {
        self.parameter_definition_impl_get_length()
    }
    fn set_name(&mut self, name: Option<String>) {
        self.parameter_definition_impl_set_name(name)
    }
    fn get_comment(&self) -> Option<String> {
        self.parameter_definition_impl_get_comment()
    }
    fn set_comment(&mut self, comment: Option<String>) {
        self.parameter_definition_impl_set_comment(comment)
    }
    fn is_equivalent_variable(&self, variable: &dyn crate::program::model::listing::Variable) -> bool {
        self.parameter_definition_impl_is_equivalent_variable(variable)
    }
    fn is_equivalent_parameter(&self, parm: &dyn ParameterDefinition) -> bool {
        self.parameter_definition_impl_is_equivalent_parameter(parm)
    }
    fn compare_to(&self, other: &dyn ParameterDefinition) -> std::cmp::Ordering {
        self.parameter_definition_impl_compare_to(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    struct MockDataType {
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            "int".to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_length() == dt.get_length()
        }
        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            Box::new(*self)
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockFunctionDefinitionDataType {
        name: String,
        return_type: MockDataType,
        params: Vec<(Option<String>, MockDataType, Option<String>)>,
        comment: Option<String>,
        has_var_args: bool,
        has_no_return: bool,
        calling_convention_name: String,
        has_manager: bool,
    }

    impl MockFunctionDefinitionDataType {
        fn new(name: &str) -> Self {
            MockFunctionDefinitionDataType {
                name: name.to_string(),
                return_type: MockDataType { length: 4 },
                params: Vec::new(),
                comment: None,
                has_var_args: false,
                has_no_return: false,
                calling_convention_name: CALLING_CONVENTION_UNKNOWN.to_string(),
                has_manager: false,
            }
        }
    }

    impl DataType for MockFunctionDefinitionDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.function_definition_data_type_impl_mnemonic(settings)
        }
        fn get_length(&self) -> i32 {
            self.function_definition_data_type_impl_length()
        }
        fn get_description(&self) -> String {
            self.function_definition_data_type_impl_description()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            self.has_manager.then(|| Box::new(MockDataTypeManager) as Box<dyn DataTypeManager>)
        }
        fn is_function_definition_type(&self) -> bool {
            true
        }
    }

    impl FunctionSignature for MockFunctionDefinitionDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_prototype_string_with_calling_convention(
            &self,
            include_calling_convention: bool,
        ) -> String {
            self.function_definition_data_type_impl_prototype_string(include_calling_convention)
        }
        fn get_arguments(&self) -> Vec<Box<dyn ParameterDefinition>> {
            self.function_definition_data_type_impl_get_arguments()
        }
        fn get_return_type(&self) -> Box<dyn DataType> {
            self.function_definition_data_type_impl_get_return_type()
        }
        fn get_comment(&self) -> Option<String> {
            self.function_definition_data_type_impl_get_comment()
        }
        fn has_var_args(&self) -> bool {
            self.function_definition_data_type_impl_has_var_args()
        }
        fn has_no_return(&self) -> bool {
            self.function_definition_data_type_impl_has_no_return()
        }
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            self.function_definition_data_type_impl_calling_convention()
        }
        fn get_calling_convention_name(&self) -> String {
            self.function_definition_data_type_impl_calling_convention_name()
        }
        fn is_equivalent_signature(&self, signature: &dyn FunctionSignature) -> bool {
            self.function_definition_data_type_impl_is_equivalent_signature(signature)
        }
    }

    impl FunctionDefinition for MockFunctionDefinitionDataType {
        fn set_arguments(&mut self, args: Vec<Box<dyn ParameterDefinition>>) {
            self.function_definition_data_type_impl_set_arguments(args)
        }
        fn set_return_type(&mut self, data_type: Box<dyn DataType>) -> Result<(), String> {
            self.function_definition_data_type_impl_set_return_type(data_type)
        }
        fn set_comment(&mut self, comment: Option<String>) {
            self.function_definition_data_type_impl_set_comment(comment)
        }
        fn set_var_args(&mut self, has_var_args: bool) {
            self.function_definition_data_type_impl_set_var_args(has_var_args)
        }
        fn set_no_return(&mut self, has_no_return: bool) {
            self.function_definition_data_type_impl_set_no_return(has_no_return)
        }
        fn set_generic_calling_convention(
            &mut self,
            generic_calling_convention: &dyn GenericCallingConventionPlaceholder,
        ) {
            self.function_definition_data_type_impl_set_generic_calling_convention(
                generic_calling_convention,
            )
        }
        fn set_calling_convention(
            &mut self,
            convention_name: Option<String>,
        ) -> Result<(), InvalidInputException> {
            self.function_definition_data_type_impl_set_calling_convention(convention_name)
        }
        fn replace_argument(
            &mut self,
            ordinal: i32,
            name: Option<String>,
            dt: Box<dyn DataType>,
            comment: Option<String>,
            source: SourceType,
        ) {
            self.function_definition_data_type_impl_replace_argument(
                ordinal, name, dt, comment, source,
            )
        }
    }

    impl FunctionDefinitionDataType for MockFunctionDefinitionDataType {
        fn stored_return_type(&self) -> Box<dyn DataType> {
            Box::new(self.return_type)
        }
        fn set_stored_return_type(&mut self, return_type: Box<dyn DataType>) {
            self.return_type = MockDataType {
                length: return_type.get_length(),
            };
        }
        fn stored_arguments(&self) -> Vec<Box<dyn ParameterDefinition>> {
            self.params
                .iter()
                .enumerate()
                .map(|(i, (name, dt, comment))| {
                    Box::new(BasicParameterDefinition {
                        ordinal: i as i32,
                        name: name.clone(),
                        data_type: Arc::new(*dt),
                        comment: comment.clone(),
                    }) as Box<dyn ParameterDefinition>
                })
                .collect()
        }
        fn set_stored_arguments(&mut self, arguments: Vec<Box<dyn ParameterDefinition>>) {
            self.params = arguments
                .iter()
                .map(|p| {
                    (
                        p.get_name(),
                        MockDataType {
                            length: p.get_data_type().get_length(),
                        },
                        p.get_comment(),
                    )
                })
                .collect();
        }
        fn stored_comment(&self) -> Option<String> {
            self.comment.clone()
        }
        fn set_stored_comment(&mut self, comment: Option<String>) {
            self.comment = comment;
        }
        fn stored_has_var_args(&self) -> bool {
            self.has_var_args
        }
        fn set_stored_has_var_args(&mut self, has_var_args: bool) {
            self.has_var_args = has_var_args;
        }
        fn stored_has_no_return(&self) -> bool {
            self.has_no_return
        }
        fn set_stored_has_no_return(&mut self, has_no_return: bool) {
            self.has_no_return = has_no_return;
        }
        fn stored_calling_convention_name(&self) -> String {
            self.calling_convention_name.clone()
        }
        fn set_stored_calling_convention_name(&mut self, calling_convention_name: String) {
            self.calling_convention_name = calling_convention_name;
        }
    }

    fn sample() -> MockFunctionDefinitionDataType {
        let mut def = MockFunctionDefinitionDataType::new("foo");
        def.params.push((Some("a".to_string()), MockDataType { length: 4 }, None));
        def.params.push((Some("b".to_string()), MockDataType { length: 1 }, None));
        def
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut def: Box<dyn FunctionDefinitionDataType> = Box::new(sample());
        assert_eq!(
            def.get_prototype_string_with_calling_convention(false),
            "int foo(int a, int b)"
        );
        def.set_var_args(true);
        assert!(def.has_var_args());
    }

    #[test]
    fn prototype_string_renders_fixed_arguments() {
        let def = sample();
        assert_eq!(
            def.function_definition_data_type_impl_prototype_string(false),
            "int foo(int a, int b)"
        );
    }

    #[test]
    fn prototype_string_renders_var_args() {
        let mut def = MockFunctionDefinitionDataType::new("foo");
        def.has_var_args = true;
        assert_eq!(
            def.function_definition_data_type_impl_prototype_string(false),
            "int foo(...)"
        );
    }

    #[test]
    fn prototype_string_renders_void_for_no_parameters() {
        let def = MockFunctionDefinitionDataType::new("foo");
        assert_eq!(
            def.function_definition_data_type_impl_prototype_string(false),
            "int foo(void)"
        );
    }

    #[test]
    fn prototype_string_includes_no_return_and_known_calling_convention() {
        let mut def = sample();
        def.has_no_return = true;
        def.calling_convention_name = "__stdcall".to_string();
        assert_eq!(
            def.function_definition_data_type_impl_prototype_string(true),
            "noreturn int __stdcall foo(int a, int b)"
        );
    }

    #[test]
    fn to_string_includes_calling_convention_form() {
        let def = sample();
        assert_eq!(
            def.function_definition_data_type_impl_to_string(),
            "int foo(int a, int b)"
        );
    }

    #[test]
    fn mnemonic_length_and_description_delegate_to_prototype_string() {
        struct MockSettings;
        impl Settings for MockSettings {}

        let def = sample();
        assert_eq!(def.get_mnemonic(&MockSettings), "int foo(int a, int b)");
        assert_eq!(def.get_length(), -1);
        assert_eq!(def.get_description(), "Function:     int foo(int a, int b)");
    }

    #[test]
    fn set_return_type_validates_and_stores() {
        let mut def = sample();
        assert!(def.function_definition_data_type_impl_set_return_type(Box::new(MockDataType { length: 8 })).is_ok());
        assert_eq!(def.get_return_type().get_length(), 8);
    }

    #[test]
    fn set_calling_convention_rejects_unknown_name_without_manager() {
        let mut def = sample();
        assert!(def
            .function_definition_data_type_impl_set_calling_convention(Some("bogus".to_string()))
            .is_err());
        assert!(def
            .function_definition_data_type_impl_set_calling_convention(Some("__stdcall".to_string()))
            .is_ok());
        assert_eq!(def.get_calling_convention_name(), "__stdcall");
    }

    #[test]
    fn set_arguments_renumbers_ordinals() {
        let mut def = MockFunctionDefinitionDataType::new("foo");
        let args: Vec<Box<dyn ParameterDefinition>> = vec![
            Box::new(BasicParameterDefinition {
                ordinal: 5,
                name: Some("x".to_string()),
                data_type: Arc::new(MockDataType { length: 4 }),
                comment: None,
            }),
            Box::new(BasicParameterDefinition {
                ordinal: 9,
                name: Some("y".to_string()),
                data_type: Arc::new(MockDataType { length: 1 }),
                comment: None,
            }),
        ];
        def.set_arguments(args);
        let stored = def.get_arguments();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].get_ordinal(), 0);
        assert_eq!(stored[1].get_ordinal(), 1);
    }

    #[test]
    fn replace_argument_fills_gap_with_default_named_parameters() {
        let mut def = MockFunctionDefinitionDataType::new("foo");
        def.replace_argument(
            2,
            Some("z".to_string()),
            Box::new(MockDataType { length: 4 }),
            None,
            SourceType::UserDefined,
        );
        let args = def.get_arguments();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0].get_name(), Some(format!("{DEFAULT_PARAM_PREFIX}1")));
        assert_eq!(args[1].get_name(), Some(format!("{DEFAULT_PARAM_PREFIX}2")));
        assert_eq!(args[2].get_name(), Some("z".to_string()));
    }

    #[test]
    fn is_equivalent_signature_compares_shape() {
        let a = sample();
        let b = sample();
        assert!(a.is_equivalent_signature(&b));

        let mut c = sample();
        c.has_no_return = true;
        assert!(!a.is_equivalent_signature(&c));
    }

    #[test]
    fn data_type_deleted_resets_matching_fields_to_placeholder() {
        let mut def = sample();
        // Every `MockDataType` (any length) shares the same `get_data_type_path()` (they all
        // report the name "int"), which is how identity is approximated here -- so deleting any
        // one of them matches the return type and every parameter. The replacement
        // (`undefined_data_type(1)`, standing in for `DataType.DEFAULT`) always has length 1.
        let deleted = MockDataType { length: 999 };
        def.function_definition_data_type_impl_data_type_deleted(&deleted);
        assert_eq!(def.get_return_type().get_length(), 1);
        assert_eq!(def.get_arguments()[0].get_data_type().get_length(), 1);
        assert_eq!(def.get_arguments()[1].get_data_type().get_length(), 1);
    }

    #[test]
    fn data_type_replaced_clones_matching_fields_via_manager() {
        let mut def = sample();
        def.has_manager = true;
        // Every `MockDataType` shares the name "int" (and so the same `get_data_type_path()`),
        // so this matches the return type and both parameters; the replacement is cloned fresh
        // (via `DataType::clone_data_type`) for each.
        let old_dt = MockDataType { length: 4 };
        let new_dt = MockDataType { length: 8 };
        def.function_definition_data_type_impl_data_type_replaced(&old_dt, &new_dt);
        assert_eq!(def.get_return_type().get_length(), 8);
        assert_eq!(def.get_arguments()[0].get_data_type().get_length(), 8);
        assert_eq!(def.get_arguments()[1].get_data_type().get_length(), 8);
    }

    #[test]
    fn data_type_replaced_does_nothing_without_a_manager() {
        let mut def = sample();
        let old_dt = MockDataType { length: 4 };
        let new_dt = MockDataType { length: 8 };
        def.function_definition_data_type_impl_data_type_replaced(&old_dt, &new_dt);
        assert_eq!(def.get_return_type().get_length(), 4);
    }
}

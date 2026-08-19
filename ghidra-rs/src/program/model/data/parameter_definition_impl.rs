//! Port of `ghidra.program.model.data.ParameterDefinitionImpl`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class is the sole first-party implementation of the already-ported
//! [`ParameterDefinition`] interface. Rust does not allow a subtrait to provide a default body
//! for a method its supertrait already declares as required (the call becomes ambiguous at every
//! call site), so the field-backed default implementations of `ParameterDefinition`'s methods are
//! exposed here under a `parameter_definition_impl_` prefix, mirroring the `composite_impl_*`
//! convention set by
//! [`CompositeDataTypeImpl`](crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl).
//! A concrete `impl ParameterDefinition for Foo` is expected to delegate each method to its
//! `parameter_definition_impl_*` counterpart.
//!
//! The private fields `ordinal`, `name`, `dataType`, and `comment` have no home on a trait, so
//! they are exposed via required accessor methods (`stored_*`) that implementors back with real
//! storage, again mirroring `CompositeDataTypeImpl`'s accessor convention.
//!
//! `validateDataType(DataType, DataTypeManager, boolean)` delegates to
//! `VariableUtilities.checkDataType`, which is already ported as
//! [`VariableUtilities::check_data_type_simple`]. It is exposed here as the free function
//! [`validate_data_type`] (rather than a trait method) since it needs no `&self`; it drives a
//! private zero-sized [`VariableUtilities`] implementor to reach that default method.
//!
//! `isEquivalent(Parameter)`/`isEquivalent(ParameterDefinition)` delegate to
//! `DataTypeUtilities.isSameOrEquivalentDataType`, which is not yet ported. The relevant two-way
//! `isEquivalent` check is inlined directly as [`is_same_or_equivalent_data_type`]; unlike the
//! real method, it has no access to a `DataTypeDB`-style identity/id short-circuit, so it always
//! falls through to the `isEquivalent` calls on both sides.
//!
//! The `instanceof Parameter` downcast in `isEquivalent(Variable)` is expressed via
//! [`Variable::parameter_ordinal`], which already exists on the ported `Variable` trait for
//! exactly this purpose.
//!
//! `SymbolUtilities.isDefaultParameterName(String)` (used by `setName`) is not yet ported as a
//! reusable helper; the small amount of logic it needs is inlined locally as
//! [`is_default_parameter_name`] rather than pulled in as a placeholder stub, since it operates
//! only on primitives (a `String` and the already-ported
//! [`function::DEFAULT_PARAM_PREFIX`](crate::program::model::listing::function::DEFAULT_PARAM_PREFIX)
//! constant) and references no unported type.
//!
//! The Java constructors (`ParameterDefinitionImpl(name, dataType, comment)` and the protected
//! `ParameterDefinitionImpl(name, dataType, comment, ordinal)`) are exposed as the free function
//! [`init_fields`], which performs the constructor's `validateDataType` call and returns the four
//! field values ready to store; implementors' own constructors are expected to call it and feed
//! the result into their `stored_*` backing fields.

use std::cmp::Ordering;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::parameter_definition::ParameterDefinition;
use crate::program::model::listing::function::DEFAULT_PARAM_PREFIX;
use crate::program::model::listing::variable_utilities::VariableUtilities;
use crate::program::model::listing::Variable;

/// Zero-sized [`VariableUtilities`] implementor used solely to reach that trait's
/// default-implemented `check_data_type_simple` method from the free function
/// [`validate_data_type`], mirroring the Java static method's lack of any instance state. Not a
/// port of any specific Java class.
struct DefaultVariableUtilities;

impl VariableUtilities for DefaultVariableUtilities {}

/// Check the specified datatype for use as a return, parameter or variable type. It may not be
/// suitable for other uses. Function definition datatypes and unsized/zero-element arrays will be
/// mutated into a default pointer datatype.
///
/// `data_type` of `None` results in the DEFAULT (undefined) datatype being returned. `dt_mgr` is
/// the target datatype manager (`None` permitted, which will adopt default data organization).
/// `void_ok` is true if checking a return datatype and void is allowed, else false.
///
/// # Errors
/// Returns `Err` if an unacceptable datatype was specified, mirroring the
/// `IllegalArgumentException` thrown by the Java static method.
pub fn validate_data_type(
    data_type: Option<Box<dyn DataType>>,
    dt_mgr: Option<&dyn DataTypeManager>,
    void_ok: bool,
) -> Result<Box<dyn DataType>, String> {
    DefaultVariableUtilities
        .check_data_type_simple(data_type, void_ok, dt_mgr)
        .map_err(|e| e.to_string())
}

/// Determine if two datatypes represent the same or an equivalent datatype. Stands in for
/// `DataTypeUtilities.isSameOrEquivalentDataType(DataType, DataType)`, minus that method's
/// identity/`DataTypeDB`-optimization short-circuit (neither concept exists yet on the ported
/// [`DataType`] trait), leaving the two-way `isEquivalent` fallback it always has available.
pub fn is_same_or_equivalent_data_type(a: &dyn DataType, b: &dyn DataType) -> bool {
    a.is_equivalent(b) || b.is_equivalent(a)
}

/// Stands in for `SymbolUtilities.isDefaultParameterName(String)`: true if `name` is `None`,
/// empty, or of the form `param_<N>` for some integer `N`.
pub fn is_default_parameter_name(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return true;
    };
    if name.is_empty() {
        return true;
    }
    match name.strip_prefix(DEFAULT_PARAM_PREFIX) {
        Some(tail) => tail.parse::<i32>().is_ok(),
        None => false,
    }
}

/// Build the four field values backing a new parameter definition, mirroring the Java protected
/// constructor `ParameterDefinitionImpl(String name, DataType dataType, String comment, int
/// ordinal)`: `data_type` is validated (and possibly mutated/cloned) against its own data type
/// manager before being stored. `name` and `comment` are stored as given (unlike
/// [`ParameterDefinitionImpl::parameter_definition_impl_set_name`]/
/// [`ParameterDefinitionImpl::parameter_definition_impl_set_comment`], which apply extra
/// normalization only performed by the setters, not the constructor).
///
/// # Errors
/// Returns `Err` if an unacceptable parameter datatype was specified.
pub fn init_fields(
    name: Option<String>,
    data_type: Box<dyn DataType>,
    comment: Option<String>,
    ordinal: i32,
) -> Result<(Option<String>, Box<dyn DataType>, Option<String>, i32), String> {
    let dt_mgr = data_type.get_data_type_manager();
    let data_type = validate_data_type(Some(data_type), dt_mgr.as_deref(), false)?;
    Ok((name, data_type, comment, ordinal))
}

/// Field-backed default implementation of the already-ported [`ParameterDefinition`] interface.
///
/// Port of `ghidra.program.model.data.ParameterDefinitionImpl`.
pub trait ParameterDefinitionImpl: ParameterDefinition {
    /// Backing storage for the `ordinal` field.
    fn stored_ordinal(&self) -> i32;
    /// Update the backing storage for the `ordinal` field.
    fn set_stored_ordinal(&mut self, ordinal: i32);
    /// Backing storage for the `name` field.
    fn stored_name(&self) -> Option<String>;
    /// Update the backing storage for the `name` field.
    fn set_stored_name(&mut self, name: Option<String>);
    /// Backing storage for the `dataType` field.
    fn stored_data_type(&self) -> Box<dyn DataType>;
    /// Update the backing storage for the `dataType` field.
    fn set_stored_data_type(&mut self, data_type: Box<dyn DataType>);
    /// Backing storage for the `comment` field.
    fn stored_comment(&self) -> Option<String>;
    /// Update the backing storage for the `comment` field.
    fn set_stored_comment(&mut self, comment: Option<String>);

    /// Default body for [`ParameterDefinition::get_ordinal`].
    fn parameter_definition_impl_get_ordinal(&self) -> i32 {
        self.stored_ordinal()
    }

    /// Default body for [`ParameterDefinition::get_comment`].
    fn parameter_definition_impl_get_comment(&self) -> Option<String> {
        self.stored_comment()
    }

    /// Default body for [`ParameterDefinition::get_data_type`].
    fn parameter_definition_impl_get_data_type(&self) -> Box<dyn DataType> {
        self.stored_data_type()
    }

    /// Default body for [`ParameterDefinition::get_length`].
    fn parameter_definition_impl_get_length(&self) -> i32 {
        self.stored_data_type().get_length()
    }

    /// Default body for [`ParameterDefinition::get_name`]. Unlike that method's general contract
    /// (`None` if unnamed), this implementation always reports a name, substituting `""` for an
    /// unassigned one -- exactly mirroring `ParameterDefinitionImpl.getName()`'s
    /// null-to-empty-string conversion.
    fn parameter_definition_impl_get_name(&self) -> Option<String> {
        Some(self.stored_name().unwrap_or_default())
    }

    /// Default body for [`ParameterDefinition::set_comment`]. Strips one trailing newline, if
    /// present.
    fn parameter_definition_impl_set_comment(&mut self, comment: Option<String>) {
        let comment = comment.map(|c| match c.strip_suffix('\n') {
            Some(stripped) => stripped.to_string(),
            None => c,
        });
        self.set_stored_comment(comment);
    }

    /// Default body for [`ParameterDefinition::set_data_type`]. Validates against the *current*
    /// stored datatype's manager (not the new datatype's own manager), exactly mirroring
    /// `ParameterDefinitionImpl.setDataType(DataType)`.
    ///
    /// # Errors
    /// Returns `Err` if the specified parameter datatype is invalid.
    fn parameter_definition_impl_set_data_type(
        &mut self,
        data_type: Box<dyn DataType>,
    ) -> Result<(), String> {
        let dt_mgr = self.stored_data_type().get_data_type_manager();
        let validated = validate_data_type(Some(data_type), dt_mgr.as_deref(), false)?;
        self.set_stored_data_type(validated);
        Ok(())
    }

    /// Default body for [`ParameterDefinition::set_name`]. Normalizes a default-looking name
    /// (see [`is_default_parameter_name`]) to `None`.
    fn parameter_definition_impl_set_name(&mut self, name: Option<String>) {
        let name = match &name {
            Some(n) if !is_default_parameter_name(Some(n)) => name,
            _ => None,
        };
        self.set_stored_name(name);
    }

    /// Default body for [`ParameterDefinition::is_equivalent_variable`].
    fn parameter_definition_impl_is_equivalent_variable(&self, variable: &dyn Variable) -> bool {
        match variable.parameter_ordinal() {
            Some(other_ordinal) if other_ordinal == self.stored_ordinal() => {
                is_same_or_equivalent_data_type(
                    self.stored_data_type().as_ref(),
                    variable.get_data_type().as_ref(),
                )
            }
            _ => false,
        }
    }

    /// Default body for [`ParameterDefinition::is_equivalent_parameter`].
    fn parameter_definition_impl_is_equivalent_parameter(
        &self,
        parm: &dyn ParameterDefinition,
    ) -> bool {
        if self.stored_ordinal() != parm.get_ordinal() {
            return false;
        }
        is_same_or_equivalent_data_type(
            self.stored_data_type().as_ref(),
            parm.get_data_type().as_ref(),
        )
    }

    /// Default body for [`ParameterDefinition::compare_to`].
    fn parameter_definition_impl_compare_to(&self, other: &dyn ParameterDefinition) -> Ordering {
        self.stored_ordinal().cmp(&other.get_ordinal())
    }

    /// Default body for `ParameterDefinitionImpl.toString()`.
    fn parameter_definition_impl_to_string(&self) -> String {
        format!(
            "{} {}",
            self.stored_data_type().get_name(),
            self.stored_name().unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::listing::parameter::UNASSIGNED_ORDINAL;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    struct MockDataType {
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            "dword".to_string()
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_length() == dt.get_length()
        }
    }

    struct MockVariable {
        ordinal: Option<i32>,
        data_type: MockDataType,
    }

    impl Variable for MockVariable {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.data_type)
        }

        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn set_data_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn set_data_type_aligned(
            &mut self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
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

        fn get_function(&self) -> Option<Box<dyn crate::program::model::listing::Function>> {
            None
        }

        fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl crate::program::model::listing::Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock".to_string()
                }
                fn get_language_id(&self) -> String {
                    "mock:LE:32:default".to_string()
                }
            }
            std::sync::Arc::new(MockProgram)
        }

        fn get_source(&self) -> crate::program::model::symbol::SourceType {
            crate::program::model::symbol::SourceType::UserDefined
        }

        fn set_name(
            &mut self,
            _name: &str,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::variable::SetVariableNameError> {
            Ok(())
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn set_comment(&mut self, _comment: Option<String>) {}

        fn get_variable_storage(&self) -> Option<Box<dyn crate::program::model::listing::variable_storage::VariableStorage>> {
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

        fn get_min_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }

        fn get_stack_offset(
            &self,
        ) -> Result<i32, crate::program::model::listing::variable::UnsupportedOperationError> {
            Err(crate::program::model::listing::variable::UnsupportedOperationError(
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

        fn get_symbol(&self) -> Option<std::sync::Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }

        fn is_equivalent(&self, _variable: &dyn Variable) -> bool {
            false
        }

        fn compare_to(&self, _other: &dyn Variable) -> Ordering {
            Ordering::Equal
        }

        fn parameter_ordinal(&self) -> Option<i32> {
            self.ordinal
        }
    }

    struct MockParameterDefinitionImpl {
        ordinal: i32,
        name: Option<String>,
        data_type: MockDataType,
        comment: Option<String>,
    }

    impl ParameterDefinitionImpl for MockParameterDefinitionImpl {
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
    }

    impl ParameterDefinition for MockParameterDefinitionImpl {
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
        fn is_equivalent_variable(&self, variable: &dyn Variable) -> bool {
            self.parameter_definition_impl_is_equivalent_variable(variable)
        }
        fn is_equivalent_parameter(&self, parm: &dyn ParameterDefinition) -> bool {
            self.parameter_definition_impl_is_equivalent_parameter(parm)
        }
        fn compare_to(&self, other: &dyn ParameterDefinition) -> Ordering {
            self.parameter_definition_impl_compare_to(other)
        }
    }

    fn new_param(name: Option<&str>, length: i32, ordinal: i32) -> MockParameterDefinitionImpl {
        let (name, data_type, comment, ordinal) = init_fields(
            name.map(str::to_string),
            Box::new(MockDataType { length }),
            None,
            ordinal,
        )
        .expect("valid parameter datatype");
        let data_type = MockDataType {
            length: data_type.get_length(),
        };
        MockParameterDefinitionImpl {
            ordinal,
            name,
            data_type,
            comment,
        }
    }

    #[test]
    fn get_name_converts_unassigned_to_empty_string() {
        let param = new_param(None, 4, UNASSIGNED_ORDINAL);
        assert_eq!(param.get_name(), Some(String::new()));
    }

    #[test]
    fn set_name_normalizes_default_looking_names_to_none() {
        let mut param = new_param(Some("count"), 4, 0);
        assert_eq!(param.get_name(), Some("count".to_string()));

        param.set_name(Some("param_2".to_string()));
        assert_eq!(param.get_name(), Some(String::new()));

        param.set_name(Some("length".to_string()));
        assert_eq!(param.get_name(), Some("length".to_string()));
    }

    #[test]
    fn set_comment_strips_one_trailing_newline() {
        let mut param = new_param(Some("x"), 4, 0);
        param.set_comment(Some("a comment\n".to_string()));
        assert_eq!(param.get_comment(), Some("a comment".to_string()));
    }

    #[test]
    fn is_equivalent_variable_checks_ordinal_and_data_type() {
        let param = new_param(Some("x"), 4, 2);
        let same = MockVariable {
            ordinal: Some(2),
            data_type: MockDataType { length: 4 },
        };
        let wrong_ordinal = MockVariable {
            ordinal: Some(3),
            data_type: MockDataType { length: 4 },
        };
        let not_a_parameter = MockVariable {
            ordinal: None,
            data_type: MockDataType { length: 4 },
        };
        let wrong_length = MockVariable {
            ordinal: Some(2),
            data_type: MockDataType { length: 8 },
        };
        assert!(param.is_equivalent_variable(&same));
        assert!(!param.is_equivalent_variable(&wrong_ordinal));
        assert!(!param.is_equivalent_variable(&not_a_parameter));
        assert!(!param.is_equivalent_variable(&wrong_length));
    }

    #[test]
    fn compare_to_orders_by_ordinal() {
        let a = new_param(Some("a"), 4, 0);
        let b = new_param(Some("b"), 4, 1);
        assert_eq!(ParameterDefinition::compare_to(&a, &b), Ordering::Less);
        assert_eq!(ParameterDefinition::compare_to(&b, &a), Ordering::Greater);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let param: Box<dyn ParameterDefinitionImpl> = Box::new(new_param(Some("len"), 8, 2));
        assert_eq!(param.stored_ordinal(), 2);
        assert_eq!(param.parameter_definition_impl_get_length(), 8);
        assert_eq!(
            param.parameter_definition_impl_to_string(),
            "dword len".to_string()
        );
    }

    #[test]
    fn init_fields_rejects_invalid_data_type() {
        struct BitFieldDataType;
        impl DataType for BitFieldDataType {
            fn is_bit_field_type(&self) -> bool {
                true
            }
        }
        let result = init_fields(None, Box::new(BitFieldDataType), None, UNASSIGNED_ORDINAL);
        assert!(result.is_err());
    }
}

use std::cmp::Ordering;

use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::Variable;

/// Specifies a parameter which can be used to specify a function definition.
///
/// Mirrors Java's `Comparable<ParameterDefinition>.compareTo` via
/// [`ParameterDefinition::compare_to`].
pub trait ParameterDefinition {
    /// Get the parameter ordinal.
    ///
    /// Returns the ordinal (index) of this parameter within the function signature.
    fn get_ordinal(&self) -> i32;

    /// Get the Data Type of this variable.
    fn get_data_type(&self) -> Box<dyn DataType>;

    /// Set the Data Type of this variable.
    ///
    /// # Errors
    /// Returns `Err` if the specified parameter datatype is invalid, mirroring the
    /// `IllegalArgumentException` thrown by the Java source.
    fn set_data_type(&mut self, data_type: Box<dyn DataType>) -> Result<(), String>;

    /// Get the Name of this variable.
    ///
    /// Returns the name of the variable, or `None` if no name has been specified.
    fn get_name(&self) -> Option<String>;

    /// Get the length of this variable.
    fn get_length(&self) -> i32;

    /// Set the name of this variable.
    fn set_name(&mut self, name: Option<String>);

    /// Get the Comment for this variable.
    fn get_comment(&self) -> Option<String>;

    /// Set the comment for this variable.
    fn set_comment(&mut self, comment: Option<String>);

    /// Determine if a variable corresponds to a parameter which is equivalent to this parameter
    /// definition by both ordinal and datatype. Name is not considered relevant.
    ///
    /// Returns true if the specified variable represents the same parameter by ordinal and
    /// dataType. False will always be returned if the specified variable is not a `Parameter`.
    fn is_equivalent_variable(&self, variable: &dyn Variable) -> bool;

    /// Determine if `parm` is equivalent to this parameter definition by both ordinal and
    /// datatype. Name is not considered relevant.
    ///
    /// Returns true if the specified parameter definition represents the same parameter by
    /// ordinal and dataType.
    fn is_equivalent_parameter(&self, parm: &dyn ParameterDefinition) -> bool;

    /// Compares this parameter definition with `other` for ordering.
    fn compare_to(&self, other: &dyn ParameterDefinition) -> Ordering;
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering as StdOrdering;
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::listing::{Function, Program};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::program::seam_stubs::VariableStorage;
    use crate::util::exception::InvalidInputException;

    struct MockDataType;

    impl DataType for MockDataType {}

    struct MockVariable;

    impl Variable for MockVariable {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
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
            0
        }

        fn is_valid(&self) -> bool {
            true
        }

        fn get_function(&self) -> Option<Box<dyn Function>> {
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

        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
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

        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }

        fn is_equivalent(&self, _variable: &dyn Variable) -> bool {
            false
        }

        fn compare_to(&self, _other: &dyn Variable) -> StdOrdering {
            StdOrdering::Equal
        }
    }

    struct MockParameterDefinition {
        ordinal: i32,
        name: Option<String>,
        comment: Option<String>,
        length: i32,
    }

    impl ParameterDefinition for MockParameterDefinition {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }

        fn set_data_type(&mut self, _data_type: Box<dyn DataType>) -> Result<(), String> {
            Ok(())
        }

        fn get_name(&self) -> Option<String> {
            self.name.clone()
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn set_name(&mut self, name: Option<String>) {
            self.name = name;
        }

        fn get_comment(&self) -> Option<String> {
            self.comment.clone()
        }

        fn set_comment(&mut self, comment: Option<String>) {
            self.comment = comment;
        }

        fn is_equivalent_variable(&self, _variable: &dyn Variable) -> bool {
            false
        }

        fn is_equivalent_parameter(&self, parm: &dyn ParameterDefinition) -> bool {
            self.ordinal == parm.get_ordinal()
        }

        fn compare_to(&self, other: &dyn ParameterDefinition) -> Ordering {
            self.ordinal.cmp(&other.get_ordinal())
        }
    }

    #[test]
    fn set_name_and_comment_update_state() {
        let mut param = MockParameterDefinition {
            ordinal: 0,
            name: None,
            comment: None,
            length: 4,
        };
        assert_eq!(param.get_name(), None);
        param.set_name(Some("count".to_string()));
        assert_eq!(param.get_name(), Some("count".to_string()));

        param.set_comment(Some("a comment".to_string()));
        assert_eq!(param.get_comment(), Some("a comment".to_string()));
    }

    #[test]
    fn compare_to_orders_by_ordinal() {
        let a = MockParameterDefinition {
            ordinal: 0,
            name: None,
            comment: None,
            length: 4,
        };
        let b = MockParameterDefinition {
            ordinal: 1,
            name: None,
            comment: None,
            length: 4,
        };
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
        assert!(a.is_equivalent_parameter(&a));
        assert!(!a.is_equivalent_parameter(&b));
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let param: Box<dyn ParameterDefinition> = Box::new(MockParameterDefinition {
            ordinal: 2,
            name: Some("len".to_string()),
            comment: None,
            length: 8,
        });
        assert_eq!(param.get_ordinal(), 2);
        assert_eq!(param.get_length(), 8);
        assert!(!param.is_equivalent_variable(&MockVariable));
        let _dt: Box<dyn DataType> = param.get_data_type();
    }
}

use std::cmp::Ordering;
use std::sync::Arc;

use thiserror::Error;

use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::{Function, Program};
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::{SourceType, Symbol};
use crate::program::model::address::Address;
use crate::program::seam_stubs::VariableStorage;
use crate::util::exception::{DuplicateNameException, InvalidInputException};

/// Error produced when [`Variable::set_name`] fails.
///
/// Combines the two checked exceptions declared on the Java method
/// `Variable.setName(String, SourceType)`.
#[derive(Error, Debug, PartialEq)]
pub enum SetVariableNameError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// Error produced by [`Variable::get_stack_offset`] when this variable is not a simple stack
/// variable, standing in for `java.lang.UnsupportedOperationException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedOperationError(pub String);

impl std::fmt::Display for UnsupportedOperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UnsupportedOperationError {}

/// Defines an object that stores a value of some specific data type. The variable has a name,
/// type, size, and a comment.
///
/// Mirrors Java's `Comparable<Variable>.compareTo` via [`Variable::compare_to`].
pub trait Variable {
    /// Get the Data Type of this variable.
    fn get_data_type(&self) -> Box<dyn DataType>;

    /// Set the Data Type of this variable and the associated storage whose size matches the
    /// data type length.
    ///
    /// NOTE: The storage and source are ignored if the function does not have custom storage
    /// enabled.
    ///
    /// # Errors
    /// Returns `Err` if the data type is not a fixed length or violates storage constraints, or
    /// if `force` is false and the data type size causes a conflict with other variables.
    fn set_data_type_with_storage(
        &mut self,
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException>;

    /// Set the Data Type of this variable using the default alignment behavior (implementation
    /// specific). The given data type must have a fixed length. If contained within a
    /// stack-frame, data-type size will be constrained by existing variables (equivalent to
    /// `force = false`). Stack offset will be maintained for stack variables.
    ///
    /// # Errors
    /// Returns `Err` if the data type is not a fixed length or violates storage constraints, or
    /// if the data type size causes a conflict with other variables.
    fn set_data_type(
        &mut self,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<(), InvalidInputException>;

    /// Set the Data Type of this variable. The given data type must have a fixed length.
    ///
    /// `align_stack` requests that proper stack alignment/justification be maintained if
    /// supported by the implementation. If false and this is a stack variable, the current
    /// stack address/offset will not change. If true, the effect is implementation dependent
    /// since alignment cannot be performed without access to a compiler specification.
    ///
    /// # Errors
    /// Returns `Err` if the data type is not a fixed length or violates storage constraints, or
    /// if `force` is false and the data type size causes a conflict with other variables.
    fn set_data_type_aligned(
        &mut self,
        data_type: Box<dyn DataType>,
        align_stack: bool,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException>;

    /// Get the Name of this variable, or `None` if not assigned or not-applicable.
    fn get_name(&self) -> Option<String>;

    /// Get the length of this variable.
    fn get_length(&self) -> i32;

    /// Verify that the variable is valid (i.e., storage is valid and size matches variable data
    /// type size).
    fn is_valid(&self) -> bool;

    /// Returns the function that contains this Variable. May be `None` if the variable is not
    /// in a function.
    fn get_function(&self) -> Option<Box<dyn Function>>;

    /// Returns the program that contains this variable or is the intended target.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Get the source of this variable.
    fn get_source(&self) -> SourceType;

    /// Set the name of this variable.
    ///
    /// # Errors
    /// Returns `Err` if the name collides with the name of another variable, or if the name
    /// contains blank characters, is zero length, or is otherwise invalid.
    fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetVariableNameError>;

    /// Get the Comment for this variable.
    fn get_comment(&self) -> Option<String>;

    /// Set the comment for this variable.
    fn set_comment(&mut self, comment: Option<String>);

    /// Get the variable storage associated with this variable.
    fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>>;

    /// Get the first storage varnode for this variable.
    fn get_first_storage_varnode(&self) -> Option<Varnode>;

    /// Get the last storage varnode for this variable.
    fn get_last_storage_varnode(&self) -> Option<Varnode>;

    /// Returns true if this is a simple variable consisting of a single stack varnode which
    /// will be returned by either [`Variable::get_first_storage_varnode`] or
    /// [`Variable::get_last_storage_varnode`].
    fn is_stack_variable(&self) -> bool;

    /// Returns true if this variable uses simple or compound storage which contains a stack
    /// element. If true, the last storage varnode will always be the stack element.
    fn has_stack_storage(&self) -> bool;

    /// Returns true if this is a simple variable consisting of a single register varnode which
    /// will be returned by either [`Variable::get_first_storage_varnode`] or
    /// [`Variable::get_last_storage_varnode`]. The register can be obtained using
    /// [`Variable::get_register`].
    fn is_register_variable(&self) -> bool;

    /// Returns the first storage register associated with this variable, else `None` is
    /// returned. A variable with compound storage may have more than one register or other
    /// storage in addition to the register returned by this method.
    fn get_register(&self) -> Option<RegisterRef>;

    /// Returns all storage register(s) associated with this variable, else `None` is returned if
    /// no registers are used. A variable with compound storage may have more than one register
    /// or other storage in addition to the register(s) returned by this method.
    fn get_registers(&self) -> Option<Vec<RegisterRef>>;

    /// Returns the minimum address corresponding to the first varnode of this storage, or `None`
    /// if this is a special empty storage.
    fn get_min_address(&self) -> Option<Address>;

    /// Returns the stack offset associated with a simple stack variable (i.e.,
    /// [`Variable::is_stack_variable`] returns true).
    ///
    /// # Errors
    /// Returns `Err` if storage is not a simple stack variable.
    fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError>;

    /// Returns true if this is a simple variable consisting of a single storage memory element
    /// which will be returned by either [`Variable::get_first_storage_varnode`] or
    /// [`Variable::get_variable_storage`].
    fn is_memory_variable(&self) -> bool;

    /// Returns true if this is a simple variable consisting of a single storage unique/hash
    /// element which will be returned by either [`Variable::get_first_storage_varnode`] or
    /// [`Variable::get_variable_storage`]. The unique hash can be obtained from the storage
    /// address offset corresponding to the single storage element.
    fn is_unique_variable(&self) -> bool;

    /// Returns true if this variable uses compound storage consisting of two or more storage
    /// elements which will be returned by [`Variable::get_variable_storage`]. Compound variables
    /// will always use a register(s) optionally followed by other storage (i.e., stack).
    fn is_compound_variable(&self) -> bool;

    /// Returns true if this variable has been assigned storage. This is equivalent to
    /// `get_variable_storage().is_some()`.
    fn has_assigned_storage(&self) -> bool;

    /// Returns the first use offset relative to the function entry point.
    fn get_first_use_offset(&self) -> i32;

    /// Returns the symbol associated with this variable, or `None` if no symbol is associated.
    /// Certain dynamic variables such as auto-parameters do not have a symbol and will return
    /// `None`.
    fn get_symbol(&self) -> Option<Arc<dyn Symbol>>;

    /// Determine if another variable is equivalent to this variable.
    fn is_equivalent(&self, variable: &dyn Variable) -> bool;

    /// Compares this variable with `other` for ordering.
    fn compare_to(&self, other: &dyn Variable) -> Ordering;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl DataType for MockDataType {}

    struct MockVariable {
        name: Option<String>,
        comment: Option<String>,
        length: i32,
    }

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
            self.name.clone()
        }

        fn get_length(&self) -> i32 {
            self.length
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

        fn set_name(&mut self, name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            self.name = Some(name.to_string());
            Ok(())
        }

        fn get_comment(&self) -> Option<String> {
            self.comment.clone()
        }

        fn set_comment(&mut self, comment: Option<String>) {
            self.comment = comment;
        }

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
            self.get_variable_storage().is_some()
        }

        fn get_first_use_offset(&self) -> i32 {
            0
        }

        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }

        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name() && self.get_length() == variable.get_length()
        }

        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.get_name().cmp(&other.get_name())
        }
    }

    #[test]
    fn set_name_and_comment_update_state() {
        let mut var = MockVariable {
            name: None,
            comment: None,
            length: 4,
        };
        assert_eq!(var.get_name(), None);
        var.set_name("local_1", SourceType::UserDefined).unwrap();
        assert_eq!(var.get_name(), Some("local_1".to_string()));

        var.set_comment(Some("a comment".to_string()));
        assert_eq!(var.get_comment(), Some("a comment".to_string()));
    }

    #[test]
    fn stack_offset_is_unsupported_by_default_mock() {
        let var = MockVariable {
            name: None,
            comment: None,
            length: 4,
        };
        assert!(var.get_stack_offset().is_err());
    }

    #[test]
    fn is_equivalent_compares_name_and_length() {
        let a = MockVariable {
            name: Some("x".to_string()),
            comment: None,
            length: 4,
        };
        let b = MockVariable {
            name: Some("x".to_string()),
            comment: None,
            length: 4,
        };
        let c = MockVariable {
            name: Some("y".to_string()),
            comment: None,
            length: 4,
        };
        assert!(a.is_equivalent(&b));
        assert!(!a.is_equivalent(&c));
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let var: Box<dyn Variable> = Box::new(MockVariable {
            name: Some("param_1".to_string()),
            comment: None,
            length: 8,
        });
        assert_eq!(var.get_length(), 8);
        assert_eq!(var.get_source(), SourceType::UserDefined);
        let _dt: Box<dyn DataType> = var.get_data_type();
    }
}

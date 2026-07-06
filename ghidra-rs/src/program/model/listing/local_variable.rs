use crate::program::model::listing::Variable;

/// Represents a local variable within a function.
///
/// Extends the [`Variable`] trait with functionality specific to local variables, such as
/// tracking the first use offset within the function.
pub trait LocalVariable: Variable {
    /// Set the first use offset relative to the function entry point.
    ///
    /// # Arguments
    /// * `first_use_offset` - The offset in bytes from the function entry point where this
    ///   variable is first used.
    ///
    /// # Returns
    /// Returns `true` if the offset was successfully set, `false` otherwise.
    fn set_first_use_offset(&mut self, first_use_offset: i32) -> bool;
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::listing::{Function, Program};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::program::seam_stubs::VariableStorage;
    use crate::util::exception::InvalidInputException;

    struct MockDataType;

    impl DataType for MockDataType {}

    struct MockLocalVariable {
        name: Option<String>,
        comment: Option<String>,
        length: i32,
        first_use_offset: i32,
    }

    impl Variable for MockLocalVariable {
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
            false
        }

        fn get_first_use_offset(&self) -> i32 {
            self.first_use_offset
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

    impl LocalVariable for MockLocalVariable {
        fn set_first_use_offset(&mut self, first_use_offset: i32) -> bool {
            self.first_use_offset = first_use_offset;
            true
        }
    }

    #[test]
    fn set_first_use_offset_updates_state() {
        let mut var = MockLocalVariable {
            name: Some("local_1".to_string()),
            comment: None,
            length: 4,
            first_use_offset: 0,
        };
        assert_eq!(var.get_first_use_offset(), 0);
        assert!(var.set_first_use_offset(16));
        assert_eq!(var.get_first_use_offset(), 16);
    }

    #[test]
    fn set_first_use_offset_accepts_negative_offsets() {
        let mut var = MockLocalVariable {
            name: Some("param".to_string()),
            comment: None,
            length: 8,
            first_use_offset: 0,
        };
        assert!(var.set_first_use_offset(-4));
        assert_eq!(var.get_first_use_offset(), -4);
    }

    #[test]
    fn set_first_use_offset_returns_true_on_success() {
        let mut var = MockLocalVariable {
            name: Some("local_2".to_string()),
            comment: None,
            length: 4,
            first_use_offset: 0,
        };
        assert_eq!(var.set_first_use_offset(32), true);
    }

    #[test]
    fn trait_object_usage_with_local_variable() {
        let mut var: Box<dyn LocalVariable> = Box::new(MockLocalVariable {
            name: Some("local_3".to_string()),
            comment: None,
            length: 4,
            first_use_offset: 8,
        });
        assert_eq!(var.get_first_use_offset(), 8);
        assert!(var.set_first_use_offset(20));
        assert_eq!(var.get_first_use_offset(), 20);
    }
}

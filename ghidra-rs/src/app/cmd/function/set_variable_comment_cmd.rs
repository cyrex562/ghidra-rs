use std::sync::Arc;

use crate::framework::cmd::Command;
use crate::program::model::listing::{Program, Variable};

/// A command to set the comment on a function variable.
pub struct SetVariableCommentCmd {
    var: Arc<dyn Variable>,
    comment: Option<String>,
}

impl SetVariableCommentCmd {
    /// Creates a new command that will set the comment on the given variable.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable on which to set the comment.
    /// * `comment` - The comment string to set on the specified variable.
    pub fn new(var: Arc<dyn Variable>, comment: Option<String>) -> Self {
        SetVariableCommentCmd { var, comment }
    }
}

impl Command<dyn Program + 'static> for SetVariableCommentCmd {
    fn apply_to(&mut self, _program: &mut (dyn Program + 'static)) -> bool {
        let var_ptr = self.var.as_ref() as *const dyn Variable as *mut dyn Variable;
        unsafe {
            (*var_ptr).set_comment(self.comment.clone());
        }
        true
    }

    fn status_msg(&self) -> Option<String> {
        None
    }

    fn name(&self) -> String {
        "Set Variable Comment".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::variable::UnsupportedOperationError;
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::program::seam_stubs::VariableStorage;
    use crate::util::exception::InvalidInputException;
    use std::cmp::Ordering;
    use std::sync::Arc;

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

        fn get_function(&self) -> Option<Box<dyn crate::program::model::listing::Function>> {
            None
        }

        fn get_program(&self) -> Arc<dyn Program> {
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
            Arc::new(MockProgram)
        }

        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_name(
            &mut self,
            name: &str,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::variable::SetVariableNameError> {
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

        fn get_min_address(&self) -> Option<crate::program::model::address::Address> {
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

        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name() && self.get_length() == variable.get_length()
        }

        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.get_name().cmp(&other.get_name())
        }
    }

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    #[test]
    fn command_name_is_correct() {
        let var = Arc::new(MockVariable {
            name: Some("local_1".to_string()),
            comment: None,
            length: 4,
        });
        let cmd = SetVariableCommentCmd::new(var, Some("test comment".to_string()));
        assert_eq!(cmd.name(), "Set Variable Comment");
    }

    #[test]
    fn command_status_msg_is_none() {
        let var = Arc::new(MockVariable {
            name: Some("local_1".to_string()),
            comment: None,
            length: 4,
        });
        let cmd = SetVariableCommentCmd::new(var, Some("test comment".to_string()));
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_sets_comment() {
        let var = Arc::new(MockVariable {
            name: Some("local_1".to_string()),
            comment: None,
            length: 4,
        });
        let mut cmd = SetVariableCommentCmd::new(var.clone(), Some("new comment".to_string()));
        let mut program = MockProgram;

        assert_eq!(var.get_comment(), None);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(var.get_comment(), Some("new comment".to_string()));
    }

    #[test]
    fn apply_to_sets_none_comment() {
        let var = Arc::new(MockVariable {
            name: Some("local_1".to_string()),
            comment: Some("old comment".to_string()),
            length: 4,
        });
        let mut cmd = SetVariableCommentCmd::new(var.clone(), None);
        let mut program = MockProgram;

        assert_eq!(var.get_comment(), Some("old comment".to_string()));
        assert!(cmd.apply_to(&mut program));
        assert_eq!(var.get_comment(), None);
    }
}

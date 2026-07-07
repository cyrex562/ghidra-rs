use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::{Function, Program};

/// A command to set the stack purge size of a function.
pub struct SetFunctionPurgeCommand {
    entry_point: Address,
    purge_size: i32,
}

impl SetFunctionPurgeCommand {
    /// Creates a new command that will set the given purge size on the given function.
    ///
    /// # Arguments
    ///
    /// * `function` - The function on which to set the purge size.
    /// * `new_purge` - The new stack purge size.
    pub fn new(function: &dyn Function, new_purge: i32) -> Self {
        SetFunctionPurgeCommand {
            entry_point: function.get_entry_point(),
            purge_size: new_purge,
        }
    }
}

impl Command<dyn Program + 'static> for SetFunctionPurgeCommand {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        if let Some(listing) = program.get_listing() {
            if let Some(function) = listing.get_function_at(&self.entry_point) {
                let func_ptr = function.as_ref() as *const dyn Function as *mut dyn Function;
                unsafe {
                    (*func_ptr).set_stack_purge_size(self.purge_size);
                }
                return true;
            }
        }
        false
    }

    fn status_msg(&self) -> Option<String> {
        None
    }

    fn name(&self) -> String {
        "Set Function Purge".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockFunction {
        purge_size: i32,
        entry_point: Address,
    }

    impl crate::program::model::symbol::Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!()
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn has_var_args(&self) -> bool {
            false
        }

        fn set_var_args(&mut self, _has_var_args: bool) {}

        fn get_name(&self) -> String {
            "test_func".to_string()
        }

        fn set_name(
            &mut self,
            _name: &str,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            Ok(())
        }

        fn get_entry_point(&self) -> crate::program::model::address::Address {
            self.entry_point
        }

        fn set_stack_purge_size(&mut self, purge_size: i32) {
            self.purge_size = purge_size;
        }

        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }
    }

    struct MockListing;

    impl crate::program::model::listing::Listing for MockListing {
        fn get_function_at(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_code_units_containing(&self, _addr: &Address) -> Option<Box<dyn crate::program::seam_stubs::CodeUnitIterator + '_>> {
            None
        }

        fn get_instruction_at(&self, _addr: &Address) -> Option<Arc<dyn crate::program::model::listing::Instruction>> {
            None
        }
    }

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl Program for MockProgram {
        fn get_listing(&self) -> Option<Arc<dyn crate::program::model::listing::Listing>> {
            None
        }
    }

    #[test]
    fn test_set_function_purge_size() {
        let mock_func = MockFunction {
            purge_size: 0,
            entry_point: Address::from(0x1000),
        };

        let mut cmd = SetFunctionPurgeCommand::new(&mock_func, 8);
        assert_eq!(cmd.purge_size, 8);
        assert_eq!(cmd.entry_point, Address::from(0x1000));
    }

    #[test]
    fn test_command_name() {
        let mock_func = MockFunction {
            purge_size: 0,
            entry_point: Address::from(0x1000),
        };

        let cmd = SetFunctionPurgeCommand::new(&mock_func, 8);
        assert_eq!(cmd.name(), "Set Function Purge");
    }

    #[test]
    fn test_command_status_msg() {
        let mock_func = MockFunction {
            purge_size: 0,
            entry_point: Address::from(0x1000),
        };

        let cmd = SetFunctionPurgeCommand::new(&mock_func, 8);
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn test_apply_to_with_no_listing() {
        let mock_func = MockFunction {
            purge_size: 0,
            entry_point: Address::from(0x1000),
        };

        let mut cmd = SetFunctionPurgeCommand::new(&mock_func, 8);
        let mut program = MockProgram;

        assert!(!cmd.apply_to(&mut program));
    }
}

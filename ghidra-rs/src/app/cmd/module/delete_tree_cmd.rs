use crate::framework::cmd::Command;
use crate::program::model::listing::Program;

/// Deletes a tree (module hierarchy) from a program.
pub struct DeleteTreeCmd {
    tree_name: String,
}

impl DeleteTreeCmd {
    /// Creates a new delete tree command for the given tree name.
    pub fn new(tree_name: String) -> Self {
        Self { tree_name }
    }
}

impl<T: Program + ?Sized> Command<T> for DeleteTreeCmd {
    fn apply_to(&mut self, program: &mut T) -> bool {
        if let Some(listing) = program.get_listing() {
            listing.remove_tree(&self.tree_name)
        } else {
            false
        }
    }

    fn status_msg(&self) -> Option<String> {
        None
    }

    fn name(&self) -> String {
        format!("Delete {}", self.tree_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TaskMonitor;
    use std::sync::Arc;

    struct MockListing {
        removed_trees: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl crate::program::model::listing::Listing for MockListing {
        fn get_code_unit_at(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_code_unit_containing(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_code_unit_after(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_code_unit_before(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_code_unit_iterator(
            &self,
            _property: &str,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _addr: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_code_unit_iterator(
            &self,
            _comment_type: crate::program::seam_stubs::CommentType,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_address_iterator(
            &self,
            _comment_type: crate::program::seam_stubs::CommentType,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_any_comment_address_iterator(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment(&self, _comment_type: crate::program::seam_stubs::CommentType, _address: &crate::program::model::address::Address) -> Option<String> {
            None
        }
        fn get_all_comments(&self, _address: &crate::program::model::address::Address) -> Box<dyn crate::program::seam_stubs::CodeUnitComments> {
            struct MockComments;
            impl crate::program::seam_stubs::CodeUnitComments for MockComments {}
            Box::new(MockComments)
        }
        fn set_comment(
            &mut self,
            _address: &crate::program::model::address::Address,
            _comment_type: crate::program::seam_stubs::CommentType,
            _comment: Option<String>,
        ) {
        }
        fn get_code_units(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_units_from(&self, _addr: &crate::program::model::address::Address, _forward: bool) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_units_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instruction_at(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instruction_containing(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instruction_after(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instruction_before(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instructions(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instructions_from(
            &self,
            _addr: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instructions_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_at(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_data_containing(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_data_after(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_data_before(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_data(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_from(&self, _addr: &crate::program::model::address::Address, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_at(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_defined_data_containing(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_defined_data_after(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_defined_data_before(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_defined_data(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_from(&self, _addr: &crate::program::model::address::Address, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_undefined_data_at(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_undefined_data_after(
            &self,
            _addr: &crate::program::model::address::Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_first_undefined_data(
            &self,
            _set: &dyn crate::program::model::address::AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_undefined_data_before(
            &self,
            _addr: &crate::program::model::address::Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_undefined_ranges(
            &self,
            _set: &dyn crate::program::model::address::AddressSetView,
            _initialized_memory_only: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn crate::program::model::address::AddressSetView>, crate::util::exception::CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_code_unit_after(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_defined_code_unit_before(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_user_defined_properties(&self) -> Vec<String> {
            Vec::new()
        }
        fn remove_user_defined_property(&mut self, _property_name: &str) {}
        fn get_property_map(&self, _property_name: &str) -> Option<Box<dyn crate::program::model::util::PropertyMap>> {
            None
        }
        fn create_instruction(
            &mut self,
            _addr: crate::program::model::address::Address,
            _prototype: Arc<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            _mem_buf: &dyn crate::program::seam_stubs::MemBuffer,
            _context: &dyn crate::program::model::lang::ProcessorContextView,
            _length: i32,
        ) -> Result<Arc<dyn crate::program::model::listing::instruction::Instruction>, crate::program::util::CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn add_instructions(
            &mut self,
            _instruction_set: &dyn crate::program::seam_stubs::InstructionSet,
            _overwrite: bool,
        ) -> Result<Box<dyn crate::program::model::address::AddressSetView>, crate::program::util::CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_data_sized(
            &mut self,
            _addr: crate::program::model::address::Address,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _length: i32,
        ) -> Result<Arc<dyn crate::program::model::listing::data::Data>, crate::program::util::CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_data(
            &mut self,
            _addr: crate::program::model::address::Address,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
        ) -> Result<Arc<dyn crate::program::model::listing::data::Data>, crate::program::util::CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn clear_code_units(
            &mut self,
            _start_addr: &crate::program::model::address::Address,
            _end_addr: &crate::program::model::address::Address,
            _clear_context: bool,
        ) {
        }
        fn clear_code_units_with_monitor(
            &mut self,
            _start_addr: &crate::program::model::address::Address,
            _end_addr: &crate::program::model::address::Address,
            _clear_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn is_undefined(&self, _start: &crate::program::model::address::Address, _end: &crate::program::model::address::Address) -> bool {
            true
        }
        fn clear_comments(&mut self, _start_addr: &crate::program::model::address::Address, _end_addr: &crate::program::model::address::Address) {}
        fn clear_properties(
            &mut self,
            _start_addr: &crate::program::model::address::Address,
            _end_addr: &crate::program::model::address::Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn clear_all(&mut self, _clear_context: bool, _monitor: &dyn TaskMonitor) {}
        fn get_fragment(
            &self,
            _tree_name: &str,
            _addr: &crate::program::model::address::Address,
        ) -> Option<Arc<dyn crate::program::model::listing::program_fragment::ProgramFragment>> {
            None
        }
        fn get_module(&self, _tree_name: &str, _name: &str) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }
        fn get_fragment_by_name(
            &self,
            _tree_name: &str,
            _name: &str,
        ) -> Option<Arc<dyn crate::program::model::listing::program_fragment::ProgramFragment>> {
            None
        }
        fn create_root_module(
            &mut self,
            _tree_name: &str,
        ) -> Result<Arc<dyn crate::program::model::listing::program_module::ProgramModule>, crate::util::exception::DuplicateNameException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_root_module(&self, _tree_name: &str) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }
        fn get_root_module_by_id(&self, _tree_id: i64) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }
        fn get_default_root_module(&self) -> Arc<dyn crate::program::model::listing::program_module::ProgramModule> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_tree_names(&self) -> Vec<String> {
            vec!["Program Tree".to_string()]
        }
        fn remove_tree(&mut self, tree_name: &str) -> bool {
            self.removed_trees
                .lock()
                .unwrap()
                .push(tree_name.to_string());
            true
        }
        fn rename_tree(
            &mut self,
            _old_name: &str,
            _new_name: &str,
        ) -> Result<(), crate::util::exception::DuplicateNameException> {
            Ok(())
        }
        fn get_num_code_units(&self) -> i64 {
            0
        }
        fn get_num_defined_data(&self) -> i64 {
            0
        }
        fn get_num_instructions(&self) -> i64 {
            0
        }
        fn get_data_type_manager(&self) -> Box<dyn crate::program::model::data::data_type_manager::DataTypeManager> {
            struct MockDataTypeManager;
            impl crate::program::model::data::data_type_manager::DataTypeManager for MockDataTypeManager {}
            Box::new(MockDataTypeManager)
        }
        fn create_function(
            &mut self,
            _name: &str,
            _entry_point: crate::program::model::address::Address,
            _body: &dyn crate::program::model::address::AddressSetView,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn crate::program::model::listing::function::Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_function_in_namespace(
            &mut self,
            _name: &str,
            _name_space: Arc<dyn crate::program::model::symbol::Namespace>,
            _entry_point: crate::program::model::address::Address,
            _body: &dyn crate::program::model::address::AddressSetView,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn crate::program::model::listing::function::Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn remove_function(&mut self, _entry_point: &crate::program::model::address::Address) {}
        fn get_function_at(&self, _entry_point: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            None
        }
        fn get_global_functions(&self, _name: &str) -> Vec<Arc<dyn crate::program::model::listing::function::Function>> {
            Vec::new()
        }
        fn get_functions_by_name(
            &self,
            _namespace: Option<&str>,
            _name: &str,
        ) -> Vec<Arc<dyn crate::program::model::listing::function::Function>> {
            Vec::new()
        }
        fn get_function_containing(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            None
        }
        fn get_external_functions(&self) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_from(&self, _start: &crate::program::model::address::Address, _forward: bool) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_in(
            &self,
            _asv: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_in_function(&self, _addr: &crate::program::model::address::Address) -> bool {
            false
        }
        fn get_comment_history(
            &self,
            _addr: &crate::program::model::address::Address,
            _comment_type: crate::program::seam_stubs::CommentType,
        ) -> Vec<Box<dyn crate::program::seam_stubs::CommentHistory>> {
            Vec::new()
        }
        fn get_comment_address_count(&self) -> i64 {
            0
        }
    }

    struct MockProgram {
        listing: MockListing,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl crate::program::model::listing::Program for MockProgram {
        fn get_name(&self) -> String {
            "test_program".to_string()
        }

        fn get_language_id(&self) -> String {
            "test_lang".to_string()
        }

        fn get_listing(&mut self) -> Option<&mut dyn crate::program::model::listing::Listing> {
            Some(&mut self.listing)
        }
    }

    #[test]
    fn test_delete_tree_applies_successfully() {
        let removed_trees = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cmd = DeleteTreeCmd::new("MyTree".to_string());
        let mut program = MockProgram {
            listing: MockListing {
                removed_trees: removed_trees.clone(),
            },
        };

        assert!(cmd.apply_to(&mut program));
        assert_eq!(removed_trees.lock().unwrap().as_slice(), &["MyTree"]);
    }

    #[test]
    fn test_delete_tree_command_name() {
        let cmd = DeleteTreeCmd::new("MyTree".to_string());
        assert_eq!(cmd.name(), "Delete MyTree");
    }

    #[test]
    fn test_delete_tree_status_msg() {
        let cmd = DeleteTreeCmd::new("MyTree".to_string());
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn test_delete_tree_with_special_characters() {
        let removed_trees = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cmd = DeleteTreeCmd::new("Program Tree".to_string());
        let mut program = MockProgram {
            listing: MockListing {
                removed_trees: removed_trees.clone(),
            },
        };

        assert!(cmd.apply_to(&mut program));
        assert_eq!(removed_trees.lock().unwrap().as_slice(), &["Program Tree"]);
    }

    #[test]
    fn test_delete_tree_multiple_invocations() {
        let removed_trees = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cmd = DeleteTreeCmd::new("Tree1".to_string());
        let mut program = MockProgram {
            listing: MockListing {
                removed_trees: removed_trees.clone(),
            },
        };

        cmd.apply_to(&mut program);
        let mut cmd2 = DeleteTreeCmd::new("Tree2".to_string());
        cmd2.apply_to(&mut program);

        let removed = removed_trees.lock().unwrap();
        assert_eq!(removed.as_slice(), &["Tree1", "Tree2"]);
    }
}

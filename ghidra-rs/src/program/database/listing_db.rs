//! Port of `ghidra.program.database.ListingDB`.
//!
//! The Java type is a package-private class that implements `Listing` by delegating every
//! method to the program's [`CodeManager`](crate::program::database::code::CodeManager),
//! [`TreeManager`](crate::program::database::module::TreeManager), and
//! [`FunctionManager`](crate::program::model::listing::FunctionManager) (obtained from a
//! [`ProgramDB`] via `setProgram`). Because `ListingDB` sits between `ProgramDB` and those three
//! managers, it was selected as a dependency-cycle cut-point. Following the same convention
//! already used for
//! [`TreeManager`](crate::program::database::module::TreeManager), this port models `ListingDB`
//! as an object-safe trait rather than a concrete struct wired to concrete manager types: it
//! extends [`Listing`] (whose full method surface `ListingDB` implements verbatim, with
//! `@Override` on every method) and adds the one method `ListingDB` itself introduces,
//! `setProgram`. The actual field wiring (which manager backs which delegated call) is an
//! implementation detail left to whatever concrete type implements this trait, matching how
//! `TreeManager::set_program` already takes the concrete [`ProgramDB`] without requiring this
//! crate to have ported `ProgramDB`'s own manager accessors yet.

use std::sync::Arc;

use crate::program::database::program_db::ProgramDB;
use crate::program::model::listing::Listing;

/// Database implementation of [`Listing`].
///
/// Port of `ghidra.program.database.ListingDB`. See the module docs for why this is modeled as a
/// trait (a dependency-cycle cut-point) rather than a concrete struct.
pub trait ListingDB: Listing {
    /// Callback from the program used to bind this listing to its owning program and (in a
    /// concrete implementation) the program's code/tree/function managers.
    ///
    /// Stands in for `ListingDB.setProgram(ProgramDB)`.
    fn set_program(&mut self, program: Arc<ProgramDB>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, BoxedAddressIterator, AddressSetView};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::ProcessorContextView;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::function::Function;
    use crate::program::model::listing::instruction::Instruction;
    use crate::program::model::listing::program_fragment::ProgramFragment;
    use crate::program::model::listing::program_module::ProgramModule;
    use crate::program::model::listing::CreateFunctionError;
    use crate::program::model::symbol::{Namespace, SourceType};
    use crate::program::model::util::PropertyMap;
    use crate::program::seam_stubs::{
        CodeUnitComments, CodeUnitIterator, CommentHistory, CommentType, DataIterator,
        FunctionIterator, InstructionIterator, InstructionSet, MemBuffer,
    };
    use crate::program::util::CodeUnitInsertionException;
    use crate::util::exception::{CancelledException, DuplicateNameException};
    use crate::util::task::TaskMonitor;

    /// Mock proving `ListingDB` is object-safe and usable as a trait object, and that a
    /// concrete implementation can genuinely delegate to injected state (as the real class
    /// delegates to its managers) rather than being wired up with stubs everywhere.
    struct MockListingDb {
        tree_names: Vec<String>,
        num_instructions: i64,
    }

    impl MockListingDb {
        fn new() -> Self {
            Self {
                tree_names: vec!["Program Tree".to_string()],
                num_instructions: 0,
            }
        }
    }

    impl ListingDB for MockListingDb {
        // A concrete implementation would bind its manager fields here (as `ListingDB.setProgram`
        // does via `program.getCodeManager()` etc.); building a full `ProgramDB` is out of scope
        // for this object-safety smoke test.
        fn set_program(&mut self, _program: Arc<ProgramDB>) {}
    }

    impl Listing for MockListingDb {
        fn get_code_unit_at(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_containing(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_iterator(
            &self,
            _property: &str,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_code_unit_iterator(
            &self,
            _comment_type: CommentType,
            _addr_set: &dyn AddressSetView,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_address_iterator(
            &self,
            _comment_type: CommentType,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> BoxedAddressIterator {
            unimplemented!("not needed for this smoke test")
        }
        fn get_any_comment_address_iterator(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> BoxedAddressIterator {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment(&self, _comment_type: CommentType, _address: &Address) -> Option<String> {
            None
        }
        fn get_all_comments(&self, _address: &Address) -> Box<dyn CodeUnitComments> {
            struct MockComments;
            impl CodeUnitComments for MockComments {}
            Box::new(MockComments)
        }
        fn set_comment(
            &mut self,
            _address: &Address,
            _comment_type: CommentType,
            _comment: Option<String>,
        ) {
        }
        fn get_code_units(&self, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_units_from(&self, _addr: &Address, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_units_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instruction_at(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_containing(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_after(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_before(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instructions(&self, _forward: bool) -> Box<dyn InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instructions_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instructions_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_containing(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_after(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_before(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data(&self, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_from(&self, _addr: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_containing(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_after(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_before(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data(&self, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_from(&self, _addr: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_undefined_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_after(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_first_undefined_data(
            &self,
            _set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_before(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_ranges(
            &self,
            _set: &dyn AddressSetView,
            _initialized_memory_only: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn AddressSetView>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_defined_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_user_defined_properties(&self) -> Vec<String> {
            Vec::new()
        }
        fn remove_user_defined_property(&mut self, _property_name: &str) {}
        fn get_property_map(&self, _property_name: &str) -> Option<Box<dyn PropertyMap>> {
            None
        }
        fn create_instruction(
            &mut self,
            _addr: Address,
            _prototype: Arc<dyn InstructionPrototype>,
            _mem_buf: &dyn MemBuffer,
            _context: &dyn ProcessorContextView,
            _length: i32,
        ) -> Result<Arc<dyn Instruction>, CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn add_instructions(
            &mut self,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Result<Box<dyn AddressSetView>, CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_data_sized(
            &mut self,
            _addr: Address,
            _data_type: Box<dyn DataType>,
            _length: i32,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_data(
            &mut self,
            _addr: Address,
            _data_type: Box<dyn DataType>,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn clear_code_units(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _clear_context: bool,
        ) {
        }
        fn clear_code_units_with_monitor(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _clear_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn is_undefined(&self, _start: &Address, _end: &Address) -> bool {
            true
        }
        fn clear_comments(&mut self, _start_addr: &Address, _end_addr: &Address) {}
        fn clear_properties(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn clear_all(&mut self, _clear_context: bool, _monitor: &dyn TaskMonitor) {}
        fn get_fragment(
            &self,
            _tree_name: &str,
            _addr: &Address,
        ) -> Option<Arc<dyn ProgramFragment>> {
            None
        }
        fn get_module(&self, _tree_name: &str, _name: &str) -> Option<Arc<dyn ProgramModule>> {
            None
        }
        fn get_fragment_by_name(
            &self,
            _tree_name: &str,
            _name: &str,
        ) -> Option<Arc<dyn ProgramFragment>> {
            None
        }
        fn create_root_module(
            &mut self,
            _tree_name: &str,
        ) -> Result<Arc<dyn ProgramModule>, DuplicateNameException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_root_module(&self, _tree_name: &str) -> Option<Arc<dyn ProgramModule>> {
            None
        }
        fn get_root_module_by_id(&self, _tree_id: i64) -> Option<Arc<dyn ProgramModule>> {
            None
        }
        fn get_default_root_module(&self) -> Arc<dyn ProgramModule> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_tree_names(&self) -> Vec<String> {
            self.tree_names.clone()
        }
        fn remove_tree(&mut self, tree_name: &str) -> bool {
            if self.tree_names.len() <= 1 {
                return false;
            }
            let before = self.tree_names.len();
            self.tree_names.retain(|n| n != tree_name);
            self.tree_names.len() < before
        }
        fn rename_tree(
            &mut self,
            old_name: &str,
            new_name: &str,
        ) -> Result<(), DuplicateNameException> {
            if self.tree_names.iter().any(|n| n == new_name) {
                return Err(DuplicateNameException::with_message(new_name.to_string()));
            }
            if let Some(entry) = self.tree_names.iter_mut().find(|n| n.as_str() == old_name) {
                *entry = new_name.to_string();
            }
            Ok(())
        }
        fn get_num_code_units(&self) -> i64 {
            self.get_num_defined_data() + self.get_num_instructions()
        }
        fn get_num_defined_data(&self) -> i64 {
            0
        }
        fn get_num_instructions(&self) -> i64 {
            self.num_instructions
        }
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            struct MockDataTypeManager;
            impl DataTypeManager for MockDataTypeManager {}
            Box::new(MockDataTypeManager)
        }
        fn create_function(
            &mut self,
            _name: &str,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_function_in_namespace(
            &mut self,
            _name: &str,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn remove_function(&mut self, _entry_point: &Address) {}
        fn get_function_at(&self, _entry_point: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_global_functions(&self, _name: &str) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn get_functions_by_name(
            &self,
            _namespace: Option<&str>,
            _name: &str,
        ) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_external_functions(&self) -> Box<dyn FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions(&self, _forward: bool) -> Box<dyn FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_from(&self, _start: &Address, _forward: bool) -> Box<dyn FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }
        fn get_comment_history(
            &self,
            _addr: &Address,
            _comment_type: CommentType,
        ) -> Vec<Box<dyn CommentHistory>> {
            Vec::new()
        }
        fn get_comment_address_count(&self) -> i64 {
            0
        }
    }

    #[test]
    fn usable_as_trait_object_and_delegates_state() {
        let mut listing: Box<dyn ListingDB> = Box::new(MockListingDb::new());

        // Real behavior: renaming and removing trees mutates the underlying state, not a
        // trivially-true stub.
        assert_eq!(listing.get_tree_names(), vec!["Program Tree".to_string()]);
        assert!(!listing.remove_tree("Program Tree"), "last tree cannot be removed");

        listing
            .rename_tree("Program Tree", "Main Tree")
            .expect("rename should succeed");
        assert_eq!(listing.get_tree_names(), vec!["Main Tree".to_string()]);

        assert_eq!(
            listing.rename_tree("Main Tree", "Main Tree"),
            Err(DuplicateNameException::with_message("Main Tree".to_string()))
        );

        assert_eq!(listing.get_num_instructions(), 0);
        assert_eq!(listing.get_num_code_units(), 0);
    }
}

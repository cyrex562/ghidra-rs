//! Listing of code units in a trace program view.
//!
//! Java source: `ghidra.trace.model.program.TraceProgramViewListing`.
use crate::program::model::listing::listing::Listing;
use crate::trace::model::program::snap_specific_trace_view::SnapSpecificTraceView;
use crate::trace::model::program::trace_program_view::TraceProgramView;

/// A [`Listing`] as seen through a [`TraceProgramView`], specific to a snapshot.
///
/// Port of `ghidra.trace.model.program.TraceProgramViewListing`.
pub trait TraceProgramViewListing: Listing + SnapSpecificTraceView {
    /// Returns the trace program view that owns this listing.
    fn get_program(&self) -> Box<dyn TraceProgramView>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::{Address, AddressSetView, BoxedAddressIterator};
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
    use crate::program::model::listing::CommentType;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::symbol::Namespace;
    use crate::program::model::util::PropertyMap;
    use crate::program::seam_stubs::{
        CodeUnitComments, CodeUnitIterator, CommentHistory, DataIterator, FunctionIterator,
        InstructionIterator, InstructionSet,
    };
    use crate::program::util::CodeUnitInsertionException;
    use crate::util::exception::{CancelledException, DuplicateNameException};
    use crate::util::task::TaskMonitor;
    use std::sync::Arc;

    struct MockTraceProgramView;

    impl DomainObject for MockTraceProgramView {}

    impl crate::program::model::listing::program::Program for MockTraceProgramView {
        fn get_name(&self) -> String {
            "mock-view".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    impl TraceProgramView for MockTraceProgramView {
        fn get_trace_program_view_memory(
            &self,
        ) -> Box<dyn crate::trace::model::program::trace_program_view_memory::TraceProgramViewMemory>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_snap(&self) -> i64 {
            0
        }

        fn get_viewport(
            &self,
        ) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_max_snap(&self) -> Option<i64> {
            None
        }
    }

    struct MockListing {
        snap: i64,
    }

    impl Listing for MockListing {
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

        fn get_code_unit_iterator(&self, _property: &str, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_comment_code_unit_iterator_by_ordinal(
            &self,
            _comment_type: i32,
            _addr_set: &dyn AddressSetView,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_comment_code_unit_iterator(
            &self,
            _comment_type: CommentType,
            _addr_set: &dyn AddressSetView,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_comment_address_iterator_by_ordinal(
            &self,
            _comment_type: i32,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> BoxedAddressIterator {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_comment_address_iterator(
            &self,
            _comment_type: CommentType,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> BoxedAddressIterator {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_any_comment_address_iterator(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> BoxedAddressIterator {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_comment_by_ordinal(&self, _comment_type: i32, _address: &Address) -> Option<String> {
            None
        }

        fn get_comment(&self, _comment_type: CommentType, _address: &Address) -> Option<String> {
            None
        }

        fn get_all_comments(&self, _address: &Address) -> Box<dyn CodeUnitComments> {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_comment_by_ordinal(
            &mut self,
            _address: &Address,
            _comment_type: i32,
            _comment: Option<String>,
        ) {
        }

        fn set_comment(
            &mut self,
            _address: &Address,
            _comment_type: CommentType,
            _comment: Option<String>,
        ) {
        }

        fn get_code_units(&self, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_units_from(&self, _addr: &Address, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_units_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
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
            unimplemented!("not exercised by this smoke test")
        }

        fn get_instructions_from(&self, _addr: &Address, _forward: bool) -> Box<dyn InstructionIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_instructions_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!("not exercised by this smoke test")
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
            unimplemented!("not exercised by this smoke test")
        }

        fn get_data_from(&self, _addr: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_data_in(&self, _addr_set: &dyn AddressSetView, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this smoke test")
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
            unimplemented!("not exercised by this smoke test")
        }

        fn get_defined_data_from(&self, _addr: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_defined_data_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this smoke test")
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
            unimplemented!("not exercised by this smoke test")
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
            unimplemented!("not exercised by this smoke test")
        }

        fn add_instructions(
            &mut self,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Result<Box<dyn AddressSetView>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_data_sized(
            &mut self,
            _addr: Address,
            _data_type: Box<dyn DataType>,
            _length: i32,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_data(
            &mut self,
            _addr: Address,
            _data_type: Box<dyn DataType>,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn clear_code_units(&mut self, _start_addr: &Address, _end_addr: &Address, _clear_context: bool) {}

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
            false
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

        fn get_fragment(&self, _tree_name: &str, _addr: &Address) -> Option<Arc<dyn ProgramFragment>> {
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
            unimplemented!("not exercised by this smoke test")
        }

        fn get_root_module(&self, _tree_name: &str) -> Option<Arc<dyn ProgramModule>> {
            None
        }

        fn get_root_module_by_id(&self, _tree_id: i64) -> Option<Arc<dyn ProgramModule>> {
            None
        }

        fn get_default_root_module(&self) -> Arc<dyn ProgramModule> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_tree_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn remove_tree(&mut self, _tree_name: &str) -> bool {
            false
        }

        fn rename_tree(
            &mut self,
            _old_name: &str,
            _new_name: &str,
        ) -> Result<(), DuplicateNameException> {
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

        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_function(
            &mut self,
            _name: &str,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionErrorAlias> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_function_in_namespace(
            &mut self,
            _name: &str,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionErrorAlias> {
            unimplemented!("not exercised by this smoke test")
        }

        fn remove_function(&mut self, _entry_point: &Address) {}

        fn get_function_at(&self, _entry_point: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_global_functions(&self, _name: &str) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }

        fn get_functions_by_name(&self, _namespace: Option<&str>, _name: &str) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }

        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_external_functions(&self) -> Box<dyn FunctionIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_functions(&self, _forward: bool) -> Box<dyn FunctionIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_functions_from(&self, _start: &Address, _forward: bool) -> Box<dyn FunctionIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_functions_in(&self, _asv: &dyn AddressSetView, _forward: bool) -> Box<dyn FunctionIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }

        fn get_comment_history_by_ordinal(
            &self,
            _addr: &Address,
            _comment_type: i32,
        ) -> Vec<Box<dyn CommentHistory>> {
            Vec::new()
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

    impl SnapSpecificTraceView for MockListing {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_snap(&self) -> i64 {
            self.snap
        }
    }

    impl TraceProgramViewListing for MockListing {
        fn get_program(&self) -> Box<dyn TraceProgramView> {
            Box::new(MockTraceProgramView)
        }
    }

    type CreateFunctionErrorAlias = crate::program::model::listing::listing::CreateFunctionError;

    #[test]
    fn reports_snap_from_snap_specific_view() {
        let listing = MockListing { snap: 9 };
        assert_eq!(SnapSpecificTraceView::get_snap(&listing), 9);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let listing: Box<dyn TraceProgramViewListing> = Box::new(MockListing { snap: 4 });
        assert_eq!(SnapSpecificTraceView::get_snap(&*listing), 4);
        let program = listing.get_program();
        assert_eq!(program.get_snap(), 0);
        assert!(listing.get_code_unit_at(&test_address(0x100)).is_none());
    }

    fn test_address(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }
}

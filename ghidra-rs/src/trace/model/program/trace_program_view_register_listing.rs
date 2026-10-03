use crate::trace::model::program::trace_program_view_listing::TraceProgramViewListing;
use crate::trace::model::thread::TraceThread;

/// A [`TraceProgramViewListing`] specific to a single thread's register space.
///
/// Port of `ghidra.trace.model.program.TraceProgramViewRegisterListing`.
pub trait TraceProgramViewRegisterListing: TraceProgramViewListing {
    /// Returns the thread whose register space this listing presents.
    fn get_thread(&self) -> Box<dyn TraceThread>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressSetView, BoxedAddressIterator};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::ProcessorContextView;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::function::Function;
    use crate::program::model::listing::instruction::Instruction;
    use crate::program::model::listing::listing::Listing;
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
    use crate::trace::model::program::snap_specific_trace_view::SnapSpecificTraceView;
    use crate::trace::model::program::trace_program_view::TraceProgramView;
    use crate::trace::model::target::iface::TraceObjectInterface;
    use crate::trace::model::target::trace_object::TraceObject;
    use crate::trace::model::trace_unique_object::TraceUniqueObject;
    use crate::trace::seam_stubs::ObjectKey;
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

    struct MockObjectKey(i32);

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>().is_some_and(|other| other.0 == self.0)
        }
        fn hash_code(&self) -> i32 {
            self.0
        }
        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    struct MockThread {
        name: String,
    }

    impl TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl crate::trace::model::thread::TraceThread for MockThread {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_key(&self) -> i64 {
            1
        }
        fn get_path(&self) -> String {
            self.name.clone()
        }
        fn get_name(&self, _snap: i64) -> String {
            self.name.clone()
        }
        fn set_name(&mut self, _lifespan: crate::trace::model::lifespan::Lifespan, name: &str) {
            self.name = name.to_string();
        }
        fn set_name_at(&mut self, _snap: i64, name: &str) {
            self.name = name.to_string();
        }
        fn set_comment(&mut self, _snap: i64, _comment: Option<&str>) {}
        fn get_comment(&self, _snap: i64) -> Option<String> {
            None
        }
        fn delete(&mut self) {}
        fn remove(&mut self, _snap: i64) {}
        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
        fn is_alive(&self, _span: crate::trace::model::lifespan::Lifespan) -> bool {
            true
        }
    }

    /// A `Listing` + `SnapSpecificTraceView` implementor, matching (method-for-method) the
    /// `MockListing` test double already established in
    /// [`crate::trace::model::program::trace_program_view_listing`]'s own tests, extended here
    /// with a `thread` field to also satisfy `TraceProgramViewRegisterListing::get_thread`.
    struct MockRegisterListing {
        snap: i64,
        thread_name: String,
    }

    impl Listing for MockRegisterListing {
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
        ) -> Result<Arc<dyn Function>, crate::program::model::listing::listing::CreateFunctionError> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_function_in_namespace(
            &mut self,
            _name: &str,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn Function>, crate::program::model::listing::listing::CreateFunctionError> {
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

    impl SnapSpecificTraceView for MockRegisterListing {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_snap(&self) -> i64 {
            self.snap
        }
    }

    impl TraceProgramViewListing for MockRegisterListing {
        fn get_program(&self) -> Box<dyn TraceProgramView> {
            Box::new(MockTraceProgramView)
        }
    }

    impl TraceProgramViewRegisterListing for MockRegisterListing {
        fn get_thread(&self) -> Box<dyn crate::trace::model::thread::TraceThread> {
            Box::new(MockThread { name: self.thread_name.clone() })
        }
    }

    #[test]
    fn get_thread_returns_configured_thread() {
        let listing = MockRegisterListing { snap: 0, thread_name: "thread0".to_string() };
        let thread = listing.get_thread();
        assert_eq!(thread.get_path(), "thread0");
    }

    #[test]
    fn get_program_reachable_via_trace_program_view_listing_supertrait() {
        let listing = MockRegisterListing { snap: 0, thread_name: "thread0".to_string() };
        let program = TraceProgramViewListing::get_program(&listing);
        assert_eq!(
            crate::program::model::listing::program::Program::get_name(program.as_ref()),
            "mock-view"
        );
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let listing: Box<dyn TraceProgramViewRegisterListing> =
            Box::new(MockRegisterListing { snap: 4, thread_name: "main".to_string() });
        assert_eq!(listing.get_thread().get_path(), "main");
        assert_eq!(SnapSpecificTraceView::get_snap(&*listing), 4);
    }
}

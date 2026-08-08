//! View of a trace at a particular time, as a program.
//!
//! Java source: `ghidra.trace.model.program.TraceProgramView`.
use crate::program::model::listing::program::Program;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_time_viewport::TraceTimeViewport;
use crate::trace::model::program::trace_program_view_memory::TraceProgramViewMemory;

/// A view of a trace at a particular time, as a program.
///
/// Port of `ghidra.trace.model.program.TraceProgramView`.
///
/// The Java interface overrides `Program::getMemory()` to covariantly narrow its return type to
/// `TraceProgramViewMemory`. Rust does not support covariant trait-method overrides, so that
/// override is exposed here under a distinct name,
/// [`TraceProgramView::get_trace_program_view_memory`], rather than redeclaring
/// [`Program::get_memory`]. Implementors should still implement `Program::get_memory`
/// (delegating to `get_trace_program_view_memory`), mirroring the Java override.
pub trait TraceProgramView: Program {
    /// Returns the memory of this view.
    ///
    /// This is the covariant override of `Program::getMemory()` in the Java source; see the
    /// trait-level documentation for why it is exposed under a distinct name here.
    fn get_trace_program_view_memory(&self) -> Box<dyn TraceProgramViewMemory>;

    /// Get the trace this view presents.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the current snap.
    fn get_snap(&self) -> i64;

    /// Get the viewport this view is using for forked queries.
    fn get_viewport(&self) -> Box<dyn TraceTimeViewport>;

    /// Get the trace's latest snap.
    fn get_max_snap(&self) -> Option<i64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::app::merge::DataTypeManagerOwner;

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockTrace;
    impl DomainObject for MockTrace {}

    impl DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> &dyn DataTypeManager {
            static MANAGER: MockDataTypeManager = MockDataTypeManager;
            &MANAGER
        }
    }

    impl DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_emulator_cache_version(&mut self, _version: i64) {}

        fn get_emulator_cache_version(&self) -> i64 {
            0
        }

        fn get_base_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_property_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_breakpoint_manager(&self) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_data_type_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_equate_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform_manager(&self) -> Box<dyn crate::trace::model::guest::trace_platform_manager::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_object_manager(&self) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_reference_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_symbol_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_time_manager(&self) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_program_view(&self) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_time_viewport(&self) -> Box<dyn TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }

        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
        }

        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
        }

        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }

        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockMemory;
    impl crate::program::model::mem::memory::Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_byte(
            &self,
            _addr: &crate::program::model::address::Address,
        ) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            Ok(0)
        }

        fn get_bytes(&self, _addr: &crate::program::model::address::Address, dest: &mut [u8]) -> usize {
            dest.len()
        }

        fn set_bytes(
            &mut self,
            _addr: &crate::program::model::address::Address,
            _source: &[u8],
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            Ok(())
        }
    }

    impl crate::trace::model::program::snap_specific_trace_view::SnapSpecificTraceView for MockMemory {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace)
        }

        fn get_snap(&self) -> i64 {
            5
        }
    }

    impl TraceProgramViewMemory for MockMemory {
        fn get_trace_program_view(&self) -> Box<dyn TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_force_full_view(&mut self, _force_full_view: bool) {}

        fn is_force_full_view(&self) -> bool {
            false
        }
    }

    struct MockTimeViewport;
    impl TraceTimeViewport for MockTimeViewport {
        fn set_snap(&mut self, _snap: i64) {}

        fn add_change_listener(&mut self, _l: crate::util::function::Runnable) {}

        fn remove_change_listener(&mut self, _l: &crate::util::function::Runnable) {}

        fn is_forked(&self) -> bool {
            false
        }

        fn contains_any_upper(&self, _lifespan: &dyn crate::trace::model::lifespan::Lifespan) -> bool {
            false
        }

        fn is_completely_visible(
            &self,
            _range: &crate::program::model::address::range::AddressRange,
            _lifespan: &dyn crate::trace::model::lifespan::Lifespan,
            _object: &dyn std::any::Any,
            _occlusion: &dyn crate::trace::model::trace_time_viewport::Occlusion,
        ) -> bool {
            true
        }

        fn compute_visible_parts(
            &self,
            _set: &dyn crate::program::model::address::address_set::AddressSetView,
            _lifespan: &dyn crate::trace::model::lifespan::Lifespan,
            _object: &dyn std::any::Any,
            _occlusion: &dyn crate::trace::model::trace_time_viewport::Occlusion,
        ) -> crate::program::model::address::address_set::AddressSet {
            crate::program::model::address::address_set::AddressSet::new()
        }

        fn get_ordered_spans(&self) -> Vec<Box<dyn crate::trace::model::lifespan::Lifespan>> {
            Vec::new()
        }

        fn get_reversed_spans(&self) -> Vec<Box<dyn crate::trace::model::lifespan::Lifespan>> {
            Vec::new()
        }

        fn get_ordered_snaps(&self) -> Vec<i64> {
            Vec::new()
        }

        fn get_reversed_snaps(&self) -> Vec<i64> {
            Vec::new()
        }

        fn get_top(&self, _func: &dyn Fn(i64) -> Option<Box<dyn std::any::Any>>) -> Option<Box<dyn std::any::Any>> {
            None
        }

        fn merged_iterator(
            &self,
            _iter_func: &dyn Fn(i64) -> Box<dyn Iterator<Item = Box<dyn std::any::Any>>>,
            _comparator: &dyn Fn(&dyn std::any::Any, &dyn std::any::Any) -> std::cmp::Ordering,
        ) -> Box<dyn Iterator<Item = Box<dyn std::any::Any>>> {
            Box::new(std::iter::empty())
        }

        fn unioned_addresses(
            &self,
            _set_func: &dyn Fn(i64) -> Box<dyn crate::program::model::address::address_set::AddressSetView>,
        ) -> Box<dyn crate::program::model::address::address_set::AddressSetView> {
            Box::new(crate::program::model::address::address_set::AddressSet::new())
        }
    }

    struct MockProgramView {
        snap: i64,
        max_snap: Option<i64>,
    }

    impl DomainObject for MockProgramView {}

    impl Program for MockProgramView {
        fn get_name(&self) -> String {
            "mock-view".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    impl TraceProgramView for MockProgramView {
        fn get_trace_program_view_memory(&self) -> Box<dyn TraceProgramViewMemory> {
            Box::new(MockMemory)
        }

        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace)
        }

        fn get_snap(&self) -> i64 {
            self.snap
        }

        fn get_viewport(&self) -> Box<dyn TraceTimeViewport> {
            Box::new(MockTimeViewport)
        }

        fn get_max_snap(&self) -> Option<i64> {
            self.max_snap
        }
    }

    #[test]
    fn reports_snap_and_max_snap() {
        let view = MockProgramView {
            snap: 3,
            max_snap: Some(10),
        };
        assert_eq!(view.get_snap(), 3);
        assert_eq!(view.get_max_snap(), Some(10));
    }

    #[test]
    fn max_snap_can_be_absent() {
        let view = MockProgramView {
            snap: 0,
            max_snap: None,
        };
        assert_eq!(view.get_max_snap(), None);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let view: Box<dyn TraceProgramView> = Box::new(MockProgramView {
            snap: 1,
            max_snap: Some(1),
        });
        assert_eq!(Program::get_name(&*view), "mock-view");
        let _ = view.get_trace();
        let _ = view.get_viewport();
        let _ = view.get_trace_program_view_memory();
    }
}

//! A trace program view whose displayed snap can be changed after creation.
//!
//! Java source: `ghidra.trace.model.program.TraceVariableSnapProgramView`.
use crate::trace::model::program::trace_program_view::TraceProgramView;
use crate::trace::seam_stubs::TracePlatform;

/// A [`TraceProgramView`] whose snap (and current platform) can be changed after creation.
///
/// Port of `ghidra.trace.model.program.TraceVariableSnapProgramView`.
pub trait TraceVariableSnapProgramView: TraceProgramView {
    /// Seek to a particular snap.
    fn set_snap(&mut self, snap: i64);

    /// Seek to the latest snap.
    fn seek_latest(&mut self) {
        if let Some(max_snap) = self.get_max_snap() {
            self.set_snap(max_snap);
        }
    }

    /// Set the current platform, so that actions have context.
    fn set_platform(&mut self, platform: Box<dyn TracePlatform>);
}

#[cfg(test)]
mod tests {
    use crate::trace::model::lifespan::Lifespan;
    use super::*;
    use crate::app::merge::DataTypeManagerOwner;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::listing::program::Program;
    use crate::trace::model::program::trace_program_view_memory::TraceProgramViewMemory;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_time_viewport::TraceTimeViewport;

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
        ) -> Box<dyn crate::trace::model::property::TraceAddressPropertyManager> {
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

        fn get_memory_manager(&self) -> Box<dyn crate::trace::model::memory::trace_memory_manager::TraceMemoryManager> {
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

        fn get_stack_manager(&self) -> Box<dyn crate::trace::model::stack::trace_stack_manager::TraceStackManager> {
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
        ) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_program_view(&self) -> Box<dyn TraceVariableSnapProgramView> {
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

        fn contains_any_upper(&self, _lifespan: Lifespan) -> bool {
            false
        }

        fn is_completely_visible(
            &self,
            _range: &crate::program::model::address::range::AddressRange,
            _lifespan: Lifespan,
            _object: &dyn std::any::Any,
            _occlusion: &dyn crate::trace::model::trace_time_viewport::Occlusion,
        ) -> bool {
            true
        }

        fn compute_visible_parts(
            &self,
            _set: &dyn crate::program::model::address::address_set::AddressSetView,
            _lifespan: Lifespan,
            _object: &dyn std::any::Any,
            _occlusion: &dyn crate::trace::model::trace_time_viewport::Occlusion,
        ) -> crate::program::model::address::address_set::AddressSet {
            crate::program::model::address::address_set::AddressSet::new()
        }

        fn get_ordered_spans(&self) -> Vec<Lifespan> {
            Vec::new()
        }

        fn get_reversed_spans(&self) -> Vec<Lifespan> {
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

    struct MockPlatform;
    impl TracePlatform for MockPlatform {}

    struct MockVariableSnapProgramView {
        snap: i64,
        max_snap: Option<i64>,
        platform_set: bool,
    }

    impl DomainObject for MockVariableSnapProgramView {}

    impl Program for MockVariableSnapProgramView {
        fn get_name(&self) -> String {
            "mock-variable-snap-view".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    impl TraceProgramView for MockVariableSnapProgramView {
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

    impl TraceVariableSnapProgramView for MockVariableSnapProgramView {
        fn set_snap(&mut self, snap: i64) {
            self.snap = snap;
        }

        fn set_platform(&mut self, _platform: Box<dyn TracePlatform>) {
            self.platform_set = true;
        }
    }

    #[test]
    fn set_snap_updates_the_current_snap() {
        let mut view = MockVariableSnapProgramView {
            snap: 0,
            max_snap: Some(10),
            platform_set: false,
        };
        view.set_snap(7);
        assert_eq!(view.get_snap(), 7);
    }

    #[test]
    fn seek_latest_moves_to_the_max_snap() {
        let mut view = MockVariableSnapProgramView {
            snap: 0,
            max_snap: Some(42),
            platform_set: false,
        };
        view.seek_latest();
        assert_eq!(view.get_snap(), 42);
    }

    #[test]
    fn seek_latest_is_a_no_op_without_a_max_snap() {
        let mut view = MockVariableSnapProgramView {
            snap: 3,
            max_snap: None,
            platform_set: false,
        };
        view.seek_latest();
        assert_eq!(view.get_snap(), 3);
    }

    #[test]
    fn set_platform_is_observed_before_boxing() {
        let mut view = MockVariableSnapProgramView {
            snap: 0,
            max_snap: None,
            platform_set: false,
        };
        view.set_platform(Box::new(MockPlatform));
        assert!(view.platform_set);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut view: Box<dyn TraceVariableSnapProgramView> = Box::new(MockVariableSnapProgramView {
            snap: 1,
            max_snap: Some(5),
            platform_set: false,
        });
        view.set_platform(Box::new(MockPlatform));
        view.set_snap(5);
        assert_eq!(Program::get_name(&*view), "mock-variable-snap-view");
        assert_eq!(view.get_snap(), 5);
    }
}

use std::sync::Arc;

use crate::debug::api::platform::DebuggerPlatformMapper;
use crate::framework::plugintool::PluginEvent;
use crate::trace::model::trace::Trace;

/// The name of this plugin event.
///
/// Mirrors the package-private `DebuggerPlatformPluginEvent.NAME` (`static final String NAME`,
/// with no visibility modifier -- Java package-private). It is exported here so sibling modules
/// within this crate can reference it, mirroring same-package Java access.
pub const NAME: &str = "Platform";

/// Event fired when the chosen platform mapper for a trace changes.
///
/// Port of `ghidra.app.plugin.core.debug.event.DebuggerPlatformPluginEvent`, a class extending
/// `PluginEvent` directly. Rust has no inheritance, so this struct composes a [`PluginEvent`] the
/// same way [`TraceActivatedPluginEvent`](super::trace_activated_plugin_event::TraceActivatedPluginEvent)
/// and friends do. This class overrides no `PluginEvent` hooks (no `getDetails()` override, no
/// `@ToolEventName` annotation), so the composed event needs no
/// [`PluginEventBehavior`](crate::framework::plugintool::PluginEventBehavior).
pub struct DebuggerPlatformPluginEvent {
    event: PluginEvent,
    trace: Arc<dyn Trace>,
    mapper: Box<dyn DebuggerPlatformMapper>,
}

impl DebuggerPlatformPluginEvent {
    /// Construct a new `DebuggerPlatformPluginEvent`.
    ///
    /// Mirrors `DebuggerPlatformPluginEvent(String sourceName, Trace trace,
    /// DebuggerPlatformMapper mapper)`, which forwards to `super(sourceName, NAME)`.
    pub fn new(
        source_name: impl Into<String>,
        trace: Arc<dyn Trace>,
        mapper: Box<dyn DebuggerPlatformMapper>,
    ) -> Self {
        Self {
            event: PluginEvent::new(source_name, NAME),
            trace,
            mapper,
        }
    }

    /// Returns the trace whose platform mapper changed.
    ///
    /// Mirrors `getTrace()`.
    pub fn get_trace(&self) -> Arc<dyn Trace> {
        self.trace.clone()
    }

    /// Returns the new platform mapper.
    ///
    /// Mirrors `getMapper()`. Returned by reference (rather than a clone) since
    /// `DebuggerPlatformMapper` implementations are not required to be `Clone`; this still
    /// mirrors Java's getter handing back the same underlying object.
    pub fn get_mapper(&self) -> &dyn DebuggerPlatformMapper {
        self.mapper.as_ref()
    }

    /// Returns a reference to the underlying `PluginEvent`.
    pub fn event(&self) -> &PluginEvent {
        &self.event
    }

    /// Returns a mutable reference to the underlying `PluginEvent`.
    pub fn event_mut(&mut self) -> &mut PluginEvent {
        &mut self.event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSetView};
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::trace::model::target::trace_object::TraceObject;
    use crate::trace::model::thread::TraceThread;
    use crate::util::task::TaskMonitor;

    struct MockTrace;
    impl crate::framework::model::DomainObject for MockTrace {}
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject
        for MockTrace
    {
    }
    impl crate::app::merge::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(
            &self,
        ) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_emulator_cache_version(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_address_factory(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressFactory> {
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
        fn get_breakpoint_manager(
            &self,
        ) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(
            &self,
        ) -> Box<dyn crate::trace::model::data::trace_based_data_type_manager::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(
            &self,
        ) -> Box<dyn crate::trace::model::guest::trace_platform_manager::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_manager(
            &self,
        ) -> Box<dyn crate::trace::model::memory::trace_memory_manager::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(
            &self,
        ) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(
            &self,
        ) -> Box<dyn crate::trace::model::stack::trace_stack_manager::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(
            &self,
        ) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(
            &self,
        ) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(
            &self,
        ) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(
            &self,
        ) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockMapper;
    impl DebuggerPlatformMapper for MockMapper {
        fn get_compiler_spec(
            &self,
            _object: &dyn TraceObject,
            _snap: i64,
        ) -> Option<Box<dyn CompilerSpec>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_to_trace(
            &self,
            _new_focus: &dyn TraceObject,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::guest::trace_platform::TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }
        fn can_interpret(&self, _new_focus: &dyn TraceObject, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn disassemble(
            &self,
            _thread: Option<&dyn TraceThread>,
            _object: &dyn TraceObject,
            _start: Address,
            _restricted: &dyn AddressSetView,
            _snap: i64,
            _monitor: &dyn TaskMonitor,
        ) -> crate::debug::api::platform::disassembly_result::DisassemblyResult {
            unimplemented!("not exercised by this smoke test")
        }
    }

    #[test]
    fn name_constant_matches_java() {
        assert_eq!(NAME, "Platform");
    }

    #[test]
    fn new_stores_source_and_fixed_event_name() {
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let mapper: Box<dyn DebuggerPlatformMapper> = Box::new(MockMapper);
        let event = DebuggerPlatformPluginEvent::new("MyPlugin", trace, mapper);
        assert_eq!(event.event().source_name(), "MyPlugin");
        assert_eq!(event.event().event_name(), NAME);
    }

    #[test]
    fn get_trace_returns_the_stored_trace() {
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let trace_ptr = Arc::as_ptr(&trace);
        let mapper: Box<dyn DebuggerPlatformMapper> = Box::new(MockMapper);
        let event = DebuggerPlatformPluginEvent::new("P", trace, mapper);
        assert_eq!(Arc::as_ptr(&event.get_trace()), trace_ptr);
    }

    #[test]
    fn get_mapper_returns_the_stored_mapper() {
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let mapper: Box<dyn DebuggerPlatformMapper> = Box::new(MockMapper);
        let mapper_ptr = mapper.as_ref() as *const dyn DebuggerPlatformMapper as *const ();
        let event = DebuggerPlatformPluginEvent::new("P", trace, mapper);
        let got_ptr = event.get_mapper() as *const dyn DebuggerPlatformMapper as *const ();
        assert_eq!(got_ptr, mapper_ptr);
    }

    #[test]
    fn event_mut_allows_modification() {
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let mapper: Box<dyn DebuggerPlatformMapper> = Box::new(MockMapper);
        let mut event = DebuggerPlatformPluginEvent::new("Orig", trace, mapper);
        event.event_mut().set_source_name("Updated");
        assert_eq!(event.event().source_name(), "Updated");
    }
}

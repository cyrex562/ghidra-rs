use crate::framework::plugintool::PluginEvent;
use crate::trace::model::trace::Trace;
use std::sync::{Arc, Weak};

const NAME: &str = "Trace Closed @";

/// Event fired when a trace is closed.
///
/// Mirrors `ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent`.
pub struct TraceClosedPluginEvent {
    event: PluginEvent,
    trace_ref: Weak<dyn Trace>,
}

impl TraceClosedPluginEvent {
    /// Creates a new trace closed event.
    ///
    /// The event name is constructed as `NAME` followed by the hex representation of the trace's
    /// pointer address, mirroring Java's `System.identityHashCode()`.
    pub fn new(source: impl Into<String>, trace: Arc<dyn Trace>) -> Self {
        let trace_ptr = Arc::as_ptr(&trace) as *const () as usize;
        let trace_id = format!("{:x}", trace_ptr);
        let event_name = format!("{}{}", NAME, trace_id);
        let trace_ref = Arc::downgrade(&trace);

        Self {
            event: PluginEvent::new(source, event_name),
            trace_ref,
        }
    }

    /// Returns the trace associated with this event, or `None` if it has been dropped.
    ///
    /// Mirrors `getTrace()`.
    pub fn get_trace(&self) -> Option<Arc<dyn Trace>> {
        self.trace_ref.upgrade()
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

    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::seam_stubs::DataTypeManagerOwner;
    use crate::trace::model::trace::TraceProgramViewListener;
    use crate::util::lock_hold::{Lock, LockHold};

    /// Mock lock for testing.
    struct MockLock;
    impl Lock for MockLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    /// Mock trace for testing.
    struct MockTrace;

    impl DomainObject for MockTrace {}

    impl DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }
    }

    impl DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!()
        }

        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!()
        }

        fn set_emulator_cache_version(&mut self, _version: i64) {
            unimplemented!()
        }

        fn get_emulator_cache_version(&self) -> i64 {
            unimplemented!()
        }

        fn get_base_address_factory(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!()
        }

        fn get_address_property_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
            unimplemented!()
        }

        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!()
        }

        fn get_breakpoint_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceBreakpointManager> {
            unimplemented!()
        }

        fn get_code_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceCodeManager> {
            unimplemented!()
        }

        fn get_base_data_type_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!()
        }

        fn get_equate_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceEquateManager> {
            unimplemented!()
        }

        fn get_platform_manager(&self) -> Box<dyn crate::trace::seam_stubs::TracePlatformManager> {
            unimplemented!()
        }

        fn get_memory_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceMemoryManager> {
            unimplemented!()
        }

        fn get_module_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceModuleManager> {
            unimplemented!()
        }

        fn get_object_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceObjectManager> {
            unimplemented!()
        }

        fn get_reference_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceReferenceManager> {
            unimplemented!()
        }

        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!()
        }

        fn get_stack_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceStackManager> {
            unimplemented!()
        }

        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceStaticMappingManager> {
            unimplemented!()
        }

        fn get_symbol_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceSymbolManager> {
            unimplemented!()
        }

        fn get_thread_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceThreadManager> {
            unimplemented!()
        }

        fn get_time_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceTimeManager> {
            unimplemented!()
        }

        fn get_fixed_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::seam_stubs::TraceProgramView> {
            unimplemented!()
        }

        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!()
        }

        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::seam_stubs::TraceProgramView>> {
            vec![]
        }

        fn get_program_view(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!()
        }

        fn create_time_viewport(&self) -> Box<dyn crate::trace::seam_stubs::TraceTimeViewport> {
            unimplemented!()
        }

        fn add_program_view_listener(&mut self, _listener: Box<dyn TraceProgramViewListener>) {}

        fn remove_program_view_listener(&mut self, _listener: &dyn TraceProgramViewListener) {}

        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            static LOCK: MockLock = MockLock;
            LockHold::lock(&LOCK)
        }

        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            static LOCK: MockLock = MockLock;
            LockHold::lock(&LOCK)
        }
    }

    #[test]
    fn new_stores_source_and_trace() {
        let trace = Arc::new(MockTrace);
        let event = TraceClosedPluginEvent::new("TestSource", trace.clone());

        assert_eq!(event.event().source_name(), "TestSource");
        assert!(event.get_trace().is_some());
    }

    #[test]
    fn event_name_includes_trace_pointer() {
        let trace = Arc::new(MockTrace);
        let trace_ptr = Arc::as_ptr(&trace) as usize;
        let event = TraceClosedPluginEvent::new("TestSource", trace.clone());

        let expected = format!("Trace Closed @{:x}", trace_ptr);
        assert_eq!(event.event().event_name(), expected);
    }

    #[test]
    fn get_trace_returns_trace_while_arc_alive() {
        let trace = Arc::new(MockTrace);
        let event = TraceClosedPluginEvent::new("TestSource", trace.clone());

        assert!(event.get_trace().is_some());
    }

    #[test]
    fn get_trace_returns_none_after_arc_dropped() {
        let trace = Arc::new(MockTrace);
        let event = TraceClosedPluginEvent::new("TestSource", trace.clone());

        drop(trace);

        assert!(event.get_trace().is_none());
    }

    #[test]
    fn event_name_constant_is_correct() {
        assert_eq!(NAME, "Trace Closed @");
    }

    #[test]
    fn event_mut_allows_modification() {
        let trace = Arc::new(MockTrace);
        let mut event = TraceClosedPluginEvent::new("TestSource", trace);

        event.event_mut().set_source_name("NewSource");
        assert_eq!(event.event().source_name(), "NewSource");
    }
}

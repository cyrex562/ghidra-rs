use crate::program::model::address::AddressFactory;
use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
use crate::program::model::lang::{CompilerSpec, Language};
use crate::trace::seam_stubs::{
    TraceAddressPropertyManager, TraceBasedDataTypeManager, TraceBookmarkManager,
    TraceBreakpointManager, TraceCodeManager, TraceEquateManager, TraceMemoryManager,
    TraceModuleManager, TraceObjectManager, TracePlatformManager, TraceProgramView,
    TraceReferenceManager, TraceRegisterContextManager, TraceStackManager,
    TraceStaticMappingManager, TraceSymbolManager, TraceThreadManager, TraceTimeManager,
    TraceTimeViewport, TraceVariableSnapProgramView,
};
use crate::util::lock_hold::{Lock, LockHold};

/// Notified when a new [`TraceProgramView`] is created for a [`Trace`].
///
/// Port of `ghidra.trace.model.Trace.TraceProgramViewListener`.
pub trait TraceProgramViewListener {
    /// Called when a new program view has been created.
    fn view_created(&self, view: &dyn TraceProgramView);
}

/// An indexed record of observations over the course of a target's execution.
///
/// Conceptually, this is the same as a `Program`, but multiplied by a concrete dimension of time
/// and organized into snapshots. This also includes information about other objects not
/// ordinarily of concern for static analysis, for example threads, modules, and breakpoints. To
/// view a specific snapshot and/or manipulate the trace as if it were a program, use
/// [`Trace::get_program_view`].
///
/// Port of `ghidra.trace.model.Trace`.
///
/// The `TRACE_ICON` constant is omitted: it is a Swing `Icon`, and no GUI icon type has been
/// ported into this crate yet.
///
/// The `getDataTypeManager()` default method (which simply delegates to
/// [`Trace::get_base_data_type_manager`]) is not re-declared here, since Rust does not support
/// covariant trait-method overrides: it would collide with
/// [`DataTypeManagerOwner::get_data_type_manager`](crate::program::seam_stubs::DataTypeManagerOwner::get_data_type_manager),
/// which this trait already inherits (via [`DataTypeManagerDomainObject`]) and which returns a
/// different (non-covariant) type. Implementors of `Trace` should implement that supertrait
/// method to delegate to `get_base_data_type_manager`, mirroring the Java default.
pub trait Trace: DataTypeManagerDomainObject {
    /// Returns the base (host) language of this trace.
    fn get_base_language(&self) -> Box<dyn Language>;

    /// Returns the base (host) compiler spec of this trace.
    fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec>;

    /// Sets the emulator cache version, effectively invalidating any cached emulator states from
    /// prior versions.
    fn set_emulator_cache_version(&mut self, version: i64);

    /// Gets the current emulator cache version.
    fn get_emulator_cache_version(&self) -> i64;

    /// Returns the base address factory of this trace.
    fn get_base_address_factory(&self) -> Box<dyn AddressFactory>;

    /// Returns the manager for address-keyed properties.
    fn get_address_property_manager(&self) -> Box<dyn TraceAddressPropertyManager>;

    /// Returns the bookmark manager.
    fn get_bookmark_manager(&self) -> Box<dyn TraceBookmarkManager>;

    /// Returns the breakpoint manager.
    fn get_breakpoint_manager(&self) -> Box<dyn TraceBreakpointManager>;

    /// Returns the code manager.
    fn get_code_manager(&self) -> Box<dyn TraceCodeManager>;

    /// Returns the "base" or "host" data type manager. For platform-specific managers, see
    /// `TracePlatform::get_data_type_manager`.
    fn get_base_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager>;

    /// Returns the equate manager.
    fn get_equate_manager(&self) -> Box<dyn TraceEquateManager>;

    /// Returns the platform manager.
    fn get_platform_manager(&self) -> Box<dyn TracePlatformManager>;

    /// Returns the memory manager.
    fn get_memory_manager(&self) -> Box<dyn TraceMemoryManager>;

    /// Returns the module manager.
    fn get_module_manager(&self) -> Box<dyn TraceModuleManager>;

    /// Returns the object manager.
    fn get_object_manager(&self) -> Box<dyn TraceObjectManager>;

    /// Returns the reference manager.
    fn get_reference_manager(&self) -> Box<dyn TraceReferenceManager>;

    /// Returns the register context manager.
    fn get_register_context_manager(&self) -> Box<dyn TraceRegisterContextManager>;

    /// Returns the stack manager.
    fn get_stack_manager(&self) -> Box<dyn TraceStackManager>;

    /// Returns the static mapping manager.
    fn get_static_mapping_manager(&self) -> Box<dyn TraceStaticMappingManager>;

    /// Returns the symbol manager.
    fn get_symbol_manager(&self) -> Box<dyn TraceSymbolManager>;

    /// Returns the thread manager.
    fn get_thread_manager(&self) -> Box<dyn TraceThreadManager>;

    /// Returns the time manager.
    fn get_time_manager(&self) -> Box<dyn TraceTimeManager>;

    /// Returns a fixed (single-snapshot) program view at the given snap.
    fn get_fixed_program_view(&self, snap: i64) -> Box<dyn TraceProgramView>;

    /// Creates a new variable-snap program view starting at the given snap.
    fn create_program_view(&self, snap: i64) -> Box<dyn TraceVariableSnapProgramView>;

    /// Collects all program views, fixed or variable, of this trace.
    fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>>;

    /// Gets the "canonical" program view for this trace.
    ///
    /// This view is the view returned, e.g., by `TraceCodeUnit::get_program`, no matter which
    /// view was actually used to retrieve that unit.
    fn get_program_view(&self) -> Box<dyn TraceVariableSnapProgramView>;

    /// Creates a new time viewport over this trace.
    fn create_time_viewport(&self) -> Box<dyn TraceTimeViewport>;

    /// Adds a listener to be notified when new program views are created.
    fn add_program_view_listener(&mut self, listener: Box<dyn TraceProgramViewListener>);

    /// Removes a previously-added program view listener.
    fn remove_program_view_listener(&mut self, listener: &dyn TraceProgramViewListener);

    /// Acquires the read lock, releasing it when the returned guard is dropped.
    fn lock_read(&self) -> LockHold<'_, dyn Lock>;

    /// Acquires the write lock, releasing it when the returned guard is dropped.
    fn lock_write(&self) -> LockHold<'_, dyn Lock>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::seam_stubs::DataTypeManagerOwner;

    struct MockLock;
    impl Lock for MockLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockTraceBasedDataTypeManager;
    impl DataTypeManager for MockTraceBasedDataTypeManager {}
    impl TraceBasedDataTypeManager for MockTraceBasedDataTypeManager {}

    struct MockTrace {
        lock: MockLock,
        emulator_cache_version: i64,
    }

    impl DomainObject for MockTrace {}

    impl DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }
    }

    impl DataTypeManagerDomainObject for MockTrace {}

    struct MockAddressPropertyManager;
    impl TraceAddressPropertyManager for MockAddressPropertyManager {}
    struct MockBookmarkManager;
    impl TraceBookmarkManager for MockBookmarkManager {}
    struct MockBreakpointManager;
    impl TraceBreakpointManager for MockBreakpointManager {}
    struct MockCodeManager;
    impl TraceCodeManager for MockCodeManager {}
    struct MockEquateManager;
    impl TraceEquateManager for MockEquateManager {}
    struct MockPlatformManager;
    impl TracePlatformManager for MockPlatformManager {}
    struct MockMemoryManager;
    impl TraceMemoryManager for MockMemoryManager {}
    struct MockModuleManager;
    impl TraceModuleManager for MockModuleManager {}
    struct MockObjectManager;
    impl TraceObjectManager for MockObjectManager {}
    struct MockReferenceManager;
    impl TraceReferenceManager for MockReferenceManager {}
    struct MockRegisterContextManager;
    impl TraceRegisterContextManager for MockRegisterContextManager {}
    struct MockStackManager;
    impl TraceStackManager for MockStackManager {}
    struct MockStaticMappingManager;
    impl TraceStaticMappingManager for MockStaticMappingManager {}
    struct MockSymbolManager;
    impl TraceSymbolManager for MockSymbolManager {}
    struct MockThreadManager;
    impl TraceThreadManager for MockThreadManager {}
    struct MockTimeManager;
    impl TraceTimeManager for MockTimeManager {}
    struct MockProgramView;
    impl TraceProgramView for MockProgramView {}
    struct MockVariableSnapProgramView;
    impl TraceProgramView for MockVariableSnapProgramView {}
    impl TraceVariableSnapProgramView for MockVariableSnapProgramView {}
    struct MockTimeViewport;
    impl TraceTimeViewport for MockTimeViewport {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_emulator_cache_version(&mut self, version: i64) {
            self.emulator_cache_version = version;
        }

        fn get_emulator_cache_version(&self) -> i64 {
            self.emulator_cache_version
        }

        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_property_manager(&self) -> Box<dyn TraceAddressPropertyManager> {
            Box::new(MockAddressPropertyManager)
        }

        fn get_bookmark_manager(&self) -> Box<dyn TraceBookmarkManager> {
            Box::new(MockBookmarkManager)
        }

        fn get_breakpoint_manager(&self) -> Box<dyn TraceBreakpointManager> {
            Box::new(MockBreakpointManager)
        }

        fn get_code_manager(&self) -> Box<dyn TraceCodeManager> {
            Box::new(MockCodeManager)
        }

        fn get_base_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager> {
            Box::new(MockTraceBasedDataTypeManager)
        }

        fn get_equate_manager(&self) -> Box<dyn TraceEquateManager> {
            Box::new(MockEquateManager)
        }

        fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
            Box::new(MockPlatformManager)
        }

        fn get_memory_manager(&self) -> Box<dyn TraceMemoryManager> {
            Box::new(MockMemoryManager)
        }

        fn get_module_manager(&self) -> Box<dyn TraceModuleManager> {
            Box::new(MockModuleManager)
        }

        fn get_object_manager(&self) -> Box<dyn TraceObjectManager> {
            Box::new(MockObjectManager)
        }

        fn get_reference_manager(&self) -> Box<dyn TraceReferenceManager> {
            Box::new(MockReferenceManager)
        }

        fn get_register_context_manager(&self) -> Box<dyn TraceRegisterContextManager> {
            Box::new(MockRegisterContextManager)
        }

        fn get_stack_manager(&self) -> Box<dyn TraceStackManager> {
            Box::new(MockStackManager)
        }

        fn get_static_mapping_manager(&self) -> Box<dyn TraceStaticMappingManager> {
            Box::new(MockStaticMappingManager)
        }

        fn get_symbol_manager(&self) -> Box<dyn TraceSymbolManager> {
            Box::new(MockSymbolManager)
        }

        fn get_thread_manager(&self) -> Box<dyn TraceThreadManager> {
            Box::new(MockThreadManager)
        }

        fn get_time_manager(&self) -> Box<dyn TraceTimeManager> {
            Box::new(MockTimeManager)
        }

        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn TraceProgramView> {
            Box::new(MockProgramView)
        }

        fn create_program_view(&self, _snap: i64) -> Box<dyn TraceVariableSnapProgramView> {
            Box::new(MockVariableSnapProgramView)
        }

        fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
            vec![Box::new(MockProgramView)]
        }

        fn get_program_view(&self) -> Box<dyn TraceVariableSnapProgramView> {
            Box::new(MockVariableSnapProgramView)
        }

        fn create_time_viewport(&self) -> Box<dyn TraceTimeViewport> {
            Box::new(MockTimeViewport)
        }

        fn add_program_view_listener(&mut self, _listener: Box<dyn TraceProgramViewListener>) {}

        fn remove_program_view_listener(&mut self, _listener: &dyn TraceProgramViewListener) {}

        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            LockHold::lock(&self.lock)
        }

        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            LockHold::lock(&self.lock)
        }
    }

    struct MockListener;
    impl TraceProgramViewListener for MockListener {
        fn view_created(&self, _view: &dyn TraceProgramView) {}
    }

    #[test]
    fn usable_as_trait_object() {
        let mut trace: Box<dyn Trace> = Box::new(MockTrace {
            lock: MockLock,
            emulator_cache_version: 0,
        });

        assert_eq!(trace.get_emulator_cache_version(), 0);
        trace.set_emulator_cache_version(7);
        assert_eq!(trace.get_emulator_cache_version(), 7);

        {
            let _read = trace.lock_read();
        }
        {
            let _write = trace.lock_write();
        }

        assert_eq!(trace.get_all_program_views().len(), 1);

        trace.add_program_view_listener(Box::new(MockListener));
        let listener = MockListener;
        trace.remove_program_view_listener(&listener);
    }
}

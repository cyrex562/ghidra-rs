//! The interface for managing open traces and navigating among them and their contents.
//!
//! Port of `ghidra.app.services.DebuggerTraceManagerService`. The Java `@ServiceInfo` annotation
//! (default provider `DebuggerTraceManagerServicePlugin`) has no Rust equivalent and is omitted.
//!
//! Java overloads `activate(DebuggerCoordinates)`/`activate(DebuggerCoordinates,
//! ActivationCause)` on arity alone; Rust traits cannot overload by arity, so the two-argument
//! form becomes [`activate_with_cause`](DebuggerTraceManagerService::activate_with_cause), while
//! the one-argument default keeps the name `activate`. Java's `openTrace(Trace)` (track an
//! already-constructed trace) and `openTrace(DomainFile, int)` (open a trace from a project file)
//! overload on parameter type; the latter becomes `open_trace_from_file`. Likewise
//! `openTraces(Collection<DomainFile>)` becomes `open_traces_from_files`.

use std::future::Future;
use std::pin::Pin;

use crate::app::seam_stubs::{DebuggerCoordinates, Target, TraceObject, TracePlatform, TraceSchedule, TraceThread};
use crate::framework::model::DomainFile;
use crate::trace::model::target::path::KeyPath;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::TraceProgramView;

/// A future representing an asynchronous, possibly-failable operation that produces no value.
///
/// Port of Java's `CompletableFuture<Void>` return type used by
/// [`DebuggerTraceManagerService::save_trace`], [`DebuggerTraceManagerService::save_trace_as`],
/// and [`DebuggerTraceManagerService::activate_and_notify`].
pub type TraceManagerVoidFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A future representing the asynchronous result of
/// [`DebuggerTraceManagerService::materialize`].
///
/// Port of Java's `CompletableFuture<Long>` return type, carrying the materialized snapshot key.
pub type MaterializeFuture = Pin<Box<dyn Future<Output = i64> + Send>>;

/// The reason coordinates were activated.
///
/// Port of `DebuggerTraceManagerService.ActivationCause`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ActivationCause {
    /// The change was driven by the user.
    User,
    /// The request was driven by the user, but its some alternative view, e.g., to compare
    /// snapshots.
    UserAlt,
    /// A trace was activated because a target was published or withdrawn.
    TargetUpdated,
    /// The change was driven by the model activation, possibly indirectly by the user.
    SyncModel,
    /// The change was driven by the recorder advancing a snapshot.
    FollowPresent,
    /// The tool is activating scratch coordinates to display an emulator state change.
    EmuStateEdit,
    /// The change was caused by a change to the mapper selection, probably indirectly by the
    /// user.
    MapperChanged,
    /// Some default coordinates were activated.
    ActivateDefault,
    /// The tool is restoring its data state.
    RestoreState,
}

/// An adapter that works nicely with an `AsyncReference`.
///
/// Port of `DebuggerTraceManagerService.BooleanChangeAdapter`, which implements Java's
/// `TriConsumer<Boolean, Boolean, Void>`. The `Void` cause parameter carries no information, so
/// it is dropped from the Rust port.
pub trait BooleanChangeAdapter {
    /// Called with the old and new value on change. Default delegates to
    /// [`changed`](Self::changed) with the new value, mirroring
    /// `TriConsumer.accept(Boolean, Boolean, Void)`'s default implementation.
    fn accept(&self, _old_val: bool, new_val: bool) {
        self.changed(new_val);
    }

    /// The value has changed.
    fn changed(&self, value: bool);
}

/// The interface for managing open traces and navigating among them and their contents.
///
/// Port of `ghidra.app.services.DebuggerTraceManagerService`.
pub trait DebuggerTraceManagerService {
    /// Get all the open traces.
    fn get_open_traces(&self) -> Vec<Box<dyn Trace>>;

    /// Get the current coordinates.
    ///
    /// This entails everything except the current address.
    fn get_current(&self) -> Box<dyn DebuggerCoordinates>;

    /// Get the current coordinates for a given trace.
    fn get_current_for(&self, trace: &dyn Trace) -> Box<dyn DebuggerCoordinates>;

    /// Get the active trace, or `None`.
    fn get_current_trace(&self) -> Option<Box<dyn Trace>>;

    /// Get the active platform, or `None`.
    fn get_current_platform(&self) -> Option<Box<dyn TracePlatform>>;

    /// Get the active view, or `None`.
    ///
    /// Every trace has an associated variable-snap view. When the manager navigates to a new
    /// point in time, it is accomplished by changing the snap of this view.
    fn get_current_view(&self) -> Option<Box<dyn TraceProgramView>>;

    /// Get the active thread, or `None`.
    ///
    /// It is possible to have an active trace, but no active thread.
    fn get_current_thread(&self) -> Option<Box<dyn TraceThread>>;

    /// Get the active snap, or `0`.
    ///
    /// Note that if emulation was used to materialize the current coordinates, then the current
    /// snap will differ from the view's snap.
    fn get_current_snap(&self) -> i64;

    /// Get the active frame, or `0`.
    fn get_current_frame(&self) -> i32;

    /// Get the active object, or `None`.
    fn get_current_object(&self) -> Option<Box<dyn TraceObject>>;

    /// Open a trace.
    ///
    /// This does not activate the trace. Use
    /// [`activate_trace`](Self::activate_trace) or [`activate_thread`](Self::activate_thread) if
    /// necessary.
    fn open_trace(&mut self, trace: Box<dyn Trace>);

    /// Open a trace from a domain file.
    ///
    /// `version` is the version (read-only if non-default).
    fn open_trace_from_file(&mut self, file: &dyn DomainFile, version: i32) -> Box<dyn Trace>;

    /// Open traces from a collection of domain files.
    ///
    /// The returned trace collection is ordered by position of its file in the input file
    /// collection.
    fn open_traces_from_files(&mut self, files: &[&dyn DomainFile]) -> Vec<Box<dyn Trace>>;

    /// Save the trace to the "New Traces" folder of the project.
    ///
    /// If a different domain file of the trace's name already exists, an incrementing integer is
    /// appended.
    fn save_trace(&self, trace: &dyn Trace) -> TraceManagerVoidFuture;

    /// Prompt the user and save the trace to a chosen path in the project.
    fn save_trace_as(&self, trace: &dyn Trace) -> TraceManagerVoidFuture;

    /// Close the given trace.
    fn close_trace(&mut self, trace: &dyn Trace);

    /// Close the given trace without confirmation.
    ///
    /// Ordinarily, [`close_trace`](Self::close_trace) will prompt the user to confirm
    /// termination of live targets associated with traces to be closed. Such prompts can cause
    /// issues during automated tests.
    fn close_trace_no_confirm(&mut self, trace: &dyn Trace);

    /// Close all traces.
    fn close_all_traces(&mut self);

    /// Close all traces except the given one.
    fn close_other_traces(&mut self, keep: &dyn Trace);

    /// Close all traces which are not the destination of a live recording.
    ///
    /// Operation of this method depends on the model service. If that service is not present,
    /// this method performs no operation at all.
    fn close_dead_traces(&mut self);

    /// Activate the given coordinates with future notification.
    ///
    /// This operation may be completed asynchronously, esp., if emulation is required to
    /// materialize the coordinates. The returned future is completed when the coordinates are
    /// actually materialized and active. The coordinates are "resolved" as a means of filling in
    /// missing parts. For example, if the thread is not specified, the manager may activate the
    /// last-active thread for the desired trace.
    fn activate_and_notify(
        &mut self,
        coordinates: Box<dyn DebuggerCoordinates>,
        cause: ActivationCause,
    ) -> TraceManagerVoidFuture;

    /// Activate the given coordinates, caused by the user.
    ///
    /// See [`activate_with_cause`](Self::activate_with_cause).
    fn activate(&mut self, coordinates: Box<dyn DebuggerCoordinates>) {
        self.activate_with_cause(coordinates, ActivationCause::User);
    }

    /// Activate the given coordinates, synchronizing the current target, if possible.
    ///
    /// If asynchronous notification is needed, use
    /// [`activate_and_notify`](Self::activate_and_notify).
    fn activate_with_cause(&mut self, coordinates: Box<dyn DebuggerCoordinates>, cause: ActivationCause);

    /// Resolve coordinates for the given trace using the manager's "best judgment".
    ///
    /// The manager may use a variety of sources of context including the current trace, the last
    /// coordinates for a trace, the target's last/current activation, the list of live threads,
    /// etc.
    fn resolve_trace(&self, trace: &dyn Trace) -> Box<dyn DebuggerCoordinates>;

    /// Activate the given trace.
    fn activate_trace(&mut self, trace: &dyn Trace) {
        let coordinates = self.resolve_trace(trace);
        self.activate(coordinates);
    }

    /// Resolve coordinates for the given target using the manager's "best judgment".
    ///
    /// See [`resolve_trace`](Self::resolve_trace).
    fn resolve_target(&self, target: &dyn Target) -> Box<dyn DebuggerCoordinates>;

    /// Activate the given target.
    fn activate_target(&mut self, target: &dyn Target) {
        let coordinates = self.resolve_target(target);
        self.activate(coordinates);
    }

    /// Resolve coordinates for the given platform using the manager's "best judgment".
    ///
    /// See [`resolve_trace`](Self::resolve_trace).
    fn resolve_platform(&self, platform: &dyn TracePlatform) -> Box<dyn DebuggerCoordinates>;

    /// Activate the given platform.
    fn activate_platform(&mut self, platform: &dyn TracePlatform) {
        let coordinates = self.resolve_platform(platform);
        self.activate(coordinates);
    }

    /// Resolve coordinates for the given thread using the manager's "best judgment".
    ///
    /// See [`resolve_trace`](Self::resolve_trace).
    fn resolve_thread(&self, thread: &dyn TraceThread) -> Box<dyn DebuggerCoordinates>;

    /// Activate the given thread.
    fn activate_thread(&mut self, thread: &dyn TraceThread) {
        let coordinates = self.resolve_thread(thread);
        self.activate(coordinates);
    }

    /// Resolve coordinates for the given snap using the manager's "best judgment".
    ///
    /// See [`resolve_trace`](Self::resolve_trace).
    fn resolve_snap(&self, snap: i64) -> Box<dyn DebuggerCoordinates>;

    /// Activate the given snapshot key.
    fn activate_snap(&mut self, snap: i64) {
        let coordinates = self.resolve_snap(snap);
        self.activate(coordinates);
    }

    /// Resolve coordinates for the given time using the manager's "best judgment".
    ///
    /// See [`resolve_trace`](Self::resolve_trace).
    fn resolve_time(&self, time: &dyn TraceSchedule) -> Box<dyn DebuggerCoordinates>;

    /// Activate the given point in time, possibly invoking emulation.
    fn activate_time(&mut self, time: &dyn TraceSchedule) {
        let coordinates = self.resolve_time(time);
        self.activate(coordinates);
    }

    /// Resolve coordinates for the given view using the manager's "best judgment".
    ///
    /// See [`resolve_trace`](Self::resolve_trace).
    fn resolve_view(&self, view: &dyn TraceProgramView) -> Box<dyn DebuggerCoordinates>;

    /// Resolve coordinates for the given frame level using the manager's "best judgment".
    ///
    /// `frame_level` is the frame level, `0` being the innermost. See
    /// [`resolve_trace`](Self::resolve_trace).
    fn resolve_frame(&self, frame_level: i32) -> Box<dyn DebuggerCoordinates>;

    /// Activate the given stack frame, `0` being innermost.
    fn activate_frame(&mut self, frame_level: i32) {
        let coordinates = self.resolve_frame(frame_level);
        self.activate(coordinates);
    }

    /// Resolve coordinates for the given object path using the manager's "best judgment".
    ///
    /// See [`resolve_trace`](Self::resolve_trace).
    fn resolve_path(&self, path: &KeyPath) -> Box<dyn DebuggerCoordinates>;

    /// Activate the given canonical object path.
    fn activate_path(&mut self, path: &KeyPath) {
        let coordinates = self.resolve_path(path);
        self.activate(coordinates);
    }

    /// Resolve coordinates for the given object using the manager's "best judgment".
    ///
    /// See [`resolve_trace`](Self::resolve_trace).
    fn resolve_object(&self, object: &dyn TraceObject) -> Box<dyn DebuggerCoordinates>;

    /// Activate the given object.
    fn activate_object(&mut self, object: &dyn TraceObject) {
        let coordinates = self.resolve_object(object);
        self.activate(coordinates);
    }

    /// Control whether traces should be saved by default.
    fn set_save_traces_by_default(&mut self, enabled: bool);

    /// Check whether traces should by saved by default.
    fn is_save_traces_by_default(&self) -> bool;

    /// Add a listener for changes to save-by-default enablement.
    fn add_save_traces_by_default_change_listener(&mut self, listener: Box<dyn BooleanChangeAdapter>);

    /// Remove a listener for changes to save-by-default enablement.
    fn remove_save_traces_by_default_change_listener(&mut self, listener: &dyn BooleanChangeAdapter);

    /// Control whether live traces are automatically closed upon target termination.
    fn set_auto_close_on_terminate(&mut self, enabled: bool);

    /// Check whether live traces are automatically closed upon target termination.
    fn is_auto_close_on_terminate(&self) -> bool;

    /// Add a listener for changes to close-on-terminate enablement.
    fn add_auto_close_on_terminate_change_listener(&mut self, listener: Box<dyn BooleanChangeAdapter>);

    /// Remove a listener for changes to close-on-terminate enablement.
    fn remove_auto_close_on_terminate_change_listener(&mut self, listener: &dyn BooleanChangeAdapter);

    /// If the given coordinates are already materialized, get the snapshot.
    ///
    /// If the coordinates do not include a schedule, this simply returns the coordinates'
    /// snapshot. Otherwise, it searches for the first snapshot whose schedule is the
    /// coordinates' schedule.
    fn find_snapshot(&self, coordinates: &dyn DebuggerCoordinates) -> Option<i64>;

    /// Materialize the given coordinates to a snapshot in the same trace.
    ///
    /// If the given coordinates do not require emulation, then this must complete immediately
    /// with the snapshot key given by the coordinates. If the given schedule is already
    /// materialized in the trace, then this may complete immediately with the
    /// previously-materialized snapshot key. Otherwise, this must invoke emulation, store the
    /// result into a chosen snapshot, and complete with its key.
    fn materialize(&mut self, coordinates: Box<dyn DebuggerCoordinates>) -> MaterializeFuture;
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::framework::model::DomainObject;
    use crate::program::model::address::AddressFactory;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::program::seam_stubs::DataTypeManagerOwner;
    use crate::trace::model::trace::TraceProgramViewListener;
    use crate::trace::seam_stubs::{
        TraceAddressPropertyManager, TraceBasedDataTypeManager, TraceBookmarkManager,
        TraceBreakpointManager, TraceCodeManager, TraceEquateManager, TraceMemoryManager,
        TraceModuleManager, TraceObjectManager, TracePlatformManager,
        TraceReferenceManager, TraceRegisterContextManager, TraceStackManager,
        TraceStaticMappingManager, TraceSymbolManager, TraceThreadManager, TraceTimeManager,
        TraceTimeViewport, TraceVariableSnapProgramView,
    };
    use crate::util::lock_hold::{Lock, LockHold};

    struct MockTrace;

    impl DomainObject for MockTrace {}

    impl DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_emulator_cache_version(&mut self, _version: i64) {}

        fn get_emulator_cache_version(&self) -> i64 {
            0
        }

        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_property_manager(&self) -> Box<dyn TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bookmark_manager(&self) -> Box<dyn TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_breakpoint_manager(&self) -> Box<dyn TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_manager(&self) -> Box<dyn TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_equate_manager(&self) -> Box<dyn TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_manager(&self) -> Box<dyn TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_module_manager(&self) -> Box<dyn TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_object_manager(&self) -> Box<dyn TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_reference_manager(&self) -> Box<dyn TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_context_manager(&self) -> Box<dyn TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack_manager(&self) -> Box<dyn TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_static_mapping_manager(&self) -> Box<dyn TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_symbol_manager(&self) -> Box<dyn TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread_manager(&self) -> Box<dyn TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_time_manager(&self) -> Box<dyn TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_program_view(&self, _snap: i64) -> Box<dyn TraceVariableSnapProgramView> {
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

        fn add_program_view_listener(&mut self, _listener: Box<dyn TraceProgramViewListener>) {}

        fn remove_program_view_listener(&mut self, _listener: &dyn TraceProgramViewListener) {}

        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by this smoke test")
        }

        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockCoordinates;
    impl DebuggerCoordinates for MockCoordinates {}

    struct MockService {
        open: Vec<()>,
        save_by_default: bool,
        auto_close: bool,
    }

    impl DebuggerTraceManagerService for MockService {
        fn get_open_traces(&self) -> Vec<Box<dyn Trace>> {
            self.open.iter().map(|_| Box::new(MockTrace) as Box<dyn Trace>).collect()
        }

        fn get_current(&self) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn get_current_for(&self, _trace: &dyn Trace) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn get_current_trace(&self) -> Option<Box<dyn Trace>> {
            None
        }

        fn get_current_platform(&self) -> Option<Box<dyn TracePlatform>> {
            None
        }

        fn get_current_view(&self) -> Option<Box<dyn TraceProgramView>> {
            None
        }

        fn get_current_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }

        fn get_current_snap(&self) -> i64 {
            0
        }

        fn get_current_frame(&self) -> i32 {
            0
        }

        fn get_current_object(&self) -> Option<Box<dyn TraceObject>> {
            None
        }

        fn open_trace(&mut self, _trace: Box<dyn Trace>) {
            self.open.push(());
        }

        fn open_trace_from_file(&mut self, _file: &dyn DomainFile, _version: i32) -> Box<dyn Trace> {
            self.open.push(());
            Box::new(MockTrace)
        }

        fn open_traces_from_files(&mut self, files: &[&dyn DomainFile]) -> Vec<Box<dyn Trace>> {
            files
                .iter()
                .map(|_| {
                    self.open.push(());
                    Box::new(MockTrace) as Box<dyn Trace>
                })
                .collect()
        }

        fn save_trace(&self, _trace: &dyn Trace) -> TraceManagerVoidFuture {
            Box::pin(async {})
        }

        fn save_trace_as(&self, _trace: &dyn Trace) -> TraceManagerVoidFuture {
            Box::pin(async {})
        }

        fn close_trace(&mut self, _trace: &dyn Trace) {
            self.open.pop();
        }

        fn close_trace_no_confirm(&mut self, _trace: &dyn Trace) {
            self.open.pop();
        }

        fn close_all_traces(&mut self) {
            self.open.clear();
        }

        fn close_other_traces(&mut self, _keep: &dyn Trace) {
            self.open.truncate(1);
        }

        fn close_dead_traces(&mut self) {}

        fn activate_and_notify(
            &mut self,
            _coordinates: Box<dyn DebuggerCoordinates>,
            _cause: ActivationCause,
        ) -> TraceManagerVoidFuture {
            Box::pin(async {})
        }

        fn activate_with_cause(
            &mut self,
            _coordinates: Box<dyn DebuggerCoordinates>,
            _cause: ActivationCause,
        ) {
        }

        fn resolve_trace(&self, _trace: &dyn Trace) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn resolve_target(&self, _target: &dyn Target) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn resolve_platform(&self, _platform: &dyn TracePlatform) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn resolve_thread(&self, _thread: &dyn TraceThread) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn resolve_snap(&self, _snap: i64) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn resolve_time(&self, _time: &dyn TraceSchedule) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn resolve_view(&self, _view: &dyn TraceProgramView) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn resolve_frame(&self, _frame_level: i32) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn resolve_path(&self, _path: &KeyPath) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn resolve_object(&self, _object: &dyn TraceObject) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn set_save_traces_by_default(&mut self, enabled: bool) {
            self.save_by_default = enabled;
        }

        fn is_save_traces_by_default(&self) -> bool {
            self.save_by_default
        }

        fn add_save_traces_by_default_change_listener(&mut self, _listener: Box<dyn BooleanChangeAdapter>) {}

        fn remove_save_traces_by_default_change_listener(&mut self, _listener: &dyn BooleanChangeAdapter) {}

        fn set_auto_close_on_terminate(&mut self, enabled: bool) {
            self.auto_close = enabled;
        }

        fn is_auto_close_on_terminate(&self) -> bool {
            self.auto_close
        }

        fn add_auto_close_on_terminate_change_listener(&mut self, _listener: Box<dyn BooleanChangeAdapter>) {}

        fn remove_auto_close_on_terminate_change_listener(&mut self, _listener: &dyn BooleanChangeAdapter) {}

        fn find_snapshot(&self, _coordinates: &dyn DebuggerCoordinates) -> Option<i64> {
            None
        }

        fn materialize(&mut self, _coordinates: Box<dyn DebuggerCoordinates>) -> MaterializeFuture {
            Box::pin(async { 0 })
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn DebuggerTraceManagerService> =
            Box::new(MockService { open: Vec::new(), save_by_default: false, auto_close: false });

        service.open_trace(Box::new(MockTrace));
        assert_eq!(service.get_open_traces().len(), 1);

        service.set_save_traces_by_default(true);
        assert!(service.is_save_traces_by_default());

        service.close_all_traces();
        assert!(service.get_open_traces().is_empty());
    }

    #[test]
    fn activate_default_delegates_to_activate_with_cause() {
        // Observe the cause forwarded by the default `activate` method, since
        // MockService's `activate_with_cause` ignores its arguments.
        struct CauseCapturingService(std::cell::RefCell<Option<ActivationCause>>);

        impl DebuggerTraceManagerService for CauseCapturingService {
            fn get_open_traces(&self) -> Vec<Box<dyn Trace>> {
                Vec::new()
            }
            fn get_current(&self) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn get_current_for(&self, _trace: &dyn Trace) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn get_current_trace(&self) -> Option<Box<dyn Trace>> {
                None
            }
            fn get_current_platform(&self) -> Option<Box<dyn TracePlatform>> {
                None
            }
            fn get_current_view(&self) -> Option<Box<dyn TraceProgramView>> {
                None
            }
            fn get_current_thread(&self) -> Option<Box<dyn TraceThread>> {
                None
            }
            fn get_current_snap(&self) -> i64 {
                0
            }
            fn get_current_frame(&self) -> i32 {
                0
            }
            fn get_current_object(&self) -> Option<Box<dyn TraceObject>> {
                None
            }
            fn open_trace(&mut self, _trace: Box<dyn Trace>) {}
            fn open_trace_from_file(&mut self, _file: &dyn DomainFile, _version: i32) -> Box<dyn Trace> {
                Box::new(MockTrace)
            }
            fn open_traces_from_files(&mut self, _files: &[&dyn DomainFile]) -> Vec<Box<dyn Trace>> {
                Vec::new()
            }
            fn save_trace(&self, _trace: &dyn Trace) -> TraceManagerVoidFuture {
                Box::pin(async {})
            }
            fn save_trace_as(&self, _trace: &dyn Trace) -> TraceManagerVoidFuture {
                Box::pin(async {})
            }
            fn close_trace(&mut self, _trace: &dyn Trace) {}
            fn close_trace_no_confirm(&mut self, _trace: &dyn Trace) {}
            fn close_all_traces(&mut self) {}
            fn close_other_traces(&mut self, _keep: &dyn Trace) {}
            fn close_dead_traces(&mut self) {}
            fn activate_and_notify(
                &mut self,
                _coordinates: Box<dyn DebuggerCoordinates>,
                _cause: ActivationCause,
            ) -> TraceManagerVoidFuture {
                Box::pin(async {})
            }
            fn activate_with_cause(
                &mut self,
                _coordinates: Box<dyn DebuggerCoordinates>,
                cause: ActivationCause,
            ) {
                *self.0.borrow_mut() = Some(cause);
            }
            fn resolve_trace(&self, _trace: &dyn Trace) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn resolve_target(&self, _target: &dyn Target) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn resolve_platform(&self, _platform: &dyn TracePlatform) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn resolve_thread(&self, _thread: &dyn TraceThread) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn resolve_snap(&self, _snap: i64) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn resolve_time(&self, _time: &dyn TraceSchedule) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn resolve_view(&self, _view: &dyn TraceProgramView) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn resolve_frame(&self, _frame_level: i32) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn resolve_path(&self, _path: &KeyPath) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn resolve_object(&self, _object: &dyn TraceObject) -> Box<dyn DebuggerCoordinates> {
                Box::new(MockCoordinates)
            }
            fn set_save_traces_by_default(&mut self, _enabled: bool) {}
            fn is_save_traces_by_default(&self) -> bool {
                false
            }
            fn add_save_traces_by_default_change_listener(&mut self, _listener: Box<dyn BooleanChangeAdapter>) {}
            fn remove_save_traces_by_default_change_listener(&mut self, _listener: &dyn BooleanChangeAdapter) {}
            fn set_auto_close_on_terminate(&mut self, _enabled: bool) {}
            fn is_auto_close_on_terminate(&self) -> bool {
                false
            }
            fn add_auto_close_on_terminate_change_listener(&mut self, _listener: Box<dyn BooleanChangeAdapter>) {}
            fn remove_auto_close_on_terminate_change_listener(&mut self, _listener: &dyn BooleanChangeAdapter) {}
            fn find_snapshot(&self, _coordinates: &dyn DebuggerCoordinates) -> Option<i64> {
                None
            }
            fn materialize(&mut self, _coordinates: Box<dyn DebuggerCoordinates>) -> MaterializeFuture {
                Box::pin(async { 0 })
            }
        }

        let mut service = CauseCapturingService(std::cell::RefCell::new(None));
        service.activate(Box::new(MockCoordinates));
        assert_eq!(*service.0.borrow(), Some(ActivationCause::User));
    }

    #[test]
    fn boolean_change_adapter_accept_delegates_to_changed() {
        struct RecordingAdapter(std::cell::Cell<Option<bool>>);
        impl BooleanChangeAdapter for RecordingAdapter {
            fn changed(&self, value: bool) {
                self.0.set(Some(value));
            }
        }

        let adapter = RecordingAdapter(std::cell::Cell::new(None));
        adapter.accept(false, true);
        assert_eq!(adapter.0.get(), Some(true));
    }
}

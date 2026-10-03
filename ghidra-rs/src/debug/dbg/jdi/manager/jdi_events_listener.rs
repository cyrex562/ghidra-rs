use super::breakpoint::jdi_breakpoint_info::JdiBreakpointInfo;
use super::jdi_cause::JdiCause;
use super::jdi_reason::JdiReason;
use super::jdi_thread_info::ThreadReference;
use super::r#impl::debug_status::DebugStatus;

/// Opaque handle for a JDI `com.sun.jdi.VirtualMachine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VirtualMachine(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.StackFrame`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackFrame(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.Event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Event(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.EventSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventSet(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.BreakpointEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BreakpointEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.ExceptionEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExceptionEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.MethodEntryEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MethodEntryEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.MethodExitEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MethodExitEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.ClassPrepareEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClassPrepareEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.ClassUnloadEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClassUnloadEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.MonitorContendedEnteredEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MonitorContendedEnteredEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.MonitorContendedEnterEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MonitorContendedEnterEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.MonitorWaitedEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MonitorWaitedEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.MonitorWaitEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MonitorWaitEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.StepEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StepEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.WatchpointEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WatchpointEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.AccessWatchpointEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessWatchpointEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.ModificationWatchpointEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModificationWatchpointEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.ThreadDeathEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadDeathEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.ThreadStartEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadStartEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.VMDeathEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VmDeathEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.VMDisconnectEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VmDisconnectEvent(pub u64);

/// Opaque handle for a JDI `com.sun.jdi.event.VMStartEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VmStartEvent(pub u64);

/// A listener for events related to objects known to the manager.
///
/// Mirrors `JdiEventsListener` from `ghidra.dbg.jdi.manager`. Each method reports an
/// event and returns the [`DebugStatus`] indicating how the manager should proceed.
pub trait JdiEventsListener: Send + Sync {
    /// A different vm has been selected (gained focus).
    fn vm_selected(&self, vm: VirtualMachine, cause: &dyn JdiCause) -> DebugStatus;

    /// A different thread has been selected (gained focus).
    fn thread_selected(
        &self,
        thread: ThreadReference,
        frame: StackFrame,
        cause: &dyn JdiCause,
    ) -> DebugStatus;

    /// A library has been loaded by a vm.
    fn class_loaded(&self, vm: VirtualMachine, name: &str, cause: &dyn JdiCause) -> DebugStatus;

    /// A library has been unloaded from a vm.
    fn class_unloaded(&self, vm: VirtualMachine, name: &str, cause: &dyn JdiCause) -> DebugStatus;

    /// A breakpoint has been created in the session.
    fn breakpoint_created(&self, info: &JdiBreakpointInfo, cause: &dyn JdiCause) -> DebugStatus;

    /// A breakpoint in the session has been modified.
    fn breakpoint_modified(
        &self,
        new_info: &JdiBreakpointInfo,
        old_info: &JdiBreakpointInfo,
        cause: &dyn JdiCause,
    ) -> DebugStatus;

    /// A breakpoint has been deleted from the session.
    fn breakpoint_deleted(&self, info: &JdiBreakpointInfo, cause: &dyn JdiCause) -> DebugStatus;

    /// Memory in the target has changed.
    ///
    /// It is not clear whether JDI detects when a target writes into its own memory, or
    /// if this event is emitted when JDI changes the target's memory, or both.
    fn memory_changed(
        &self,
        vm: VirtualMachine,
        addr: i64,
        len: i32,
        cause: &dyn JdiCause,
    ) -> DebugStatus;

    /// The vm has been interrupted.
    fn vm_interrupted(&self) -> DebugStatus;

    /// A breakpoint has been hit.
    fn breakpoint_hit(&self, evt: BreakpointEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// An exception has been hit.
    fn exception_hit(&self, evt: ExceptionEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A method has been invoked.
    fn method_entry(&self, evt: MethodEntryEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A method is about to finish.
    fn method_exit(&self, evt: MethodExitEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A class has been prepared.
    fn class_prepare(&self, evt: ClassPrepareEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A class is being unloaded.
    fn class_unload(&self, evt: ClassUnloadEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A thread has entered a monitor after release from another thread.
    fn monitor_contended_entered(
        &self,
        evt: MonitorContendedEnteredEvent,
        cause: &dyn JdiCause,
    ) -> DebugStatus;

    /// A thread is attempting to enter a monitor acquired by another thread.
    fn monitor_contended_enter(
        &self,
        evt: MonitorContendedEnterEvent,
        cause: &dyn JdiCause,
    ) -> DebugStatus;

    /// A vm has finished waiting on a monitor object.
    fn monitor_waited(&self, evt: MonitorWaitedEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A vm is about to wait on a monitor object.
    fn monitor_wait(&self, evt: MonitorWaitEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A step has completed.
    fn step_complete(&self, evt: StepEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A watchpoint has been hit.
    fn watchpoint_hit(&self, evt: WatchpointEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A field has been accessed.
    fn access_watchpoint_hit(
        &self,
        evt: AccessWatchpointEvent,
        cause: &dyn JdiCause,
    ) -> DebugStatus;

    /// A field has been modified.
    fn watchpoint_modified(
        &self,
        evt: ModificationWatchpointEvent,
        cause: &dyn JdiCause,
    ) -> DebugStatus;

    /// A thread has exited.
    fn thread_exited(&self, evt: ThreadDeathEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A thread has started.
    fn thread_started(&self, evt: ThreadStartEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A thread has changed state.
    fn thread_state_changed(
        &self,
        thread: ThreadReference,
        state: Option<i32>,
        cause: &dyn JdiCause,
        reason: &dyn JdiReason,
    ) -> DebugStatus;

    /// A vm has exited.
    fn vm_died(&self, evt: VmDeathEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A vm has been disconnected.
    fn vm_disconnected(&self, evt: VmDisconnectEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// A vm has started.
    fn vm_started(&self, evt: VmStartEvent, cause: &dyn JdiCause) -> DebugStatus;

    /// The process associated with an event set has stopped.
    fn process_stop(&self, event_set: EventSet, cause: &dyn JdiCause) -> DebugStatus;

    /// The process is shutting down.
    fn process_shutdown(&self, event: Event, cause: &dyn JdiCause) -> DebugStatus;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::dbg::jdi::manager::breakpoint::jdi_breakpoint_info::EventRequest;
    use crate::debug::dbg::jdi::manager::jdi_cause::Causes;
    use crate::debug::dbg::jdi::manager::jdi_reason::Reasons;
    use std::sync::Mutex;

    struct Recorder {
        calls: Mutex<Vec<String>>,
        result: DebugStatus,
    }

    impl Recorder {
        fn new(result: DebugStatus) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                result,
            }
        }

        fn record(&self, call: &str) -> DebugStatus {
            self.calls.lock().unwrap().push(call.to_owned());
            self.result
        }
    }

    impl JdiEventsListener for Recorder {
        fn vm_selected(&self, _vm: VirtualMachine, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("vm_selected")
        }

        fn thread_selected(
            &self,
            _thread: ThreadReference,
            _frame: StackFrame,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("thread_selected")
        }

        fn class_loaded(
            &self,
            _vm: VirtualMachine,
            _name: &str,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("class_loaded")
        }

        fn class_unloaded(
            &self,
            _vm: VirtualMachine,
            _name: &str,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("class_unloaded")
        }

        fn breakpoint_created(
            &self,
            _info: &JdiBreakpointInfo,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("breakpoint_created")
        }

        fn breakpoint_modified(
            &self,
            _new_info: &JdiBreakpointInfo,
            _old_info: &JdiBreakpointInfo,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("breakpoint_modified")
        }

        fn breakpoint_deleted(
            &self,
            _info: &JdiBreakpointInfo,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("breakpoint_deleted")
        }

        fn memory_changed(
            &self,
            _vm: VirtualMachine,
            _addr: i64,
            _len: i32,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("memory_changed")
        }

        fn vm_interrupted(&self) -> DebugStatus {
            self.record("vm_interrupted")
        }

        fn breakpoint_hit(&self, _evt: BreakpointEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("breakpoint_hit")
        }

        fn exception_hit(&self, _evt: ExceptionEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("exception_hit")
        }

        fn method_entry(&self, _evt: MethodEntryEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("method_entry")
        }

        fn method_exit(&self, _evt: MethodExitEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("method_exit")
        }

        fn class_prepare(&self, _evt: ClassPrepareEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("class_prepare")
        }

        fn class_unload(&self, _evt: ClassUnloadEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("class_unload")
        }

        fn monitor_contended_entered(
            &self,
            _evt: MonitorContendedEnteredEvent,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("monitor_contended_entered")
        }

        fn monitor_contended_enter(
            &self,
            _evt: MonitorContendedEnterEvent,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("monitor_contended_enter")
        }

        fn monitor_waited(&self, _evt: MonitorWaitedEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("monitor_waited")
        }

        fn monitor_wait(&self, _evt: MonitorWaitEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("monitor_wait")
        }

        fn step_complete(&self, _evt: StepEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("step_complete")
        }

        fn watchpoint_hit(&self, _evt: WatchpointEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("watchpoint_hit")
        }

        fn access_watchpoint_hit(
            &self,
            _evt: AccessWatchpointEvent,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("access_watchpoint_hit")
        }

        fn watchpoint_modified(
            &self,
            _evt: ModificationWatchpointEvent,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("watchpoint_modified")
        }

        fn thread_exited(&self, _evt: ThreadDeathEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("thread_exited")
        }

        fn thread_started(&self, _evt: ThreadStartEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("thread_started")
        }

        fn thread_state_changed(
            &self,
            _thread: ThreadReference,
            _state: Option<i32>,
            _cause: &dyn JdiCause,
            _reason: &dyn JdiReason,
        ) -> DebugStatus {
            self.record("thread_state_changed")
        }

        fn vm_died(&self, _evt: VmDeathEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("vm_died")
        }

        fn vm_disconnected(&self, _evt: VmDisconnectEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("vm_disconnected")
        }

        fn vm_started(&self, _evt: VmStartEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("vm_started")
        }

        fn process_stop(&self, _event_set: EventSet, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("process_stop")
        }

        fn process_shutdown(&self, _event: Event, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("process_shutdown")
        }
    }

    #[test]
    fn vm_selected_records_call_and_returns_status() {
        let r = Recorder::new(DebugStatus::Go);
        let status = r.vm_selected(VirtualMachine(1), &Causes::Unclaimed);
        assert_eq!(status, DebugStatus::Go);
        assert_eq!(*r.calls.lock().unwrap(), vec!["vm_selected"]);
    }

    #[test]
    fn thread_selected_records_call() {
        let r = Recorder::new(DebugStatus::Break);
        let status = r.thread_selected(ThreadReference(1), StackFrame(2), &Causes::Unclaimed);
        assert_eq!(status, DebugStatus::Break);
        assert_eq!(*r.calls.lock().unwrap(), vec!["thread_selected"]);
    }

    #[test]
    fn class_loaded_and_unloaded_record_calls() {
        let r = Recorder::new(DebugStatus::NoChange);
        r.class_loaded(VirtualMachine(1), "com.example.Foo", &Causes::Unclaimed);
        r.class_unloaded(VirtualMachine(1), "com.example.Foo", &Causes::Unclaimed);
        assert_eq!(
            *r.calls.lock().unwrap(),
            vec!["class_loaded", "class_unloaded"]
        );
    }

    #[test]
    fn breakpoint_lifecycle_records_calls() {
        let r = Recorder::new(DebugStatus::NoChange);
        let info = JdiBreakpointInfo::from_breakpoint(EventRequest(1));
        let other = JdiBreakpointInfo::from_breakpoint(EventRequest(2));
        r.breakpoint_created(&info, &Causes::Unclaimed);
        r.breakpoint_modified(&other, &info, &Causes::Unclaimed);
        r.breakpoint_deleted(&info, &Causes::Unclaimed);
        assert_eq!(
            *r.calls.lock().unwrap(),
            vec!["breakpoint_created", "breakpoint_modified", "breakpoint_deleted"]
        );
    }

    #[test]
    fn memory_changed_records_call() {
        let r = Recorder::new(DebugStatus::NoChange);
        let status = r.memory_changed(VirtualMachine(1), 0x1000, 16, &Causes::Unclaimed);
        assert_eq!(status, DebugStatus::NoChange);
        assert_eq!(*r.calls.lock().unwrap(), vec!["memory_changed"]);
    }

    #[test]
    fn vm_interrupted_records_call() {
        let r = Recorder::new(DebugStatus::Break);
        let status = r.vm_interrupted();
        assert_eq!(status, DebugStatus::Break);
        assert_eq!(*r.calls.lock().unwrap(), vec!["vm_interrupted"]);
    }

    #[test]
    fn breakpoint_hit_records_call() {
        let r = Recorder::new(DebugStatus::Break);
        let status = r.breakpoint_hit(BreakpointEvent(5), &Causes::Unclaimed);
        assert_eq!(status, DebugStatus::Break);
        assert_eq!(*r.calls.lock().unwrap(), vec!["breakpoint_hit"]);
    }

    #[test]
    fn thread_state_changed_accepts_state_and_reason() {
        let r = Recorder::new(DebugStatus::NoChange);
        r.thread_state_changed(
            ThreadReference(1),
            Some(1),
            &Causes::Unclaimed,
            &Reasons::BreakpointHit,
        );
        r.thread_state_changed(ThreadReference(1), None, &Causes::Unclaimed, &Reasons::None);
        assert_eq!(
            *r.calls.lock().unwrap(),
            vec!["thread_state_changed", "thread_state_changed"]
        );
    }

    #[test]
    fn process_stop_and_shutdown_record_calls() {
        let r = Recorder::new(DebugStatus::NoChange);
        r.process_stop(EventSet(1), &Causes::Unclaimed);
        r.process_shutdown(Event(2), &Causes::Unclaimed);
        assert_eq!(
            *r.calls.lock().unwrap(),
            vec!["process_stop", "process_shutdown"]
        );
    }

    #[test]
    fn listener_usable_as_trait_object() {
        let r = Recorder::new(DebugStatus::Go);
        let listener: &dyn JdiEventsListener = &r;
        let status = listener.vm_interrupted();
        assert_eq!(status, DebugStatus::Go);
    }

    #[test]
    fn listener_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Recorder>();
    }

    #[test]
    fn opaque_handles_support_equality_and_copy() {
        let a = VirtualMachine(1);
        let b = a;
        assert_eq!(a, b);
        assert_ne!(VirtualMachine(1), VirtualMachine(2));
        assert_eq!(EventSet(7), EventSet(7));
        assert_ne!(Event(1), Event(2));
    }
}

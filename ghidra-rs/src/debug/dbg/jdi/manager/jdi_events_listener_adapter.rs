use super::breakpoint::jdi_breakpoint_info::JdiBreakpointInfo;
use super::jdi_cause::JdiCause;
use super::jdi_events_listener::*;
use super::jdi_reason::JdiReason;
use super::jdi_thread_info::ThreadReference;
use super::r#impl::debug_status::DebugStatus;

/// An adapter providing default implementations for all [`JdiEventsListener`] methods.
///
/// Mirrors `ghidra.dbg.jdi.manager.JdiEventsListenerAdapter`. Each method returns a sensible
/// default: most return [`DebugStatus::NoChange`], while certain methods return [`DebugStatus::Break`]
/// or [`DebugStatus::StepInto`] to match the original behavior.
///
/// Users can subclass or wrap this adapter and override only the methods they care about.
#[derive(Debug, Clone, Copy)]
pub struct JdiEventsListenerAdapter;

impl JdiEventsListener for JdiEventsListenerAdapter {
    fn vm_selected(&self, _vm: VirtualMachine, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn thread_selected(
        &self,
        _thread: ThreadReference,
        _frame: StackFrame,
        _cause: &dyn JdiCause,
    ) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn thread_state_changed(
        &self,
        _thread: ThreadReference,
        _state: Option<i32>,
        _cause: &dyn JdiCause,
        _reason: &dyn JdiReason,
    ) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn class_loaded(&self, _vm: VirtualMachine, _name: &str, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn class_unloaded(&self, _vm: VirtualMachine, _name: &str, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn breakpoint_created(&self, _info: &JdiBreakpointInfo, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn breakpoint_modified(
        &self,
        _new_info: &JdiBreakpointInfo,
        _old_info: &JdiBreakpointInfo,
        _cause: &dyn JdiCause,
    ) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn breakpoint_deleted(&self, _info: &JdiBreakpointInfo, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn memory_changed(
        &self,
        _vm: VirtualMachine,
        _addr: i64,
        _len: i32,
        _cause: &dyn JdiCause,
    ) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn vm_interrupted(&self) -> DebugStatus {
        DebugStatus::Break
    }

    fn breakpoint_hit(&self, _evt: BreakpointEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::Break
    }

    fn exception_hit(&self, _evt: ExceptionEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::Break
    }

    fn method_entry(&self, _evt: MethodEntryEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn method_exit(&self, _evt: MethodExitEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn class_prepare(&self, _evt: ClassPrepareEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn class_unload(&self, _evt: ClassUnloadEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn monitor_contended_entered(
        &self,
        _evt: MonitorContendedEnteredEvent,
        _cause: &dyn JdiCause,
    ) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn monitor_contended_enter(
        &self,
        _evt: MonitorContendedEnterEvent,
        _cause: &dyn JdiCause,
    ) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn monitor_waited(&self, _evt: MonitorWaitedEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn monitor_wait(&self, _evt: MonitorWaitEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn step_complete(&self, _evt: StepEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::StepInto
    }

    fn watchpoint_hit(&self, _evt: WatchpointEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::Break
    }

    fn access_watchpoint_hit(
        &self,
        _evt: AccessWatchpointEvent,
        _cause: &dyn JdiCause,
    ) -> DebugStatus {
        DebugStatus::Break
    }

    fn watchpoint_modified(
        &self,
        _evt: ModificationWatchpointEvent,
        _cause: &dyn JdiCause,
    ) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn thread_exited(&self, _evt: ThreadDeathEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn thread_started(&self, _evt: ThreadStartEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn vm_died(&self, _evt: VmDeathEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn vm_disconnected(&self, _evt: VmDisconnectEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn vm_started(&self, _evt: VmStartEvent, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }

    fn process_stop(&self, _event_set: EventSet, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::Break
    }

    fn process_shutdown(&self, _event: Event, _cause: &dyn JdiCause) -> DebugStatus {
        DebugStatus::NoChange
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::dbg::jdi::manager::jdi_cause::Causes;
    use crate::debug::dbg::jdi::manager::jdi_reason::Reasons;

    #[test]
    fn vm_selected_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.vm_selected(VirtualMachine(1), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn thread_selected_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.thread_selected(
            ThreadReference(1),
            StackFrame(2),
            &Causes::Unclaimed,
        );
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn class_loaded_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.class_loaded(VirtualMachine(1), "com.example.Foo", &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn class_unloaded_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.class_unloaded(VirtualMachine(1), "com.example.Foo", &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn breakpoint_created_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let info = JdiBreakpointInfo::from_breakpoint(crate::debug::dbg::jdi::manager::breakpoint::jdi_breakpoint_info::EventRequest(1));
        let result = adapter.breakpoint_created(&info, &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn breakpoint_modified_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let info1 = JdiBreakpointInfo::from_breakpoint(crate::debug::dbg::jdi::manager::breakpoint::jdi_breakpoint_info::EventRequest(1));
        let info2 = JdiBreakpointInfo::from_breakpoint(crate::debug::dbg::jdi::manager::breakpoint::jdi_breakpoint_info::EventRequest(2));
        let result = adapter.breakpoint_modified(&info2, &info1, &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn breakpoint_deleted_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let info = JdiBreakpointInfo::from_breakpoint(crate::debug::dbg::jdi::manager::breakpoint::jdi_breakpoint_info::EventRequest(1));
        let result = adapter.breakpoint_deleted(&info, &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn memory_changed_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.memory_changed(VirtualMachine(1), 0x1000, 16, &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn vm_interrupted_returns_break() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.vm_interrupted();
        assert_eq!(result, DebugStatus::Break);
    }

    #[test]
    fn breakpoint_hit_returns_break() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.breakpoint_hit(BreakpointEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::Break);
    }

    #[test]
    fn exception_hit_returns_break() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.exception_hit(ExceptionEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::Break);
    }

    #[test]
    fn method_entry_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.method_entry(MethodEntryEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn method_exit_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.method_exit(MethodExitEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn class_prepare_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.class_prepare(ClassPrepareEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn class_unload_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.class_unload(ClassUnloadEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn monitor_contended_entered_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.monitor_contended_entered(
            MonitorContendedEnteredEvent(5),
            &Causes::Unclaimed,
        );
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn monitor_contended_enter_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.monitor_contended_enter(
            MonitorContendedEnterEvent(5),
            &Causes::Unclaimed,
        );
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn monitor_waited_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.monitor_waited(MonitorWaitedEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn monitor_wait_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.monitor_wait(MonitorWaitEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn step_complete_returns_step_into() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.step_complete(StepEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::StepInto);
    }

    #[test]
    fn watchpoint_hit_returns_break() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.watchpoint_hit(WatchpointEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::Break);
    }

    #[test]
    fn access_watchpoint_hit_returns_break() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.access_watchpoint_hit(AccessWatchpointEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::Break);
    }

    #[test]
    fn watchpoint_modified_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.watchpoint_modified(
            ModificationWatchpointEvent(5),
            &Causes::Unclaimed,
        );
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn thread_exited_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.thread_exited(ThreadDeathEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn thread_started_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.thread_started(ThreadStartEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn thread_state_changed_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.thread_state_changed(
            ThreadReference(1),
            Some(1),
            &Causes::Unclaimed,
            &Reasons::BreakpointHit,
        );
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn vm_died_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.vm_died(VmDeathEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn vm_disconnected_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.vm_disconnected(VmDisconnectEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn vm_started_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.vm_started(VmStartEvent(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn process_stop_returns_break() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.process_stop(EventSet(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::Break);
    }

    #[test]
    fn process_shutdown_returns_no_change() {
        let adapter = JdiEventsListenerAdapter;
        let result = adapter.process_shutdown(Event(5), &Causes::Unclaimed);
        assert_eq!(result, DebugStatus::NoChange);
    }

    #[test]
    fn adapter_is_copy() {
        let a = JdiEventsListenerAdapter;
        let b = a;
        let _ = a;
        let _ = b;
    }

    #[test]
    fn adapter_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<JdiEventsListenerAdapter>();
    }

    #[test]
    fn adapter_usable_as_trait_object() {
        let adapter = JdiEventsListenerAdapter;
        let listener: &dyn JdiEventsListener = &adapter;
        let status = listener.vm_interrupted();
        assert_eq!(status, DebugStatus::Break);
    }
}

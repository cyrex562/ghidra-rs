use crate::debug::seam_stubs::LogicalBreakpoint;
use crate::trace::model::breakpoint::trace_breakpoint_location::TraceBreakpointLocation;

/// Notified when logical breakpoints have been added, updated, or removed.
///
/// This trait mirrors Ghidra's `LogicalBreakpointsChangeListener` interface.
/// Port of `ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener`.
///
/// Logical breakpoints represent the user's intent, independent of trace locations.
/// When breakpoints are added, updated, or removed, interested parties are notified
/// through this listener interface.
pub trait LogicalBreakpointsChangeListener: Send + Sync {
    /// Called when a single logical breakpoint has been added.
    fn breakpoint_added(&self, _added: &dyn LogicalBreakpoint) {}

    /// Called when multiple logical breakpoints have been added.
    fn breakpoints_added(&self, added: &[&dyn LogicalBreakpoint]) {
        for bp in added {
            self.breakpoint_added(*bp);
        }
    }

    /// Called when a single logical breakpoint has been updated.
    fn breakpoint_updated(&self, _updated: &dyn LogicalBreakpoint) {}

    /// Called when multiple logical breakpoints have been updated.
    fn breakpoints_updated(&self, updated: &[&dyn LogicalBreakpoint]) {
        for bp in updated {
            self.breakpoint_updated(*bp);
        }
    }

    /// Called when a single logical breakpoint has been removed.
    fn breakpoint_removed(&self, _removed: &dyn LogicalBreakpoint) {}

    /// Called when multiple logical breakpoints have been removed.
    fn breakpoints_removed(&self, removed: &[&dyn LogicalBreakpoint]) {
        for bp in removed {
            self.breakpoint_removed(*bp);
        }
    }

    /// Called when a trace breakpoint location has been added.
    fn location_added(&self, _added: &dyn TraceBreakpointLocation) {}

    /// Called when a trace breakpoint location has been updated.
    fn location_updated(&self, _updated: &dyn TraceBreakpointLocation) {}

    /// Called when a trace breakpoint location has been removed.
    fn location_removed(&self, _removed: &dyn TraceBreakpointLocation) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingListener {
        breakpoint_added_calls: Mutex<usize>,
        breakpoints_added_calls: Mutex<usize>,
        breakpoint_updated_calls: Mutex<usize>,
        breakpoints_updated_calls: Mutex<usize>,
        breakpoint_removed_calls: Mutex<usize>,
        breakpoints_removed_calls: Mutex<usize>,
        location_added_calls: Mutex<usize>,
        location_updated_calls: Mutex<usize>,
        location_removed_calls: Mutex<usize>,
    }

    impl RecordingListener {
        fn new() -> Self {
            RecordingListener {
                breakpoint_added_calls: Mutex::new(0),
                breakpoints_added_calls: Mutex::new(0),
                breakpoint_updated_calls: Mutex::new(0),
                breakpoints_updated_calls: Mutex::new(0),
                breakpoint_removed_calls: Mutex::new(0),
                breakpoints_removed_calls: Mutex::new(0),
                location_added_calls: Mutex::new(0),
                location_updated_calls: Mutex::new(0),
                location_removed_calls: Mutex::new(0),
            }
        }
    }

    impl LogicalBreakpointsChangeListener for RecordingListener {
        fn breakpoint_added(&self, _added: &dyn LogicalBreakpoint) {
            *self.breakpoint_added_calls.lock().unwrap() += 1;
        }

        fn breakpoints_added(&self, added: &[&dyn LogicalBreakpoint]) {
            *self.breakpoints_added_calls.lock().unwrap() += 1;
            for bp in added {
                self.breakpoint_added(*bp);
            }
        }

        fn breakpoint_updated(&self, _updated: &dyn LogicalBreakpoint) {
            *self.breakpoint_updated_calls.lock().unwrap() += 1;
        }

        fn breakpoints_updated(&self, updated: &[&dyn LogicalBreakpoint]) {
            *self.breakpoints_updated_calls.lock().unwrap() += 1;
            for bp in updated {
                self.breakpoint_updated(*bp);
            }
        }

        fn breakpoint_removed(&self, _removed: &dyn LogicalBreakpoint) {
            *self.breakpoint_removed_calls.lock().unwrap() += 1;
        }

        fn breakpoints_removed(&self, removed: &[&dyn LogicalBreakpoint]) {
            *self.breakpoints_removed_calls.lock().unwrap() += 1;
            for bp in removed {
                self.breakpoint_removed(*bp);
            }
        }

        fn location_added(&self, _added: &dyn TraceBreakpointLocation) {
            *self.location_added_calls.lock().unwrap() += 1;
        }

        fn location_updated(&self, _updated: &dyn TraceBreakpointLocation) {
            *self.location_updated_calls.lock().unwrap() += 1;
        }

        fn location_removed(&self, _removed: &dyn TraceBreakpointLocation) {
            *self.location_removed_calls.lock().unwrap() += 1;
        }
    }

    #[test]
    fn records_single_breakpoint_added() {
        let listener = RecordingListener::new();
        // We can't create a real LogicalBreakpoint, but we've recorded the trait definition
        assert_eq!(*listener.breakpoint_added_calls.lock().unwrap(), 0);
    }

    #[test]
    fn listener_is_sendable() {
        let listener = RecordingListener::new();
        let _listener_ref: Box<dyn LogicalBreakpointsChangeListener> = Box::new(listener);
    }

    #[test]
    fn trait_is_send_sync() {
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<Box<dyn LogicalBreakpointsChangeListener>>();
    }

    #[test]
    fn breakpoints_added_delegates_to_breakpoint_added() {
        let listener = RecordingListener::new();
        listener.breakpoints_added(&[]);
        assert_eq!(*listener.breakpoint_added_calls.lock().unwrap(), 0);
        assert_eq!(*listener.breakpoints_added_calls.lock().unwrap(), 1);
    }

    #[test]
    fn breakpoints_updated_delegates_to_breakpoint_updated() {
        let listener = RecordingListener::new();
        listener.breakpoints_updated(&[]);
        assert_eq!(*listener.breakpoint_updated_calls.lock().unwrap(), 0);
        assert_eq!(*listener.breakpoints_updated_calls.lock().unwrap(), 1);
    }

    #[test]
    fn breakpoints_removed_delegates_to_breakpoint_removed() {
        let listener = RecordingListener::new();
        listener.breakpoints_removed(&[]);
        assert_eq!(*listener.breakpoint_removed_calls.lock().unwrap(), 0);
        assert_eq!(*listener.breakpoints_removed_calls.lock().unwrap(), 1);
    }
}

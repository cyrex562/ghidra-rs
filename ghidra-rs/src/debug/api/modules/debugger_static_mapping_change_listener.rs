use std::collections::HashSet;
use std::sync::Arc;

use crate::program::model::listing::Program;
use crate::trace::model::trace::Trace;

/// Notified when mappings among programs and traces in a debugger tool have changed.
///
/// This trait mirrors Ghidra's `DebuggerStaticMappingChangeListener` interface.
/// Port of `ghidra.debug.api.modules.DebuggerStaticMappingChangeListener`.
///
/// The mappings association relates statically-analyzed programs to dynamically-recorded traces,
/// allowing them to be viewed and edited together. When the collection of such associations
/// changes, all affected traces and programs are reported.
///
/// Note: This callback is invoked whenever any mapping changes, regardless of which snapshot(s)
/// the affected entries pertain to. Future refinements might provide snapshot-specific callbacks.
pub trait DebuggerStaticMappingChangeListener: Send + Sync {
    /// Called when the mappings among programs and traces have changed.
    ///
    /// # Arguments
    ///
    /// * `affected_traces` - the set of traces affected by the change(s)
    /// * `affected_programs` - the set of programs affected by the change(s)
    fn mappings_changed(
        &self,
        affected_traces: &HashSet<Arc<dyn Trace>>,
        affected_programs: &HashSet<Arc<dyn Program>>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingListener {
        calls: Mutex<Vec<(usize, usize)>>,
    }

    impl DebuggerStaticMappingChangeListener for RecordingListener {
        fn mappings_changed(
            &self,
            affected_traces: &HashSet<Arc<dyn Trace>>,
            affected_programs: &HashSet<Arc<dyn Program>>,
        ) {
            self.calls
                .lock()
                .unwrap()
                .push((affected_traces.len(), affected_programs.len()));
        }
    }

    #[test]
    fn records_callback_counts() {
        let listener = RecordingListener {
            calls: Mutex::new(Vec::new()),
        };

        listener.mappings_changed(&HashSet::new(), &HashSet::new());

        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (0, 0));
    }

    #[test]
    fn listener_is_sendable() {
        let listener = RecordingListener {
            calls: Mutex::new(Vec::new()),
        };
        let _listener_ref: Arc<dyn DebuggerStaticMappingChangeListener> = Arc::new(listener);
    }

    #[test]
    fn listener_is_usable_as_trait_object() {
        let listener: Arc<dyn DebuggerStaticMappingChangeListener> = Arc::new(RecordingListener {
            calls: Mutex::new(Vec::new()),
        });

        listener.mappings_changed(&HashSet::new(), &HashSet::new());

        if let Some(recording_listener) = unsafe {
            (listener.as_ref() as *const dyn DebuggerStaticMappingChangeListener
                as *const RecordingListener)
                .as_ref()
        } {
            // We verify this compiles and runs, showing the trait object works.
            let calls = recording_listener.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
        }
    }

    #[test]
    fn trait_is_send_sync() {
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<Box<dyn DebuggerStaticMappingChangeListener>>();
    }
}

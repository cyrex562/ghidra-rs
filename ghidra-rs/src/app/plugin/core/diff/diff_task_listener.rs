/// A listener for signalling when a diff task starts and ends.
///
/// Maps to `ghidra.app.plugin.core.diff.DiffTaskListener`.
pub trait DiffTaskListener {
    /// Called to indicate whether a diff task is currently running.
    ///
    /// `in_progress` is `true` when the task has started, `false` when it ends.
    fn task_in_progress(&mut self, in_progress: bool);
}

/// A no-op [`DiffTaskListener`] that ignores all notifications.
///
/// Equivalent to `DiffTaskListener.NULL_LISTENER` in the Java source.
pub struct NullDiffTaskListener;

impl DiffTaskListener for NullDiffTaskListener {
    fn task_in_progress(&mut self, _in_progress: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingListener {
        calls: Vec<bool>,
    }

    impl RecordingListener {
        fn new() -> Self {
            RecordingListener { calls: Vec::new() }
        }
    }

    impl DiffTaskListener for RecordingListener {
        fn task_in_progress(&mut self, in_progress: bool) {
            self.calls.push(in_progress);
        }
    }

    #[test]
    fn task_started_then_ended() {
        let mut listener = RecordingListener::new();
        listener.task_in_progress(true);
        listener.task_in_progress(false);
        assert_eq!(listener.calls, vec![true, false]);
    }

    #[test]
    fn null_listener_is_no_op() {
        let mut listener = NullDiffTaskListener;
        listener.task_in_progress(true);
        listener.task_in_progress(false);
    }

    #[test]
    fn multiple_in_progress_calls() {
        let mut listener = RecordingListener::new();
        listener.task_in_progress(true);
        listener.task_in_progress(true);
        listener.task_in_progress(false);
        assert_eq!(listener.calls, vec![true, true, false]);
    }
}

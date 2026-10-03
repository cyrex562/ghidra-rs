use crate::util::seam_stubs::Task;

/// Listener that is notified when a thread completes its task.
///
/// Port of `ghidra.util.task.TaskListener`.
pub trait TaskListener: Send + Sync {
    /// Notification that the task completed.
    fn task_completed(&self, task: &dyn Task);

    /// Notification that the task was canceled.
    fn task_cancelled(&self, task: &dyn Task);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockTask;
    impl Task for MockTask {}

    struct RecordingTaskListener {
        events: Mutex<Vec<&'static str>>,
    }

    impl TaskListener for RecordingTaskListener {
        fn task_completed(&self, _task: &dyn Task) {
            self.events.lock().unwrap().push("completed");
        }

        fn task_cancelled(&self, _task: &dyn Task) {
            self.events.lock().unwrap().push("cancelled");
        }
    }

    #[test]
    fn reports_completion_and_cancellation_as_trait_object() {
        let recorder = RecordingTaskListener { events: Mutex::new(Vec::new()) };
        let listener: &dyn TaskListener = &recorder;
        let task = MockTask;

        listener.task_completed(&task);
        listener.task_cancelled(&task);

        assert_eq!(*recorder.events.lock().unwrap(), vec!["completed", "cancelled"]);
    }
}

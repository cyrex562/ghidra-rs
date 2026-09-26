use super::seam_stubs::Task;

/// Receives callbacks as tasks start and stop being tracked.
pub trait TrackedTaskListener: Send + Sync {
    /// Called when a task is starting to be tracked.
    fn task_added(&self, task: &dyn Task);

    /// Called when a task is no longer being tracked.
    fn task_removed(&self, task: &dyn Task);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockTask;
    impl Task for MockTask {}

    struct Recorder {
        events: Mutex<Vec<&'static str>>,
    }

    impl TrackedTaskListener for Recorder {
        fn task_added(&self, _task: &dyn Task) {
            self.events.lock().unwrap().push("added");
        }

        fn task_removed(&self, _task: &dyn Task) {
            self.events.lock().unwrap().push("removed");
        }
    }

    #[test]
    fn tracks_task_lifecycle_as_trait_object() {
        let recorder = Recorder { events: Mutex::new(Vec::new()) };
        let listener: &dyn TrackedTaskListener = &recorder;
        let task = MockTask;

        listener.task_added(&task);
        listener.task_removed(&task);

        assert_eq!(*recorder.events.lock().unwrap(), vec!["added", "removed"]);
    }
}

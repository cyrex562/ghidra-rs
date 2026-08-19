use crate::framework::seam_stubs::{GScheduledTask, GTaskGroup, GTaskResult};
use std::sync::{Arc, Mutex};

/// Listener interface for tracking the state of a GTaskManager.
///
/// Port of `ghidra.framework.task.GTaskListener`.
pub trait GTaskListener: Send + Sync {
    /// Called when a task listener is added so that the listener can get all the initial state of
    /// the task manager while the task manager is in a locked state where nothing will change.
    fn initialize(&self);

    /// Notification that a task is starting to run.
    fn task_started(&self, task: &dyn GScheduledTask);

    /// Notification that a task is no longer running regardless of whether it completed normally,
    /// was cancelled, or threw an unhandled exception.
    fn task_completed(&self, task: &dyn GScheduledTask, result: &dyn GTaskResult);

    /// Notification that a GTaskGroup has been scheduled.
    fn task_group_scheduled(&self, group: &dyn GTaskGroup);

    /// Notification that a new GTask has been scheduled to run.
    fn task_scheduled(&self, scheduled_task: &dyn GScheduledTask);

    /// Notification that a new GTaskGroup has started to run.
    fn task_group_started(&self, task_group: &dyn GTaskGroup);

    /// Notification that the GTaskGroup has completed running.
    fn task_group_completed(&self, task_group: &dyn GTaskGroup);

    /// Notification that the GTaskManager has been suspended or resumed.
    fn suspended_state_changed(&self, suspended: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockGTaskListener {
        initialize_called: Arc<Mutex<bool>>,
    }

    impl GTaskListener for MockGTaskListener {
        fn initialize(&self) {
            *self.initialize_called.lock().unwrap() = true;
        }

        fn task_started(&self, _task: &dyn GScheduledTask) {}
        fn task_completed(&self, _task: &dyn GScheduledTask, _result: &dyn GTaskResult) {}
        fn task_group_scheduled(&self, _group: &dyn GTaskGroup) {}
        fn task_scheduled(&self, _scheduled_task: &dyn GScheduledTask) {}
        fn task_group_started(&self, _task_group: &dyn GTaskGroup) {}
        fn task_group_completed(&self, _task_group: &dyn GTaskGroup) {}
        fn suspended_state_changed(&self, _suspended: bool) {}
    }

    #[test]
    fn test_listener_trait_object() {
        let initialize_called = Arc::new(Mutex::new(false));
        let listener = MockGTaskListener {
            initialize_called: Arc::clone(&initialize_called),
        };

        let listener_obj: &dyn GTaskListener = &listener;
        listener_obj.initialize();

        assert!(*initialize_called.lock().unwrap());
    }

    #[test]
    fn test_listener_multiple_suspensions() {
        let initialize_called = Arc::new(Mutex::new(false));
        let listener = MockGTaskListener {
            initialize_called: Arc::clone(&initialize_called),
        };

        let listener_obj: &dyn GTaskListener = &listener;

        listener_obj.suspended_state_changed(true);
        listener_obj.suspended_state_changed(false);
        listener_obj.suspended_state_changed(true);

        listener_obj.initialize();
        assert!(*initialize_called.lock().unwrap());
    }
}

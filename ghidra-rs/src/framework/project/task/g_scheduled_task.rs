//! Port of `ghidra.framework.task.GScheduledTask`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use crate::framework::project::task::GTask;
use crate::framework::seam_stubs::GTaskGroup;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// One-up id generator so tasks of equal priority sort in the order they were added, matching
/// Java's static `nextID` counter.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Tracks a [`GTask`] scheduled with a `GTaskManager`: the group it was assigned to, the priority
/// it is to run at, and the monitor used while it runs.
pub struct GScheduledTask {
    task: Arc<dyn GTask>,
    priority: i32,
    thread: Mutex<Option<ThreadId>>,
    id: u64,
    group: Arc<dyn GTaskGroup>,
    monitor: Arc<dyn TaskMonitor>,
}

impl GScheduledTask {
    /// Creates a new scheduled task, as done when a task is scheduled with the `GTaskManager`.
    ///
    /// `group` is the group this task belongs to and `priority` is the priority at which this
    /// task is to be executed relative to other scheduled tasks; lower numbers run first.
    pub fn new(group: Arc<dyn GTaskGroup>, task: Arc<dyn GTask>, priority: i32) -> Self {
        Self {
            task,
            priority,
            thread: Mutex::new(None),
            id: NEXT_ID.fetch_add(1, Ordering::SeqCst),
            group,
            monitor: Arc::new(DummyMonitor),
        }
    }

    /// Returns the `GTask` that is scheduled.
    pub fn get_task(&self) -> Arc<dyn GTask> {
        Arc::clone(&self.task)
    }

    /// Returns the priority at which the task was scheduled. Lower numbers have higher priority.
    pub fn get_priority(&self) -> i32 {
        self.priority
    }

    /// Returns the monitor that will be used for this task.
    pub fn get_task_monitor(&self) -> Arc<dyn TaskMonitor> {
        Arc::clone(&self.monitor)
    }

    /// Ordering is compatible with the default identity-based equality: it only returns `0` when
    /// comparing an instance to itself.
    pub fn compare_to(&self, other: &GScheduledTask) -> i32 {
        if std::ptr::eq(self, other) {
            return 0;
        }
        if self.priority == other.priority {
            if self.id > other.id {
                1
            } else {
                -1
            }
        } else {
            self.priority - other.priority
        }
    }

    /// Records the calling thread as the thread that is executing this task.
    pub(crate) fn set_thread(&self) {
        *self.thread.lock().unwrap() = Some(std::thread::current().id());
    }

    /// True if this task was started on the thread that is asking.
    pub(crate) fn is_running_in_current_thread(&self) -> bool {
        *self.thread.lock().unwrap() == Some(std::thread::current().id())
    }

    /// Returns the `GTaskGroup` for this task.
    pub fn get_group(&self) -> Arc<dyn GTaskGroup> {
        Arc::clone(&self.group)
    }

    /// Returns the description for the scheduled `GTask`.
    pub fn get_description(&self) -> String {
        self.task.get_name()
    }

    /// Matches Java's `toString()`.
    pub fn to_string(&self) -> String {
        format!("{} : {}", self.task.get_name(), self.priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::framework::seam_stubs::GTaskGroupStub;
    use crate::util::exception::CancelledException;

    struct NamedTask(String);

    impl GTask for NamedTask {
        fn get_name(&self) -> String {
            self.0.clone()
        }

        fn run(
            &self,
            _domain_object: &dyn DomainObject,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    fn group() -> Arc<dyn GTaskGroup> {
        GTaskGroupStub::new("group", true) as Arc<dyn GTaskGroup>
    }

    #[test]
    fn accessors_match_java_getters() {
        let task: Arc<dyn GTask> = Arc::new(NamedTask("analyze".to_string()));
        let scheduled = GScheduledTask::new(group(), Arc::clone(&task), 5);

        assert_eq!(scheduled.get_priority(), 5);
        assert_eq!(scheduled.get_task().get_name(), "analyze");
        assert_eq!(scheduled.get_description(), "analyze");
        assert_eq!(scheduled.to_string(), "analyze : 5");
    }

    #[test]
    fn compare_to_orders_by_priority_then_by_insertion_order() {
        let task: Arc<dyn GTask> = Arc::new(NamedTask("t".to_string()));
        let g = group();
        let low_priority_first = GScheduledTask::new(Arc::clone(&g), Arc::clone(&task), 10);
        let low_priority_second = GScheduledTask::new(Arc::clone(&g), Arc::clone(&task), 10);
        let higher_priority = GScheduledTask::new(g, task, 1);

        // Equal priority: earlier-created task sorts first.
        assert_eq!(low_priority_first.compare_to(&low_priority_second), -1);
        assert_eq!(low_priority_second.compare_to(&low_priority_first), 1);

        // Lower priority number sorts first.
        assert!(higher_priority.compare_to(&low_priority_first) < 0);
        assert!(low_priority_first.compare_to(&higher_priority) > 0);

        // Compatible with identity-based equality.
        assert_eq!(low_priority_first.compare_to(&low_priority_first), 0);
    }

    #[test]
    fn thread_tracking_matches_java_package_private_helpers() {
        let task: Arc<dyn GTask> = Arc::new(NamedTask("t".to_string()));
        let scheduled = GScheduledTask::new(group(), task, 1);

        assert!(!scheduled.is_running_in_current_thread());
        scheduled.set_thread();
        assert!(scheduled.is_running_in_current_thread());
    }
}

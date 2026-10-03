//! Port of `ghidra.framework.task.GTaskGroup`.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::framework::project::task::{GScheduledTask, GTask};
use crate::util::task::{DummyMonitor, TaskMonitor};

/// One-up id generator so groups sort in the order they were created, matching Java's static
/// `nextID` counter.
static NEXT_ID: AtomicI64 = AtomicI64::new(0);

/// Groups several [`GTask`]s that must all run before any task in the next group runs,
/// regardless of priority.
///
/// See `GTaskManager`.
pub struct GTaskGroup {
    id: i64,
    description: String,
    start_new_transaction: bool,
    monitor: Arc<dyn TaskMonitor>,
    task_list: Mutex<Vec<Arc<GScheduledTask>>>,
    cancelled: AtomicBool,
    /// True once scheduled in a `GTaskManager`; prevents new tasks being added.
    scheduled: AtomicBool,
    me: Weak<GTaskGroup>,
}

impl GTaskGroup {
    /// Creates a new named group with a do-nothing task monitor.
    ///
    /// `start_new_transaction`: if true, any existing transaction will be closed and a new
    /// transaction created when this group runs. Otherwise the tasks in this group execute in
    /// the same transaction as the previous group, if one was open when this group started.
    pub fn new(description: &str, start_new_transaction: bool) -> Arc<Self> {
        Self::with_monitor(description, start_new_transaction, Arc::new(DummyMonitor))
    }

    /// Creates a new named group whose progress is reported to `monitor`.
    pub fn with_monitor(
        description: &str,
        start_new_transaction: bool,
        monitor: Arc<dyn TaskMonitor>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            id: NEXT_ID.fetch_add(1, Ordering::SeqCst),
            description: description.to_string(),
            start_new_transaction,
            monitor,
            task_list: Mutex::new(Vec::new()),
            cancelled: AtomicBool::new(false),
            scheduled: AtomicBool::new(false),
            me: me.clone(),
        })
    }

    /// Adds a task to this group with the given priority. Tasks can only be added before the
    /// group is added to a `GTaskManager`.
    ///
    /// # Panics
    /// Panics (Java throws `IllegalStateException`) if called after the group has been scheduled
    /// with a `GTaskManager`.
    pub fn add_task(&self, task: Arc<dyn GTask>, priority: i32) -> Arc<GScheduledTask> {
        if self.scheduled.load(Ordering::SeqCst) {
            panic!(
                "Can't directly add new tasks on a group that has been scheduled with a \
                 GTaskManager"
            );
        }
        self.do_add_task(task, priority)
    }

    /// Adds a task without checking whether this group has already been scheduled. Used by
    /// `GTaskManager`, which is allowed to grow the current group while it is running.
    pub(crate) fn do_add_task(&self, task: Arc<dyn GTask>, priority: i32) -> Arc<GScheduledTask> {
        let group = self
            .me
            .upgrade()
            .expect("GTaskGroup must be kept in the Arc returned by its constructor");
        let scheduled_task = Arc::new(GScheduledTask::new(group, task, priority));
        let mut task_list = self.task_list.lock().unwrap();
        task_list.push(Arc::clone(&scheduled_task));
        self.monitor.set_maximum(task_list.len() as i64);
        scheduled_task
    }

    /// Returns the scheduled tasks in the group, sorted by priority.
    pub fn get_tasks(&self) -> Vec<Arc<GScheduledTask>> {
        let mut list: Vec<Arc<GScheduledTask>> = self.task_list.lock().unwrap().clone();
        list.sort_by(|a, b| a.compare_to(b).cmp(&0));
        list
    }

    /// Returns the task monitor that tracks the overall progress of tasks within this group.
    pub fn get_task_monitor(&self) -> Arc<dyn TaskMonitor> {
        Arc::clone(&self.monitor)
    }

    /// True if this group wants to start a new transaction when it runs. Otherwise the group
    /// adds on to any existing transaction from the previous group.
    pub fn wants_new_transaction(&self) -> bool {
        self.start_new_transaction
    }

    /// Returns the description for the group.
    pub fn get_description(&self) -> String {
        self.description.clone()
    }

    /// Orders groups by creation order, compatible with identity-based equality.
    pub fn compare_to(&self, other: &GTaskGroup) -> i32 {
        (self.id - other.id) as i32
    }

    /// Matches Java's `toString()`.
    pub fn to_string(&self) -> String {
        format!("Task Group: {}", self.description)
    }

    /// Cancels the group. Any tasks that haven't yet started will never run.
    pub fn set_cancelled(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// True if this group was cancelled.
    pub fn was_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Notification that a task in the group has completed. Keeps track of the overall progress
    /// of the tasks completed in this group.
    pub fn task_completed(&self) {
        self.monitor.increment_progress(1);
    }

    /// Marks this group as scheduled with a `GTaskManager`, preventing further calls to
    /// [`Self::add_task`].
    pub fn set_scheduled(&self) {
        self.scheduled.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
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

    fn named_task(name: &str) -> Arc<dyn GTask> {
        Arc::new(NamedTask(name.to_string()))
    }

    /// A [`TaskMonitor`] that actually records `set_maximum`/`increment_progress` calls, unlike
    /// [`DummyMonitor`] which discards them. Used to verify [`GTaskGroup`] drives its monitor
    /// correctly, independent of which monitor implementation is plugged in.
    #[derive(Default)]
    struct RecordingMonitor {
        maximum: std::sync::atomic::AtomicI64,
        progress: std::sync::atomic::AtomicI64,
    }

    impl TaskMonitor for RecordingMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, value: i64) {
            self.progress.store(value, Ordering::SeqCst);
        }
        fn initialize(&self, max: i64) {
            self.maximum.store(max, Ordering::SeqCst);
        }
        fn set_maximum(&self, max: i64) {
            self.maximum.store(max, Ordering::SeqCst);
        }
        fn get_maximum(&self) -> i64 {
            self.maximum.load(Ordering::SeqCst)
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, amount: i64) {
            self.progress.fetch_add(amount, Ordering::SeqCst);
        }
        fn get_progress(&self) -> i64 {
            self.progress.load(Ordering::SeqCst)
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn accessors_match_java_getters() {
        let group = GTaskGroup::new("analysis", true);
        assert_eq!(group.get_description(), "analysis");
        assert!(group.wants_new_transaction());
        assert!(!group.was_cancelled());
        assert_eq!(group.to_string(), "Task Group: analysis");
    }

    #[test]
    fn get_tasks_returns_tasks_sorted_by_priority() {
        let group = GTaskGroup::new("g", true);
        group.add_task(named_task("low"), 30);
        group.add_task(named_task("high"), 10);
        group.add_task(named_task("medium"), 20);

        let tasks = group.get_tasks();
        let names: Vec<String> = tasks.iter().map(|t| t.get_description()).collect();
        assert_eq!(names, vec!["high", "medium", "low"]);
    }

    #[test]
    fn task_monitor_tracks_task_count_and_completion() {
        let monitor: Arc<dyn TaskMonitor> = Arc::new(RecordingMonitor::default());
        let group = GTaskGroup::with_monitor("g", true, Arc::clone(&monitor));
        group.add_task(named_task("a"), 1);
        group.add_task(named_task("b"), 1);
        assert_eq!(group.get_task_monitor().get_maximum(), 2);

        group.task_completed();
        group.task_completed();
        assert_eq!(group.get_task_monitor().get_progress(), 2);
    }

    #[test]
    fn set_cancelled_is_reflected_in_was_cancelled() {
        let group = GTaskGroup::new("g", true);
        assert!(!group.was_cancelled());
        group.set_cancelled();
        assert!(group.was_cancelled());
    }

    #[test]
    fn compare_to_orders_groups_by_creation_order() {
        let first = GTaskGroup::new("first", true);
        let second = GTaskGroup::new("second", true);
        assert!(first.compare_to(&second) < 0);
        assert!(second.compare_to(&first) > 0);
        assert_eq!(first.compare_to(&first), 0);
    }

    #[test]
    #[should_panic(expected = "has been scheduled")]
    fn add_task_after_scheduled_panics() {
        let group = GTaskGroup::new("g", true);
        group.set_scheduled();
        group.add_task(named_task("late"), 1);
    }
}

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use crate::util::exception::CancelledException;
use crate::util::task::{CancelledListener, TaskMonitor};

/// Fixed unit size used to represent the parent monitor's full progress range while it is
/// divided among sub-monitors.
///
/// Port of `ghidra.util.task.TaskMonitorSplitter.MONITOR_SIZE`. The Java field is a mutable
/// `public static int`, but nothing in the codebase reassigns it, so it is ported as a
/// constant.
pub const MONITOR_SIZE: i64 = 100_000;

/// Splits `monitor`'s progress range into `n` independent sub-monitors, each occupying an
/// equal-sized slice of the parent's overall progress.
///
/// Port of `ghidra.util.task.TaskMonitorSplitter.splitTaskMonitor`.
pub fn split_task_monitor(monitor: Arc<dyn TaskMonitor>, n: usize) -> Vec<Box<dyn TaskMonitor>> {
    monitor.initialize(MONITOR_SIZE);
    let sub_size = MONITOR_SIZE as f64 / n as f64;
    (0..n)
        .map(|_| Box::new(SubTaskMonitor::new(Arc::clone(&monitor), sub_size)) as Box<dyn TaskMonitor>)
        .collect()
}

/// Shared, interior-mutable state for a [`SubTaskMonitor`].
///
/// Split out from [`SubTaskMonitor`] itself so that a clone of the monitor can be registered
/// as a [`CancelledListener`] on the parent, mirroring the Java class implementing both
/// `TaskMonitor` and `CancelledListener` on the same object.
struct SubTaskMonitorState {
    parent: Arc<dyn TaskMonitor>,
    sub_size: f64,
    max: AtomicI64,
    progress: AtomicI64,
    parent_progress: AtomicI64,
    listeners: Mutex<Vec<Box<dyn CancelledListener>>>,
}

impl SubTaskMonitorState {
    fn normalize_progress(&self) {
        let max = self.max.load(Ordering::SeqCst);
        if self.progress.load(Ordering::SeqCst) > max {
            self.progress.store(max, Ordering::SeqCst);
        }
    }

    fn update_parent(&self) {
        let max = self.max.load(Ordering::SeqCst);
        let progress = self.progress.load(Ordering::SeqCst);
        let new_parent_progress = if max == 0 {
            0
        }
        else {
            ((progress as f64 * self.sub_size) / max as f64) as i64
        };
        let previous_parent_progress = self.parent_progress.swap(new_parent_progress, Ordering::SeqCst);
        self.parent.increment_progress(new_parent_progress - previous_parent_progress);
    }
}

/// A [`TaskMonitor`] representing one equal-sized slice of a parent monitor's progress range.
///
/// Port of `ghidra.util.task.TaskMonitorSplitter.SubTaskMonitor`. The Java class tracks a
/// local `Set<SubTaskMonitor> notDoneYetSet` constructor argument that is populated but never
/// read anywhere in the class or its callers; that dead bookkeeping is dropped here.
#[derive(Clone)]
struct SubTaskMonitor {
    state: Arc<SubTaskMonitorState>,
}

impl SubTaskMonitor {
    fn new(parent: Arc<dyn TaskMonitor>, sub_size: f64) -> Self {
        let state = Arc::new(SubTaskMonitorState {
            parent: Arc::clone(&parent),
            sub_size,
            max: AtomicI64::new(100),
            progress: AtomicI64::new(0),
            parent_progress: AtomicI64::new(0),
            listeners: Mutex::new(Vec::new()),
        });
        let monitor = SubTaskMonitor { state };
        parent.add_cancelled_listener(Box::new(monitor.clone()));
        monitor
    }
}

impl CancelledListener for SubTaskMonitor {
    fn cancelled(&self) {
        let listeners = self.state.listeners.lock().unwrap();
        for listener in listeners.iter() {
            listener.cancelled();
        }
    }
}

impl TaskMonitor for SubTaskMonitor {
    fn is_cancelled(&self) -> bool {
        self.state.parent.is_cancelled()
    }

    fn set_show_progress_value(&self, show: bool) {
        self.state.parent.set_show_progress_value(show);
    }

    fn set_message(&self, message: &str) {
        self.state.parent.set_message(message);
    }

    fn get_message(&self) -> String {
        self.state.parent.get_message()
    }

    fn set_progress(&self, value: i64) {
        self.state.progress.store(value, Ordering::SeqCst);
        self.state.normalize_progress();
        self.state.update_parent();
    }

    fn initialize(&self, new_max: i64) {
        self.set_maximum(new_max);
        self.set_progress(0);
    }

    fn set_maximum(&self, new_max: i64) {
        self.state.max.store(new_max, Ordering::SeqCst);
        self.state.normalize_progress();
        self.state.update_parent();
    }

    fn get_maximum(&self) -> i64 {
        self.state.max.load(Ordering::SeqCst)
    }

    fn set_indeterminate(&self, indeterminate: bool) {
        self.state.parent.set_indeterminate(indeterminate);
    }

    fn is_indeterminate(&self) -> bool {
        self.state.parent.is_indeterminate()
    }

    fn check_cancelled(&self) -> Result<(), CancelledException> {
        self.state.parent.check_cancelled()
    }

    fn increment_progress(&self, increment_amount: i64) {
        self.state.progress.fetch_add(increment_amount, Ordering::SeqCst);
        self.state.normalize_progress();
        self.state.update_parent();
    }

    fn get_progress(&self) -> i64 {
        self.state.progress.load(Ordering::SeqCst)
    }

    fn cancel(&self) {
        self.state.parent.cancel();
    }

    fn add_cancelled_listener(&self, listener: Box<dyn CancelledListener>) {
        self.state.listeners.lock().unwrap().push(listener);
    }

    fn remove_cancelled_listener(&self, listener: &dyn CancelledListener) {
        let mut listeners = self.state.listeners.lock().unwrap();
        listeners.retain(|l| {
            !std::ptr::eq(
                l.as_ref() as *const dyn CancelledListener as *const (),
                listener as *const dyn CancelledListener as *const (),
            )
        });
    }

    fn set_cancel_enabled(&self, enabled: bool) {
        self.state.parent.set_cancel_enabled(enabled);
    }

    fn is_cancel_enabled(&self) -> bool {
        self.state.parent.is_cancel_enabled()
    }

    fn clear_cancelled(&self) {
        unimplemented!("clear_cancelled is not supported on SubTaskMonitor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    struct RecordingMonitor {
        progress: AtomicI64,
        max: AtomicI64,
        message: Mutex<String>,
        cancelled: AtomicBool,
        listeners: Mutex<Vec<Box<dyn CancelledListener>>>,
    }

    impl RecordingMonitor {
        fn new() -> Self {
            RecordingMonitor {
                progress: AtomicI64::new(0),
                max: AtomicI64::new(0),
                message: Mutex::new(String::new()),
                cancelled: AtomicBool::new(false),
                listeners: Mutex::new(Vec::new()),
            }
        }
    }

    impl TaskMonitor for RecordingMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, message: &str) {
            *self.message.lock().unwrap() = message.to_string();
        }
        fn get_message(&self) -> String {
            self.message.lock().unwrap().clone()
        }
        fn set_progress(&self, value: i64) {
            self.progress.store(value, Ordering::SeqCst);
        }
        fn initialize(&self, max: i64) {
            self.max.store(max, Ordering::SeqCst);
            self.progress.store(0, Ordering::SeqCst);
        }
        fn set_maximum(&self, max: i64) {
            self.max.store(max, Ordering::SeqCst);
        }
        fn get_maximum(&self) -> i64 {
            self.max.load(Ordering::SeqCst)
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            if self.is_cancelled() {
                return Err(CancelledException::default());
            }
            Ok(())
        }
        fn increment_progress(&self, amount: i64) {
            self.progress.fetch_add(amount, Ordering::SeqCst);
        }
        fn get_progress(&self) -> i64 {
            self.progress.load(Ordering::SeqCst)
        }
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
            let listeners = self.listeners.lock().unwrap();
            for listener in listeners.iter() {
                listener.cancelled();
            }
        }
        fn add_cancelled_listener(&self, listener: Box<dyn CancelledListener>) {
            self.listeners.lock().unwrap().push(listener);
        }
        fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {
            self.cancelled.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn split_initializes_parent_to_monitor_size() {
        let parent = Arc::new(RecordingMonitor::new());
        let _subs = split_task_monitor(parent.clone(), 4);
        assert_eq!(parent.get_maximum(), MONITOR_SIZE);
        assert_eq!(parent.get_progress(), 0);
    }

    #[test]
    fn split_creates_requested_number_of_sub_monitors() {
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent, 4);
        assert_eq!(subs.len(), 4);
    }

    #[test]
    fn basic_use_mirrors_java_test() {
        // Port of TaskMonitorSplitterTest.testBasicUse.
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent.clone(), 4);

        subs[0].initialize(100);
        subs[0].set_progress(1);
        assert_eq!(subs[0].get_progress(), 1);
        assert_eq!(parent.get_progress(), MONITOR_SIZE / 400);

        subs[0].increment_progress(1);
        assert_eq!(parent.get_progress(), 2 * MONITOR_SIZE / 400);

        subs[0].set_progress(10);
        assert_eq!(parent.get_progress(), 10 * MONITOR_SIZE / 400);
    }

    #[test]
    fn max_settings_mirror_java_test() {
        // Port of TaskMonitorSplitterTest.testMaxSettings.
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent.clone(), 4);

        subs[0].initialize(100);
        subs[0].set_progress(50);
        assert_eq!(parent.get_progress(), 50 * MONITOR_SIZE / 400);

        subs[0].set_maximum(25);
        assert_eq!(subs[0].get_maximum(), 25);
        assert_eq!(parent.get_progress(), MONITOR_SIZE / 4);

        subs[0].set_maximum(100);
        assert_eq!(parent.get_progress(), 25 * MONITOR_SIZE / 400);
    }

    #[test]
    fn progress_is_clamped_to_maximum() {
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent, 2);

        subs[0].initialize(10);
        subs[0].set_progress(999);
        assert_eq!(subs[0].get_progress(), 10);
    }

    #[test]
    fn cancel_delegates_to_parent() {
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent.clone(), 1);

        assert!(!subs[0].is_cancelled());
        subs[0].cancel();
        assert!(parent.is_cancelled());
        assert!(subs[0].is_cancelled());
    }

    #[test]
    fn check_cancelled_delegates_to_parent() {
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent.clone(), 1);

        assert!(subs[0].check_cancelled().is_ok());
        parent.cancel();
        assert!(subs[0].check_cancelled().is_err());
    }

    #[test]
    #[should_panic(expected = "not supported")]
    fn clear_cancelled_is_unsupported() {
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent, 1);
        subs[0].clear_cancelled();
    }

    struct FlagListener {
        flagged: Arc<AtomicBool>,
    }

    impl CancelledListener for FlagListener {
        fn cancelled(&self) {
            self.flagged.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn parent_cancellation_is_forwarded_to_sub_monitor_listeners() {
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent.clone(), 2);

        let flagged = Arc::new(AtomicBool::new(false));
        subs[0].add_cancelled_listener(Box::new(FlagListener { flagged: flagged.clone() }));

        parent.cancel();

        assert!(flagged.load(Ordering::SeqCst));
    }

    #[test]
    fn remove_cancelled_listener_nonexistent_is_noop() {
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent.clone(), 1);

        let flagged = Arc::new(AtomicBool::new(false));
        subs[0].add_cancelled_listener(Box::new(FlagListener { flagged: flagged.clone() }));

        let other = FlagListener { flagged: Arc::new(AtomicBool::new(false)) };
        subs[0].remove_cancelled_listener(&other);

        parent.cancel();
        assert!(flagged.load(Ordering::SeqCst));
    }

    #[test]
    fn message_delegates_to_parent() {
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent.clone(), 1);

        subs[0].set_message("working");
        assert_eq!(parent.get_message(), "working");
        assert_eq!(subs[0].get_message(), "working");
    }

    #[test]
    fn sub_monitors_share_parent_progress_independently() {
        let parent = Arc::new(RecordingMonitor::new());
        let subs = split_task_monitor(parent.clone(), 2);

        subs[0].initialize(10);
        subs[1].initialize(10);

        subs[0].set_progress(5);
        let after_first = parent.get_progress();
        assert!(after_first > 0);

        subs[1].set_progress(5);
        let after_second = parent.get_progress();
        assert_eq!(after_second, 2 * after_first);
    }
}

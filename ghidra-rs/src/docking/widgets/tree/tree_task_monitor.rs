use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use crate::util::exception::CancelledException;
use crate::util::task::{CancelledListener, TaskMonitor};

/// Initial full-range size for a root [`TreeTaskMonitor`]; chosen huge so it can be
/// subdivided many times without losing precision.
const MAX_VALUE: i64 = 0x1000_0000_0000_0000;

/// A [`TaskMonitor`] useful for monitoring work when traversing trees.
///
/// Corresponds to `docking.widgets.tree.TreeTaskMonitor`.
///
/// It works by subdividing the distance of the top-most progress bar (represented by the
/// top-most monitor) into equal size chunks depending on how many children have to be
/// visited. For example, assume the root node has 5 children, then the task bar for that
/// node would increment 20% of the bar as it completed work on each of its children. Now,
/// assume each child of the root node has 10 children. The task monitor for each root child
/// will operate entirely within its 20% as mentioned above. So the first child of the first
/// child will increment the progress bar 2% (10% of 20%) when it is complete.
///
/// The Java source picks between two construction modes via `instanceof` on the given
/// monitor. Rust's static typing surfaces that choice as two constructors instead:
/// [`TreeTaskMonitor::new`] wraps a fresh top-most monitor, and
/// [`TreeTaskMonitor::from_parent`] chains beneath an existing `TreeTaskMonitor`, reusing
/// its underlying root delegate.
pub struct TreeTaskMonitor {
    monitor: Arc<dyn TaskMonitor>,

    // This monitor operates on a sub-range of the top-most monitor. The range min/max define
    // that range.
    current_range_min: i64,
    current_range_max: i64,

    // The amount by which one increment increases the top-most monitor.
    chunk_size: AtomicI64,

    // These values are the max and progress for this sub-monitor.
    max: AtomicI64,
    progress: AtomicI64,
}

impl TreeTaskMonitor {
    /// Wraps `monitor` as a top-most [`TreeTaskMonitor`], operating over its full range.
    pub fn new(monitor: Arc<dyn TaskMonitor>, max: i64) -> Self {
        monitor.initialize(MAX_VALUE);
        let result = TreeTaskMonitor {
            monitor,
            current_range_min: 0,
            current_range_max: MAX_VALUE,
            chunk_size: AtomicI64::new(0),
            max: AtomicI64::new(0),
            progress: AtomicI64::new(0),
        };
        result.set_maximum(max);
        result
    }

    /// Chains beneath `parent`, operating over the sub-range `parent` currently occupies
    /// within its own root delegate.
    pub fn from_parent(parent: &TreeTaskMonitor, max: i64) -> Self {
        let current_range_min = parent.get_true_progress();
        let current_range_max = current_range_min + parent.chunk_size.load(Ordering::SeqCst);
        let result = TreeTaskMonitor {
            monitor: Arc::clone(&parent.monitor),
            current_range_min,
            current_range_max,
            chunk_size: AtomicI64::new(0),
            max: AtomicI64::new(0),
            progress: AtomicI64::new(0),
        };
        result.set_maximum(max);
        result
    }

    fn get_true_progress(&self) -> i64 {
        self.monitor.get_progress()
    }
}

impl TaskMonitor for TreeTaskMonitor {
    fn is_cancelled(&self) -> bool {
        self.monitor.is_cancelled()
    }

    fn set_show_progress_value(&self, show_progress_value: bool) {
        self.monitor.set_show_progress_value(show_progress_value);
    }

    fn set_message(&self, message: &str) {
        self.monitor.set_message(message);
    }

    fn get_message(&self) -> String {
        self.monitor.get_message()
    }

    fn set_progress(&self, value: i64) {
        self.progress.store(value, Ordering::SeqCst);
        let chunk_size = self.chunk_size.load(Ordering::SeqCst);
        self.monitor
            .set_progress(self.current_range_min + value * chunk_size);
    }

    fn initialize(&self, max_value: i64) {
        self.set_maximum(max_value);
    }

    fn set_maximum(&self, max_value: i64) {
        if max_value > 0 {
            self.max.store(max_value, Ordering::SeqCst);

            // The size of the current window/section of the overall monitor.
            let current_range = self.current_range_max - self.current_range_min;

            // The size of one increment within the current range.
            let chunk_size = (current_range / max_value).max(1);
            self.chunk_size.store(chunk_size, Ordering::SeqCst);
        }
        else {
            self.max.store(0, Ordering::SeqCst);
            self.chunk_size.store(0, Ordering::SeqCst);
        }
    }

    fn get_maximum(&self) -> i64 {
        self.max.load(Ordering::SeqCst)
    }

    fn set_indeterminate(&self, indeterminate: bool) {
        self.monitor.set_indeterminate(indeterminate);
    }

    fn is_indeterminate(&self) -> bool {
        self.monitor.is_indeterminate()
    }

    fn check_cancelled(&self) -> Result<(), CancelledException> {
        self.monitor.check_cancelled()
    }

    fn increment_progress(&self, increment_amount: i64) {
        let progress = self.progress.fetch_add(increment_amount, Ordering::SeqCst) + increment_amount;
        let chunk_size = self.chunk_size.load(Ordering::SeqCst);
        self.monitor
            .set_progress(self.current_range_min + progress * chunk_size);
    }

    fn get_progress(&self) -> i64 {
        self.progress.load(Ordering::SeqCst)
    }

    fn cancel(&self) {
        self.monitor.cancel();
    }

    fn add_cancelled_listener(&self, listener: Box<dyn CancelledListener>) {
        self.monitor.add_cancelled_listener(listener);
    }

    fn remove_cancelled_listener(&self, listener: &dyn CancelledListener) {
        self.monitor.remove_cancelled_listener(listener);
    }

    fn set_cancel_enabled(&self, enabled: bool) {
        self.monitor.set_cancel_enabled(enabled);
    }

    fn is_cancel_enabled(&self) -> bool {
        self.monitor.is_cancel_enabled()
    }

    fn clear_cancelled(&self) {
        self.monitor.clear_cancelled();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    #[test]
    fn new_initializes_root_delegate_to_max_value() {
        let root = Arc::new(DummyMonitor);
        let tree_monitor = TreeTaskMonitor::new(root, 5);
        assert_eq!(tree_monitor.get_maximum(), 5);
        assert_eq!(tree_monitor.get_progress(), 0);
    }

    #[test]
    fn set_maximum_computes_chunk_size_from_range() {
        let root = Arc::new(DummyMonitor);
        let tree_monitor = TreeTaskMonitor::new(root, 4);
        // current_range = MAX_VALUE - 0; chunk_size = current_range / 4
        assert_eq!(tree_monitor.chunk_size.load(Ordering::SeqCst), MAX_VALUE / 4);
    }

    #[test]
    fn set_maximum_zero_clears_chunk_size() {
        let root = Arc::new(DummyMonitor);
        let tree_monitor = TreeTaskMonitor::new(root, 4);
        tree_monitor.set_maximum(0);
        assert_eq!(tree_monitor.get_maximum(), 0);
        assert_eq!(tree_monitor.chunk_size.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn set_maximum_chunk_size_is_at_least_one() {
        let root = Arc::new(DummyMonitor);
        // A max close to the full range collapses the division to 0; it must clamp to 1.
        let tree_monitor = TreeTaskMonitor::new(root, MAX_VALUE);
        assert_eq!(tree_monitor.chunk_size.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn set_progress_scales_into_root_delegate_range() {
        let root: Arc<SharedProgressMonitor> = Arc::new(SharedProgressMonitor::new());
        let tree_monitor = TreeTaskMonitor::new(root.clone(), 4);
        tree_monitor.set_progress(2);
        assert_eq!(tree_monitor.get_progress(), 2);
        assert_eq!(root.get_progress(), 2 * (MAX_VALUE / 4));
    }

    #[test]
    fn increment_progress_accumulates() {
        let root: Arc<SharedProgressMonitor> = Arc::new(SharedProgressMonitor::new());
        let tree_monitor = TreeTaskMonitor::new(root.clone(), 4);
        tree_monitor.increment_progress(1);
        tree_monitor.increment_progress(1);
        assert_eq!(tree_monitor.get_progress(), 2);
        assert_eq!(root.get_progress(), 2 * (MAX_VALUE / 4));
    }

    #[test]
    fn from_parent_subdivides_parents_current_chunk() {
        let root: Arc<SharedProgressMonitor> = Arc::new(SharedProgressMonitor::new());
        let parent = TreeTaskMonitor::new(root.clone(), 5);
        // Advance the parent by one increment (20% of MAX_VALUE range).
        parent.increment_progress(1);
        let parent_progress_before_child = root.get_progress();

        let child = TreeTaskMonitor::from_parent(&parent, 10);
        child.increment_progress(5);

        // The child's progress should land halfway between the parent's current position
        // and the start of the parent's next chunk, i.e. still within the parent's window.
        let child_reported = root.get_progress();
        assert!(child_reported > parent_progress_before_child);
        assert!(child_reported < parent_progress_before_child + (MAX_VALUE / 5));
    }

    #[test]
    fn from_parent_reuses_root_delegate() {
        let root: Arc<SharedProgressMonitor> = Arc::new(SharedProgressMonitor::new());
        let parent = TreeTaskMonitor::new(root.clone(), 5);
        let child = TreeTaskMonitor::from_parent(&parent, 10);
        child.set_message("hello");
        assert_eq!(root.get_message(), "hello");
    }

    #[test]
    fn delegates_cancellation_state() {
        let root: Arc<SharedProgressMonitor> = Arc::new(SharedProgressMonitor::new());
        let tree_monitor = TreeTaskMonitor::new(root.clone(), 4);
        assert!(!tree_monitor.is_cancelled());
        tree_monitor.cancel();
        assert!(tree_monitor.is_cancelled());
        assert!(tree_monitor.check_cancelled().is_err());
    }

    /// A minimal in-memory [`TaskMonitor`] that actually tracks progress/message state, used
    /// to assert on values propagated through a [`TreeTaskMonitor`] to its root delegate.
    struct SharedProgressMonitor {
        progress: AtomicI64,
        message: std::sync::Mutex<String>,
        cancelled: std::sync::atomic::AtomicBool,
    }

    impl SharedProgressMonitor {
        fn new() -> Self {
            SharedProgressMonitor {
                progress: AtomicI64::new(0),
                message: std::sync::Mutex::new(String::new()),
                cancelled: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl TaskMonitor for SharedProgressMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
        fn set_show_progress_value(&self, _show_progress_value: bool) {}
        fn set_message(&self, message: &str) {
            *self.message.lock().unwrap() = message.to_string();
        }
        fn get_message(&self) -> String {
            self.message.lock().unwrap().clone()
        }
        fn set_progress(&self, value: i64) {
            self.progress.store(value, Ordering::SeqCst);
        }
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
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
        }
        fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {
            self.cancelled.store(false, Ordering::SeqCst);
        }
    }
}

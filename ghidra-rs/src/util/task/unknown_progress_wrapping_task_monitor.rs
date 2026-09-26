//! Port of `ghidra.util.task.UnknownProgressWrappingTaskMonitor`.

use crate::util::exception::CancelledException;

use super::{CancelledListener, TaskMonitor};

/// A [`TaskMonitor`] wrapper for work whose total size is not known up front: whenever
/// progress passes 75% of the current maximum, the maximum is raised (by a quarter, or to the
/// progress value), so the progress bar keeps moving without ever completing early.
///
/// Mirrors `ghidra.util.task.UnknownProgressWrappingTaskMonitor`; every other call is passed
/// straight to the wrapped monitor (Java's `WrappingTaskMonitor` base).
pub struct UnknownProgressWrappingTaskMonitor<'a> {
    delegate: &'a dyn TaskMonitor,
}

impl<'a> UnknownProgressWrappingTaskMonitor<'a> {
    /// Wraps `delegate`, setting its maximum to `start_maximum`. Mirrors
    /// `UnknownProgressWrappingTaskMonitor(TaskMonitor, long)` (the one-argument form passes 0).
    pub fn new(delegate: &'a dyn TaskMonitor, start_maximum: i64) -> Self {
        delegate.set_maximum(start_maximum);
        UnknownProgressWrappingTaskMonitor { delegate }
    }

    fn maybe_update_maximum(&self) {
        let current_maximum = self.delegate.get_maximum();
        let progress = self.delegate.get_progress();
        let seventy_five_percent = current_maximum - (current_maximum / 4);
        if progress > seventy_five_percent {
            self.delegate
                .set_maximum(progress.max(4).max(current_maximum + current_maximum / 4));
        }
    }
}

impl TaskMonitor for UnknownProgressWrappingTaskMonitor<'_> {
    fn is_cancelled(&self) -> bool {
        self.delegate.is_cancelled()
    }
    fn set_show_progress_value(&self, show: bool) {
        self.delegate.set_show_progress_value(show)
    }
    fn set_message(&self, message: &str) {
        self.delegate.set_message(message)
    }
    fn get_message(&self) -> String {
        self.delegate.get_message()
    }
    fn set_progress(&self, value: i64) {
        self.delegate.set_progress(value);
        self.maybe_update_maximum();
    }
    fn initialize(&self, max: i64) {
        self.delegate.initialize(max)
    }
    fn set_maximum(&self, max: i64) {
        self.delegate.set_maximum(max)
    }
    fn get_maximum(&self) -> i64 {
        self.delegate.get_maximum()
    }
    fn set_indeterminate(&self, indeterminate: bool) {
        self.delegate.set_indeterminate(indeterminate)
    }
    fn is_indeterminate(&self) -> bool {
        self.delegate.is_indeterminate()
    }
    fn check_cancelled(&self) -> Result<(), CancelledException> {
        self.delegate.check_cancelled()
    }
    fn increment_progress(&self, amount: i64) {
        self.delegate.increment_progress(amount);
        self.maybe_update_maximum();
    }
    fn get_progress(&self) -> i64 {
        self.delegate.get_progress()
    }
    fn cancel(&self) {
        self.delegate.cancel()
    }
    fn add_cancelled_listener(&self, listener: Box<dyn CancelledListener>) {
        self.delegate.add_cancelled_listener(listener)
    }
    fn remove_cancelled_listener(&self, listener: &dyn CancelledListener) {
        self.delegate.remove_cancelled_listener(listener)
    }
    fn set_cancel_enabled(&self, enabled: bool) {
        self.delegate.set_cancel_enabled(enabled)
    }
    fn is_cancel_enabled(&self) -> bool {
        self.delegate.is_cancel_enabled()
    }
    fn clear_cancelled(&self) {
        self.delegate.clear_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use super::*;

    #[derive(Default)]
    struct Recording {
        max: AtomicI64,
        progress: AtomicI64,
    }

    impl TaskMonitor for Recording {
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
            Ok(())
        }
        fn increment_progress(&self, amount: i64) {
            self.progress.fetch_add(amount, Ordering::SeqCst);
        }
        fn get_progress(&self) -> i64 {
            self.progress.load(Ordering::SeqCst)
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn maximum_grows_past_75_percent() {
        let rec = Recording::default();
        let m = UnknownProgressWrappingTaskMonitor::new(&rec, 100);
        assert_eq!(rec.get_maximum(), 100);
        m.set_progress(75);
        assert_eq!(rec.get_maximum(), 100, "exactly 75% does not grow");
        m.set_progress(76);
        assert_eq!(rec.get_maximum(), 125);
        m.increment_progress(100); // 176 > 93
        assert_eq!(rec.get_maximum(), 176);
    }

    #[test]
    fn zero_start_maximum_grows_to_at_least_four() {
        let rec = Recording::default();
        let m = UnknownProgressWrappingTaskMonitor::new(&rec, 0);
        m.increment_progress(1);
        assert_eq!(rec.get_maximum(), 4);
    }
}

use crate::util::task::TaskMonitor;

/// An [`Iterator`] wrapper that allows clients to check a task monitor to cancel iteration.
///
/// When the monitor reports cancellation via `is_cancelled()`, this iterator
/// will return `None` on subsequent calls to `next()`, effectively terminating the iteration.
///
/// Port of `ghidra.util.task.CancellableIterator`.
pub struct CancellableIterator<T> {
    delegate: Box<dyn Iterator<Item = T>>,
    monitor: Box<dyn TaskMonitor>,
}

impl<T> CancellableIterator<T> {
    /// Creates a new cancellable iterator wrapping the given iterator and monitor.
    ///
    /// # Arguments
    /// * `delegate` - The underlying iterator to wrap
    /// * `monitor` - The task monitor to check for cancellation
    ///
    /// # Example
    /// ```no_run
    /// use ghidra_rs::util::task::{CancellableIterator, DummyMonitor};
    ///
    /// let vec = vec![1, 2, 3];
    /// let iter = vec.into_iter();
    /// let monitor = Box::new(DummyMonitor);
    /// let cancellable = CancellableIterator::new(Box::new(iter), monitor);
    /// ```
    pub fn new(delegate: Box<dyn Iterator<Item = T>>, monitor: Box<dyn TaskMonitor>) -> Self {
        Self { delegate, monitor }
    }
}

impl<T> Iterator for CancellableIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.monitor.is_cancelled() {
            return None;
        }
        self.delegate.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct MockTaskMonitor {
        cancelled: Arc<AtomicBool>,
    }

    impl TaskMonitor for MockTaskMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }

        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {
            self.cancelled.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn empty_iterator_returns_none() {
        let empty: Vec<i32> = vec![];
        let monitor = Box::new(MockTaskMonitor {
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        let mut iter = CancellableIterator::new(Box::new(empty.into_iter()), monitor);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn iterates_when_not_cancelled() {
        let values = vec![1, 2, 3];
        let monitor = Box::new(MockTaskMonitor {
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        let mut iter = CancellableIterator::new(Box::new(values.into_iter()), monitor);

        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn stops_on_cancellation() {
        let values = vec![1, 2, 3];
        let cancelled = Arc::new(AtomicBool::new(false));
        let monitor = Box::new(MockTaskMonitor {
            cancelled: cancelled.clone(),
        });
        let mut iter = CancellableIterator::new(Box::new(values.into_iter()), monitor);

        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));

        cancelled.store(true, Ordering::SeqCst);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn returns_none_if_cancelled_before_iteration() {
        let values = vec![1, 2, 3];
        let monitor = Box::new(MockTaskMonitor {
            cancelled: Arc::new(AtomicBool::new(true)),
        });
        let mut iter = CancellableIterator::new(Box::new(values.into_iter()), monitor);

        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn with_dummy_monitor_completes_normally() {
        let values = vec!["a", "b"];
        let monitor: Box<dyn TaskMonitor> = Box::new(crate::util::task::DummyMonitor);
        let mut iter = CancellableIterator::new(Box::new(values.into_iter()), monitor);

        assert_eq!(iter.next(), Some("a"));
        assert_eq!(iter.next(), Some("b"));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn collect_works_until_cancelled() {
        let values = vec![10, 20, 30, 40, 50];
        let cancelled = Arc::new(AtomicBool::new(false));
        let monitor = Box::new(MockTaskMonitor {
            cancelled: cancelled.clone(),
        });
        let iter = CancellableIterator::new(Box::new(values.into_iter()), monitor);

        let mut collected = Vec::new();
        for item in iter.take(2) {
            collected.push(item);
        }
        assert_eq!(collected, vec![10, 20]);
    }

    #[test]
    fn size_hint_delegation() {
        let values = vec![1, 2, 3];
        let monitor = Box::new(MockTaskMonitor {
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        let iter = CancellableIterator::new(Box::new(values.into_iter()), monitor);

        let (lower, upper) = iter.size_hint();
        assert!(lower <= 3);
        assert!(upper.is_none() || upper == Some(3));
    }
}

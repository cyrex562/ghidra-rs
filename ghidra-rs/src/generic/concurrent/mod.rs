pub mod concurrent_q;
pub mod listener_set;
pub mod named_daemon_thread_factory;
pub mod progress_tracker;
pub mod q_runnable_adapter;
pub mod reentry_guard;
pub mod thread_pool;

pub use concurrent_q::ConcurrentQ;
pub use listener_set::ConcurrentListenerSet;
pub use named_daemon_thread_factory::NamedDaemonThreadFactory;
pub use progress_tracker::ProgressTracker;
pub use q_runnable_adapter::QRunnableAdapter;
pub use reentry_guard::{Guarded, ReentryGuard};
pub use thread_pool::GThreadPool;

use crate::util::task::TaskMonitor;
use std::sync::Arc;

pub trait QCallback<I, R>: Send + Sync {
    fn process(&self, item: I, monitor: &dyn TaskMonitor) -> Result<R, anyhow::Error>;
}

/// Holds the result of processing an item in a [`ConcurrentQ`].
///
/// Port of `generic.concurrent.QResult<I, R>`.
///
/// Java's constructor unwraps a `Future<R>` inline (`future.get()`, catching whatever
/// `Exception` that throws) and stores exactly one of a result or an error; `error instanceof
/// CancellationException` is how Java distinguishes a cancelled item from a genuinely failed
/// one. This crate's [`ConcurrentQ`] already resolves a task's outcome into a plain
/// `Result<R, anyhow::Error>` (see [`concurrent_q::FutureTaskMonitor`](concurrent_q) and its
/// callers) before a `QResult` is ever constructed, so rather than re-deriving cancellation from
/// the error's dynamic type, the three outcomes are constructed explicitly via
/// [`Self::new`]/[`Self::error`]/[`Self::cancelled`] and `is_cancelled` is tracked as its own
/// field. The three constructors keep the fields in the same mutually-exclusive states Java's
/// constructor would leave them in for each case, so every accessor below still matches Java's
/// observable behavior.
pub struct QResult<I, R> {
    pub item: I,
    pub result: Option<R>,
    pub error: Option<Arc<anyhow::Error>>,
    pub is_cancelled: bool,
}

impl<I, R> QResult<I, R> {
    pub fn new(item: I, result: R) -> Self {
        Self {
            item,
            result: Some(result),
            error: None,
            is_cancelled: false,
        }
    }

    pub fn error(item: I, error: anyhow::Error) -> Self {
        Self {
            item,
            result: None,
            error: Some(Arc::new(error)),
            is_cancelled: false,
        }
    }

    pub fn cancelled(item: I) -> Self {
        Self {
            item,
            result: None,
            error: None,
            is_cancelled: true,
        }
    }

    /// Returns true if the item encountered an error while processing (and was not merely
    /// cancelled).
    ///
    /// Port of `QResult.hasError()`.
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Returns the item that was processed.
    ///
    /// Port of `QResult.getItem()`.
    pub fn get_item(&self) -> &I {
        &self.item
    }

    /// The result from processing the item, propagating any processing error the way Java's
    /// declared-`throws Exception` method does.
    ///
    /// `Ok(None)` covers both "the item was cancelled" and "processing completed with no
    /// result" (Java can likewise return a `null` result without throwing); `Ok(Some(_))` is a
    /// successful result; `Err(_)` is a genuine (non-cancellation) processing error, mirroring
    /// Java re-throwing the stored `Exception`.
    ///
    /// Port of `QResult.getResult()`.
    pub fn get_result(&self) -> Result<Option<&R>, Arc<anyhow::Error>> {
        if self.has_error() {
            // `has_error()` is only true when `error` is `Some`.
            return Err(self.error.clone().unwrap());
        }
        Ok(self.result.as_ref())
    }

    /// Returns any error encountered while processing the item, or `None` if it completed
    /// successfully or was merely cancelled.
    ///
    /// Port of `QResult.getError()`.
    pub fn get_error(&self) -> Option<&Arc<anyhow::Error>> {
        if self.has_error() {
            self.error.as_ref()
        } else {
            None
        }
    }

    /// Returns true if the item's processing was cancelled.
    ///
    /// Port of `QResult.isCancelled()`.
    pub fn is_cancelled(&self) -> bool {
        self.is_cancelled
    }
}

#[cfg(test)]
mod q_result_tests {
    use super::*;

    #[test]
    fn new_result_reports_success() {
        let r = QResult::new("item", 42);
        assert_eq!(*r.get_item(), "item");
        assert!(!r.has_error());
        assert!(!r.is_cancelled());
        assert_eq!(r.get_result().unwrap(), Some(&42));
        assert!(r.get_error().is_none());
    }

    #[test]
    fn error_result_reports_has_error_and_propagates_it_from_get_result() {
        let r: QResult<&str, i32> = QResult::error("item", anyhow::anyhow!("boom"));
        assert!(r.has_error());
        assert!(!r.is_cancelled());
        assert!(r.result.is_none());

        // Java: `getResult()` re-throws the stored exception rather than returning a value.
        let err = r.get_result().unwrap_err();
        assert_eq!(err.to_string(), "boom");

        assert_eq!(r.get_error().unwrap().to_string(), "boom");
    }

    #[test]
    fn cancelled_result_has_no_error_and_no_result() {
        // Java: `hasError()` is `error != null && !(error instanceof CancellationException)`,
        // so a cancelled item -- whose stored exception *is* the CancellationException --
        // reports `hasError() == false`. `getResult()` therefore does not throw for a
        // cancelled item; it just returns `null` (here, `Ok(None)`).
        let r: QResult<&str, i32> = QResult::cancelled("item");
        assert!(!r.has_error());
        assert!(r.is_cancelled());
        assert_eq!(r.get_result().unwrap(), None);
        assert!(r.get_error().is_none());
    }

    #[test]
    fn get_item_returns_the_exact_item() {
        let r = QResult::new(vec![1, 2, 3], "ok");
        assert_eq!(r.get_item(), &vec![1, 2, 3]);
    }
}

pub trait QItemListener<I, R>: Send + Sync {
    fn item_processed(&self, result: &QResult<I, R>);
}

pub trait QProgressListener<I>: Send + Sync {
    fn task_started(&self, id: i64, item: &I);
    fn task_ended(&self, id: i64, item: &I, total_count: i64, completed_count: i64);
    fn progress_changed(&self, id: i64, item: &I, current_progress: i64);
    fn max_progress_changed(&self, id: i64, item: &I, max_progress: i64);
    fn progress_mode_changed(&self, id: i64, item: &I, indeterminate: bool);
    fn progress_message_changed(&self, id: i64, item: &I, message: &str);
}

/// Processes items handed to [`ConcurrentQ::add`], each on a background thread
/// provided by a `GThreadPool`.
pub trait QRunnable<I>: Send + Sync {
    fn run(&self, item: I, monitor: &dyn TaskMonitor) -> Result<(), anyhow::Error>;
}

#[cfg(test)]
mod qrunnable_tests {
    use super::*;
    use crate::util::task::DummyMonitor;
    use std::sync::Mutex;

    struct DoublingRunnable {
        results: Arc<Mutex<Vec<i32>>>,
    }

    impl QRunnable<i32> for DoublingRunnable {
        fn run(&self, item: i32, monitor: &dyn TaskMonitor) -> Result<(), anyhow::Error> {
            if monitor.is_cancelled() {
                anyhow::bail!("cancelled");
            }
            self.results.lock().unwrap().push(item * 2);
            Ok(())
        }
    }

    #[test]
    fn run_processes_item_and_reports_via_monitor() {
        let results = Arc::new(Mutex::new(Vec::new()));
        let runnable: Box<dyn QRunnable<i32>> = Box::new(DoublingRunnable {
            results: results.clone(),
        });
        let monitor = DummyMonitor;

        runnable.run(21, &monitor).unwrap();

        assert_eq!(*results.lock().unwrap(), vec![42]);
    }
}

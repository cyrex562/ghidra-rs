//! Port of `ghidra.util.worker.Job`.
//!
//! A unit of work a `Worker` (not yet ported; the queue/thread-pool infrastructure that selects
//! and runs jobs) executes on a background thread, while other threads may concurrently poll its
//! completion/cancellation/error state -- hence Java's four fields being `volatile`.
//!
//! # Shape
//!
//! Java's abstract class carries both state (the four fields) and one abstract method (`run`).
//! Per this crate's composition-over-inheritance convention, that splits into [`JobBase`] (the
//! state, plus the concrete methods the Java class already gives real bodies to) and the [`Job`]
//! trait (just the one abstract method, plus a required [`Job::job_base`] accessor a concrete job
//! implements by holding a `base: JobBase` field), the same split
//! [`InjectPayloadJavaBase`](crate::app::util::pcode_inject::InjectPayloadJavaBase)/
//! [`InjectPayloadJava`](crate::app::util::pcode_inject::InjectPayloadJava) use.
//!
//! # Deviations
//!
//! * Java's `Throwable error` field becomes `Arc<dyn Error + Send + Sync>`: an `Arc` (rather
//!   than, say, `Box`) so [`JobBase::get_error`] can hand back an owned, cheaply-cloned reference
//!   to the stored error without needing `Throwable`'s `Clone`-unfriendly shape or requiring
//!   callers to hold a lock across the read.
//! * [`Job::run`] takes `&self` rather than `&mut self`: real jobs are expected to be run through
//!   a shared handle (e.g. `Arc<dyn Job>`, since other threads read [`JobBase`]'s state
//!   concurrently while `run` executes, exactly as Java's `volatile` fields anticipate); a
//!   concrete job that needs to mutate its own state during `run` should use interior mutability
//!   (as [`JobBase`] itself does), the same way Java's un-synchronized instance-field mutation
//!   during `run()` is only safe because nothing else concurrently writes those fields either.

use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// The state Java's `Job` abstract class carries: completion/cancellation flags, a captured
/// error, and the [`TaskMonitor`] the job is currently running under (if any).
///
/// Port of the field/concrete-method surface of `ghidra.util.worker.Job`.
pub struct JobBase {
    completed: AtomicBool,
    cancelled: AtomicBool,
    error: Mutex<Option<Arc<dyn Error + Send + Sync>>>,
    task_monitor: Mutex<Option<Arc<dyn TaskMonitor>>>,
}

impl JobBase {
    /// Constructs a fresh, not-yet-run job state: not completed, not cancelled, no error, no
    /// monitor -- matching Java's implicit default field values.
    pub fn new() -> Self {
        JobBase {
            completed: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            error: Mutex::new(None),
            task_monitor: Mutex::new(None),
        }
    }

    /// Port of `Job.isCompleted()`.
    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    /// Port of `Job.setCompleted()`.
    pub fn set_completed(&self) {
        self.completed.store(true, Ordering::SeqCst);
    }

    /// Port of `Job.isCancelled()`.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Port of `Job.setError(Throwable)`.
    pub fn set_error(&self, error: Arc<dyn Error + Send + Sync>) {
        *self.error.lock().unwrap() = Some(error);
    }

    /// Port of `Job.hasError()`.
    pub fn has_error(&self) -> bool {
        self.error.lock().unwrap().is_some()
    }

    /// Port of `Job.getError()`.
    pub fn get_error(&self) -> Option<Arc<dyn Error + Send + Sync>> {
        self.error.lock().unwrap().clone()
    }

    /// Marks this job cancelled and, if a [`TaskMonitor`] has been attached (via
    /// [`Self::set_task_monitor`]), cancels it too.
    ///
    /// Port of `Job.cancel()`.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Some(monitor) = self.task_monitor.lock().unwrap().as_ref() {
            monitor.cancel();
        }
    }

    /// Attaches the [`TaskMonitor`] this job is running under, so a later [`Self::cancel`] call
    /// can propagate to it.
    ///
    /// Port of the `protected` `Job.setTaskMonitor(TaskMonitor)`. Rust has no protected
    /// visibility; this is `pub` since the `Worker` that would normally be the sole caller (the
    /// queue/thread-pool that selects and runs jobs) is not yet ported.
    pub fn set_task_monitor(&self, monitor: Arc<dyn TaskMonitor>) {
        *self.task_monitor.lock().unwrap() = Some(monitor);
    }
}

impl Default for JobBase {
    fn default() -> Self {
        Self::new()
    }
}

/// A unit of work a `Worker` executes on a background thread.
///
/// Port of `ghidra.util.worker.Job`.
pub trait Job: Send + Sync {
    /// The shared state a concrete job holds via composition (`base: JobBase`), standing in for
    /// Java's inherited fields.
    fn job_base(&self) -> &JobBase;

    /// The method that gets called by the Worker when this job is selected to be run by the
    /// Worker.
    ///
    /// Port of `Job.run(TaskMonitor)`.
    ///
    /// # Errors
    /// Jobs may choose to return a [`CancelledException`], mirroring Java's `throws
    /// CancelledException`.
    fn run(&self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn new_job_base_starts_uncompleted_uncancelled_and_error_free() {
        let base = JobBase::new();
        assert!(!base.is_completed());
        assert!(!base.is_cancelled());
        assert!(!base.has_error());
        assert!(base.get_error().is_none());
    }

    #[test]
    fn set_completed_marks_the_job_completed() {
        let base = JobBase::new();
        base.set_completed();
        assert!(base.is_completed());
    }

    #[test]
    fn set_error_is_visible_through_has_error_and_get_error() {
        let base = JobBase::new();
        let err: Arc<dyn Error + Send + Sync> = Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "boom"));
        base.set_error(err);
        assert!(base.has_error());
        assert_eq!(base.get_error().unwrap().to_string(), "boom");
    }

    #[test]
    fn cancel_sets_cancelled_even_without_a_task_monitor() {
        let base = JobBase::new();
        base.cancel();
        assert!(base.is_cancelled());
    }

    #[test]
    fn cancel_propagates_to_an_attached_task_monitor() {
        struct RecordingMonitor {
            cancelled: AtomicBool,
        }
        impl TaskMonitor for RecordingMonitor {
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
            fn check_cancelled(&self) -> Result<(), CancelledException> {
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
            fn clear_cancelled(&self) {}
        }

        let base = JobBase::new();
        let monitor = Arc::new(RecordingMonitor { cancelled: AtomicBool::new(false) });
        base.set_task_monitor(monitor.clone());

        base.cancel();

        assert!(base.is_cancelled());
        assert!(monitor.is_cancelled());
    }

    /// A trivial concrete job that increments a shared counter each time it runs, and can be
    /// told to fail with a [`CancelledException`] instead.
    struct CountingJob {
        base: JobBase,
        counter: Arc<AtomicUsize>,
        fail: bool,
    }

    impl Job for CountingJob {
        fn job_base(&self) -> &JobBase {
            &self.base
        }

        fn run(&self, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            if self.fail {
                return Err(CancelledException::new("counting job was told to fail"));
            }
            self.counter.fetch_add(1, Ordering::SeqCst);
            self.base.set_completed();
            Ok(())
        }
    }

    #[test]
    fn concrete_job_run_executes_and_reports_completion_through_its_base() {
        let counter = Arc::new(AtomicUsize::new(0));
        let job = CountingJob { base: JobBase::new(), counter: counter.clone(), fail: false };

        assert!(!job.job_base().is_completed());
        let result = job.run(&DummyMonitor);

        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(job.job_base().is_completed());
    }

    #[test]
    fn concrete_job_run_can_report_cancellation_as_an_error() {
        let counter = Arc::new(AtomicUsize::new(0));
        let job = CountingJob { base: JobBase::new(), counter: counter.clone(), fail: true };

        let result = job.run(&DummyMonitor);

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(!job.job_base().is_completed());
    }

    #[test]
    fn usable_as_a_trait_object() {
        let job: Box<dyn Job> =
            Box::new(CountingJob { base: JobBase::new(), counter: Arc::new(AtomicUsize::new(0)), fail: false });
        assert!(job.run(&DummyMonitor).is_ok());
        assert!(job.job_base().is_completed());
    }
}

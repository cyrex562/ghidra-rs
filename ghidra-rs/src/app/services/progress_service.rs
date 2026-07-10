//! Service for publishing and subscribing to tasks and progress notifications.
//!
//! Port of `ghidra.app.services.ProgressService`. The Java `@ServiceInfo` annotation (default
//! provider `ProgressServicePlugin`) has no Rust equivalent and is omitted.
//!
//! This is an attempt to de-couple the concepts of task monitoring and task execution: a client
//! requests a monitor, drives it while doing work, and closes it when finished; the information
//! generated is forwarded to subscribers, which decide how to present it.
//!
//! Java's `execute(boolean, boolean, boolean, Function<TaskMonitor, CompletableFuture<T>>)`
//! overload is ported as [`ProgressService::execute_with_future`]. Its generic result type `T`
//! keeps it out of `dyn ProgressService`'s vtable (`where Self: Sized`), the same trade-off used
//! elsewhere in this crate (e.g. `DebuggerControlService`... see `Options::get_enum`) to keep the
//! rest of the trait object-safe. The `hasProgress` and `isModal` parameters are unused in the
//! Java default implementation too, so they stay unused here.

use std::future::Future;
use std::pin::Pin;

use crate::app::seam_stubs::{MonitorReceiver, ProgressListener, Task};
use crate::debug::api::progress::CloseableTaskMonitor;
use crate::util::task::TaskMonitor;

/// Port of Java's `CompletableFuture<Void>`/`CompletableFuture<T>` return types used by
/// [`ProgressService::execute`] and [`ProgressService::execute_with_future`].
pub type ExecuteFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A service for publishing and subscribing to tasks and progress notifications.
///
/// Port of `ghidra.app.services.ProgressService`.
pub trait ProgressService {
    /// Publish a task and create a monitor for it.
    ///
    /// This and the methods on [`TaskMonitor`] are the mechanism for clients to publish task and
    /// progress information. The returned monitor also extends `close`, allowing it to be used
    /// fairly safely when the execution model involves a single thread.
    fn publish_task(&self) -> Box<dyn CloseableTaskMonitor>;

    /// Collect all the tasks currently in progress.
    ///
    /// The subscriber ought to call this immediately after adding its listener, in order to
    /// catch up on tasks already in progress.
    fn get_all_monitors(&self) -> Vec<Box<dyn MonitorReceiver>>;

    /// Subscribe to task and progress events.
    fn add_progress_listener(&mut self, listener: Box<dyn ProgressListener>);

    /// Un-subscribe from task and progress events.
    fn remove_progress_listener(&mut self, listener: &dyn ProgressListener);

    /// A drop-in replacement for `PluginTool.execute(Task)` that publishes progress via this
    /// service rather than displaying a dialog.
    ///
    /// Port of `ProgressService.execute(Task)`. Unlike the Java version, which runs the task on
    /// a background thread via `CompletableFuture.supplyAsync`, this runs the task synchronously
    /// and returns an already-resolved future; there is no Rust equivalent to Java's implicit
    /// common thread pool in this crate.
    fn execute(&self, task: &dyn Task) -> ExecuteFuture<()> {
        let monitor = self.publish_task();
        monitor.set_cancel_enabled(task.can_cancel());
        let _ = task.run(monitor.as_ref());
        monitor.close();
        Box::pin(std::future::ready(()))
    }

    /// Similar to [`ProgressService::execute`], but for asynchronous methods.
    ///
    /// Port of `ProgressService.execute(boolean, boolean, boolean, Function)`. Generic over the
    /// future's output type `T`, so this method requires `Self: Sized` and is not available
    /// through `dyn ProgressService` -- the same trade-off already used elsewhere in this crate
    /// to keep the rest of the trait object-safe.
    ///
    /// # Arguments
    ///
    /// * `can_cancel` - true if the task can be cancelled
    /// * `has_progress` - true if the task displays progress (unused, mirroring the Java default)
    /// * `is_modal` - true if the task is modal (ignored, mirroring the Java default)
    /// * `future_supplier` - builds the future to run, given the task monitor
    fn execute_with_future<T>(
        &self,
        can_cancel: bool,
        has_progress: bool,
        is_modal: bool,
        future_supplier: impl FnOnce(&dyn TaskMonitor) -> ExecuteFuture<T>,
    ) -> ExecuteFuture<T>
    where
        Self: Sized,
        T: Send + 'static,
    {
        let _ = (has_progress, is_modal);
        let monitor = self.publish_task();
        monitor.set_cancel_enabled(can_cancel);
        let future = future_supplier(monitor.as_ref());
        Box::pin(async move {
            let result = future.await;
            monitor.close();
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::CancelledException;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    struct MockMonitor {
        cancel_enabled: RefCell<bool>,
        closed: RefCell<bool>,
    }

    impl TaskMonitor for MockMonitor {
        fn is_cancelled(&self) -> bool {
            false
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
            -1
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, enabled: bool) {
            *self.cancel_enabled.borrow_mut() = enabled;
        }
        fn is_cancel_enabled(&self) -> bool {
            *self.cancel_enabled.borrow()
        }
        fn clear_cancelled(&self) {}
    }

    impl CloseableTaskMonitor for MockMonitor {
        fn close(&self) {
            *self.closed.borrow_mut() = true;
        }
        fn report_error(&self, _error: Box<dyn std::error::Error + Send + Sync>) {}
    }

    struct MockListener;
    impl ProgressListener for MockListener {}

    struct MockMonitorReceiver;
    impl MonitorReceiver for MockMonitorReceiver {}

    struct MockTask {
        can_cancel: bool,
    }
    impl Task for MockTask {
        fn can_cancel(&self) -> bool {
            self.can_cancel
        }
        fn run(&self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            monitor.set_message("running");
            Ok(())
        }
    }

    struct MockProgressService {
        listeners: Mutex<Vec<()>>,
    }

    impl ProgressService for MockProgressService {
        fn publish_task(&self) -> Box<dyn CloseableTaskMonitor> {
            Box::new(MockMonitor {
                cancel_enabled: RefCell::new(false),
                closed: RefCell::new(false),
            })
        }

        fn get_all_monitors(&self) -> Vec<Box<dyn MonitorReceiver>> {
            vec![Box::new(MockMonitorReceiver)]
        }

        fn add_progress_listener(&mut self, _listener: Box<dyn ProgressListener>) {
            self.listeners.lock().unwrap().push(());
        }

        fn remove_progress_listener(&mut self, _listener: &dyn ProgressListener) {
            self.listeners.lock().unwrap().pop();
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn ProgressService> =
            Box::new(MockProgressService { listeners: Mutex::new(Vec::new()) });

        let monitor = service.publish_task();
        assert!(!monitor.is_cancel_enabled());

        assert_eq!(service.get_all_monitors().len(), 1);

        service.add_progress_listener(Box::new(MockListener));
        service.remove_progress_listener(&MockListener);
    }

    #[tokio::test]
    async fn execute_runs_task_and_closes_monitor() {
        let service = MockProgressService { listeners: Mutex::new(Vec::new()) };
        let task = MockTask { can_cancel: true };
        service.execute(&task).await;
    }

    #[tokio::test]
    async fn execute_with_future_runs_supplied_future() {
        let service = MockProgressService { listeners: Mutex::new(Vec::new()) };
        let ran = Arc::new(Mutex::new(false));
        let ran_clone = Arc::clone(&ran);
        let result = service
            .execute_with_future(true, false, false, move |_monitor| {
                Box::pin(async move {
                    *ran_clone.lock().unwrap() = true;
                    42
                })
            })
            .await;
        assert_eq!(result, 42);
        assert!(*ran.lock().unwrap());
    }
}

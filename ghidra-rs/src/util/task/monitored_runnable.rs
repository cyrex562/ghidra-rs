use crate::util::task::TaskMonitor;

/// Similar to a `Runnable` except the `monitored_run` method is given a
/// monitor to report progress and check for cancellation.
///
/// Port of `ghidra.util.task.MonitoredRunnable`.
pub trait MonitoredRunnable: Send + Sync {
    /// Runs this runnable, given a monitor to report progress and check for cancellation.
    fn monitored_run(&self, monitor: &dyn TaskMonitor);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};

    /// A stateful stub monitor that actually records the message set on it, so tests can
    /// verify a runnable interacts with the monitor it is given. `DummyMonitor` is a no-op
    /// and always returns an empty message, which cannot exercise this behavior.
    struct RecordingMonitor {
        message: Mutex<String>,
    }

    impl RecordingMonitor {
        fn new() -> Self {
            Self {
                message: Mutex::new(String::new()),
            }
        }
    }

    impl TaskMonitor for RecordingMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, message: &str) {
            *self.message.lock().unwrap() = message.to_string();
        }
        fn get_message(&self) -> String {
            self.message.lock().unwrap().clone()
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
            -1
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

    struct TestMonitoredRunnable {
        run_count: Arc<AtomicI32>,
        monitor_message: Arc<std::sync::Mutex<String>>,
    }

    impl MonitoredRunnable for TestMonitoredRunnable {
        fn monitored_run(&self, monitor: &dyn TaskMonitor) {
            self.run_count.fetch_add(1, Ordering::SeqCst);
            monitor.set_message("test run");
            *self.monitor_message.lock().unwrap() = monitor.get_message();
        }
    }

    #[test]
    fn monitored_runnable_executes() {
        let run_count = Arc::new(AtomicI32::new(0));
        let runnable = TestMonitoredRunnable {
            run_count: run_count.clone(),
            monitor_message: Arc::new(std::sync::Mutex::new(String::new())),
        };
        let monitor = crate::util::task::DummyMonitor;
        runnable.monitored_run(&monitor);
        assert_eq!(run_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn monitored_runnable_receives_monitor() {
        let run_count = Arc::new(AtomicI32::new(0));
        let message_holder = Arc::new(std::sync::Mutex::new(String::new()));
        let runnable = TestMonitoredRunnable {
            run_count: run_count.clone(),
            monitor_message: message_holder.clone(),
        };
        let monitor = RecordingMonitor::new();
        runnable.monitored_run(&monitor);
        assert_eq!(*message_holder.lock().unwrap(), "test run");
    }

    #[test]
    fn monitored_runnable_multiple_invocations() {
        let run_count = Arc::new(AtomicI32::new(0));
        let runnable = TestMonitoredRunnable {
            run_count: run_count.clone(),
            monitor_message: Arc::new(std::sync::Mutex::new(String::new())),
        };
        let monitor = crate::util::task::DummyMonitor;
        runnable.monitored_run(&monitor);
        runnable.monitored_run(&monitor);
        runnable.monitored_run(&monitor);
        assert_eq!(run_count.load(Ordering::SeqCst), 3);
    }

    struct SimpleCountingRunnable {
        executed: Arc<AtomicBool>,
    }

    impl MonitoredRunnable for SimpleCountingRunnable {
        fn monitored_run(&self, _monitor: &dyn TaskMonitor) {
            self.executed.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn monitored_runnable_trait_object() {
        let executed = Arc::new(AtomicBool::new(false));
        let runnable: Arc<dyn MonitoredRunnable> =
            Arc::new(SimpleCountingRunnable { executed: executed.clone() });
        let monitor = crate::util::task::DummyMonitor;
        runnable.monitored_run(&monitor);
        assert!(executed.load(Ordering::SeqCst));
    }
}

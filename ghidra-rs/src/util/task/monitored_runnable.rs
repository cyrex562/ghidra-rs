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
    use std::sync::Arc;

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
        let monitor = crate::util::task::DummyMonitor;
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

use crate::util::task::TaskMonitor;

/// A task monitor that can be used in a context manager pattern.
///
/// Mirrors `ghidra.debug.api.progress.CloseableTaskMonitor`. Extends `TaskMonitor`
/// with resource cleanup (close) and error reporting capabilities.
pub trait CloseableTaskMonitor: TaskMonitor {
    /// Clean up resources associated with this task monitor.
    fn close(&self);

    /// Report an error while working on this task.
    ///
    /// # Arguments
    ///
    /// * `error` - The error that occurred.
    fn report_error(&self, error: Box<dyn std::error::Error + Send + Sync>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::CancelledException;
    use std::sync::{Arc, Mutex};

    struct TestMonitor {
        closed: Arc<Mutex<bool>>,
        reported_error: Arc<Mutex<Option<String>>>,
    }

    impl TaskMonitor for TestMonitor {
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
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    impl CloseableTaskMonitor for TestMonitor {
        fn close(&self) {
            *self.closed.lock().unwrap() = true;
        }

        fn report_error(&self, error: Box<dyn std::error::Error + Send + Sync>) {
            *self.reported_error.lock().unwrap() = Some(error.to_string());
        }
    }

    #[test]
    fn close_method_callable() {
        let monitor = TestMonitor {
            closed: Arc::new(Mutex::new(false)),
            reported_error: Arc::new(Mutex::new(None)),
        };
        assert!(!*monitor.closed.lock().unwrap());
        monitor.close();
        assert!(*monitor.closed.lock().unwrap());
    }

    #[test]
    fn report_error_captures_error_message() {
        let monitor = TestMonitor {
            closed: Arc::new(Mutex::new(false)),
            reported_error: Arc::new(Mutex::new(None)),
        };
        let error = Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "test error",
        )) as Box<dyn std::error::Error + Send + Sync>;
        monitor.report_error(error);
        let reported = monitor.reported_error.lock().unwrap();
        assert!(reported.is_some());
        assert!(reported.as_ref().unwrap().contains("test error"));
    }

    #[test]
    fn monitor_extends_task_monitor() {
        let monitor = TestMonitor {
            closed: Arc::new(Mutex::new(false)),
            reported_error: Arc::new(Mutex::new(None)),
        };
        assert!(!monitor.is_cancelled());
        assert_eq!(monitor.get_maximum(), 0);
        assert!(!monitor.is_indeterminate());
    }

    #[test]
    fn trait_object_construction() {
        let monitor = Box::new(TestMonitor {
            closed: Arc::new(Mutex::new(false)),
            reported_error: Arc::new(Mutex::new(None)),
        }) as Box<dyn CloseableTaskMonitor>;
        monitor.close();
    }
}

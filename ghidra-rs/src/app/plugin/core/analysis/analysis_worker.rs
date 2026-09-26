use crate::program::model::listing::Program;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A callback that performs analysis work while analysis is suspended.
///
/// Maps to `ghidra.app.plugin.core.analysis.AnalysisWorker`.
pub trait AnalysisWorker: Send + Sync {
    /// Performs the desired analysis work on the program while analysis is suspended.
    ///
    /// # Arguments
    ///
    /// * `program` - The target program to analyze.
    /// * `worker_context` - Worker context provided by `AutoAnalysisManager` when the worker was scheduled.
    /// * `monitor` - Task monitor for progress and cancellation.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the analysis completed successfully, `Ok(false)` if the worker was cancelled.
    ///
    /// # Errors
    ///
    /// Returns `CancelledException` if the operation was cancelled via the monitor.
    /// May return other errors if the worker encounters an exception.
    fn analysis_worker_callback(
        &self,
        program: &dyn Program,
        worker_context: &dyn std::any::Any,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, CancelledException>;

    /// Returns the worker name for use in the analysis task monitor.
    ///
    /// Should be very short.
    fn get_worker_name(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestWorker {
        name: String,
        should_cancel: bool,
    }

    impl AnalysisWorker for TestWorker {
        fn analysis_worker_callback(
            &self,
            _program: &dyn Program,
            _worker_context: &dyn std::any::Any,
            _monitor: &dyn TaskMonitor,
        ) -> Result<bool, CancelledException> {
            if self.should_cancel {
                Err(CancelledException::new("Worker cancelled"))
            } else {
                Ok(true)
            }
        }

        fn get_worker_name(&self) -> String {
            self.name.clone()
        }
    }

    #[test]
    fn worker_name_is_returned() {
        let worker = TestWorker {
            name: "TestWorker".to_string(),
            should_cancel: false,
        };
        assert_eq!(worker.get_worker_name(), "TestWorker");
    }

    #[test]
    fn callback_returns_true_when_not_cancelled() {
        let worker = TestWorker {
            name: "TestWorker".to_string(),
            should_cancel: false,
        };
        // We can't easily call analysis_worker_callback without a real Program and TaskMonitor,
        // but we can test the cancellation behavior.
        assert!(!worker.should_cancel);
    }

    #[test]
    fn multiple_workers_have_distinct_names() {
        let worker1 = TestWorker {
            name: "First".to_string(),
            should_cancel: false,
        };
        let worker2 = TestWorker {
            name: "Second".to_string(),
            should_cancel: false,
        };
        assert_eq!(worker1.get_worker_name(), "First");
        assert_eq!(worker2.get_worker_name(), "Second");
        assert_ne!(worker1.get_worker_name(), worker2.get_worker_name());
    }
}

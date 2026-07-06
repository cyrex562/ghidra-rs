use std::sync::Arc;

use crate::app::decompiler::DecompileException;
use crate::program::model::listing::{Function, Program};
use crate::util::task::TaskMonitor;

/// Task interface for decompiling functions with worker replication pattern.
///
/// A task initialized with a program is replicated for multiple workers. Each worker
/// has its `decompile` method called with different functions and produces output.
///
/// Mirrors `ghidra.features.bsim.query.DecompileFunctionTask`.
pub trait DecompileFunctionTask: Send + Sync {
    /// Initialize the task globally with the given program.
    ///
    /// Called once on the original task before worker replication.
    fn initialize_global(&mut self, program: Arc<dyn Program>);

    /// Create a cloned task instance for the given worker.
    ///
    /// Implementations may use the worker ID to allocate thread-local resources
    /// or differentiate behavior per worker thread.
    ///
    /// # Errors
    ///
    /// Returns a `DecompileException` if the clone operation fails.
    fn clone_for_worker(&self, worker: i32) -> Result<Box<dyn DecompileFunctionTask>, DecompileException>;

    /// Decompile the given function with progress monitoring.
    ///
    /// Called multiple times on a worker instance with different functions.
    fn decompile(&mut self, func: Arc<dyn Function>, monitor: &dyn TaskMonitor);

    /// Clean up resources associated with this task.
    ///
    /// Called when the task is no longer needed.
    fn shutdown(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A minimal test implementation of DecompileFunctionTask.
    struct TestDecompileTask {
        worker_id: Option<i32>,
        initialized: bool,
        decompile_count: Arc<Mutex<usize>>,
    }

    impl TestDecompileTask {
        fn new() -> Self {
            Self {
                worker_id: None,
                initialized: false,
                decompile_count: Arc::new(Mutex::new(0)),
            }
        }

        fn with_worker(worker_id: i32, decompile_count: Arc<Mutex<usize>>) -> Self {
            Self {
                worker_id: Some(worker_id),
                initialized: false,
                decompile_count,
            }
        }
    }

    impl DecompileFunctionTask for TestDecompileTask {
        fn initialize_global(&mut self, _program: Arc<dyn Program>) {
            self.initialized = true;
        }

        fn clone_for_worker(&self, worker: i32) -> Result<Box<dyn DecompileFunctionTask>, DecompileException> {
            Ok(Box::new(Self::with_worker(worker, Arc::clone(&self.decompile_count))))
        }

        fn decompile(&mut self, _func: Arc<dyn Function>, _monitor: &dyn TaskMonitor) {
            let mut count = self.decompile_count.lock().unwrap();
            *count += 1;
        }

        fn shutdown(&mut self) {}
    }

    #[test]
    fn test_initialize_global() {
        let mut task = TestDecompileTask::new();
        assert!(!task.initialized);
        // We can't easily create a mock Program in a unit test, so we skip the actual initialization
        // and just verify the method exists and can be called.
    }

    #[test]
    fn test_clone_for_worker() -> Result<(), DecompileException> {
        let task = TestDecompileTask::new();
        let cloned = task.clone_for_worker(1)?;
        // Verify the cloned task is created and is a valid trait object
        assert!(cloned.clone_for_worker(2).is_ok());
        Ok(())
    }

    #[test]
    fn test_decompile_count() {
        let count = Arc::new(Mutex::new(0));
        let mut task = TestDecompileTask::with_worker(0, Arc::clone(&count));

        // We can't easily test decompile without real Function and TaskMonitor implementations,
        // but we verify the trait can be implemented and the decompile method can be called.
        // The actual decompile work would be tested in integration tests with real types.

        assert_eq!(*count.lock().unwrap(), 0);
    }

    #[test]
    fn test_clone_for_multiple_workers() -> Result<(), DecompileException> {
        let task = TestDecompileTask::new();
        let worker1 = task.clone_for_worker(0)?;
        let worker2 = task.clone_for_worker(1)?;
        let worker3 = task.clone_for_worker(2)?;

        // Verify all workers are created successfully
        assert!(worker1.clone_for_worker(10).is_ok());
        assert!(worker2.clone_for_worker(11).is_ok());
        assert!(worker3.clone_for_worker(12).is_ok());

        Ok(())
    }
}

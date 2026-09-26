use crate::framework::model::DomainObject;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Interface for tasks to be run by GTaskManager.
///
/// Port of `ghidra.framework.task.GTask`.
pub trait GTask: Send + Sync {
    /// Returns the name of this task.
    fn get_name(&self) -> String;

    /// The run method where work can be performed on the given domain object.
    ///
    /// # Arguments
    /// * `domain_object` - the object to affect
    /// * `monitor` - the task monitor to be used to cancel and report progress
    ///
    /// # Errors
    /// Returns `CancelledException` if the user cancelled the task.
    fn run(
        &self,
        domain_object: &dyn DomainObject,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct TestTask {
        name: String,
        run_called: Arc<Mutex<bool>>,
    }

    impl GTask for TestTask {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn run(
            &self,
            _domain_object: &dyn DomainObject,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            *self.run_called.lock().unwrap() = true;
            Ok(())
        }
    }

    #[test]
    fn test_task_name() {
        let task = TestTask {
            name: "TestTask".to_string(),
            run_called: Arc::new(Mutex::new(false)),
        };

        assert_eq!(task.get_name(), "TestTask");
    }

    #[test]
    fn test_task_as_trait_object() {
        let run_called = Arc::new(Mutex::new(false));
        let task = TestTask {
            name: "TestTask".to_string(),
            run_called: Arc::clone(&run_called),
        };

        let task_obj: &dyn GTask = &task;
        assert_eq!(task_obj.get_name(), "TestTask");

        assert!(*run_called.lock().unwrap() == false);
    }

    #[test]
    fn test_task_multiple_instances() {
        let task1 = TestTask {
            name: "Task1".to_string(),
            run_called: Arc::new(Mutex::new(false)),
        };

        let task2 = TestTask {
            name: "Task2".to_string(),
            run_called: Arc::new(Mutex::new(false)),
        };

        assert_eq!(task1.get_name(), "Task1");
        assert_eq!(task2.get_name(), "Task2");
    }
}

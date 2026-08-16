use crate::app::seam_stubs::CaptureFunctionDataTypesCmd;

/// Listener that is notified when the CaptureFunctionDataTypesCmd completes.
pub trait CaptureFunctionDataTypesListener: Send + Sync {
    /// Notification that the capture function data types command completed
    /// # Arguments
    /// * `cmd` - command that was completed; the command has the status as to whether the
    /// capture was successful
    fn capture_function_data_types_completed(&self, cmd: &dyn CaptureFunctionDataTypesCmd);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCmd {
        success: bool,
    }

    impl CaptureFunctionDataTypesCmd for MockCmd {
        fn apply_to(
            &self,
            _program: &dyn crate::program::model::listing::Program,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> bool {
            self.success
        }

        fn task_completed(&self) {}
    }

    struct TestListener {
        completed_calls: std::sync::Arc<std::sync::Mutex<Vec<bool>>>,
    }

    impl CaptureFunctionDataTypesListener for TestListener {
        fn capture_function_data_types_completed(&self, cmd: &dyn CaptureFunctionDataTypesCmd) {
            self.completed_calls.lock().unwrap().push(true);
            let _ = cmd;
        }
    }

    #[test]
    fn test_listener_can_be_implemented() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = TestListener {
            completed_calls: calls.clone(),
        };

        let cmd = MockCmd { success: true };
        listener.capture_function_data_types_completed(&cmd);

        let completed_calls = calls.lock().unwrap();
        assert_eq!(completed_calls.len(), 1);
        assert!(completed_calls[0]);
    }

    #[test]
    fn test_listener_trait_object() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener: Box<dyn CaptureFunctionDataTypesListener> = Box::new(TestListener {
            completed_calls: calls.clone(),
        });

        let cmd = MockCmd { success: true };
        listener.capture_function_data_types_completed(&cmd);

        let completed_calls = calls.lock().unwrap();
        assert_eq!(completed_calls.len(), 1);
    }
}

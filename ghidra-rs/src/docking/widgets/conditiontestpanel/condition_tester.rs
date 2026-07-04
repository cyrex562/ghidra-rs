use super::ConditionResult;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Interface for testing a condition and returning a result.
///
/// Corresponds to `docking.widgets.conditiontestpanel.ConditionTester`.
pub trait ConditionTester {
    /// Returns the name of this condition tester.
    fn get_name(&self) -> String;

    /// Returns a description of what this condition tester does.
    fn get_description(&self) -> String;

    /// Runs the condition test with the given monitor.
    ///
    /// # Arguments
    /// * `monitor` - The task monitor to track progress and cancellation
    ///
    /// # Returns
    /// A ConditionResult containing the test outcome, or CancelledException if cancelled.
    fn run(&self, monitor: &dyn TaskMonitor) -> Result<ConditionResult, CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::widgets::conditiontestpanel::ConditionStatus;
    use crate::util::task::DummyMonitor;

    struct MockConditionTester {
        name: String,
        description: String,
        result: ConditionResult,
    }

    impl ConditionTester for MockConditionTester {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_description(&self) -> String {
            self.description.clone()
        }

        fn run(&self, _monitor: &dyn TaskMonitor) -> Result<ConditionResult, CancelledException> {
            Ok(self.result.clone())
        }
    }

    #[test]
    fn get_name_returns_tester_name() {
        let tester = MockConditionTester {
            name: "Test Name".to_string(),
            description: "Test Description".to_string(),
            result: ConditionResult::new(ConditionStatus::Passed),
        };
        assert_eq!(tester.get_name(), "Test Name");
    }

    #[test]
    fn get_description_returns_tester_description() {
        let tester = MockConditionTester {
            name: "Test".to_string(),
            description: "This is a test".to_string(),
            result: ConditionResult::new(ConditionStatus::Passed),
        };
        assert_eq!(tester.get_description(), "This is a test");
    }

    #[test]
    fn run_returns_result() {
        let result = ConditionResult::new(ConditionStatus::Passed);
        let tester = MockConditionTester {
            name: "Test".to_string(),
            description: "Test".to_string(),
            result: result.clone(),
        };
        let monitor = DummyMonitor;
        let run_result = tester.run(&monitor);
        assert!(run_result.is_ok());
        assert_eq!(run_result.unwrap(), result);
    }

    #[test]
    fn run_with_error_status() {
        let result = ConditionResult::new(ConditionStatus::Error);
        let tester = MockConditionTester {
            name: "Error Test".to_string(),
            description: "Test that returns error".to_string(),
            result: result.clone(),
        };
        let monitor = DummyMonitor;
        let run_result = tester.run(&monitor);
        assert!(run_result.is_ok());
        assert_eq!(run_result.unwrap().status(), ConditionStatus::Error);
    }

    #[test]
    fn run_with_warning_status() {
        let result = ConditionResult::with_message(
            ConditionStatus::Warning,
            Some("Test warning".to_string()),
        );
        let tester = MockConditionTester {
            name: "Warning Test".to_string(),
            description: "Test that returns warning".to_string(),
            result: result.clone(),
        };
        let monitor = DummyMonitor;
        let run_result = tester.run(&monitor);
        assert!(run_result.is_ok());
        let result_val = run_result.unwrap();
        assert_eq!(result_val.status(), ConditionStatus::Warning);
        assert_eq!(result_val.message(), "Test warning");
    }

    #[test]
    fn multiple_testers_with_different_names() {
        let tester1 = MockConditionTester {
            name: "Tester A".to_string(),
            description: "First tester".to_string(),
            result: ConditionResult::new(ConditionStatus::Passed),
        };
        let tester2 = MockConditionTester {
            name: "Tester B".to_string(),
            description: "Second tester".to_string(),
            result: ConditionResult::new(ConditionStatus::Passed),
        };
        assert_eq!(tester1.get_name(), "Tester A");
        assert_eq!(tester2.get_name(), "Tester B");
        assert_ne!(tester1.get_name(), tester2.get_name());
    }
}

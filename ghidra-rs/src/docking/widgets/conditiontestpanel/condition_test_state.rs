use std::sync::Arc;

use super::{ConditionResult, ConditionStatus, ConditionTester};

/// State holder for a condition test, tracking test execution results and enabled status.
///
/// Corresponds to `docking.widgets.conditiontestpanel.ConditionTestState`.
pub struct ConditionTestState {
    condition_test: Arc<dyn ConditionTester>,
    result: Option<ConditionResult>,
    enabled: bool,
}

impl ConditionTestState {
    /// Creates a new ConditionTestState for the given condition tester.
    pub fn new(condition_test: Arc<dyn ConditionTester>) -> Self {
        Self {
            condition_test,
            result: None,
            enabled: true,
        }
    }

    /// Returns the name of the condition test.
    pub fn get_name(&self) -> String {
        self.condition_test.get_name()
    }

    /// Sets the result of the condition test.
    pub fn set_result(&mut self, result: ConditionResult) {
        self.result = Some(result);
    }

    /// Returns a reference to the condition tester.
    pub fn get_condition_test(&self) -> &Arc<dyn ConditionTester> {
        &self.condition_test
    }

    /// Returns the status of the last test result, or `ConditionStatus::None` if no result.
    pub fn get_status(&self) -> ConditionStatus {
        match &self.result {
            Some(result) => result.status(),
            None => ConditionStatus::None,
        }
    }

    /// Sets whether this condition test is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns whether this condition test is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the status message of the last test result, or an empty string if no result.
    pub fn get_status_message(&self) -> String {
        match &self.result {
            Some(result) => result.message(),
            None => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockConditionTester {
        name: String,
    }

    impl ConditionTester for MockConditionTester {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_description(&self) -> String {
            "Test description".to_string()
        }

        fn run(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<ConditionResult, crate::util::exception::CancelledException> {
            Ok(ConditionResult::new(ConditionStatus::Passed))
        }
    }

    #[test]
    fn new_creates_disabled_state() {
        let tester = Arc::new(MockConditionTester {
            name: "Test".to_string(),
        });
        let state = ConditionTestState::new(tester);
        assert!(state.is_enabled());
        assert_eq!(state.get_status(), ConditionStatus::None);
        assert_eq!(state.get_status_message(), "");
    }

    #[test]
    fn get_name_returns_tester_name() {
        let tester = Arc::new(MockConditionTester {
            name: "MyTest".to_string(),
        });
        let state = ConditionTestState::new(tester);
        assert_eq!(state.get_name(), "MyTest");
    }

    #[test]
    fn set_and_get_result() {
        let tester = Arc::new(MockConditionTester {
            name: "Test".to_string(),
        });
        let mut state = ConditionTestState::new(tester);

        let result = ConditionResult::new(ConditionStatus::Passed);
        state.set_result(result);

        assert_eq!(state.get_status(), ConditionStatus::Passed);
    }

    #[test]
    fn set_enabled_modifies_state() {
        let tester = Arc::new(MockConditionTester {
            name: "Test".to_string(),
        });
        let mut state = ConditionTestState::new(tester);

        assert!(state.is_enabled());
        state.set_enabled(false);
        assert!(!state.is_enabled());
        state.set_enabled(true);
        assert!(state.is_enabled());
    }

    #[test]
    fn get_condition_test_returns_reference() {
        let tester = Arc::new(MockConditionTester {
            name: "Test".to_string(),
        });
        let state = ConditionTestState::new(tester.clone());
        assert_eq!(state.get_condition_test().get_name(), "Test");
    }

    #[test]
    fn get_status_message_with_result() {
        let tester = Arc::new(MockConditionTester {
            name: "Test".to_string(),
        });
        let mut state = ConditionTestState::new(tester);

        let result = ConditionResult::with_message(
            ConditionStatus::Error,
            Some("Test error".to_string()),
        );
        state.set_result(result);

        assert_eq!(state.get_status_message(), "Test error");
        assert_eq!(state.get_status(), ConditionStatus::Error);
    }

    #[test]
    fn get_status_message_without_result() {
        let tester = Arc::new(MockConditionTester {
            name: "Test".to_string(),
        });
        let state = ConditionTestState::new(tester);
        assert_eq!(state.get_status_message(), "");
    }

    #[test]
    fn result_updates_both_status_and_message() {
        let tester = Arc::new(MockConditionTester {
            name: "Test".to_string(),
        });
        let mut state = ConditionTestState::new(tester);

        let result = ConditionResult::with_message(
            ConditionStatus::Warning,
            Some("Warning message".to_string()),
        );
        state.set_result(result);

        assert_eq!(state.get_status(), ConditionStatus::Warning);
        assert_eq!(state.get_status_message(), "Warning message");
    }

    #[test]
    fn multiple_set_result_overwrites_previous() {
        let tester = Arc::new(MockConditionTester {
            name: "Test".to_string(),
        });
        let mut state = ConditionTestState::new(tester);

        state.set_result(ConditionResult::new(ConditionStatus::Passed));
        assert_eq!(state.get_status(), ConditionStatus::Passed);

        state.set_result(ConditionResult::new(ConditionStatus::Error));
        assert_eq!(state.get_status(), ConditionStatus::Error);
    }
}

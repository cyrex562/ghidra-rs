use super::ConditionStatus;

/// Result of a condition test, including status and optional message.
///
/// Corresponds to `docking.widgets.conditiontestpanel.ConditionResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionResult {
    status: ConditionStatus,
    message: Option<String>,
}

impl ConditionResult {
    /// Creates a new ConditionResult with the given status and no message.
    pub fn new(status: ConditionStatus) -> Self {
        Self {
            status,
            message: None,
        }
    }

    /// Creates a new ConditionResult with the given status and message.
    pub fn with_message(status: ConditionStatus, message: Option<String>) -> Self {
        Self { status, message }
    }

    /// Returns the status of this result.
    pub fn status(&self) -> ConditionStatus {
        self.status
    }

    /// Returns the message for this result.
    ///
    /// If no message is provided or the message is only whitespace, returns a
    /// default message based on the status.
    pub fn message(&self) -> String {
        match &self.message {
            Some(msg) if !msg.trim().is_empty() => msg.clone(),
            _ => self.default_message(),
        }
    }

    fn default_message(&self) -> String {
        match self.status {
            ConditionStatus::Cancelled => "Cancelled by user".to_string(),
            ConditionStatus::Error => {
                "Error - please update test to provide a better error message".to_string()
            }
            ConditionStatus::None => String::new(),
            ConditionStatus::Passed => "Passed".to_string(),
            ConditionStatus::Skipped => "Skipped".to_string(),
            ConditionStatus::Warning => {
                "Warning - please update test to provide a better warning message".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_status_only() {
        let result = ConditionResult::new(ConditionStatus::Passed);
        assert_eq!(result.status(), ConditionStatus::Passed);
        assert_eq!(result.message(), "Passed");
    }

    #[test]
    fn with_message_stores_custom_message() {
        let result = ConditionResult::with_message(
            ConditionStatus::Error,
            Some("Custom error".to_string()),
        );
        assert_eq!(result.status(), ConditionStatus::Error);
        assert_eq!(result.message(), "Custom error");
    }

    #[test]
    fn with_message_none_returns_default() {
        let result = ConditionResult::with_message(ConditionStatus::Warning, None);
        assert_eq!(result.status(), ConditionStatus::Warning);
        assert_eq!(
            result.message(),
            "Warning - please update test to provide a better warning message"
        );
    }

    #[test]
    fn whitespace_message_returns_default() {
        let result = ConditionResult::with_message(
            ConditionStatus::Cancelled,
            Some("   \t\n  ".to_string()),
        );
        assert_eq!(result.status(), ConditionStatus::Cancelled);
        assert_eq!(result.message(), "Cancelled by user");
    }

    #[test]
    fn empty_message_returns_default() {
        let result =
            ConditionResult::with_message(ConditionStatus::Skipped, Some(String::new()));
        assert_eq!(result.status(), ConditionStatus::Skipped);
        assert_eq!(result.message(), "Skipped");
    }

    #[test]
    fn all_status_defaults() {
        assert_eq!(
            ConditionResult::new(ConditionStatus::None).message(),
            ""
        );
        assert_eq!(
            ConditionResult::new(ConditionStatus::Passed).message(),
            "Passed"
        );
        assert_eq!(
            ConditionResult::new(ConditionStatus::Cancelled).message(),
            "Cancelled by user"
        );
        assert_eq!(
            ConditionResult::new(ConditionStatus::Error).message(),
            "Error - please update test to provide a better error message"
        );
        assert_eq!(
            ConditionResult::new(ConditionStatus::Skipped).message(),
            "Skipped"
        );
        assert_eq!(
            ConditionResult::new(ConditionStatus::Warning).message(),
            "Warning - please update test to provide a better warning message"
        );
    }

    #[test]
    fn custom_message_with_whitespace_inside() {
        let result = ConditionResult::with_message(
            ConditionStatus::Error,
            Some("Custom error with spaces".to_string()),
        );
        assert_eq!(result.message(), "Custom error with spaces");
    }

    #[test]
    fn clone_equality() {
        let result = ConditionResult::with_message(
            ConditionStatus::Passed,
            Some("test".to_string()),
        );
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn debug_format() {
        let result = ConditionResult::new(ConditionStatus::Passed);
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("ConditionResult"));
        assert!(debug_str.contains("Passed"));
    }
}

use std::fmt;

/// Error type for function comparison operations in BSim GUI.
///
/// Mirrors `ghidra.features.bsim.gui.search.results.FunctionComparisonException`.
/// An exception that can be thrown if an error is encountered while trying to compare
/// two functions or apply information between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionComparisonException {
    message: String,
}

impl FunctionComparisonException {
    /// Constructs a new `FunctionComparisonException` with the given message.
    ///
    /// Corresponds to `new FunctionComparisonException(String msg)` in Java.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Constructs a new `FunctionComparisonException` with the given message and cause.
    ///
    /// Corresponds to `new FunctionComparisonException(String msg, Throwable cause)` in Java.
    /// The cause parameter is accepted for API parity with Java but is not stored,
    /// as Rust error handling uses error chains rather than exception causes.
    pub fn with_cause<E: std::error::Error + Send + Sync + 'static>(
        msg: impl Into<String>,
        _cause: E,
    ) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for FunctionComparisonException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FunctionComparisonException: {}", self.message)
    }
}

impl std::error::Error for FunctionComparisonException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_message() {
        let e = FunctionComparisonException::new("comparison failed");
        assert_eq!(e.message(), "comparison failed");
    }

    #[test]
    fn test_display() {
        let e = FunctionComparisonException::new("error details");
        assert_eq!(
            e.to_string(),
            "FunctionComparisonException: error details"
        );
    }

    #[test]
    fn test_empty_message() {
        let e = FunctionComparisonException::new("");
        assert_eq!(e.to_string(), "FunctionComparisonException: ");
        assert_eq!(e.message(), "");
    }

    #[test]
    fn test_with_cause() {
        let cause = FunctionComparisonException::new("underlying error");
        let e = FunctionComparisonException::with_cause("wrapper error", cause);
        assert_eq!(e.message(), "wrapper error");
        assert_eq!(e.to_string(), "FunctionComparisonException: wrapper error");
    }

    #[test]
    fn test_implements_error_trait() {
        let e = FunctionComparisonException::new("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_clone_and_eq() {
        let a = FunctionComparisonException::new("msg");
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, FunctionComparisonException::new("different"));
    }

    #[test]
    fn test_debug() {
        let e = FunctionComparisonException::new("test error");
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("FunctionComparisonException"));
    }
}

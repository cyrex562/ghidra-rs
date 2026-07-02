/// Error raised when a scalar operation would cause precision loss.
///
/// A ScalarOverflowException indicates that some precision would be lost. If the operation was
/// signed, unused bits did not match the sign bit. If the operation was unsigned, unused bits
/// were not all zero.
///
/// Mirrors `ghidra.program.model.scalar.ScalarOverflowException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalarOverflowException {
    message: String,
}

impl ScalarOverflowException {
    /// Constructs a ScalarOverflowException with the default message "Scalar overflow".
    pub fn new() -> Self {
        Self {
            message: "Scalar overflow".to_string(),
        }
    }

    /// Constructs a ScalarOverflowException with the specified detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for ScalarOverflowException {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ScalarOverflowException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ScalarOverflowException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_creates_default_message() {
        let ex = ScalarOverflowException::new();
        assert_eq!(ex.message(), "Scalar overflow");
    }

    #[test]
    fn default_creates_default_message() {
        let ex = ScalarOverflowException::default();
        assert_eq!(ex.message(), "Scalar overflow");
    }

    #[test]
    fn with_message_creates_custom_message() {
        let ex = ScalarOverflowException::with_message("custom overflow");
        assert_eq!(ex.message(), "custom overflow");
    }

    #[test]
    fn with_message_accepts_owned_string() {
        let msg = String::from("owned message");
        let ex = ScalarOverflowException::with_message(msg);
        assert_eq!(ex.message(), "owned message");
    }

    #[test]
    fn with_message_accepts_string_literal() {
        let ex = ScalarOverflowException::with_message("literal message");
        assert_eq!(ex.message(), "literal message");
    }

    #[test]
    fn display_formats_message() {
        let ex = ScalarOverflowException::with_message("test error");
        assert_eq!(ex.to_string(), "test error");
    }

    #[test]
    fn default_display_uses_default_message() {
        let ex = ScalarOverflowException::new();
        assert_eq!(ex.to_string(), "Scalar overflow");
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = ScalarOverflowException::with_message("test");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_holds_for_same_messages() {
        let a = ScalarOverflowException::with_message("same");
        let b = ScalarOverflowException::with_message("same");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_messages() {
        let a = ScalarOverflowException::with_message("msg1");
        let b = ScalarOverflowException::with_message("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn implements_error_trait() {
        let ex = ScalarOverflowException::new();
        let _: &dyn Error = &ex;
    }

    #[test]
    fn error_source_is_none() {
        let ex = ScalarOverflowException::new();
        assert!(ex.source().is_none());
    }

    #[test]
    fn debug_format_includes_message() {
        let ex = ScalarOverflowException::with_message("debug test");
        let debug_str = format!("{:?}", ex);
        assert!(debug_str.contains("ScalarOverflowException"));
        assert!(debug_str.contains("debug test"));
    }

    #[test]
    fn message_accessor_returns_full_message() {
        let ex = ScalarOverflowException::with_message("full message test");
        assert_eq!(ex.message(), "full message test");
    }

    #[test]
    fn empty_message_is_allowed() {
        let ex = ScalarOverflowException::with_message("");
        assert_eq!(ex.message(), "");
    }

    #[test]
    fn multiline_message_is_preserved() {
        let msg = "line1\nline2\nline3";
        let ex = ScalarOverflowException::with_message(msg);
        assert_eq!(ex.message(), msg);
    }
}

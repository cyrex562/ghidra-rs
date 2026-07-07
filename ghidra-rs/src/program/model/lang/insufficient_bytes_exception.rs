use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when there are not enough consecutive bytes available to fully parse an instruction.
///
/// This mirrors Ghidra's `InsufficientBytesException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsufficientBytesException {
    message: String,
}

impl InsufficientBytesException {
    /// Constructs an `InsufficientBytesException` with the default message.
    pub fn new() -> Self {
        Self {
            message: "Not enough bytes available to parse a legal instruction".to_string(),
        }
    }

    /// Constructs an `InsufficientBytesException` with a custom message.
    pub fn with_message(message: impl AsRef<str>) -> Self {
        Self {
            message: message.as_ref().to_string(),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for InsufficientBytesException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for InsufficientBytesException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for InsufficientBytesException {}

impl From<InsufficientBytesException> for UsrException {
    fn from(value: InsufficientBytesException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_default_message() {
        let err = InsufficientBytesException::new();
        assert_eq!(
            err.message(),
            "Not enough bytes available to parse a legal instruction"
        );
    }

    #[test]
    fn new_display_shows_default_message() {
        let err = InsufficientBytesException::new();
        assert_eq!(
            err.to_string(),
            "Not enough bytes available to parse a legal instruction"
        );
    }

    #[test]
    fn with_message_stores_custom_message() {
        let err = InsufficientBytesException::with_message("custom error");
        assert_eq!(err.message(), "custom error");
    }

    #[test]
    fn with_message_display_matches_message() {
        let err = InsufficientBytesException::with_message("insufficient bytes at offset 0x1000");
        assert_eq!(err.to_string(), "insufficient bytes at offset 0x1000");
    }

    #[test]
    fn default_same_as_new() {
        let a = InsufficientBytesException::default();
        let b = InsufficientBytesException::new();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_with_same_message() {
        let a = InsufficientBytesException::with_message("test");
        let b = InsufficientBytesException::with_message("test");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_with_different_message() {
        let a = InsufficientBytesException::with_message("msg1");
        let b = InsufficientBytesException::with_message("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn clone_is_equal() {
        let a = InsufficientBytesException::with_message("original");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn converts_to_user_exception_default_message() {
        let err = InsufficientBytesException::new();
        let usr: UsrException = err.into();
        assert_eq!(
            usr.to_string(),
            "Not enough bytes available to parse a legal instruction"
        );
    }

    #[test]
    fn converts_to_user_exception_custom_message() {
        let err = InsufficientBytesException::with_message("custom");
        let usr: UsrException = err.into();
        assert_eq!(usr.to_string(), "custom");
    }

    #[test]
    fn implements_std_error() {
        let err: &dyn std::error::Error =
            &InsufficientBytesException::with_message("error object");
        assert_eq!(err.to_string(), "error object");
    }
}

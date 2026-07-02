use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when a value for a register is looked up that is undefined.
///
/// This mirrors Ghidra's `UndefinedValueException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndefinedValueException {
    message: String,
}

impl UndefinedValueException {
    /// Constructs an `UndefinedValueException` with no message.
    pub fn new() -> Self {
        Self {
            message: String::new(),
        }
    }

    /// Constructs an `UndefinedValueException` with a descriptive message.
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

impl Default for UndefinedValueException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UndefinedValueException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UndefinedValueException {}

impl From<UndefinedValueException> for UsrException {
    fn from(value: UndefinedValueException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_empty_message() {
        let err = UndefinedValueException::new();
        assert_eq!(err.message(), "");
    }

    #[test]
    fn new_display_is_empty() {
        let err = UndefinedValueException::new();
        assert_eq!(err.to_string(), "");
    }

    #[test]
    fn with_message_stores_custom_message() {
        let err = UndefinedValueException::with_message("register value is undefined");
        assert_eq!(err.message(), "register value is undefined");
    }

    #[test]
    fn with_message_display_matches_message() {
        let err = UndefinedValueException::with_message("undefined value");
        assert_eq!(err.to_string(), "undefined value");
    }

    #[test]
    fn default_same_as_new() {
        let a = UndefinedValueException::default();
        let b = UndefinedValueException::new();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_with_same_message() {
        let a = UndefinedValueException::with_message("test");
        let b = UndefinedValueException::with_message("test");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_with_different_message() {
        let a = UndefinedValueException::with_message("msg1");
        let b = UndefinedValueException::with_message("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn clone_is_equal() {
        let a = UndefinedValueException::with_message("original");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn converts_to_user_exception_empty_message() {
        let err = UndefinedValueException::new();
        let usr: UsrException = err.into();
        assert_eq!(usr.to_string(), "");
    }

    #[test]
    fn converts_to_user_exception_custom_message() {
        let err = UndefinedValueException::with_message("undefined");
        let usr: UsrException = err.into();
        assert_eq!(usr.to_string(), "undefined");
    }

    #[test]
    fn implements_std_error() {
        let err: &dyn std::error::Error =
            &UndefinedValueException::with_message("error object");
        assert_eq!(err.to_string(), "error object");
    }
}

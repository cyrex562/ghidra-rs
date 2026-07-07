use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when processor state context must be known before parsing an instruction.
///
/// Indicates a processor state context must be known before the bytes at the parse
/// address can form a legal known instruction.
///
/// This mirrors Ghidra's `UnknownContextException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownContextException {
    message: String,
}

impl UnknownContextException {
    /// Constructs an `UnknownContextException` with the default message.
    pub fn new() -> Self {
        Self {
            message: "The current processor state is not known for constructing a legal instruction."
                .to_string(),
        }
    }

    /// Constructs an `UnknownContextException` with a custom message.
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

impl Default for UnknownContextException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UnknownContextException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UnknownContextException {}

impl From<UnknownContextException> for UsrException {
    fn from(value: UnknownContextException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_default_message() {
        let err = UnknownContextException::new();
        assert_eq!(
            err.message(),
            "The current processor state is not known for constructing a legal instruction."
        );
    }

    #[test]
    fn new_display_shows_default_message() {
        let err = UnknownContextException::new();
        assert_eq!(
            err.to_string(),
            "The current processor state is not known for constructing a legal instruction."
        );
    }

    #[test]
    fn with_message_stores_custom_message() {
        let err = UnknownContextException::with_message("custom context error");
        assert_eq!(err.message(), "custom context error");
    }

    #[test]
    fn with_message_display_matches_message() {
        let err = UnknownContextException::with_message("context required for instruction");
        assert_eq!(err.to_string(), "context required for instruction");
    }

    #[test]
    fn default_same_as_new() {
        let a = UnknownContextException::default();
        let b = UnknownContextException::new();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_with_same_message() {
        let a = UnknownContextException::with_message("test");
        let b = UnknownContextException::with_message("test");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_with_different_message() {
        let a = UnknownContextException::with_message("msg1");
        let b = UnknownContextException::with_message("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn clone_is_equal() {
        let a = UnknownContextException::with_message("original");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn converts_to_user_exception_default_message() {
        let err = UnknownContextException::new();
        let usr: UsrException = err.into();
        assert_eq!(
            usr.to_string(),
            "The current processor state is not known for constructing a legal instruction."
        );
    }

    #[test]
    fn converts_to_user_exception_custom_message() {
        let err = UnknownContextException::with_message("custom");
        let usr: UsrException = err.into();
        assert_eq!(usr.to_string(), "custom");
    }

    #[test]
    fn implements_std_error() {
        let err: &dyn std::error::Error =
            &UnknownContextException::with_message("error object");
        assert_eq!(err.to_string(), "error object");
    }
}

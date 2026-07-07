use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when the bytes at a parse address do not form a legal known instruction.
///
/// This mirrors Ghidra's `UnknownInstructionException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownInstructionException {
    message: String,
}

impl UnknownInstructionException {
    /// Constructs an `UnknownInstructionException` with the default message.
    pub fn new() -> Self {
        Self {
            message: "Bytes do not form a legal instruction.".to_string(),
        }
    }

    /// Constructs an `UnknownInstructionException` with a custom message.
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

impl Default for UnknownInstructionException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UnknownInstructionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UnknownInstructionException {}

impl From<UnknownInstructionException> for UsrException {
    fn from(value: UnknownInstructionException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_default_message() {
        let err = UnknownInstructionException::new();
        assert_eq!(err.message(), "Bytes do not form a legal instruction.");
    }

    #[test]
    fn new_display_shows_default_message() {
        let err = UnknownInstructionException::new();
        assert_eq!(
            err.to_string(),
            "Bytes do not form a legal instruction."
        );
    }

    #[test]
    fn with_message_stores_custom_message() {
        let err = UnknownInstructionException::with_message("custom error");
        assert_eq!(err.message(), "custom error");
    }

    #[test]
    fn with_message_display_matches_message() {
        let err = UnknownInstructionException::with_message("unknown instruction at 0x1000");
        assert_eq!(err.to_string(), "unknown instruction at 0x1000");
    }

    #[test]
    fn default_same_as_new() {
        let a = UnknownInstructionException::default();
        let b = UnknownInstructionException::new();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_with_same_message() {
        let a = UnknownInstructionException::with_message("test");
        let b = UnknownInstructionException::with_message("test");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_with_different_message() {
        let a = UnknownInstructionException::with_message("msg1");
        let b = UnknownInstructionException::with_message("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn clone_is_equal() {
        let a = UnknownInstructionException::with_message("original");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn converts_to_user_exception_default_message() {
        let err = UnknownInstructionException::new();
        let usr: UsrException = err.into();
        assert_eq!(
            usr.to_string(),
            "Bytes do not form a legal instruction."
        );
    }

    #[test]
    fn converts_to_user_exception_custom_message() {
        let err = UnknownInstructionException::with_message("custom");
        let usr: UsrException = err.into();
        assert_eq!(usr.to_string(), "custom");
    }

    #[test]
    fn implements_std_error() {
        let err: &dyn std::error::Error =
            &UnknownInstructionException::with_message("error object");
        assert_eq!(err.to_string(), "error object");
    }
}

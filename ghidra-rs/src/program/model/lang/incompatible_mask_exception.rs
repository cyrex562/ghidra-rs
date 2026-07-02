use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when operations are attempted involving two masks of different lengths.
///
/// This mirrors Ghidra's `IncompatibleMaskException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompatibleMaskException {
    message: String,
}

impl IncompatibleMaskException {
    /// Constructs an `IncompatibleMaskException` with no message.
    pub fn new() -> Self {
        Self { message: String::new() }
    }

    /// Constructs an `IncompatibleMaskException` with a descriptive message.
    pub fn with_message(message: impl AsRef<str>) -> Self {
        Self { message: message.as_ref().to_string() }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for IncompatibleMaskException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for IncompatibleMaskException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IncompatibleMaskException {}

impl From<IncompatibleMaskException> for UsrException {
    fn from(value: IncompatibleMaskException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arg_constructor_has_empty_message() {
        let err = IncompatibleMaskException::new();
        assert_eq!(err.message(), "");
    }

    #[test]
    fn no_arg_display_is_empty() {
        let err = IncompatibleMaskException::new();
        assert_eq!(err.to_string(), "");
    }

    #[test]
    fn with_message_stores_message() {
        let err = IncompatibleMaskException::with_message("mask lengths differ");
        assert_eq!(err.message(), "mask lengths differ");
    }

    #[test]
    fn with_message_display_matches_message() {
        let err = IncompatibleMaskException::with_message("8-bit mask vs 16-bit mask");
        assert_eq!(err.to_string(), "8-bit mask vs 16-bit mask");
    }

    #[test]
    fn default_same_as_new() {
        let a = IncompatibleMaskException::default();
        let b = IncompatibleMaskException::new();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_with_same_message() {
        let a = IncompatibleMaskException::with_message("error");
        let b = IncompatibleMaskException::with_message("error");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_with_different_message() {
        let a = IncompatibleMaskException::with_message("msg1");
        let b = IncompatibleMaskException::with_message("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn clone_is_equal() {
        let a = IncompatibleMaskException::with_message("test");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn converts_to_user_exception_preserves_message() {
        let err = IncompatibleMaskException::with_message("incompatible");
        let usr: UsrException = err.into();
        assert_eq!(usr.to_string(), "incompatible");
    }

    #[test]
    fn converts_to_user_exception_empty_message() {
        let err = IncompatibleMaskException::new();
        let usr: UsrException = err.into();
        assert_eq!(usr.to_string(), "");
    }

    #[test]
    fn implements_std_error() {
        let err: &dyn std::error::Error = &IncompatibleMaskException::with_message("test");
        assert_eq!(err.to_string(), "test");
    }
}

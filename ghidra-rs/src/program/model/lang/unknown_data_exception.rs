use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when the bytes at the parse address did not form a legal known data item.
///
/// This mirrors Ghidra's `UnknownDataException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownDataException {
    message: String,
}

impl UnknownDataException {
    /// Constructs an `UnknownDataException` with the default message.
    pub fn new() -> Self {
        Self {
            message: "Bytes do not form a legal data item.".to_string(),
        }
    }

    /// Constructs an `UnknownDataException` with a custom message.
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

impl Default for UnknownDataException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UnknownDataException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UnknownDataException {}

impl From<UnknownDataException> for UsrException {
    fn from(value: UnknownDataException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_default_message() {
        let err = UnknownDataException::new();
        assert_eq!(
            err.message(),
            "Bytes do not form a legal data item."
        );
    }

    #[test]
    fn new_display_shows_default_message() {
        let err = UnknownDataException::new();
        assert_eq!(
            err.to_string(),
            "Bytes do not form a legal data item."
        );
    }

    #[test]
    fn with_message_stores_custom_message() {
        let err = UnknownDataException::with_message("custom error");
        assert_eq!(err.message(), "custom error");
    }

    #[test]
    fn with_message_display_matches_message() {
        let err = UnknownDataException::with_message("unknown data at offset 0x1000");
        assert_eq!(err.to_string(), "unknown data at offset 0x1000");
    }

    #[test]
    fn default_same_as_new() {
        let a = UnknownDataException::default();
        let b = UnknownDataException::new();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_with_same_message() {
        let a = UnknownDataException::with_message("test");
        let b = UnknownDataException::with_message("test");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_with_different_message() {
        let a = UnknownDataException::with_message("msg1");
        let b = UnknownDataException::with_message("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn clone_is_equal() {
        let a = UnknownDataException::with_message("original");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn converts_to_user_exception_default_message() {
        let err = UnknownDataException::new();
        let usr: UsrException = err.into();
        assert_eq!(
            usr.to_string(),
            "Bytes do not form a legal data item."
        );
    }

    #[test]
    fn converts_to_user_exception_custom_message() {
        let err = UnknownDataException::with_message("custom");
        let usr: UsrException = err.into();
        assert_eq!(usr.to_string(), "custom");
    }

    #[test]
    fn implements_std_error() {
        let err: &dyn std::error::Error =
            &UnknownDataException::with_message("error object");
        assert_eq!(err.to_string(), "error object");
    }
}

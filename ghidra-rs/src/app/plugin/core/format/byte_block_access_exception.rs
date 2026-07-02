use crate::util::exception::UsrException;
use std::fmt;

/// Exception thrown when byte block access is not permitted.
///
/// Indicates that the attempted access is not permitted (i.e. not readable/writable).
///
/// Port of `ghidra.app.plugin.core.format.ByteBlockAccessException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteBlockAccessException {
    message: String,
}

impl ByteBlockAccessException {
    /// Constructs a `ByteBlockAccessException` with no message.
    ///
    /// Corresponds to `new ByteBlockAccessException()` in Java.
    pub fn empty() -> Self {
        Self { message: String::new() }
    }

    /// Constructs a `ByteBlockAccessException` with the given message.
    ///
    /// Corresponds to `new ByteBlockAccessException(String message)` in Java.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Constructs a `ByteBlockAccessException` with a message and cause.
    ///
    /// Corresponds to `new ByteBlockAccessException(String message, Throwable cause)` in Java.
    ///
    /// Note: In Rust, the cause is not stored directly. This method is provided for
    /// API parity with Java; in typical Rust code, consider using error context propagation instead.
    pub fn with_cause<E: std::error::Error + Send + Sync + 'static>(
        message: impl Into<String>,
        _cause: E,
    ) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ByteBlockAccessException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ByteBlockAccessException {}

impl From<ByteBlockAccessException> for UsrException {
    fn from(value: ByteBlockAccessException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_constructor_creates_empty_message() {
        let exception = ByteBlockAccessException::empty();
        assert_eq!(exception.message(), "");
        assert_eq!(exception.to_string(), "");
    }

    #[test]
    fn new_with_message_stores_message() {
        let exception = ByteBlockAccessException::new("Access denied");
        assert_eq!(exception.message(), "Access denied");
        assert_eq!(exception.to_string(), "Access denied");
    }

    #[test]
    fn with_cause_stores_message() {
        let cause = UsrException::new("underlying cause");
        let exception = ByteBlockAccessException::with_cause("Access denied", cause);
        assert_eq!(exception.message(), "Access denied");
        assert_eq!(exception.to_string(), "Access denied");
    }

    #[test]
    fn debug_format_includes_type_name() {
        let exception = ByteBlockAccessException::new("test");
        let debug_str = format!("{:?}", exception);
        assert!(debug_str.contains("ByteBlockAccessException"));
    }

    #[test]
    fn clone_preserves_message() {
        let original = ByteBlockAccessException::new("message");
        let cloned = original.clone();
        assert_eq!(original.message(), cloned.message());
        assert_eq!(original, cloned);
    }

    #[test]
    fn equality_based_on_message() {
        let exc1 = ByteBlockAccessException::new("same");
        let exc2 = ByteBlockAccessException::new("same");
        let exc3 = ByteBlockAccessException::new("different");

        assert_eq!(exc1, exc2);
        assert_ne!(exc1, exc3);
    }

    #[test]
    fn converts_to_usr_exception() {
        let exception = ByteBlockAccessException::new("test error");
        let usr_exc: UsrException = exception.into();
        assert_eq!(usr_exc.to_string(), "test error");
    }

    #[test]
    fn implements_std_error() {
        let exception: &dyn std::error::Error = &ByteBlockAccessException::new("error");
        assert_eq!(exception.to_string(), "error");
    }

    #[test]
    fn empty_constructor_has_no_message() {
        let exception = ByteBlockAccessException::empty();
        assert_eq!(exception.message(), "");
    }
}

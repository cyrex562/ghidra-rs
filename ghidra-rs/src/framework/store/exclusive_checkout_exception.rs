use std::fmt;

/// Raised when an exclusive checkout operation fails.
///
/// Mirrors `ghidra.framework.store.ExclusiveCheckoutException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusiveCheckoutException {
    message: String,
}

impl ExclusiveCheckoutException {
    /// Creates a new `ExclusiveCheckoutException` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ExclusiveCheckoutException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ExclusiveCheckoutException {}

impl From<ExclusiveCheckoutException> for std::io::Error {
    fn from(e: ExclusiveCheckoutException) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_with_message() {
        let e = ExclusiveCheckoutException::new("test message");
        assert_eq!(e.message(), "test message");
    }

    #[test]
    fn display_shows_message() {
        let e = ExclusiveCheckoutException::new("exclusive lock failed");
        assert_eq!(format!("{}", e), "exclusive lock failed");
    }

    #[test]
    fn from_string() {
        let msg = String::from("checkout conflict");
        let e = ExclusiveCheckoutException::new(msg);
        assert_eq!(e.message(), "checkout conflict");
    }

    #[test]
    fn clone_equality() {
        let a = ExclusiveCheckoutException::new("msg");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_message() {
        let a = ExclusiveCheckoutException::new("msg1");
        let b = ExclusiveCheckoutException::new("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn implements_error_trait() {
        let e = ExclusiveCheckoutException::new("error");
        let _: &dyn Error = &e;
    }

    #[test]
    fn error_source_is_none() {
        let e = ExclusiveCheckoutException::new("error");
        assert!(e.source().is_none());
    }

    #[test]
    fn debug_format_includes_type() {
        let e = ExclusiveCheckoutException::new("test");
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("ExclusiveCheckoutException"));
    }

    #[test]
    fn into_io_error() {
        let e = ExclusiveCheckoutException::new("exclusive lock");
        let io_err: std::io::Error = e.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::Other);
        assert!(io_err.to_string().contains("exclusive lock"));
    }

    #[test]
    fn message_accessor_returns_full_text() {
        let e = ExclusiveCheckoutException::new("detailed error message");
        let msg = e.message();
        assert_eq!(msg, "detailed error message");
    }
}

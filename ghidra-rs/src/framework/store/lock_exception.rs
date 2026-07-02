use std::fmt;

/// Indicates a failure to obtain a required lock.
///
/// Mirrors `ghidra.framework.store.LockException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockException {
    message: String,
}

impl LockException {
    /// Creates a new `LockException` with the given message.
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

impl fmt::Display for LockException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for LockException {}

impl From<LockException> for std::io::Error {
    fn from(e: LockException) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_with_message() {
        let e = LockException::new("test message");
        assert_eq!(e.message(), "test message");
    }

    #[test]
    fn display_shows_message() {
        let e = LockException::new("lock acquisition failed");
        assert_eq!(format!("{}", e), "lock acquisition failed");
    }

    #[test]
    fn from_string() {
        let msg = String::from("cannot obtain lock");
        let e = LockException::new(msg);
        assert_eq!(e.message(), "cannot obtain lock");
    }

    #[test]
    fn clone_equality() {
        let a = LockException::new("msg");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_message() {
        let a = LockException::new("msg1");
        let b = LockException::new("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn implements_error_trait() {
        let e = LockException::new("error");
        let _: &dyn Error = &e;
    }

    #[test]
    fn error_source_is_none() {
        let e = LockException::new("error");
        assert!(e.source().is_none());
    }

    #[test]
    fn debug_format_includes_type() {
        let e = LockException::new("test");
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("LockException"));
    }

    #[test]
    fn into_io_error() {
        let e = LockException::new("lock failed");
        let io_err: std::io::Error = e.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::Other);
        assert!(io_err.to_string().contains("lock failed"));
    }

    #[test]
    fn message_accessor_returns_full_text() {
        let e = LockException::new("detailed error message");
        let msg = e.message();
        assert_eq!(msg, "detailed error message");
    }
}

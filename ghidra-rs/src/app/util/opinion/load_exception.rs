//! Exception thrown when a load operation fails in an expected way.

use thiserror::Error;

/// Thrown when a [`Loader`] load fails in an expected way.
///
/// The supplied message should explain the reason for the failure.
///
/// Mirrors `ghidra.app.util.opinion.LoadException`.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct LoadException {
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl LoadException {
    /// Creates a new `LoadException` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Creates a new `LoadException` with the given message and cause.
    pub fn with_cause<E: std::error::Error + Send + Sync + 'static>(
        message: impl Into<String>,
        cause: E,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(cause)),
        }
    }

    /// Creates a new `LoadException` whose message is derived from the cause.
    pub fn from_cause<E: std::error::Error + Send + Sync + 'static>(cause: E) -> Self {
        Self {
            message: cause.to_string(),
            source: Some(Box::new(cause)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_new_message() {
        let exc = LoadException::new("load failed");
        assert_eq!(exc.to_string(), "load failed");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_new_empty_message() {
        let exc = LoadException::new("");
        assert_eq!(exc.to_string(), "");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_with_cause_preserves_message() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let exc = LoadException::with_cause("could not load binary", inner);
        assert_eq!(exc.to_string(), "could not load binary");
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_with_cause_source_accessible() {
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let exc = LoadException::with_cause("load error", inner);
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_from_cause_derives_message() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let expected = inner.to_string();
        let exc = LoadException::from_cause(inner);
        assert_eq!(exc.to_string(), expected);
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_from_cause_source_accessible() {
        let inner = std::io::Error::new(std::io::ErrorKind::Other, "something went wrong");
        let exc = LoadException::from_cause(inner);
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_debug_format() {
        let exc = LoadException::new("debug test");
        let debug_str = format!("{:?}", exc);
        assert!(debug_str.contains("LoadException"));
    }

    #[test]
    fn test_message_with_special_chars() {
        let exc = LoadException::new("Error: file\t'test.bin'\ncorrupted");
        assert_eq!(exc.to_string(), "Error: file\t'test.bin'\ncorrupted");
    }
}

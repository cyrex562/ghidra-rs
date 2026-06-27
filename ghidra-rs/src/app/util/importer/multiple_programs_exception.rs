//! Exception thrown when multiple programs are unexpectedly encountered.

use thiserror::Error;

/// Exception indicating that multiple programs were encountered where only one was expected.
///
/// Mirrors `ghidra.app.util.importer.MultipleProgramsException`.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct MultipleProgramsException {
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl MultipleProgramsException {
    /// Constructs a `MultipleProgramsException` with no message or cause.
    pub fn new() -> Self {
        Self {
            message: String::new(),
            source: None,
        }
    }

    /// Constructs a `MultipleProgramsException` with the given message.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            source: None,
        }
    }

    /// Constructs a `MultipleProgramsException` wrapping an underlying cause.
    pub fn from_cause<E: std::error::Error + Send + Sync + 'static>(cause: E) -> Self {
        Self {
            message: cause.to_string(),
            source: Some(Box::new(cause)),
        }
    }

    /// Constructs a `MultipleProgramsException` with a message and an underlying cause.
    pub fn with_message_and_cause<E: std::error::Error + Send + Sync + 'static>(
        msg: impl Into<String>,
        cause: E,
    ) -> Self {
        Self {
            message: msg.into(),
            source: Some(Box::new(cause)),
        }
    }
}

impl Default for MultipleProgramsException {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_new_no_message() {
        let exc = MultipleProgramsException::new();
        assert_eq!(exc.to_string(), "");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_default() {
        let exc = MultipleProgramsException::default();
        assert_eq!(exc.to_string(), "");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_with_message() {
        let exc = MultipleProgramsException::with_message("too many programs");
        assert_eq!(exc.to_string(), "too many programs");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_with_empty_message() {
        let exc = MultipleProgramsException::with_message("");
        assert_eq!(exc.to_string(), "");
    }

    #[test]
    fn test_from_cause() {
        let inner = std::io::Error::new(std::io::ErrorKind::Other, "underlying error");
        let exc = MultipleProgramsException::from_cause(inner);
        assert!(exc.to_string().contains("underlying error"));
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_from_cause_message_derived() {
        let inner = std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad input");
        let exc = MultipleProgramsException::from_cause(inner);
        assert_eq!(exc.to_string(), "bad input");
    }

    #[test]
    fn test_with_message_and_cause() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let exc = MultipleProgramsException::with_message_and_cause("custom msg", inner);
        assert_eq!(exc.to_string(), "custom msg");
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_with_message_and_cause_source_chain() {
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let exc =
            MultipleProgramsException::with_message_and_cause("wrapper message", inner);
        assert_eq!(exc.to_string(), "wrapper message");
        let src = exc.source().unwrap();
        assert!(src.to_string().contains("denied"));
    }

    #[test]
    fn test_debug_format() {
        let exc = MultipleProgramsException::with_message("debug test");
        let debug_str = format!("{:?}", exc);
        assert!(debug_str.contains("MultipleProgramsException"));
    }

    #[test]
    fn test_is_error_trait() {
        let exc = MultipleProgramsException::with_message("is error");
        let _: &dyn std::error::Error = &exc;
    }
}

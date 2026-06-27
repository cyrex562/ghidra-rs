//! Exception thrown when an exporter encounters an error.

use thiserror::Error;

/// Exception thrown when an exporter encounters an error condition.
///
/// Mirrors `ghidra.app.util.exporter.ExporterException`.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ExporterException {
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ExporterException {
    /// Constructs a new `ExporterException` with a descriptive message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            source: None,
        }
    }

    /// Constructs a new `ExporterException` wrapping an underlying error cause.
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
        let exc = ExporterException::new("export failed");
        assert_eq!(exc.to_string(), "export failed");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_new_empty_message() {
        let exc = ExporterException::new("");
        assert_eq!(exc.to_string(), "");
    }

    #[test]
    fn test_from_cause_preserves_message() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let exc = ExporterException::from_cause(inner);
        assert!(exc.to_string().contains("file not found"));
    }

    #[test]
    fn test_from_cause_has_source() {
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let exc = ExporterException::from_cause(inner);
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_debug_format() {
        let exc = ExporterException::new("debug test");
        let debug_str = format!("{:?}", exc);
        assert!(debug_str.contains("ExporterException"));
    }

    #[test]
    fn test_message_with_special_chars() {
        let exc = ExporterException::new("Error: file\t'test.bin'\ncorrupted");
        assert_eq!(exc.to_string(), "Error: file\t'test.bin'\ncorrupted");
    }
}

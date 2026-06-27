//! Exception thrown when a loader fails to form an opinion about a file.

use thiserror::Error;

/// Thrown when a [`Loader`] cannot form an opinion about a file (e.g., unrecognised format).
///
/// Mirrors `ghidra.app.util.opinion.LoaderOpinionException`.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct LoaderOpinionException {
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl LoaderOpinionException {
    /// Creates a new `LoaderOpinionException` with an empty message and no cause.
    pub fn new() -> Self {
        Self {
            message: String::new(),
            source: None,
        }
    }

    /// Creates a new `LoaderOpinionException` with the given message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Creates a new `LoaderOpinionException` with the given message and cause.
    pub fn with_cause<E: std::error::Error + Send + Sync + 'static>(
        message: impl Into<String>,
        cause: E,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(cause)),
        }
    }

    /// Creates a new `LoaderOpinionException` whose message is derived from the cause.
    pub fn from_cause<E: std::error::Error + Send + Sync + 'static>(cause: E) -> Self {
        Self {
            message: cause.to_string(),
            source: Some(Box::new(cause)),
        }
    }
}

impl Default for LoaderOpinionException {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_new_has_empty_message_and_no_source() {
        let exc = LoaderOpinionException::new();
        assert_eq!(exc.to_string(), "");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_default_equals_new() {
        let exc = LoaderOpinionException::default();
        assert_eq!(exc.to_string(), "");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_with_message() {
        let exc = LoaderOpinionException::with_message("not my format");
        assert_eq!(exc.to_string(), "not my format");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_with_message_empty() {
        let exc = LoaderOpinionException::with_message("");
        assert_eq!(exc.to_string(), "");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_with_cause_preserves_message() {
        let inner = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad magic");
        let exc = LoaderOpinionException::with_cause("unrecognised format", inner);
        assert_eq!(exc.to_string(), "unrecognised format");
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_with_cause_source_accessible() {
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let exc = LoaderOpinionException::with_cause("opinion failed", inner);
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_from_cause_derives_message() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let expected = inner.to_string();
        let exc = LoaderOpinionException::from_cause(inner);
        assert_eq!(exc.to_string(), expected);
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_from_cause_source_accessible() {
        let inner = std::io::Error::new(std::io::ErrorKind::Other, "unexpected");
        let exc = LoaderOpinionException::from_cause(inner);
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_debug_format_contains_type_name() {
        let exc = LoaderOpinionException::with_message("debug check");
        let s = format!("{:?}", exc);
        assert!(s.contains("LoaderOpinionException"));
    }
}

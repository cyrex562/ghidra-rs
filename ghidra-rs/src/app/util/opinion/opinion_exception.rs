//! Exception raised when processing an opinion fails.

use thiserror::Error;

/// Error raised when processing an opinion fails.
///
/// Mirrors `ghidra.app.util.opinion.OpinionException`.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct OpinionException {
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl OpinionException {
    /// Creates a new `OpinionException` with the given detail message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            source: None,
        }
    }

    /// Creates a new `OpinionException` whose message is derived from the cause.
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
    fn test_new_stores_message() {
        let exc = OpinionException::new("bad opinion");
        assert_eq!(exc.to_string(), "bad opinion");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_new_empty_message() {
        let exc = OpinionException::new("");
        assert_eq!(exc.to_string(), "");
        assert!(exc.source().is_none());
    }

    #[test]
    fn test_from_cause_derives_message() {
        let inner = std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt data");
        let expected = inner.to_string();
        let exc = OpinionException::from_cause(inner);
        assert_eq!(exc.to_string(), expected);
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_from_cause_source_accessible() {
        let inner = std::io::Error::new(std::io::ErrorKind::Other, "unexpected");
        let exc = OpinionException::from_cause(inner);
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_debug_format_contains_type_name() {
        let exc = OpinionException::new("debug check");
        let s = format!("{:?}", exc);
        assert!(s.contains("OpinionException"));
    }
}

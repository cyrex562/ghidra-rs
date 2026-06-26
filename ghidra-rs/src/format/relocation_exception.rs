use thiserror::Error;

/// Thrown when a supported relocation encounters an unexpected error during processing.
#[derive(Error, Debug)]
#[error("{message}")]
pub struct RelocationError {
    message: String,
    #[source]
    cause: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl RelocationError {
    /// Constructs a new error with the specified detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: None,
        }
    }

    /// Constructs a new error with the specified detail message and cause.
    pub(crate) fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            cause: Some(Box::new(cause)),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let err = RelocationError::new("relocation failed");
        assert_eq!(err.message(), "relocation failed");
        assert_eq!(err.to_string(), "relocation failed");
    }

    #[test]
    fn new_has_no_cause() {
        let err = RelocationError::new("no cause");
        assert!(err.source().is_none());
    }

    #[test]
    fn with_cause_stores_message_and_cause() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "underlying io error");
        let err = RelocationError::with_cause("relocation failed", cause);
        assert_eq!(err.message(), "relocation failed");
        assert_eq!(err.to_string(), "relocation failed");
        let src = err.source().expect("should have a cause");
        assert_eq!(src.to_string(), "underlying io error");
    }

    #[test]
    fn message_is_required_non_empty() {
        // Java requires non-null message via Objects.requireNonNull — in Rust we enforce
        // this by type: an owned String cannot be null. An empty string is technically
        // allowed by the Java constructor, so we accept it here too.
        let err = RelocationError::new("");
        assert_eq!(err.message(), "");
    }

    #[test]
    fn display_matches_message() {
        let err = RelocationError::new("test message");
        assert_eq!(format!("{}", err), "test message");
    }
}

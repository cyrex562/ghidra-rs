use std::fmt;

/// Error corresponding to a datatype dependency failure.
///
/// This can occur under various situations, including when trying to replace a
/// datatype with a datatype that depends on the datatype being replaced. This
/// error may also occur when a datatype dependency cannot be satisfied.
#[derive(Debug)]
pub struct DataTypeDependencyException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl DataTypeDependencyException {
    /// Constructs a dependency exception with no detail message or cause.
    pub fn new() -> Self {
        Self {
            message: String::new(),
            source: None,
        }
    }

    /// Constructs a dependency exception with a detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a dependency exception wrapping a cause; the message is
    /// derived from the cause's [`Display`](fmt::Display) representation.
    pub fn with_source(cause: Box<dyn std::error::Error + Send + Sync + 'static>) -> Self {
        Self {
            message: cause.to_string(),
            source: Some(cause),
        }
    }

    /// Constructs a dependency exception with a detail message and a cause.
    pub fn with_message_and_source(
        message: impl Into<String>,
        cause: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(cause),
        }
    }

    /// Returns the detail message string.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for DataTypeDependencyException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DataTypeDependencyException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DataTypeDependencyException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn default_constructor_has_empty_message_and_no_source() {
        let e = DataTypeDependencyException::new();
        assert_eq!(e.message(), "");
        assert!(e.source().is_none());
    }

    #[test]
    fn default_trait_matches_new() {
        let e = DataTypeDependencyException::default();
        assert_eq!(e.message(), "");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_message_stores_message() {
        let e = DataTypeDependencyException::with_message("dependency cycle detected");
        assert_eq!(e.message(), "dependency cycle detected");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_message_display_returns_message() {
        let e = DataTypeDependencyException::with_message("cannot replace type");
        assert_eq!(e.to_string(), "cannot replace type");
    }

    #[test]
    fn with_source_wraps_cause() {
        let cause = DataTypeDependencyException::with_message("root cause");
        let e = DataTypeDependencyException::with_source(Box::new(cause));
        assert!(e.source().is_some());
        assert_eq!(e.to_string(), "root cause");
    }

    #[test]
    fn with_message_and_source_stores_both() {
        let cause = DataTypeDependencyException::with_message("underlying error");
        let e = DataTypeDependencyException::with_message_and_source("high-level error", Box::new(cause));
        assert_eq!(e.message(), "high-level error");
        assert_eq!(e.to_string(), "high-level error");
        assert!(e.source().is_some());
    }

    #[test]
    fn implements_error_trait() {
        let e = DataTypeDependencyException::with_message("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn debug_contains_message() {
        let e = DataTypeDependencyException::with_message("debug check");
        assert!(format!("{:?}", e).contains("debug check"));
    }

    #[test]
    fn empty_message_allowed() {
        let e = DataTypeDependencyException::with_message("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

//! Exception thrown by the annotation classes.

use std::fmt;
use thiserror::Error;

/// Exception thrown by the annotation classes.
///
/// Corresponds to Java `ghidra.app.util.viewer.field.AnnotationException`.
#[derive(Debug, Clone, Error)]
pub struct AnnotationException {
    message: String,
}

impl AnnotationException {
    /// Creates a new `AnnotationException` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for AnnotationException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_stores_message() {
        let exc = AnnotationException::new("bad annotation");
        assert_eq!(exc.to_string(), "bad annotation");
    }

    #[test]
    fn test_display() {
        let exc = AnnotationException::new("annotation error occurred");
        assert_eq!(format!("{}", exc), "annotation error occurred");
    }

    #[test]
    fn test_debug() {
        let exc = AnnotationException::new("debug test");
        let s = format!("{:?}", exc);
        assert!(s.contains("AnnotationException"));
        assert!(s.contains("debug test"));
    }

    #[test]
    fn test_clone() {
        let exc = AnnotationException::new("original");
        let cloned = exc.clone();
        assert_eq!(exc.to_string(), cloned.to_string());
    }

    #[test]
    fn test_error_trait() {
        let exc = AnnotationException::new("error trait test");
        let _: &dyn std::error::Error = &exc;
    }

    #[test]
    fn test_empty_message() {
        let exc = AnnotationException::new("");
        assert_eq!(exc.to_string(), "");
    }
}

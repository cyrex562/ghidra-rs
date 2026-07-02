use crate::util::exception::UsrException;
use std::fmt;

/// Exception thrown when an action would cause the program's module structure to have a
/// "cycle", that is to have two modules which are both ancestors and descendants of each other.
///
/// Port of `ghidra.program.model.listing.CircularDependencyException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircularDependencyException {
    message: String,
}

impl CircularDependencyException {
    /// Java-compatible default message.
    pub const DEFAULT_MESSAGE: &'static str = "Reference is invalid.";

    /// Constructs a circular dependency exception with the Java default message.
    pub fn default() -> Self {
        Self::new(Self::DEFAULT_MESSAGE)
    }

    /// Constructs a circular dependency exception with a detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for CircularDependencyException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for CircularDependencyException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CircularDependencyException {}

impl From<CircularDependencyException> for UsrException {
    fn from(value: CircularDependencyException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_uses_java_message() {
        let error = CircularDependencyException::default();

        assert_eq!(error.message(), "Reference is invalid.");
        assert_eq!(error.to_string(), "Reference is invalid.");
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = CircularDependencyException::new("cycle detected");

        assert_eq!(error.message(), "cycle detected");
        assert_eq!(error.to_string(), "cycle detected");
    }

    #[test]
    fn converts_to_user_exception() {
        let error: UsrException =
            CircularDependencyException::new("module cycle").into();

        assert_eq!(error, UsrException("module cycle".to_string()));
    }

    #[test]
    fn default_converts_to_user_exception() {
        let error: UsrException = CircularDependencyException::default().into();

        assert_eq!(error, UsrException("Reference is invalid.".to_string()));
    }

    #[test]
    fn clone_is_independent() {
        let e = CircularDependencyException::new("original");
        let c = e.clone();

        assert_eq!(c.message(), "original");
        assert_eq!(c.to_string(), "original");
    }

    #[test]
    fn equality() {
        let e1 = CircularDependencyException::new("msg");
        let e2 = CircularDependencyException::new("msg");
        let e3 = CircularDependencyException::new("other");

        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn implements_error_trait() {
        let e = CircularDependencyException::default();
        let _: &dyn std::error::Error = &e;
    }
}

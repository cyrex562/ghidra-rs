use std::fmt;

/// An exception indicating a path or object does not provide a required interface.
///
/// Mirrors `ghidra.trace.model.target.schema.BadSchemaException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadSchemaException {
    message: String,
}

impl BadSchemaException {
    /// Constructs a new exception with a human-readable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for BadSchemaException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BadSchemaException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message() {
        let e = BadSchemaException::new("bad schema");
        assert_eq!(e.message(), "bad schema");
    }

    #[test]
    fn display_matches_message() {
        let e = BadSchemaException::new("bad schema");
        assert_eq!(e.to_string(), "bad schema");
    }

    #[test]
    fn empty_message_is_accepted() {
        let e = BadSchemaException::new("");
        assert_eq!(e.message(), "");
    }

    #[test]
    fn implements_error_trait() {
        let e: Box<dyn std::error::Error> = Box::new(BadSchemaException::new("oops"));
        assert_eq!(e.to_string(), "oops");
    }

    #[test]
    fn equality_on_same_message() {
        let a = BadSchemaException::new("x");
        let b = BadSchemaException::new("x");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_on_different_messages() {
        let a = BadSchemaException::new("x");
        let b = BadSchemaException::new("y");
        assert_ne!(a, b);
    }
}

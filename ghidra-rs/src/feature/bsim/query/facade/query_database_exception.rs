use std::fmt;

/// Error type for BSim database query failures.
///
/// Mirrors `ghidra.features.bsim.query.facade.QueryDatabaseException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDatabaseException {
    message: String,
}

impl QueryDatabaseException {
    /// Construct with an explicit message.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    /// Construct with a message and a cause; the cause description is appended.
    pub fn with_cause(message: impl Into<String>, cause: &dyn std::error::Error) -> Self {
        Self { message: format!("{}: {}", message.into(), cause) }
    }

    /// Construct from a cause alone; the cause's display text becomes the message.
    pub fn from_error(cause: &dyn std::error::Error) -> Self {
        Self { message: cause.to_string() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for QueryDatabaseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QueryDatabaseException: {}", self.message)
    }
}

impl std::error::Error for QueryDatabaseException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_message() {
        let e = QueryDatabaseException::new("query failed");
        assert_eq!(e.message(), "query failed");
    }

    #[test]
    fn test_display() {
        let e = QueryDatabaseException::new("bad query");
        assert_eq!(e.to_string(), "QueryDatabaseException: bad query");
    }

    #[test]
    fn test_empty_message() {
        let e = QueryDatabaseException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "QueryDatabaseException: ");
    }

    #[test]
    fn test_with_cause() {
        let cause = QueryDatabaseException::new("root cause");
        let e = QueryDatabaseException::with_cause("outer message", &cause);
        assert!(e.message().starts_with("outer message"));
        assert!(e.message().contains("root cause"));
    }

    #[test]
    fn test_from_error() {
        let cause = QueryDatabaseException::new("underlying error");
        let e = QueryDatabaseException::from_error(&cause);
        assert!(e.message().contains("underlying error"));
    }

    #[test]
    fn test_implements_error_trait() {
        let e = QueryDatabaseException::new("err");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_clone_and_eq() {
        let a = QueryDatabaseException::new("x");
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, QueryDatabaseException::new("y"));
    }
}

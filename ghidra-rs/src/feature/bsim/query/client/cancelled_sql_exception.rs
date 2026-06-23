use std::fmt;

/// Error indicating a SQL operation was intentionally cancelled.
///
/// Mirrors `ghidra.features.bsim.query.client.CancelledSQLException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelledSqlException {
    reason: String,
}

impl CancelledSqlException {
    pub fn new(reason: impl Into<String>) -> Self {
        Self { reason: reason.into() }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for CancelledSqlException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CancelledSQLException: {}", self.reason)
    }
}

impl std::error::Error for CancelledSqlException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_reason() {
        let e = CancelledSqlException::new("user cancelled");
        assert_eq!(e.reason(), "user cancelled");
    }

    #[test]
    fn test_display() {
        let e = CancelledSqlException::new("timeout");
        assert_eq!(e.to_string(), "CancelledSQLException: timeout");
    }

    #[test]
    fn test_empty_reason() {
        let e = CancelledSqlException::new("");
        assert_eq!(e.reason(), "");
        assert_eq!(e.to_string(), "CancelledSQLException: ");
    }

    #[test]
    fn test_implements_error_trait() {
        let e = CancelledSqlException::new("err");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_clone_and_eq() {
        let a = CancelledSqlException::new("cancelled");
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, CancelledSqlException::new("other"));
    }
}

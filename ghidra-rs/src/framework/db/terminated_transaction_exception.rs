use std::fmt;

/// Occurs when a database modification is attempted following the forced/premature termination
/// of an open transaction.
///
/// Port of `db.TerminatedTransactionException`, a `RuntimeException` subclass exposing both a
/// no-arg constructor (fixed message `"Transaction has been terminated"`) and a
/// message-carrying constructor. Ported following the same message-carrying pattern established
/// by [`super::illegal_field_access_exception::IllegalFieldAccessException`] in this package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminatedTransactionException {
    message: String,
}

impl TerminatedTransactionException {
    /// Construct with the default message `"Transaction has been terminated"`. Mirrors
    /// `TerminatedTransactionException()`.
    pub fn new() -> Self {
        Self { message: "Transaction has been terminated".to_string() }
    }

    /// Construct with a specific message. Mirrors `TerminatedTransactionException(String msg)`.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

impl Default for TerminatedTransactionException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TerminatedTransactionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TerminatedTransactionException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_default_message() {
        let e = TerminatedTransactionException::new();
        assert_eq!(e.to_string(), "Transaction has been terminated");
    }

    #[test]
    fn test_custom_message() {
        let e = TerminatedTransactionException::with_message("custom error");
        assert_eq!(e.to_string(), "custom error");
    }

    #[test]
    fn test_default_trait() {
        let e = TerminatedTransactionException::default();
        assert_eq!(e.to_string(), "Transaction has been terminated");
    }

    #[test]
    fn test_debug() {
        let e = TerminatedTransactionException::new();
        assert!(format!("{:?}", e).contains("TerminatedTransactionException"));
    }

    #[test]
    fn test_implements_error() {
        let e = TerminatedTransactionException::new();
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_clone_and_eq() {
        let e1 = TerminatedTransactionException::new();
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_custom_messages_differ() {
        let e1 = TerminatedTransactionException::with_message("a");
        let e2 = TerminatedTransactionException::with_message("b");
        assert_ne!(e1, e2);
    }
}

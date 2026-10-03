use std::fmt;

/// Occurs when a database modification is attempted when no transaction exists.
///
/// Port of `db.NoTransactionException`, a `RuntimeException` subclass with a single
/// package-private no-arg constructor that always reports the fixed message `"Transaction has
/// not been started"`. Since the Java constructor takes no arguments and the message is fixed,
/// this is ported as a fieldless unit struct (mirroring [`super::db_rollback_exception::DBRollbackException`],
/// the other fixed-message exception in this package) rather than the message-carrying pattern
/// used by [`super::illegal_field_access_exception::IllegalFieldAccessException`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoTransactionException;

impl fmt::Display for NoTransactionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Transaction has not been started")
    }
}

impl std::error::Error for NoTransactionException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_display() {
        let e = NoTransactionException;
        assert_eq!(e.to_string(), "Transaction has not been started");
    }

    #[test]
    fn test_debug() {
        let e = NoTransactionException;
        assert_eq!(format!("{:?}", e), "NoTransactionException");
    }

    #[test]
    fn test_implements_error() {
        let e = NoTransactionException;
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_clone_and_eq() {
        let e1 = NoTransactionException;
        let e2 = e1;
        assert_eq!(e1, e2);
    }
}

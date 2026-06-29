use std::fmt;

/// Thrown when a database transaction rollback was performed during transaction termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DBRollbackException;

impl fmt::Display for DBRollbackException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "database transaction rollback occurred during transaction termination")
    }
}

impl std::error::Error for DBRollbackException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_display() {
        let e = DBRollbackException;
        assert_eq!(
            e.to_string(),
            "database transaction rollback occurred during transaction termination"
        );
    }

    #[test]
    fn test_debug() {
        let e = DBRollbackException;
        assert_eq!(format!("{:?}", e), "DBRollbackException");
    }

    #[test]
    fn test_implements_error() {
        let e = DBRollbackException;
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_clone_and_eq() {
        let e1 = DBRollbackException;
        let e2 = e1;
        assert_eq!(e1, e2);
    }
}

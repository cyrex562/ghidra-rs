use std::fmt;

/// Thrown when a lock cannot be acquired during a GhidraGo launch attempt.
///
/// Java equivalent: `ghidra.app.plugin.core.go.exception.UnableToGetLockException`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnableToGetLockException;

impl fmt::Display for UnableToGetLockException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnableToGetLockException")
    }
}

impl std::error::Error for UnableToGetLockException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_is_error() {
        let e = UnableToGetLockException;
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_display() {
        let e = UnableToGetLockException;
        assert_eq!(e.to_string(), "UnableToGetLockException");
    }

    #[test]
    fn test_debug() {
        let e = UnableToGetLockException;
        assert_eq!(format!("{:?}", e), "UnableToGetLockException");
    }

    #[test]
    fn test_clone_and_eq() {
        let a = UnableToGetLockException;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_source_is_none() {
        let e = UnableToGetLockException;
        assert!(e.source().is_none());
    }
}

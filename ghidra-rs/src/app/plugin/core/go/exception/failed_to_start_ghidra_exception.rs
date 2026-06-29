use std::fmt;

/// Thrown when Ghidra fails to start during a GhidraGo launch attempt.
///
/// Java equivalent: `ghidra.app.plugin.core.go.exception.FailedToStartGhidraException`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedToStartGhidraException;

impl fmt::Display for FailedToStartGhidraException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FailedToStartGhidraException")
    }
}

impl std::error::Error for FailedToStartGhidraException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_is_error() {
        let e = FailedToStartGhidraException;
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_display() {
        let e = FailedToStartGhidraException;
        assert_eq!(e.to_string(), "FailedToStartGhidraException");
    }

    #[test]
    fn test_debug() {
        let e = FailedToStartGhidraException;
        assert_eq!(format!("{:?}", e), "FailedToStartGhidraException");
    }

    #[test]
    fn test_clone_and_eq() {
        let a = FailedToStartGhidraException;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_source_is_none() {
        let e = FailedToStartGhidraException;
        assert!(e.source().is_none());
    }
}

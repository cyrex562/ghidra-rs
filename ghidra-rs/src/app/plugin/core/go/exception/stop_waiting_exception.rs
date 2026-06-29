use std::fmt;

/// Thrown to signal that waiting should stop during a GhidraGo launch attempt.
///
/// Java equivalent: `ghidra.app.plugin.core.go.exception.StopWaitingException`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopWaitingException;

impl fmt::Display for StopWaitingException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StopWaitingException")
    }
}

impl std::error::Error for StopWaitingException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_is_error() {
        let e = StopWaitingException;
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_display() {
        let e = StopWaitingException;
        assert_eq!(e.to_string(), "StopWaitingException");
    }

    #[test]
    fn test_debug() {
        let e = StopWaitingException;
        assert_eq!(format!("{:?}", e), "StopWaitingException");
    }

    #[test]
    fn test_clone_and_eq() {
        let a = StopWaitingException;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_source_is_none() {
        let e = StopWaitingException;
        assert!(e.source().is_none());
    }
}

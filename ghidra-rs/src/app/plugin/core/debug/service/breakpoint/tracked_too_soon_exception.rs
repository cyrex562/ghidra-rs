use std::fmt;

/// Raised when a breakpoint location is tracked before the service is ready to handle it.
///
/// Java equivalent: `ghidra.app.plugin.core.debug.service.breakpoint.TrackedTooSoonException`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedTooSoonException;

impl fmt::Display for TrackedTooSoonException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TrackedTooSoonException")
    }
}

impl std::error::Error for TrackedTooSoonException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_is_error() {
        let e = TrackedTooSoonException;
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_display() {
        let e = TrackedTooSoonException;
        assert_eq!(e.to_string(), "TrackedTooSoonException");
    }

    #[test]
    fn test_debug() {
        let e = TrackedTooSoonException;
        assert_eq!(format!("{:?}", e), "TrackedTooSoonException");
    }

    #[test]
    fn test_clone_and_eq() {
        let a = TrackedTooSoonException;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_source_is_none() {
        let e = TrackedTooSoonException;
        assert!(e.source().is_none());
    }
}

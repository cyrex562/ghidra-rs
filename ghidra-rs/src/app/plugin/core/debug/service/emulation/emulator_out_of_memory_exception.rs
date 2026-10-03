use std::fmt;

/// Raised when an emulator-related operation cannot locate a suitable address in the trace's memory map.
///
/// Java equivalent: `ghidra.app.plugin.core.debug.service.emulation.EmulatorOutOfMemoryException`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmulatorOutOfMemoryException;

impl fmt::Display for EmulatorOutOfMemoryException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmulatorOutOfMemoryException")
    }
}

impl std::error::Error for EmulatorOutOfMemoryException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_is_error() {
        let e = EmulatorOutOfMemoryException;
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_display() {
        let e = EmulatorOutOfMemoryException;
        assert_eq!(e.to_string(), "EmulatorOutOfMemoryException");
    }

    #[test]
    fn test_debug() {
        let e = EmulatorOutOfMemoryException;
        assert_eq!(format!("{:?}", e), "EmulatorOutOfMemoryException");
    }

    #[test]
    fn test_clone_and_eq() {
        let a = EmulatorOutOfMemoryException;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_source_is_none() {
        let e = EmulatorOutOfMemoryException;
        assert!(e.source().is_none());
    }
}

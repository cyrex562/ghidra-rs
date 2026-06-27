use std::fmt;

/// Error type indicating an obsolete Mach-O format feature.
///
/// Mirrors Ghidra's `ObsoleteException`, which always carries the fixed message "Obsolete".
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ObsoleteException;

impl ObsoleteException {
    /// Creates a new `ObsoleteException`.
    pub fn new() -> Self {
        Self
    }
}

impl fmt::Display for ObsoleteException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Obsolete")
    }
}

impl std::error::Error for ObsoleteException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn display_is_obsolete() {
        assert_eq!(ObsoleteException::new().to_string(), "Obsolete");
    }

    #[test]
    fn no_source() {
        assert!(ObsoleteException::new().source().is_none());
    }

    #[test]
    fn implements_error() {
        let e = ObsoleteException::new();
        let _: &dyn Error = &e;
    }

    #[test]
    fn debug_impl_exists() {
        let s = format!("{:?}", ObsoleteException::new());
        assert!(s.contains("ObsoleteException"));
    }

    #[test]
    fn default_equals_new() {
        assert_eq!(ObsoleteException::default(), ObsoleteException::new());
    }
}

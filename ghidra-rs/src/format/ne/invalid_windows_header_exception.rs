use std::fmt;

/// Error type for encountering an invalid Windows NE (New Executable) header.
///
/// Mirrors Ghidra's `InvalidWindowsHeaderException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidWindowsHeaderException {
    message: String,
}

impl InvalidWindowsHeaderException {
    /// Constructs an `InvalidWindowsHeaderException` with the given detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for InvalidWindowsHeaderException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for InvalidWindowsHeaderException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message() {
        let e = InvalidWindowsHeaderException::new("invalid Windows NE header");
        assert_eq!(e.message(), "invalid Windows NE header");
    }

    #[test]
    fn display_equals_message() {
        let e = InvalidWindowsHeaderException::new("bad magic bytes");
        assert_eq!(e.to_string(), "bad magic bytes");
    }

    #[test]
    fn implements_error() {
        let e = InvalidWindowsHeaderException::new("test");
        let _: &dyn std::error::Error = &e;
    }
}

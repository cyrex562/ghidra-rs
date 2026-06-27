use std::fmt;

/// Error type for XCOFF parsing failures.
///
/// Mirrors Ghidra's `XCoffException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XCoffException {
    message: String,
}

impl XCoffException {
    /// Constructs an `XCoffException` with the given detail message.
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

impl fmt::Display for XCoffException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for XCoffException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message() {
        let e = XCoffException::new("invalid XCOFF header");
        assert_eq!(e.message(), "invalid XCOFF header");
    }

    #[test]
    fn display_equals_message() {
        let e = XCoffException::new("bad magic");
        assert_eq!(e.to_string(), "bad magic");
    }

    #[test]
    fn implements_error() {
        let e = XCoffException::new("test");
        let _: &dyn std::error::Error = &e;
    }
}

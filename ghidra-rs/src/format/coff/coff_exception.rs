use std::fmt;

/// Error type for COFF parsing failures.
///
/// Mirrors Ghidra's `CoffException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffException {
    message: String,
}

impl CoffException {
    /// Constructs a `CoffException` with the given detail message.
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

impl fmt::Display for CoffException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CoffException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message() {
        let e = CoffException::new("invalid COFF header");
        assert_eq!(e.message(), "invalid COFF header");
    }

    #[test]
    fn display_equals_message() {
        let e = CoffException::new("bad magic");
        assert_eq!(e.to_string(), "bad magic");
    }

    #[test]
    fn implements_error() {
        let e = CoffException::new("test");
        let _: &dyn std::error::Error = &e;
    }
}

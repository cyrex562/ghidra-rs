use std::fmt;

/// Error type for macOS-format parsing failures.
///
/// Mirrors Ghidra's `MacException`.
#[derive(Debug, Default)]
pub struct MacException {
    message: String,
}

impl MacException {
    /// Constructs a `MacException` with no message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs a `MacException` with the given detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MacException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MacException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_has_empty_message() {
        let e = MacException::new();
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn with_message_stores_message() {
        let e = MacException::with_message("bad mac format");
        assert_eq!(e.message(), "bad mac format");
    }

    #[test]
    fn display_equals_message() {
        let e = MacException::with_message("parse error");
        assert_eq!(e.to_string(), "parse error");
    }

    #[test]
    fn implements_error() {
        let e = MacException::with_message("test");
        let _: &dyn Error = &e;
    }

    #[test]
    fn default_is_empty() {
        let e: MacException = Default::default();
        assert_eq!(e.message(), "");
    }

    #[test]
    fn debug_impl_exists() {
        let e = MacException::with_message("debug");
        let s = format!("{:?}", e);
        assert!(s.contains("MacException"));
    }
}

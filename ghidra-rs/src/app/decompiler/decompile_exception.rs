//! An exception from (or that has passed through) the decompiler process.

use std::fmt;
use thiserror::Error;

/// An exception from (or that has passed through) the decompiler process.
#[derive(Debug, Clone, Error)]
pub struct DecompileException {
    message: String,
}

impl DecompileException {
    /// Creates a new `DecompileException` with the given type tag and message.
    ///
    /// # Arguments
    /// * `type_name` - Short label identifying the exception source (e.g. `"LostConnection"`)
    /// * `msg` - Human-readable description of the error
    pub fn new(type_name: impl AsRef<str>, msg: impl AsRef<str>) -> Self {
        Self {
            message: format!("{}: {}", type_name.as_ref(), msg.as_ref()),
        }
    }

    /// Returns the combined type/message string.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DecompileException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecompileException: {}", self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_formats_message() {
        let exc = DecompileException::new("LostConnection", "pipe closed");
        assert_eq!(exc.message(), "LostConnection: pipe closed");
    }

    #[test]
    fn test_display_prefixes_type_name() {
        let exc = DecompileException::new("Timeout", "decompiler timed out");
        assert_eq!(exc.to_string(), "DecompileException: Timeout: decompiler timed out");
    }

    #[test]
    fn test_clone_preserves_message() {
        let exc = DecompileException::new("Fatal", "unrecoverable error");
        let cloned = exc.clone();
        assert_eq!(exc.message(), cloned.message());
    }

    #[test]
    fn test_is_std_error() {
        let exc = DecompileException::new("Test", "msg");
        let _: &dyn std::error::Error = &exc;
    }

    #[test]
    fn test_empty_type_and_msg() {
        let exc = DecompileException::new("", "");
        assert_eq!(exc.message(), ": ");
        assert_eq!(exc.to_string(), "DecompileException: : ");
    }
}

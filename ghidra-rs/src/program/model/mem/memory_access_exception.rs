use std::error::Error;
use std::fmt;

/// Error indicating that a memory access operation is not permitted.
///
/// This mirrors Ghidra's `MemoryAccessException`, which extends `UsrException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryAccessException {
    message: Option<String>,
}

impl MemoryAccessException {
    /// Constructs a memory access exception with no detail message.
    pub const fn default() -> Self {
        Self { message: None }
    }

    /// Constructs a memory access exception with a detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
        }
    }

    /// Returns the detail message, if one was supplied.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl Default for MemoryAccessException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for MemoryAccessException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(message) => f.write_str(message),
            None => f.write_str("memory access not permitted"),
        }
    }
}

impl Error for MemoryAccessException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_has_no_detail_message() {
        let error = MemoryAccessException::default();

        assert_eq!(error.message(), None);
        assert_eq!(error.to_string(), "memory access not permitted");
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = MemoryAccessException::new("write protected");

        assert_eq!(error.message(), Some("write protected"));
        assert_eq!(error.to_string(), "write protected");
    }

    #[test]
    fn implements_error_trait() {
        let error: Box<dyn Error> = Box::new(MemoryAccessException::new("read denied"));
        assert_eq!(error.to_string(), "read denied");
    }

    #[test]
    fn equality() {
        assert_eq!(
            MemoryAccessException::new("test"),
            MemoryAccessException::new("test")
        );
        assert_ne!(
            MemoryAccessException::new("a"),
            MemoryAccessException::new("b")
        );
        assert_eq!(
            MemoryAccessException::default(),
            MemoryAccessException::default()
        );
    }
}

use crate::util::exception::UsrException;
use std::fmt;

/// Error for overlapping memory blocks.
///
/// This mirrors Ghidra's `MemoryConflictException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryConflictException {
    message: Option<String>,
}

impl MemoryConflictException {
    /// Constructs a memory conflict exception with no detail message.
    pub const fn default() -> Self {
        Self { message: None }
    }

    /// Constructs a memory conflict exception with a detail message.
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

impl Default for MemoryConflictException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for MemoryConflictException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(message) => f.write_str(message),
            None => f.write_str("memory conflict"),
        }
    }
}

impl std::error::Error for MemoryConflictException {}

impl From<MemoryConflictException> for UsrException {
    fn from(value: MemoryConflictException) -> Self {
        Self(value.message.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_has_no_detail_message() {
        let error = MemoryConflictException::default();

        assert_eq!(error.message(), None);
        assert_eq!(error.to_string(), "memory conflict");
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = MemoryConflictException::new("blocks overlap");

        assert_eq!(error.message(), Some("blocks overlap"));
        assert_eq!(error.to_string(), "blocks overlap");
    }

    #[test]
    fn converts_to_user_exception() {
        let error: UsrException = MemoryConflictException::new("overlap").into();

        assert_eq!(error, UsrException("overlap".to_string()));
    }
}

use crate::program::model::mem::MemoryAccessException;
use std::error::Error;
use std::fmt;

/// Error for memory block-related problems.
///
/// This mirrors Ghidra's `MemoryBlockException`, which specializes
/// `MemoryAccessException`.
#[derive(Debug)]
pub struct MemoryBlockException {
    message: Option<String>,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl MemoryBlockException {
    /// Constructs a memory block exception with no detail message.
    pub const fn default() -> Self {
        Self {
            message: None,
            source: None,
        }
    }

    /// Constructs a memory block exception with a detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            source: None,
        }
    }

    /// Constructs a memory block exception with a detail message and source error.
    pub fn with_source(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: Some(message.into()),
            source: Some(Box::new(source)),
        }
    }

    /// Returns the detail message, if one was supplied.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl Default for MemoryBlockException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for MemoryBlockException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(message) => f.write_str(message),
            None => f.write_str("memory block error"),
        }
    }
}

impl Error for MemoryBlockException {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

impl From<MemoryBlockException> for MemoryAccessException {
    fn from(value: MemoryBlockException) -> Self {
        match value.message() {
            Some(msg) => MemoryAccessException::new(msg),
            None => MemoryAccessException::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn default_constructor_has_no_detail_message() {
        let error = MemoryBlockException::default();

        assert_eq!(error.message(), None);
        assert_eq!(error.to_string(), "memory block error");
        assert!(error.source().is_none());
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = MemoryBlockException::new("overlapping block");

        assert_eq!(error.message(), Some("overlapping block"));
        assert_eq!(error.to_string(), "overlapping block");
        assert!(error.source().is_none());
    }

    #[test]
    fn source_constructor_preserves_detail_message_and_cause() {
        let error =
            MemoryBlockException::with_source("block failure", io::Error::other("disk error"));

        assert_eq!(error.message(), Some("block failure"));
        assert_eq!(error.to_string(), "block failure");
        assert_eq!(error.source().unwrap().to_string(), "disk error");
    }

    #[test]
    fn converts_to_memory_access_exception() {
        let error: MemoryAccessException = MemoryBlockException::new("bad block").into();

        assert_eq!(error, MemoryAccessException::new("bad block"));
    }
}

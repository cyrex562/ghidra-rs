use std::fmt;

/// Error type for Go bootstrap-info parsing failures.
///
/// Mirrors Ghidra's `BootstrapInfoException`, which extends `IOException`.
#[derive(Debug)]
pub struct BootstrapInfoException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl BootstrapInfoException {
    /// Constructs a `BootstrapInfoException` with no message or cause.
    pub fn new() -> Self {
        Self {
            message: String::new(),
            source: None,
        }
    }

    /// Constructs a `BootstrapInfoException` with the given detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a `BootstrapInfoException` wrapping a cause with no additional message.
    pub fn from_cause(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            message: String::new(),
            source: Some(Box::new(cause)),
        }
    }

    /// Constructs a `BootstrapInfoException` with a detail message and a cause.
    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(cause)),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for BootstrapInfoException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for BootstrapInfoException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BootstrapInfoException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_has_empty_message_no_source() {
        let e = BootstrapInfoException::new();
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_message_stores_message() {
        let e = BootstrapInfoException::with_message("invalid Go bootstrap info");
        assert_eq!(e.message(), "invalid Go bootstrap info");
        assert_eq!(e.to_string(), "invalid Go bootstrap info");
        assert!(e.source().is_none());
    }

    #[test]
    fn from_cause_wraps_error() {
        let cause = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let e = BootstrapInfoException::from_cause(cause);
        assert_eq!(e.message(), "");
        assert!(e.source().is_some());
    }

    #[test]
    fn with_cause_stores_message_and_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data");
        let e = BootstrapInfoException::with_cause("read failed", cause);
        assert_eq!(e.message(), "read failed");
        assert!(e.source().is_some());
    }

    #[test]
    fn no_cause_has_no_source() {
        let e = BootstrapInfoException::with_message("parse error");
        assert!(e.source().is_none());
    }

    #[test]
    fn implements_error() {
        let e = BootstrapInfoException::with_message("test");
        let _: &dyn Error = &e;
    }

    #[test]
    fn default_trait_works() {
        let e = BootstrapInfoException::default();
        assert_eq!(e.message(), "");
    }
}

use std::fmt;

/// Error type for DWARF line-program parsing failures.
///
/// Mirrors Ghidra's `DWARFLineException`, which extends `IOException`.
#[derive(Debug)]
pub struct DWARFLineException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl DWARFLineException {
    /// Constructs a `DWARFLineException` with no message.
    pub fn new() -> Self {
        Self {
            message: String::new(),
            source: None,
        }
    }

    /// Constructs a `DWARFLineException` with the given detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a `DWARFLineException` wrapping a cause with no additional message.
    pub fn from_cause(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        let message = cause.to_string();
        Self {
            message,
            source: Some(Box::new(cause)),
        }
    }

    /// Constructs a `DWARFLineException` with a detail message and a cause.
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

impl Default for DWARFLineException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DWARFLineException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DWARFLineException {
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
    fn default_has_empty_message() {
        let e = DWARFLineException::new();
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn with_message_stores_message() {
        let e = DWARFLineException::with_message("invalid line program");
        assert_eq!(e.message(), "invalid line program");
        assert_eq!(e.to_string(), "invalid line program");
    }

    #[test]
    fn from_cause_uses_cause_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let e = DWARFLineException::from_cause(cause);
        assert!(!e.message().is_empty());
        assert!(e.source().is_some());
    }

    #[test]
    fn with_cause_stores_message_and_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let e = DWARFLineException::with_cause("read failed", cause);
        assert_eq!(e.message(), "read failed");
        assert!(e.source().is_some());
    }

    #[test]
    fn no_cause_has_no_source() {
        let e = DWARFLineException::with_message("bad opcode");
        assert!(e.source().is_none());
    }

    #[test]
    fn implements_error() {
        let e = DWARFLineException::with_message("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn default_trait_works() {
        let e = DWARFLineException::default();
        assert_eq!(e.message(), "");
    }
}

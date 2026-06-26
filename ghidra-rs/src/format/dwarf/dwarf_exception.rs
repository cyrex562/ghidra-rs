use std::fmt;

/// Error type for DWARF parsing failures.
///
/// Mirrors Ghidra's `DWARFException`, which extends `IOException`.
#[derive(Debug)]
pub struct DWARFException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl DWARFException {
    /// Constructs a `DWARFException` with no message.
    pub fn new() -> Self {
        Self {
            message: String::new(),
            source: None,
        }
    }

    /// Constructs a `DWARFException` with the given detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a `DWARFException` with a detail message and a cause.
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

impl Default for DWARFException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DWARFException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DWARFException {
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
        let e = DWARFException::new();
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn with_message_stores_message() {
        let e = DWARFException::with_message("invalid DWARF data");
        assert_eq!(e.message(), "invalid DWARF data");
        assert_eq!(e.to_string(), "invalid DWARF data");
    }

    #[test]
    fn with_cause_stores_message_and_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let e = DWARFException::with_cause("read failed", cause);
        assert_eq!(e.message(), "read failed");
        assert!(e.source().is_some());
    }

    #[test]
    fn no_cause_has_no_source() {
        let e = DWARFException::with_message("bad section");
        assert!(e.source().is_none());
    }

    #[test]
    fn implements_error() {
        let e = DWARFException::with_message("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn default_trait_works() {
        let e = DWARFException::default();
        assert_eq!(e.message(), "");
    }
}

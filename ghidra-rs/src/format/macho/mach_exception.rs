use std::fmt;

/// Error type for invalid Mach-O headers.
///
/// Mirrors Ghidra's `MachException`.
#[derive(Debug)]
pub struct MachException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl MachException {
    /// Constructs a `MachException` with the given detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a `MachException` wrapping an existing error as the cause.
    pub fn from_cause(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        let message = cause.to_string();
        Self {
            message,
            source: Some(Box::new(cause)),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MachException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MachException {
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
    fn new_stores_message() {
        let e = MachException::new("invalid Mach-O header");
        assert_eq!(e.message(), "invalid Mach-O header");
    }

    #[test]
    fn display_equals_message() {
        let e = MachException::new("bad magic");
        assert_eq!(e.to_string(), "bad magic");
    }

    #[test]
    fn new_has_no_source() {
        let e = MachException::new("no cause");
        assert!(e.source().is_none());
    }

    #[test]
    fn from_cause_wraps_error() {
        let cause = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated header");
        let e = MachException::from_cause(cause);
        assert_eq!(e.message(), "truncated header");
        assert_eq!(e.to_string(), "truncated header");
        let src = e.source().expect("should have a cause");
        assert_eq!(src.to_string(), "truncated header");
    }

    #[test]
    fn implements_error() {
        let e = MachException::new("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn debug_impl_exists() {
        let e = MachException::new("debug");
        let s = format!("{:?}", e);
        assert!(s.contains("MachException"));
    }
}

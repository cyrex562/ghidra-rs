use std::fmt;

/// An I/O error indicating that data being transmitted was invalid or malformed.
///
/// Mirrors `ghidra.app.util.bin.InvalidDataException`, which extends `java.io.IOException`.
/// Implements [`std::error::Error`] and converts into [`std::io::Error`] (kind `InvalidData`).
#[derive(Debug)]
pub struct InvalidDataException {
    message: Option<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl InvalidDataException {
    /// Creates an `InvalidDataException` with no message or cause.
    pub fn new() -> Self {
        Self { message: None, source: None }
    }

    /// Creates an `InvalidDataException` with the given message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self { message: Some(message.into()), source: None }
    }

    /// Creates an `InvalidDataException` wrapping the given cause.
    pub fn with_source(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self { message: None, source: Some(Box::new(cause)) }
    }

    /// Creates an `InvalidDataException` with both a message and a cause.
    pub fn with_message_and_source(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { message: Some(message.into()), source: Some(Box::new(cause)) }
    }
}

impl Default for InvalidDataException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for InvalidDataException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(msg) => write!(f, "{}", msg),
            None => write!(f, "invalid data"),
        }
    }
}

impl std::error::Error for InvalidDataException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl From<InvalidDataException> for std::io::Error {
    fn from(e: InvalidDataException) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io;

    #[derive(Debug)]
    struct DummyCause;
    impl fmt::Display for DummyCause {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "dummy cause")
        }
    }
    impl Error for DummyCause {}

    #[test]
    fn new_has_no_message_or_source() {
        let e = InvalidDataException::new();
        assert_eq!(e.to_string(), "invalid data");
        assert!(e.source().is_none());
    }

    #[test]
    fn default_equals_new() {
        let e = InvalidDataException::default();
        assert_eq!(e.to_string(), "invalid data");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_message_displays_message() {
        let e = InvalidDataException::with_message("bad format");
        assert_eq!(e.to_string(), "bad format");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_source_has_no_message_but_has_cause() {
        let e = InvalidDataException::with_source(DummyCause);
        assert_eq!(e.to_string(), "invalid data");
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "dummy cause");
    }

    #[test]
    fn with_message_and_source_has_both() {
        let e = InvalidDataException::with_message_and_source("bad checksum", DummyCause);
        assert_eq!(e.to_string(), "bad checksum");
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "dummy cause");
    }

    #[test]
    fn converts_to_io_error_invalid_data_kind() {
        let io_err: io::Error = InvalidDataException::with_message("corrupted").into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(io_err.to_string(), "corrupted");
    }

    #[test]
    fn converts_no_message_to_io_error() {
        let io_err: io::Error = InvalidDataException::new().into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
    }
}

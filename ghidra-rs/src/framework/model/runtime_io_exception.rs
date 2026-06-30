use std::fmt;
use std::io;

/// A [`RuntimeIOException`] wraps an [`io::Error`] as a runtime (unchecked) error,
/// mirroring Java's `RuntimeIOException extends RuntimeException`.
pub struct RuntimeIOException {
    cause: io::Error,
}

impl RuntimeIOException {
    /// Constructs a [`RuntimeIOException`] wrapping the given [`io::Error`].
    pub fn new(e: io::Error) -> Self {
        RuntimeIOException { cause: e }
    }

    /// Returns a reference to the underlying [`io::Error`].
    pub fn io_error(&self) -> &io::Error {
        &self.cause
    }
}

impl fmt::Display for RuntimeIOException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RuntimeIOException: {}", self.cause)
    }
}

impl fmt::Debug for RuntimeIOException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeIOException")
            .field("cause", &self.cause)
            .finish()
    }
}

impl std::error::Error for RuntimeIOException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

impl From<io::Error> for RuntimeIOException {
    fn from(e: io::Error) -> Self {
        RuntimeIOException::new(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_includes_cause() {
        let e = io::Error::new(io::ErrorKind::Other, "disk full");
        let ex = RuntimeIOException::new(e);
        let s = ex.to_string();
        assert!(s.starts_with("RuntimeIOException: "));
        assert!(s.contains("disk full"));
    }

    #[test]
    fn test_source_returns_io_error() {
        let e = io::Error::new(io::ErrorKind::Other, "bad read");
        let ex = RuntimeIOException::new(e);
        let src = std::error::Error::source(&ex).expect("source should be present");
        assert!(src.to_string().contains("bad read"));
    }

    #[test]
    fn test_io_error_accessor() {
        let e = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let ex = RuntimeIOException::new(e);
        assert_eq!(ex.io_error().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_debug_format() {
        let e = io::Error::new(io::ErrorKind::Other, "oops");
        let ex = RuntimeIOException::new(e);
        let s = format!("{:?}", ex);
        assert!(s.contains("RuntimeIOException"));
    }

    #[test]
    fn test_from_io_error() {
        let e = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let ex: RuntimeIOException = e.into();
        assert!(ex.to_string().contains("file missing"));
    }

    #[test]
    fn test_is_error() {
        let e = io::Error::new(io::ErrorKind::Other, "x");
        let ex = RuntimeIOException::new(e);
        let _: &dyn std::error::Error = &ex;
    }
}

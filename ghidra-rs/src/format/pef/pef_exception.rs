use std::error::Error;
use std::fmt;

/// An error type for encountering invalid PEF headers.
///
/// Mirrors Ghidra's `ghidra.app.util.bin.format.pef.PefException`.
#[derive(Debug)]
pub enum PefException {
    /// An error with a descriptive message.
    Message(String),
    /// An error wrapping an underlying cause.
    Cause(Box<dyn Error + Send + Sync>),
}

impl PefException {
    /// Constructs a new `PefException` with the specified detail message.
    pub fn new(message: impl Into<String>) -> Self {
        PefException::Message(message.into())
    }

    /// Constructs a new `PefException` wrapping an underlying cause.
    pub fn from_cause(cause: Box<dyn Error + Send + Sync>) -> Self {
        PefException::Cause(cause)
    }
}

impl fmt::Display for PefException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PefException::Message(msg) => write!(f, "{}", msg),
            PefException::Cause(cause) => write!(f, "{}", cause),
        }
    }
}

impl Error for PefException {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PefException::Message(_) => None,
            PefException::Cause(cause) => Some(cause.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_constructor_stores_message() {
        let e = PefException::new("invalid PEF header");
        assert_eq!(e.to_string(), "invalid PEF header");
    }

    #[test]
    fn message_constructor_from_string() {
        let msg = String::from("bad magic number");
        let e = PefException::new(msg);
        assert_eq!(e.to_string(), "bad magic number");
    }

    #[test]
    fn message_variant_has_no_source() {
        let e = PefException::new("some error");
        assert!(e.source().is_none());
    }

    #[test]
    fn cause_constructor_wraps_error() {
        let inner: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated"));
        let e = PefException::from_cause(inner);
        assert_eq!(e.to_string(), "truncated");
    }

    #[test]
    fn cause_variant_exposes_source() {
        let inner: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data"));
        let e = PefException::from_cause(inner);
        assert!(e.source().is_some());
    }

    #[test]
    fn debug_output_is_non_empty() {
        let e = PefException::new("debug test");
        assert!(!format!("{:?}", e).is_empty());
    }

    #[test]
    fn implements_error_trait() {
        fn takes_error(_: &dyn Error) {}
        let e = PefException::new("trait test");
        takes_error(&e);
    }
}

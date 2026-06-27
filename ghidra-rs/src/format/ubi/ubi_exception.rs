use std::error::Error;
use std::fmt;

/// An error type for encountering invalid UBI headers.
///
/// Mirrors Ghidra's `ghidra.app.util.bin.format.ubi.UbiException`.
#[derive(Debug)]
pub enum UbiException {
    /// An error with a descriptive message.
    Message(String),
    /// An error wrapping an underlying cause.
    Cause(Box<dyn Error + Send + Sync>),
}

impl UbiException {
    /// Constructs a new `UbiException` with the specified detail message.
    pub fn new(message: impl Into<String>) -> Self {
        UbiException::Message(message.into())
    }

    /// Constructs a new `UbiException` wrapping an underlying cause.
    pub fn from_cause(cause: Box<dyn Error + Send + Sync>) -> Self {
        UbiException::Cause(cause)
    }
}

impl fmt::Display for UbiException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UbiException::Message(msg) => write!(f, "{}", msg),
            UbiException::Cause(cause) => write!(f, "{}", cause),
        }
    }
}

impl Error for UbiException {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            UbiException::Message(_) => None,
            UbiException::Cause(cause) => Some(cause.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_constructor_stores_message() {
        let e = UbiException::new("invalid UBI header");
        assert_eq!(e.to_string(), "invalid UBI header");
    }

    #[test]
    fn message_constructor_from_string() {
        let msg = String::from("bad magic number");
        let e = UbiException::new(msg);
        assert_eq!(e.to_string(), "bad magic number");
    }

    #[test]
    fn message_variant_has_no_source() {
        let e = UbiException::new("some error");
        assert!(e.source().is_none());
    }

    #[test]
    fn cause_constructor_wraps_error() {
        let inner: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated"));
        let e = UbiException::from_cause(inner);
        assert_eq!(e.to_string(), "truncated");
    }

    #[test]
    fn cause_variant_exposes_source() {
        let inner: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data"));
        let e = UbiException::from_cause(inner);
        assert!(e.source().is_some());
    }

    #[test]
    fn debug_output_is_non_empty() {
        let e = UbiException::new("debug test");
        assert!(!format!("{:?}", e).is_empty());
    }

    #[test]
    fn implements_error_trait() {
        fn takes_error(_: &dyn Error) {}
        let e = UbiException::new("trait test");
        takes_error(&e);
    }
}

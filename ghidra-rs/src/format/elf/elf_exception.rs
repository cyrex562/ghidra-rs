//! Exception type for invalid ELF headers.
//!
//! Ported from `ghidra.app.util.bin.format.elf.ElfException`.

use std::error::Error;
use std::fmt;

/// An error type for encountering invalid ELF headers.
#[derive(Debug)]
pub enum ElfException {
    /// An error with a descriptive message.
    Message(String),
    /// An error wrapping another underlying error.
    Cause(Box<dyn Error + Send + Sync>),
}

impl ElfException {
    /// Constructs a new `ElfException` with the specified detail message.
    pub fn new(message: impl Into<String>) -> Self {
        ElfException::Message(message.into())
    }

    /// Constructs a new `ElfException` wrapping an underlying cause.
    pub fn from_cause(cause: Box<dyn Error + Send + Sync>) -> Self {
        ElfException::Cause(cause)
    }
}

impl fmt::Display for ElfException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfException::Message(msg) => write!(f, "{}", msg),
            ElfException::Cause(cause) => write!(f, "{}", cause),
        }
    }
}

impl Error for ElfException {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ElfException::Message(_) => None,
            ElfException::Cause(cause) => Some(cause.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn message_constructor_stores_message() {
        let e = ElfException::new("invalid ELF header");
        assert_eq!(e.to_string(), "invalid ELF header");
    }

    #[test]
    fn message_constructor_from_string() {
        let msg = String::from("bad magic number");
        let e = ElfException::new(msg);
        assert_eq!(e.to_string(), "bad magic number");
    }

    #[test]
    fn message_variant_has_no_source() {
        let e = ElfException::new("some error");
        assert!(e.source().is_none());
    }

    #[test]
    fn cause_constructor_wraps_error() {
        let inner: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated"));
        let e = ElfException::from_cause(inner);
        assert_eq!(e.to_string(), "truncated");
    }

    #[test]
    fn cause_variant_exposes_source() {
        let inner: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data"));
        let e = ElfException::from_cause(inner);
        assert!(e.source().is_some());
    }

    #[test]
    fn debug_output_is_non_empty() {
        let e = ElfException::new("debug test");
        assert!(!format!("{:?}", e).is_empty());
    }

    #[test]
    fn implements_error_trait() {
        fn takes_error(_: &dyn Error) {}
        let e = ElfException::new("trait test");
        takes_error(&e);
    }
}

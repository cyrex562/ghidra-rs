use crate::util::exception::UsrException;
use std::fmt;

/// Exception thrown when an illegal change to program context has been attempted.
///
/// Port of `ghidra.program.model.listing.ContextChangeException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextChangeException {
    message: String,
}

impl ContextChangeException {
    /// Constructs a context change exception with an empty message.
    pub fn empty() -> Self {
        Self {
            message: String::new(),
        }
    }

    /// Constructs a context change exception with a detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for ContextChangeException {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for ContextChangeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ContextChangeException {}

impl From<ContextChangeException> for UsrException {
    fn from(value: ContextChangeException) -> Self {
        if value.message.is_empty() {
            Self::empty()
        } else {
            Self::new(&value.message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_constructor_creates_empty_message() {
        let error = ContextChangeException::empty();

        assert_eq!(error.message(), "");
        assert_eq!(error.to_string(), "");
    }

    #[test]
    fn default_constructor_creates_empty_message() {
        let error = ContextChangeException::default();

        assert_eq!(error.message(), "");
        assert_eq!(error.to_string(), "");
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = ContextChangeException::new("illegal context change");

        assert_eq!(error.message(), "illegal context change");
        assert_eq!(error.to_string(), "illegal context change");
    }

    #[test]
    fn converts_to_user_exception_with_message() {
        let error: UsrException = ContextChangeException::new("context error").into();

        assert_eq!(error, UsrException::new("context error"));
    }

    #[test]
    fn converts_to_user_exception_empty() {
        let error: UsrException = ContextChangeException::empty().into();

        assert_eq!(error, UsrException::empty());
    }

    #[test]
    fn clone_is_independent() {
        let e = ContextChangeException::new("original");
        let c = e.clone();

        assert_eq!(c.message(), "original");
        assert_eq!(c.to_string(), "original");
    }

    #[test]
    fn equality() {
        let e1 = ContextChangeException::new("msg");
        let e2 = ContextChangeException::new("msg");
        let e3 = ContextChangeException::new("other");

        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn implements_error_trait() {
        let e = ContextChangeException::new("error");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn display_with_empty_message() {
        let e = ContextChangeException::empty();
        assert_eq!(format!("{}", e), "");
    }

    #[test]
    fn into_string_conversion() {
        let e = ContextChangeException::new("context failed");
        let s = e.to_string();
        assert_eq!(s, "context failed");
    }
}

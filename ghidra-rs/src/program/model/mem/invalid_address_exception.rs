use crate::util::exception::UsrException;
use std::fmt;

/// Error for invalid addresses due to improper format or missing target definition.
///
/// This mirrors Ghidra's `InvalidAddressException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAddressException {
    message: Option<String>,
}

impl InvalidAddressException {
    /// Constructs an invalid address exception with no detail message.
    pub const fn default() -> Self {
        Self { message: None }
    }

    /// Constructs an invalid address exception with a detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
        }
    }

    /// Returns the detail message, if one was supplied.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl Default for InvalidAddressException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for InvalidAddressException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(message) => f.write_str(message),
            None => f.write_str("invalid address"),
        }
    }
}

impl std::error::Error for InvalidAddressException {}

impl From<InvalidAddressException> for UsrException {
    fn from(value: InvalidAddressException) -> Self {
        Self(value.message.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_has_no_detail_message() {
        let error = InvalidAddressException::default();

        assert_eq!(error.message(), None);
        assert_eq!(error.to_string(), "invalid address");
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = InvalidAddressException::new("bad address format");

        assert_eq!(error.message(), Some("bad address format"));
        assert_eq!(error.to_string(), "bad address format");
    }

    #[test]
    fn converts_to_user_exception() {
        let error: UsrException = InvalidAddressException::new("missing address").into();

        assert_eq!(error, UsrException("missing address".to_string()));
    }
}

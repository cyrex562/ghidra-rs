use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when an address string cannot be parsed.
///
/// This mirrors Ghidra's `AddressFormatException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressFormatException {
    message: String,
}

impl AddressFormatException {
    /// Java-compatible default message.
    pub const DEFAULT_MESSAGE: &'static str = "Cannot parse string into address.";

    /// Constructs an address format exception with the Java default message.
    pub fn default() -> Self {
        Self::new(Self::DEFAULT_MESSAGE)
    }

    /// Constructs an address format exception with a detail message.
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

impl Default for AddressFormatException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for AddressFormatException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AddressFormatException {}

impl From<AddressFormatException> for UsrException {
    fn from(value: AddressFormatException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_uses_java_message() {
        let error = AddressFormatException::default();

        assert_eq!(error.message(), "Cannot parse string into address.");
        assert_eq!(error.to_string(), "Cannot parse string into address.");
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = AddressFormatException::new("bad address");

        assert_eq!(error.message(), "bad address");
        assert_eq!(error.to_string(), "bad address");
    }

    #[test]
    fn converts_to_user_exception() {
        let error: UsrException = AddressFormatException::new("bad").into();

        assert_eq!(error, UsrException("bad".to_string()));
    }
}

use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when adding or subtracting a displacement would leave the
/// address space.
///
/// This mirrors Ghidra's `AddressOverflowException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressOverflowException {
    message: String,
}

impl AddressOverflowException {
    /// Java-compatible default message.
    pub const DEFAULT_MESSAGE: &'static str =
        "Displacement would result in an illegal address value.";

    /// Constructs an address overflow exception with the Java default message.
    pub fn default() -> Self {
        Self::new(Self::DEFAULT_MESSAGE)
    }

    /// Constructs an address overflow exception with a detail message.
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

impl Default for AddressOverflowException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for AddressOverflowException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AddressOverflowException {}

impl From<AddressOverflowException> for UsrException {
    fn from(value: AddressOverflowException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_uses_java_message() {
        let error = AddressOverflowException::default();

        assert_eq!(
            error.message(),
            "Displacement would result in an illegal address value."
        );
        assert_eq!(
            error.to_string(),
            "Displacement would result in an illegal address value."
        );
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = AddressOverflowException::new("overflow");

        assert_eq!(error.message(), "overflow");
        assert_eq!(error.to_string(), "overflow");
    }

    #[test]
    fn converts_to_user_exception() {
        let error: UsrException = AddressOverflowException::new("overflow").into();

        assert_eq!(error, UsrException("overflow".to_string()));
    }
}

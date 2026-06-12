use std::fmt;

/// Error thrown when an address is used to address memory that does not exist.
///
/// This mirrors Ghidra's `AddressOutOfBoundsException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressOutOfBoundsException {
    message: String,
}

impl AddressOutOfBoundsException {
    /// Java-compatible default message.
    pub const DEFAULT_MESSAGE: &'static str = "Address not contained in memory.";

    /// Constructs an address out-of-bounds exception with the Java default
    /// message.
    pub fn default() -> Self {
        Self::new(Self::DEFAULT_MESSAGE)
    }

    /// Constructs an address out-of-bounds exception with a detail message.
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

impl Default for AddressOutOfBoundsException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for AddressOutOfBoundsException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AddressOutOfBoundsException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_uses_java_message() {
        let error = AddressOutOfBoundsException::default();

        assert_eq!(error.message(), "Address not contained in memory.");
        assert_eq!(error.to_string(), "Address not contained in memory.");
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = AddressOutOfBoundsException::new("outside memory");

        assert_eq!(error.message(), "outside memory");
        assert_eq!(error.to_string(), "outside memory");
    }
}

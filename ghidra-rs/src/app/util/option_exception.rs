//! Exception thrown if there was a problem accessing an Option, or if an informational message
//! is to be conveyed.

use std::fmt;
use thiserror::Error;

/// Exception thrown if there was a problem accessing an Option, or if an informational message
/// is to be conveyed.
#[derive(Debug, Clone, Error)]
pub struct OptionException {
    message: String,
    is_info: bool,
}

impl OptionException {
    /// Constructs a new OptionException.
    ///
    /// # Arguments
    /// * `message` - The reason for the exception
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            is_info: false,
        }
    }

    /// Constructs a new OptionException that may be an informational message.
    ///
    /// # Arguments
    /// * `message` - The message to display
    /// * `is_info` - If true, the message is informational rather than an error
    pub fn with_info(message: impl Into<String>, is_info: bool) -> Self {
        Self {
            message: message.into(),
            is_info,
        }
    }

    /// Returns whether the message associated with this exception is informational.
    pub fn is_info_message(&self) -> bool {
        self.is_info
    }
}

impl fmt::Display for OptionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let exc = OptionException::new("test message");
        assert_eq!(exc.to_string(), "test message");
        assert!(!exc.is_info_message());
    }

    #[test]
    fn test_with_info_false() {
        let exc = OptionException::with_info("test message", false);
        assert_eq!(exc.to_string(), "test message");
        assert!(!exc.is_info_message());
    }

    #[test]
    fn test_with_info_true() {
        let exc = OptionException::with_info("informational message", true);
        assert_eq!(exc.to_string(), "informational message");
        assert!(exc.is_info_message());
    }

    #[test]
    fn test_is_info_message_default_false() {
        let exc = OptionException::new("message");
        assert!(!exc.is_info_message());
    }

    #[test]
    fn test_clone() {
        let original = OptionException::with_info("test", true);
        let cloned = original.clone();
        assert_eq!(original.to_string(), cloned.to_string());
        assert_eq!(original.is_info_message(), cloned.is_info_message());
    }

    #[test]
    fn test_string_conversion() {
        let exc = OptionException::new("error occurred");
        assert_eq!(exc.to_string(), "error occurred");
    }

    #[test]
    fn test_message_with_special_chars() {
        let exc = OptionException::new("Error: \n\t special chars!");
        assert_eq!(exc.to_string(), "Error: \n\t special chars!");
    }
}

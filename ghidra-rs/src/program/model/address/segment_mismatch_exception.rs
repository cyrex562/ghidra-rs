use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when operations require matching address segments.
///
/// This mirrors Ghidra's `SegmentMismatchException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentMismatchException {
    message: String,
}

impl SegmentMismatchException {
    /// Java-compatible default message.
    pub const DEFAULT_MESSAGE: &'static str = "The segments of the addresses do not match.";

    /// Constructs a segment mismatch exception with the Java default message.
    pub fn default() -> Self {
        Self::new(Self::DEFAULT_MESSAGE)
    }

    /// Constructs a segment mismatch exception with a detail message.
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

impl Default for SegmentMismatchException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for SegmentMismatchException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SegmentMismatchException {}

impl From<SegmentMismatchException> for UsrException {
    fn from(value: SegmentMismatchException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_uses_java_message() {
        let error = SegmentMismatchException::default();

        assert_eq!(
            error.message(),
            "The segments of the addresses do not match."
        );
        assert_eq!(
            error.to_string(),
            "The segments of the addresses do not match."
        );
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = SegmentMismatchException::new("wrong segment");

        assert_eq!(error.message(), "wrong segment");
        assert_eq!(error.to_string(), "wrong segment");
    }

    #[test]
    fn converts_to_user_exception() {
        let error: UsrException = SegmentMismatchException::new("segment").into();

        assert_eq!(error, UsrException("segment".to_string()));
    }
}

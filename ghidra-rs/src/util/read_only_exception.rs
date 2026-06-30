use thiserror::Error;

/// Error thrown if a method attempts to change an object that is marked as read-only.
///
/// Port of `ghidra.util.ReadOnlyException`.
#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct ReadOnlyException(pub String);

impl ReadOnlyException {
    pub const DEFAULT_MESSAGE: &'static str = "Object is read-only.";

    /// Creates a `ReadOnlyException` with a custom message.
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

impl Default for ReadOnlyException {
    fn default() -> Self {
        Self(Self::DEFAULT_MESSAGE.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_message() {
        let e = ReadOnlyException::default();
        assert_eq!(e.to_string(), ReadOnlyException::DEFAULT_MESSAGE);
    }

    #[test]
    fn custom_message() {
        let e = ReadOnlyException::new("cannot modify frozen object");
        assert_eq!(e.to_string(), "cannot modify frozen object");
    }

    #[test]
    fn equality() {
        assert_eq!(
            ReadOnlyException::default(),
            ReadOnlyException::new(ReadOnlyException::DEFAULT_MESSAGE)
        );
        assert_ne!(
            ReadOnlyException::default(),
            ReadOnlyException::new("other")
        );
    }

    #[test]
    fn debug_contains_message() {
        let e = ReadOnlyException::default();
        assert!(format!("{:?}", e).contains("Object is read-only."));
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &ReadOnlyException::default();
        assert_eq!(e.to_string(), ReadOnlyException::DEFAULT_MESSAGE);
    }
}

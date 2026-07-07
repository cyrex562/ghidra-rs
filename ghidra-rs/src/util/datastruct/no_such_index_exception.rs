use std::fmt;

use super::super::exception::UsrException;

/// Exception thrown if a requested index does not exist.
///
/// Port of `ghidra.util.datastruct.NoSuchIndexException`.
#[derive(Debug, Clone, PartialEq)]
pub struct NoSuchIndexException {
    message: String,
}

impl NoSuchIndexException {
    pub const DEFAULT_MESSAGE: &'static str = "Index does not exist.";

    /// Creates a `NoSuchIndexException` with the default message.
    pub fn new() -> Self {
        Self { message: Self::DEFAULT_MESSAGE.to_string() }
    }

    /// Creates a `NoSuchIndexException` with a custom message.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

impl Default for NoSuchIndexException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for NoSuchIndexException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for NoSuchIndexException {}

impl From<NoSuchIndexException> for UsrException {
    fn from(e: NoSuchIndexException) -> Self {
        UsrException::new(&e.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_message() {
        let e = NoSuchIndexException::new();
        assert_eq!(e.to_string(), NoSuchIndexException::DEFAULT_MESSAGE);
    }

    #[test]
    fn default_trait_matches_new() {
        assert_eq!(NoSuchIndexException::default(), NoSuchIndexException::new());
    }

    #[test]
    fn custom_message() {
        let e = NoSuchIndexException::with_message("index 42 not found");
        assert_eq!(e.to_string(), "index 42 not found");
    }

    #[test]
    fn equality() {
        assert_eq!(NoSuchIndexException::new(), NoSuchIndexException::new());
        assert_eq!(
            NoSuchIndexException::with_message("msg"),
            NoSuchIndexException::with_message("msg")
        );
        assert_ne!(NoSuchIndexException::new(), NoSuchIndexException::with_message("custom"));
        assert_ne!(
            NoSuchIndexException::with_message("a"),
            NoSuchIndexException::with_message("b")
        );
    }

    #[test]
    fn display_shows_message() {
        let e = NoSuchIndexException::with_message("no such index");
        assert_eq!(format!("{}", e), "no such index");
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &NoSuchIndexException::new();
        assert_eq!(e.to_string(), NoSuchIndexException::DEFAULT_MESSAGE);
        assert!(e.source().is_none());
    }

    #[test]
    fn clone_is_equal() {
        let e = NoSuchIndexException::with_message("clone me");
        assert_eq!(e.clone(), e);
    }

    #[test]
    fn into_usr_exception() {
        let exc = NoSuchIndexException::with_message("test msg");
        let usr_exc: UsrException = exc.into();
        assert_eq!(usr_exc.to_string(), "test msg");
    }

    #[test]
    fn debug_format() {
        let e = NoSuchIndexException::with_message("debug test");
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("NoSuchIndexException"));
    }
}

use crate::util::exception::UsrException;
use std::fmt;

/// Exception thrown when a fragment or child is added to a module and that fragment or module
/// is already a child.
///
/// Port of `ghidra.program.model.listing.DuplicateGroupException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateGroupException {
    message: String,
}

impl DuplicateGroupException {
    /// Java-compatible default message.
    pub const DEFAULT_MESSAGE: &'static str = "The fragment or module you are adding is already there.";

    /// Constructs a duplicate group exception with the Java default message.
    pub fn default() -> Self {
        Self::new(Self::DEFAULT_MESSAGE)
    }

    /// Constructs a duplicate group exception with a detail message.
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

impl Default for DuplicateGroupException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for DuplicateGroupException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DuplicateGroupException {}

impl From<DuplicateGroupException> for UsrException {
    fn from(value: DuplicateGroupException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_uses_java_message() {
        let error = DuplicateGroupException::default();

        assert_eq!(error.message(), "The fragment or module you are adding is already there.");
        assert_eq!(error.to_string(), "The fragment or module you are adding is already there.");
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = DuplicateGroupException::new("duplicate child");

        assert_eq!(error.message(), "duplicate child");
        assert_eq!(error.to_string(), "duplicate child");
    }

    #[test]
    fn converts_to_user_exception() {
        let error: UsrException =
            DuplicateGroupException::new("module is already a child").into();

        assert_eq!(error, UsrException("module is already a child".to_string()));
    }

    #[test]
    fn default_converts_to_user_exception() {
        let error: UsrException = DuplicateGroupException::default().into();

        assert_eq!(error, UsrException("The fragment or module you are adding is already there.".to_string()));
    }

    #[test]
    fn clone_is_independent() {
        let e = DuplicateGroupException::new("original");
        let c = e.clone();

        assert_eq!(c.message(), "original");
        assert_eq!(c.to_string(), "original");
    }

    #[test]
    fn equality() {
        let e1 = DuplicateGroupException::new("msg");
        let e2 = DuplicateGroupException::new("msg");
        let e3 = DuplicateGroupException::new("other");

        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn implements_error_trait() {
        let e = DuplicateGroupException::default();
        let _: &dyn std::error::Error = &e;
    }
}

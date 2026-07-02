use crate::util::exception::UsrException;
use std::fmt;

/// Exception thrown when a code unit cannot be created.
///
/// Port of `ghidra.program.model.util.CodeUnitInsertionException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnitInsertionException {
    message: String,
}

impl CodeUnitInsertionException {
    /// Constructs a new `CodeUnitInsertionException` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CodeUnitInsertionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CodeUnitInsertionException {}

impl From<CodeUnitInsertionException> for UsrException {
    fn from(value: CodeUnitInsertionException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_message() {
        let e = CodeUnitInsertionException::new("Cannot insert code unit at this location");
        assert_eq!(
            e.message(),
            "Cannot insert code unit at this location"
        );
        assert_eq!(
            e.to_string(),
            "Cannot insert code unit at this location"
        );
    }

    #[test]
    fn message_from_string_literal() {
        let e = CodeUnitInsertionException::new("Invalid insertion point");
        assert_eq!(e.message(), "Invalid insertion point");
    }

    #[test]
    fn implements_error() {
        let e = CodeUnitInsertionException::new("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn equality() {
        let e1 = CodeUnitInsertionException::new("same");
        let e2 = CodeUnitInsertionException::new("same");
        let e3 = CodeUnitInsertionException::new("different");

        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn clone() {
        let e = CodeUnitInsertionException::new("original");
        let cloned = e.clone();

        assert_eq!(e, cloned);
        assert_eq!(cloned.message(), "original");
    }

    #[test]
    fn converts_to_user_exception() {
        let e = CodeUnitInsertionException::new("Cannot insert");
        let user_exc: UsrException = e.into();

        assert_eq!(user_exc, UsrException("Cannot insert".to_string()));
    }

    #[test]
    fn empty_message() {
        let e = CodeUnitInsertionException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

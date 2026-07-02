use crate::util::exception::UsrException;
use std::fmt;

/// An exception for when a script provider cannot create a script instance.
///
/// Port of `ghidra.app.script.GhidraScriptLoadException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhidraScriptLoadException {
    message: String,
}

impl GhidraScriptLoadException {
    /// Constructs an exception with a custom message and cause.
    ///
    /// Note: In Rust, the cause is not stored in the exception itself but can be handled
    /// via error context propagation or the `?` operator. The error message displayed
    /// to the user does not automatically include details from the cause.
    /// The client must provide details from the cause in the message as needed.
    pub fn with_cause(message: impl Into<String>, _cause: impl std::error::Error) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Constructs an exception with a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Constructs an exception with a cause.
    ///
    /// This copies the cause's error message into this exception's message.
    pub fn from_cause(cause: impl std::error::Error) -> Self {
        Self {
            message: cause.to_string(),
        }
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for GhidraScriptLoadException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for GhidraScriptLoadException {}

impl From<GhidraScriptLoadException> for UsrException {
    fn from(value: GhidraScriptLoadException) -> Self {
        UsrException::new(&value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_message_creates_exception() {
        let exc = GhidraScriptLoadException::new("script not found");
        assert_eq!(exc.message(), "script not found");
        assert_eq!(exc.to_string(), "script not found");
    }

    #[test]
    fn with_cause_stores_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let exc = GhidraScriptLoadException::with_cause("failed to load", cause);
        assert_eq!(exc.message(), "failed to load");
    }

    #[test]
    fn from_cause_extracts_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let exc = GhidraScriptLoadException::from_cause(cause);
        assert_eq!(exc.message(), "access denied");
    }

    #[test]
    fn converts_to_usr_exception() {
        let exc = GhidraScriptLoadException::new("load error");
        let usr_exc: UsrException = exc.into();
        assert_eq!(usr_exc.0, "load error");
    }

    #[test]
    fn empty_message_is_valid() {
        let exc = GhidraScriptLoadException::new("");
        assert_eq!(exc.message(), "");
    }

    #[test]
    fn display_shows_message() {
        let exc = GhidraScriptLoadException::new("provider error");
        assert_eq!(format!("{}", exc), "provider error");
    }

    #[test]
    fn clone_preserves_message() {
        let exc = GhidraScriptLoadException::new("original");
        let cloned = exc.clone();
        assert_eq!(exc, cloned);
    }

    #[test]
    fn equality_works() {
        let exc1 = GhidraScriptLoadException::new("same");
        let exc2 = GhidraScriptLoadException::new("same");
        let exc3 = GhidraScriptLoadException::new("different");
        assert_eq!(exc1, exc2);
        assert_ne!(exc1, exc3);
    }
}

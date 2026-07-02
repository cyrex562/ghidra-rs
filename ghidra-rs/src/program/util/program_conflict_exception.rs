use crate::util::exception::UsrException;
use std::fmt;

/// Exception for incompatible programs when comparing programs for differences
/// or when merging program differences.
///
/// Port of `ghidra.program.util.ProgramConflictException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramConflictException {
    message: String,
}

impl ProgramConflictException {
    /// Constructs a new `ProgramConflictException` with no message.
    pub fn new() -> Self {
        Self {
            message: String::new(),
        }
    }

    /// Constructs a new `ProgramConflictException` with the given message.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for ProgramConflictException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProgramConflictException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProgramConflictException {}

impl From<ProgramConflictException> for UsrException {
    fn from(value: ProgramConflictException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor() {
        let e = ProgramConflictException::new();
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn with_message_constructor() {
        let e = ProgramConflictException::with_message("Incompatible programs");
        assert_eq!(e.message(), "Incompatible programs");
        assert_eq!(e.to_string(), "Incompatible programs");
    }

    #[test]
    fn default_trait() {
        let e = ProgramConflictException::default();
        assert_eq!(e.message(), "");
    }

    #[test]
    fn implements_error() {
        let e = ProgramConflictException::new();
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn equality() {
        assert_eq!(
            ProgramConflictException::new(),
            ProgramConflictException::default()
        );
        assert_ne!(
            ProgramConflictException::new(),
            ProgramConflictException::with_message("other")
        );
    }

    #[test]
    fn clone() {
        let e = ProgramConflictException::with_message("test message");
        assert_eq!(e.clone(), e);
    }

    #[test]
    fn converts_to_user_exception() {
        let e: UsrException = ProgramConflictException::with_message("conflict").into();
        assert_eq!(e, UsrException("conflict".to_string()));
    }

    #[test]
    fn converts_empty_to_user_exception() {
        let e: UsrException = ProgramConflictException::new().into();
        assert_eq!(e, UsrException(String::new()));
    }
}

use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when a register value operation fails.
///
/// This mirrors Ghidra's `ghidra.trace.model.memory.RegisterValueException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterValueException {
    message: String,
}

impl RegisterValueException {
    /// Constructs a register value exception with a detail message.
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

impl fmt::Display for RegisterValueException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RegisterValueException {}

impl From<RegisterValueException> for UsrException {
    fn from(value: RegisterValueException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message() {
        let e = RegisterValueException::new("bad register value");
        assert_eq!(e.message(), "bad register value");
    }

    #[test]
    fn display_matches_message() {
        let e = RegisterValueException::new("something went wrong");
        assert_eq!(e.to_string(), "something went wrong");
    }

    #[test]
    fn empty_message_is_accepted() {
        let e = RegisterValueException::new("");
        assert_eq!(e.message(), "");
    }

    #[test]
    fn converts_to_usr_exception() {
        let e: UsrException = RegisterValueException::new("oops").into();
        assert_eq!(e, UsrException("oops".to_string()));
    }

    #[test]
    fn implements_error_trait() {
        let e: Box<dyn std::error::Error> =
            Box::new(RegisterValueException::new("err"));
        assert_eq!(e.to_string(), "err");
    }
}

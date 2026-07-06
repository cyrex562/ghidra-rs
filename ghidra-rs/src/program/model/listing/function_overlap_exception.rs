use crate::util::exception::UsrException;
use std::fmt;

/// Exception thrown when a function creation or change would result in overlapping functions.
///
/// Port of `ghidra.program.model.listing.FunctionOverlapException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionOverlapException {
    message: String,
}

impl FunctionOverlapException {
    /// Java-compatible default message.
    pub const DEFAULT_MESSAGE: &'static str = "Function overlaps another.";

    /// Constructs a function overlap exception with the Java default message.
    pub fn default() -> Self {
        Self::new(Self::DEFAULT_MESSAGE)
    }

    /// Constructs a function overlap exception with a detail message.
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

impl Default for FunctionOverlapException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for FunctionOverlapException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FunctionOverlapException {}

impl From<FunctionOverlapException> for UsrException {
    fn from(value: FunctionOverlapException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_uses_java_message() {
        let error = FunctionOverlapException::default();

        assert_eq!(error.message(), "Function overlaps another.");
        assert_eq!(error.to_string(), "Function overlaps another.");
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = FunctionOverlapException::new("custom overlap message");

        assert_eq!(error.message(), "custom overlap message");
        assert_eq!(error.to_string(), "custom overlap message");
    }

    #[test]
    fn converts_to_user_exception() {
        let error: UsrException =
            FunctionOverlapException::new("function overlap detected").into();

        assert_eq!(error, UsrException("function overlap detected".to_string()));
    }

    #[test]
    fn default_converts_to_user_exception() {
        let error: UsrException = FunctionOverlapException::default().into();

        assert_eq!(error, UsrException("Function overlaps another.".to_string()));
    }

    #[test]
    fn clone_is_independent() {
        let e = FunctionOverlapException::new("original");
        let c = e.clone();

        assert_eq!(c.message(), "original");
        assert_eq!(c.to_string(), "original");
    }

    #[test]
    fn equality() {
        let e1 = FunctionOverlapException::new("msg");
        let e2 = FunctionOverlapException::new("msg");
        let e3 = FunctionOverlapException::new("other");

        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn implements_error_trait() {
        let e = FunctionOverlapException::default();
        let _: &dyn std::error::Error = &e;
    }
}

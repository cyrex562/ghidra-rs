use crate::util::exception::UsrException;
use std::fmt;

/// Exception thrown when a variable data-type exceeds storage constraints.
///
/// Port of `ghidra.program.model.listing.VariableSizeException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableSizeException {
    message: String,
    can_force: bool,
}

impl VariableSizeException {
    /// Constructs a variable size exception with the given message.
    /// The `can_force` value is set to false by default.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            can_force: false,
        }
    }

    /// Constructs a variable size exception with the given message and can_force flag.
    pub fn with_force(message: impl Into<String>, can_force: bool) -> Self {
        Self {
            message: message.into(),
            can_force,
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns true if the operation could be successful if forced.
    pub fn can_force(&self) -> bool {
        self.can_force
    }
}

impl fmt::Display for VariableSizeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VariableSizeException {}

impl From<VariableSizeException> for UsrException {
    fn from(value: VariableSizeException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_message_and_can_force_false() {
        let error = VariableSizeException::new("variable exceeds storage");

        assert_eq!(error.message(), "variable exceeds storage");
        assert!(!error.can_force());
        assert_eq!(error.to_string(), "variable exceeds storage");
    }

    #[test]
    fn with_force_sets_both_message_and_can_force() {
        let error = VariableSizeException::with_force("size limit exceeded", true);

        assert_eq!(error.message(), "size limit exceeded");
        assert!(error.can_force());
        assert_eq!(error.to_string(), "size limit exceeded");
    }

    #[test]
    fn with_force_false_sets_can_force_to_false() {
        let error = VariableSizeException::with_force("variable too large", false);

        assert_eq!(error.message(), "variable too large");
        assert!(!error.can_force());
    }

    #[test]
    fn converts_to_user_exception() {
        let error: UsrException =
            VariableSizeException::new("data exceeds limit").into();

        assert_eq!(error, UsrException("data exceeds limit".to_string()));
    }

    #[test]
    fn converts_with_force_to_user_exception() {
        let error: UsrException =
            VariableSizeException::with_force("exceeded", true).into();

        assert_eq!(error, UsrException("exceeded".to_string()));
    }

    #[test]
    fn clone_is_independent() {
        let e = VariableSizeException::with_force("original size", true);
        let c = e.clone();

        assert_eq!(c.message(), "original size");
        assert!(c.can_force());
        assert_eq!(c.to_string(), "original size");
    }

    #[test]
    fn equality_same_message_and_can_force() {
        let e1 = VariableSizeException::with_force("size error", true);
        let e2 = VariableSizeException::with_force("size error", true);

        assert_eq!(e1, e2);
    }

    #[test]
    fn inequality_different_message() {
        let e1 = VariableSizeException::new("msg1");
        let e2 = VariableSizeException::new("msg2");

        assert_ne!(e1, e2);
    }

    #[test]
    fn inequality_different_can_force() {
        let e1 = VariableSizeException::with_force("msg", true);
        let e2 = VariableSizeException::with_force("msg", false);

        assert_ne!(e1, e2);
    }

    #[test]
    fn implements_error_trait() {
        let e = VariableSizeException::new("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn display_format_matches_message() {
        let e = VariableSizeException::with_force("allocation failed", true);
        assert_eq!(format!("{}", e), "allocation failed");
    }

    #[test]
    fn debug_format() {
        let e = VariableSizeException::with_force("too big", true);
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("VariableSizeException"));
    }
}

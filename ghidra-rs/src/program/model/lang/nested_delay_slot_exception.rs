use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when a nested delay slotted instruction is encountered.
///
/// This mirrors Ghidra's `NestedDelaySlotException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedDelaySlotException;

impl NestedDelaySlotException {
    /// Constructs a `NestedDelaySlotException` with the fixed message.
    pub fn new() -> Self {
        Self
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        "Nested delay slotted instruction not permitted"
    }
}

impl Default for NestedDelaySlotException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for NestedDelaySlotException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for NestedDelaySlotException {}

impl From<NestedDelaySlotException> for UsrException {
    fn from(_value: NestedDelaySlotException) -> Self {
        Self("Nested delay slotted instruction not permitted".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_fixed_message() {
        let err = NestedDelaySlotException::new();
        assert_eq!(
            err.message(),
            "Nested delay slotted instruction not permitted"
        );
    }

    #[test]
    fn display_shows_fixed_message() {
        let err = NestedDelaySlotException::new();
        assert_eq!(
            err.to_string(),
            "Nested delay slotted instruction not permitted"
        );
    }

    #[test]
    fn default_same_as_new() {
        let a = NestedDelaySlotException::default();
        let b = NestedDelaySlotException::new();
        assert_eq!(a, b);
    }

    #[test]
    fn all_instances_are_equal() {
        let a = NestedDelaySlotException::new();
        let b = NestedDelaySlotException::new();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_is_equal() {
        let a = NestedDelaySlotException::new();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn converts_to_user_exception() {
        let err = NestedDelaySlotException::new();
        let usr: UsrException = err.into();
        assert_eq!(
            usr.to_string(),
            "Nested delay slotted instruction not permitted"
        );
    }

    #[test]
    fn implements_std_error() {
        let err: &dyn std::error::Error = &NestedDelaySlotException::new();
        assert_eq!(
            err.to_string(),
            "Nested delay slotted instruction not permitted"
        );
    }
}

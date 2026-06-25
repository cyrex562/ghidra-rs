use std::fmt;

/// Error thrown when a specified name is reserved for system use.
///
/// This mirrors Ghidra's `ReservedNameException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedNameException {
    message: String,
}

impl ReservedNameException {
    /// Constructs a reserved name exception with a detail message.
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

impl fmt::Display for ReservedNameException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ReservedNameException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message() {
        let exc = ReservedNameException::new("system name");
        assert_eq!(exc.message(), "system name");
    }

    #[test]
    fn display_returns_message() {
        let exc = ReservedNameException::new("reserved");
        assert_eq!(exc.to_string(), "reserved");
    }

    #[test]
    fn display_on_error_trait() {
        let exc: Box<dyn std::error::Error> = Box::new(ReservedNameException::new("test"));
        assert_eq!(exc.to_string(), "test");
    }

    #[test]
    fn empty_message_is_accepted() {
        let exc = ReservedNameException::new("");
        assert_eq!(exc.message(), "");
    }

    #[test]
    fn equality_on_same_message() {
        let a = ReservedNameException::new("same");
        let b = ReservedNameException::new("same");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_on_different_messages() {
        let a = ReservedNameException::new("msg1");
        let b = ReservedNameException::new("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn accepts_owned_string() {
        let owned = String::from("owned message");
        let exc = ReservedNameException::new(owned);
        assert_eq!(exc.message(), "owned message");
    }

    #[test]
    fn clone_preserves_message() {
        let exc = ReservedNameException::new("original");
        let cloned = exc.clone();
        assert_eq!(cloned.message(), "original");
        assert_eq!(cloned, exc);
    }
}

use std::fmt;

/// Signals that an illegal access has been performed on a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalFieldAccessException {
    message: String,
}

impl IllegalFieldAccessException {
    /// Construct with the default message `"Illegal field access"`.
    pub fn new() -> Self {
        Self { message: "Illegal field access".to_string() }
    }

    /// Construct with a specific message.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

impl Default for IllegalFieldAccessException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for IllegalFieldAccessException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for IllegalFieldAccessException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_default_message() {
        let e = IllegalFieldAccessException::new();
        assert_eq!(e.to_string(), "Illegal field access");
    }

    #[test]
    fn test_custom_message() {
        let e = IllegalFieldAccessException::with_message("custom error");
        assert_eq!(e.to_string(), "custom error");
    }

    #[test]
    fn test_default_trait() {
        let e = IllegalFieldAccessException::default();
        assert_eq!(e.to_string(), "Illegal field access");
    }

    #[test]
    fn test_debug() {
        let e = IllegalFieldAccessException::new();
        assert!(format!("{:?}", e).contains("IllegalFieldAccessException"));
    }

    #[test]
    fn test_implements_error() {
        let e = IllegalFieldAccessException::new();
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_clone_and_eq() {
        let e1 = IllegalFieldAccessException::new();
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_custom_messages_differ() {
        let e1 = IllegalFieldAccessException::with_message("a");
        let e2 = IllegalFieldAccessException::with_message("b");
        assert_ne!(e1, e2);
    }
}

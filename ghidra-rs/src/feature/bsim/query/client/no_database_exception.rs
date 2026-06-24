use std::fmt;

/// Error indicating that no BSim database is available or configured.
///
/// Mirrors `ghidra.features.bsim.query.client.NoDatabaseException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoDatabaseException {
    message: String,
}

impl NoDatabaseException {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for NoDatabaseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NoDatabaseException: {}", self.message)
    }
}

impl std::error::Error for NoDatabaseException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_message() {
        let e = NoDatabaseException::new("no database found");
        assert_eq!(e.message(), "no database found");
    }

    #[test]
    fn test_display() {
        let e = NoDatabaseException::new("connection refused");
        assert_eq!(e.to_string(), "NoDatabaseException: connection refused");
    }

    #[test]
    fn test_empty_message() {
        let e = NoDatabaseException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "NoDatabaseException: ");
    }

    #[test]
    fn test_implements_error_trait() {
        let e = NoDatabaseException::new("err");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_clone_and_eq() {
        let a = NoDatabaseException::new("missing");
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, NoDatabaseException::new("other"));
    }
}

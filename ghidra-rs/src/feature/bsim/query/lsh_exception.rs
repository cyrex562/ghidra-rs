use std::fmt;

/// Error type for BSim LSH (Locality Sensitive Hashing) operations.
///
/// Mirrors `ghidra.features.bsim.query.LSHException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LshException {
    message: String,
}

impl LshException {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LshException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LSHException: {}", self.message)
    }
}

impl std::error::Error for LshException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_message() {
        let e = LshException::new("something went wrong");
        assert_eq!(e.message(), "something went wrong");
    }

    #[test]
    fn test_display_matches_java_tostring() {
        let e = LshException::new("bad query");
        assert_eq!(e.to_string(), "LSHException: bad query");
    }

    #[test]
    fn test_empty_message() {
        let e = LshException::new("");
        assert_eq!(e.to_string(), "LSHException: ");
        assert_eq!(e.message(), "");
    }

    #[test]
    fn test_implements_error_trait() {
        let e = LshException::new("err");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_clone_and_eq() {
        let a = LshException::new("x");
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, LshException::new("y"));
    }
}

use std::fmt;

/// Error type for BSim Elastic backend operations.
///
/// Mirrors `ghidra.features.bsim.query.elastic.ElasticException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElasticException {
    message: String,
}

impl ElasticException {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ElasticException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ElasticException: {}", self.message)
    }
}

impl std::error::Error for ElasticException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_message() {
        let e = ElasticException::new("something went wrong");
        assert_eq!(e.message(), "something went wrong");
    }

    #[test]
    fn test_display_matches_java_tostring() {
        let e = ElasticException::new("bad query");
        assert_eq!(e.to_string(), "ElasticException: bad query");
    }

    #[test]
    fn test_empty_message() {
        let e = ElasticException::new("");
        assert_eq!(e.to_string(), "ElasticException: ");
        assert_eq!(e.message(), "");
    }

    #[test]
    fn test_implements_error_trait() {
        let e = ElasticException::new("err");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_clone_and_eq() {
        let a = ElasticException::new("x");
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, ElasticException::new("y"));
    }
}

use std::fmt;

/// Raised when an expression cannot be evaluated during stack analysis.
///
/// Java equivalent: `ghidra.app.plugin.core.debug.stack.EvaluationException`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationException {
    message: String,
}

impl EvaluationException {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for EvaluationException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EvaluationException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_new_stores_message() {
        let e = EvaluationException::new("cannot evaluate");
        assert_eq!(e.message(), "cannot evaluate");
    }

    #[test]
    fn test_display_shows_message() {
        let e = EvaluationException::new("bad expression");
        assert_eq!(e.to_string(), "bad expression");
    }

    #[test]
    fn test_is_error() {
        let e = EvaluationException::new("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_source_is_none() {
        let e = EvaluationException::new("err");
        assert!(e.source().is_none());
    }

    #[test]
    fn test_clone_and_eq() {
        let a = EvaluationException::new("msg");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_debug() {
        let e = EvaluationException::new("dbg");
        assert!(format!("{:?}", e).contains("dbg"));
    }

    #[test]
    fn test_empty_message() {
        let e = EvaluationException::new("");
        assert_eq!(e.to_string(), "");
    }
}

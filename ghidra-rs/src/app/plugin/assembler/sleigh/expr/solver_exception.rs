/// An exception that indicates no solution is possible.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.expr.SolverException`.
#[derive(Debug)]
pub struct SolverException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SolverException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(cause)),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for SolverException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SolverException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let e = SolverException::new("no solution");
        assert_eq!(e.message(), "no solution");
    }

    #[test]
    fn display_matches_message() {
        let e = SolverException::new("unsolvable");
        assert_eq!(e.to_string(), "unsolvable");
    }

    #[test]
    fn debug_contains_message() {
        let e = SolverException::new("oops");
        assert!(format!("{:?}", e).contains("oops"));
    }

    #[test]
    fn implements_error_trait() {
        let e = SolverException::new("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn source_is_none_without_cause() {
        let e = SolverException::new("no cause");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_cause_sets_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = SolverException::with_cause("wrapped", cause);
        assert_eq!(e.message(), "wrapped");
        assert!(e.source().is_some());
    }

    #[test]
    fn with_cause_source_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = SolverException::with_cause("outer", cause);
        assert_eq!(e.source().unwrap().to_string(), "root cause");
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned");
        let e = SolverException::new(msg);
        assert_eq!(e.message(), "owned");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = SolverException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

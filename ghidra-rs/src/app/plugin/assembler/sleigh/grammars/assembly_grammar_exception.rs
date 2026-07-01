/// An exception to identify errors associated with grammar construction.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammarException`.
#[derive(Debug)]
pub struct AssemblyGrammarException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl AssemblyGrammarException {
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

impl std::fmt::Display for AssemblyGrammarException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AssemblyGrammarException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

impl From<AssemblyGrammarException> for super::super::super::AssemblyException {
    fn from(err: AssemblyGrammarException) -> Self {
        super::super::super::AssemblyException::new(err.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let e = AssemblyGrammarException::new("grammar error");
        assert_eq!(e.message(), "grammar error");
    }

    #[test]
    fn display_matches_message() {
        let e = AssemblyGrammarException::new("invalid syntax");
        assert_eq!(e.to_string(), "invalid syntax");
    }

    #[test]
    fn debug_contains_message() {
        let e = AssemblyGrammarException::new("bad rule");
        assert!(format!("{:?}", e).contains("bad rule"));
    }

    #[test]
    fn implements_error_trait() {
        let e = AssemblyGrammarException::new("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn source_is_none_without_cause() {
        let e = AssemblyGrammarException::new("no cause");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_cause_sets_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = AssemblyGrammarException::with_cause("wrapped", cause);
        assert_eq!(e.message(), "wrapped");
        assert!(e.source().is_some());
    }

    #[test]
    fn with_cause_source_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = AssemblyGrammarException::with_cause("outer", cause);
        assert_eq!(e.source().unwrap().to_string(), "root cause");
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned");
        let e = AssemblyGrammarException::new(msg);
        assert_eq!(e.message(), "owned");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = AssemblyGrammarException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn converts_to_assembly_exception() {
        let grammar_err = AssemblyGrammarException::new("test message");
        let assembly_err: super::super::super::AssemblyException = grammar_err.into();
        assert_eq!(assembly_err.message(), "test message");
    }

    #[test]
    fn converts_with_cause_to_assembly_exception() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root");
        let grammar_err = AssemblyGrammarException::with_cause("wrapper", cause);
        let assembly_err: super::super::super::AssemblyException = grammar_err.into();
        assert_eq!(assembly_err.message(), "wrapper");
    }
}

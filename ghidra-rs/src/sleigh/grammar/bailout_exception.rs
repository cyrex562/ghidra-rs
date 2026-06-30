use std::error::Error;
use thiserror::Error as ThisError;

/// Runtime bail-out signal thrown by the Sleigh grammar parser.
///
/// Mirrors `ghidra.sleigh.grammar.BailoutException`, a `RuntimeException` subclass
/// used to abort parsing early without carrying a specific error message in all cases.
#[derive(Debug, ThisError)]
pub enum BailoutException {
    #[error("bailout")]
    Empty,
    #[error("{0}")]
    Message(String),
    #[error("bailout caused by: {0}")]
    Cause(#[source] Box<dyn Error + Send + Sync>),
    #[error("{message}")]
    MessageAndCause {
        message: String,
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
}

impl BailoutException {
    pub fn new() -> Self {
        Self::Empty
    }

    pub fn with_message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn with_cause<E: Error + Send + Sync + 'static>(cause: E) -> Self {
        Self::Cause(Box::new(cause))
    }

    pub fn with_message_and_cause<E: Error + Send + Sync + 'static>(
        message: impl Into<String>,
        cause: E,
    ) -> Self {
        Self::MessageAndCause {
            message: message.into(),
            source: Box::new(cause),
        }
    }
}

impl Default for BailoutException {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug)]
    struct DummyError(&'static str);

    impl fmt::Display for DummyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Error for DummyError {}

    #[test]
    fn empty_variant_display() {
        let e = BailoutException::new();
        assert_eq!(e.to_string(), "bailout");
    }

    #[test]
    fn message_variant_display() {
        let e = BailoutException::with_message("parser failed");
        assert_eq!(e.to_string(), "parser failed");
    }

    #[test]
    fn cause_variant_has_source() {
        let e = BailoutException::with_cause(DummyError("root cause"));
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "root cause");
    }

    #[test]
    fn message_and_cause_display_and_source() {
        let e = BailoutException::with_message_and_cause("abort", DummyError("inner"));
        assert_eq!(e.to_string(), "abort");
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "inner");
    }

    #[test]
    fn default_is_empty() {
        let e = BailoutException::default();
        assert_eq!(e.to_string(), "bailout");
    }
}

/// Runtime exception thrown during SLEIGH language processing.
///
/// Mirrors `ghidra.app.plugin.processors.sleigh.SleighException`.
#[derive(Debug)]
pub struct SleighException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SleighException {
    /// Constructs a `SleighException` with the given detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a `SleighException` with the given detail message and a cause.
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

impl std::fmt::Display for SleighException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SleighException {
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
    fn with_message_stores_message() {
        let e = SleighException::with_message("bad sleigh spec");
        assert_eq!(e.message(), "bad sleigh spec");
    }

    #[test]
    fn with_message_source_is_none() {
        let e = SleighException::with_message("no cause");
        assert!(e.source().is_none());
    }

    #[test]
    fn display_matches_message() {
        let e = SleighException::with_message("parse error");
        assert_eq!(e.to_string(), "parse error");
    }

    #[test]
    fn debug_is_implemented() {
        let e = SleighException::with_message("oops");
        assert!(format!("{:?}", e).contains("oops"));
    }

    #[test]
    fn implements_error_trait() {
        let e = SleighException::with_message("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn with_cause_stores_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root");
        let e = SleighException::with_cause("sleigh failed", cause);
        assert_eq!(e.message(), "sleigh failed");
    }

    #[test]
    fn with_cause_exposes_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = SleighException::with_cause("wrapper", cause);
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "root cause");
    }

    #[test]
    fn with_cause_display_matches_message_not_cause() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = SleighException::with_cause("sleigh error", cause);
        assert_eq!(e.to_string(), "sleigh error");
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned message");
        let e = SleighException::with_message(msg);
        assert_eq!(e.message(), "owned message");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = SleighException::with_message("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

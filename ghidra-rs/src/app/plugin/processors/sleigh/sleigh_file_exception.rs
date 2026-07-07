/// Exception thrown when error concerning a sleigh file is encountered.
///
/// Mirrors `ghidra.app.plugin.processors.sleigh.SleighFileException`.
#[derive(Debug)]
pub struct SleighFileException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SleighFileException {
    /// Constructs a `SleighFileException` with the given detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a `SleighFileException` with the given detail message and a cause.
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

impl std::fmt::Display for SleighFileException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SleighFileException {
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
        let e = SleighFileException::new("file not found");
        assert_eq!(e.message(), "file not found");
    }

    #[test]
    fn new_source_is_none() {
        let e = SleighFileException::new("bad file");
        assert!(e.source().is_none());
    }

    #[test]
    fn display_matches_message() {
        let e = SleighFileException::new("corrupt sleigh file");
        assert_eq!(e.to_string(), "corrupt sleigh file");
    }

    #[test]
    fn debug_is_implemented() {
        let e = SleighFileException::new("oops");
        assert!(format!("{:?}", e).contains("oops"));
    }

    #[test]
    fn implements_error_trait() {
        let e = SleighFileException::new("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn with_cause_stores_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "io error");
        let e = SleighFileException::with_cause("file error", cause);
        assert_eq!(e.message(), "file error");
    }

    #[test]
    fn with_cause_exposes_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = SleighFileException::with_cause("wrapper", cause);
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "root cause");
    }

    #[test]
    fn with_cause_display_matches_message_not_cause() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "io cause");
        let e = SleighFileException::with_cause("sleigh file error", cause);
        assert_eq!(e.to_string(), "sleigh file error");
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned message");
        let e = SleighFileException::new(msg);
        assert_eq!(e.message(), "owned message");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = SleighFileException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

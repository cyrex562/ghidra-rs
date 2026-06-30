/// Low-level error thrown by the p-code engine for unrecoverable conditions.
///
/// Corresponds to `ghidra.pcode.error.LowlevelError`.
#[derive(Debug)]
pub struct LowlevelError {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl LowlevelError {
    /// Constructs a `LowlevelError` with the given detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a `LowlevelError` with the given detail message and a cause.
    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(cause)),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for LowlevelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for LowlevelError {
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
        let e = LowlevelError::with_message("bad address");
        assert_eq!(e.message(), "bad address");
    }

    #[test]
    fn with_message_source_is_none() {
        let e = LowlevelError::with_message("no cause");
        assert!(e.source().is_none());
    }

    #[test]
    fn display_matches_message() {
        let e = LowlevelError::with_message("out of range");
        assert_eq!(e.to_string(), "out of range");
    }

    #[test]
    fn debug_is_implemented() {
        let e = LowlevelError::with_message("oops");
        assert!(format!("{:?}", e).contains("oops"));
    }

    #[test]
    fn implements_error_trait() {
        let e = LowlevelError::with_message("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn with_cause_stores_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root");
        let e = LowlevelError::with_cause("pcode failed", cause);
        assert_eq!(e.message(), "pcode failed");
    }

    #[test]
    fn with_cause_exposes_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = LowlevelError::with_cause("wrapper", cause);
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "root cause");
    }

    #[test]
    fn with_cause_display_matches_message_not_cause() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = LowlevelError::with_cause("lowlevel error", cause);
        assert_eq!(e.to_string(), "lowlevel error");
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned message");
        let e = LowlevelError::with_message(msg);
        assert_eq!(e.message(), "owned message");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = LowlevelError::with_message("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

use std::fmt;

/// Indicates failed or incomplete stack unwinding.
///
/// Java equivalent: `ghidra.app.plugin.core.debug.stack.UnwindException`
#[derive(Debug)]
pub struct UnwindException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl UnwindException {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), source: None }
    }

    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { message: message.into(), source: Some(Box::new(cause)) }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for UnwindException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for UnwindException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_new_stores_message() {
        let e = UnwindException::new("failed to unwind");
        assert_eq!(e.message(), "failed to unwind");
    }

    #[test]
    fn test_display_shows_message() {
        let e = UnwindException::new("stack corrupt");
        assert_eq!(e.to_string(), "stack corrupt");
    }

    #[test]
    fn test_no_cause_source_is_none() {
        let e = UnwindException::new("msg");
        assert!(e.source().is_none());
    }

    #[test]
    fn test_with_cause_source_is_some() {
        let cause = UnwindException::new("root cause");
        let e = UnwindException::with_cause("outer", cause);
        assert!(e.source().is_some());
    }

    #[test]
    fn test_with_cause_message() {
        let cause = UnwindException::new("inner");
        let e = UnwindException::with_cause("outer msg", cause);
        assert_eq!(e.message(), "outer msg");
        assert_eq!(e.to_string(), "outer msg");
    }

    #[test]
    fn test_is_error() {
        let e = UnwindException::new("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_debug() {
        let e = UnwindException::new("dbg");
        assert!(format!("{:?}", e).contains("dbg"));
    }

    #[test]
    fn test_empty_message() {
        let e = UnwindException::new("");
        assert_eq!(e.to_string(), "");
    }
}

use std::fmt;
use std::sync::Arc;

/// Exception when a custom codec is required.
#[derive(Debug, Clone)]
pub struct NoDefaultCodecException {
    message: Option<String>,
    cause: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl NoDefaultCodecException {
    pub fn new() -> Self {
        Self { message: None, cause: None }
    }

    pub fn with_message(message: impl Into<String>) -> Self {
        Self { message: Some(message.into()), cause: None }
    }

    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { message: Some(message.into()), cause: Some(Arc::new(cause)) }
    }
}

impl Default for NoDefaultCodecException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for NoDefaultCodecException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(msg) => write!(f, "{}", msg),
            None => write!(f, "NoDefaultCodecException"),
        }
    }
}

impl std::error::Error for NoDefaultCodecException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|c| c.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use super::*;

    #[derive(Debug)]
    struct SimpleError(String);
    impl fmt::Display for SimpleError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }
    impl std::error::Error for SimpleError {}

    #[test]
    fn default_constructor() {
        let e = NoDefaultCodecException::new();
        assert_eq!(e.to_string(), "NoDefaultCodecException");
        assert!(e.source().is_none());
    }

    #[test]
    fn message_constructor() {
        let e = NoDefaultCodecException::with_message("custom codec required");
        assert_eq!(e.to_string(), "custom codec required");
        assert!(e.source().is_none());
    }

    #[test]
    fn message_and_cause_constructor() {
        let cause = SimpleError("root cause".into());
        let e = NoDefaultCodecException::with_cause("custom codec required", cause);
        assert_eq!(e.to_string(), "custom codec required");
        assert_eq!(e.source().unwrap().to_string(), "root cause");
    }

    #[test]
    fn implements_error_trait() {
        let e: Box<dyn std::error::Error> =
            Box::new(NoDefaultCodecException::with_message("err"));
        assert_eq!(e.to_string(), "err");
    }

    #[test]
    fn default_trait() {
        let e = NoDefaultCodecException::default();
        assert_eq!(e.to_string(), "NoDefaultCodecException");
    }
}

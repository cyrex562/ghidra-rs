use std::fmt;

/// Runtime error for TraceRMI protocol operations.
///
/// Corresponds to `ghidra.debug.api.tracermi.TraceRmiError`.
#[derive(Debug)]
pub struct TraceRmiError {
    message: Option<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl TraceRmiError {
    /// Creates a new `TraceRmiError` with no message or cause.
    pub fn new() -> Self {
        Self { message: None, source: None }
    }

    /// Creates a new `TraceRmiError` wrapping a cause with no additional message.
    pub fn from_cause<E>(cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self { message: None, source: Some(Box::new(cause)) }
    }

    /// Creates a new `TraceRmiError` with the given detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self { message: Some(message.into()), source: None }
    }

    /// Creates a new `TraceRmiError` with the given detail message and cause.
    pub fn with_message_and_cause<E>(message: impl Into<String>, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self { message: Some(message.into()), source: Some(Box::new(cause)) }
    }

    /// Returns the detail message, if any.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl Default for TraceRmiError {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TraceRmiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(msg) => f.write_str(msg),
            None => match &self.source {
                Some(cause) => write!(f, "{}", cause),
                None => f.write_str("TraceRmiError"),
            },
        }
    }
}

impl std::error::Error for TraceRmiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_no_message_no_source() {
        let err = TraceRmiError::new();
        assert!(err.message().is_none());
        assert!(std::error::Error::source(&err).is_none());
        assert_eq!(err.to_string(), "TraceRmiError");
    }

    #[test]
    fn from_cause_wraps_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err = TraceRmiError::from_cause(cause);
        assert!(err.message().is_none());
        assert!(std::error::Error::source(&err).is_some());
        assert_eq!(err.to_string(), "not found");
    }

    #[test]
    fn with_message_stores_message() {
        let err = TraceRmiError::with_message("protocol error");
        assert_eq!(err.message(), Some("protocol error"));
        assert!(std::error::Error::source(&err).is_none());
        assert_eq!(err.to_string(), "protocol error");
    }

    #[test]
    fn with_message_and_cause_stores_both() {
        let cause = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe");
        let err = TraceRmiError::with_message_and_cause("send failed", cause);
        assert_eq!(err.message(), Some("send failed"));
        assert!(std::error::Error::source(&err).is_some());
        assert_eq!(err.to_string(), "send failed");
    }

    #[test]
    fn default_trait_matches_new() {
        let err: TraceRmiError = Default::default();
        assert!(err.message().is_none());
        assert_eq!(err.to_string(), "TraceRmiError");
    }

    #[test]
    fn debug_format_includes_type_name() {
        let err = TraceRmiError::with_message("oops");
        let debug = format!("{:?}", err);
        assert!(debug.contains("TraceRmiError"));
    }
}

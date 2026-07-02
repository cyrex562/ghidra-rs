use std::fmt;
use std::sync::Arc;

/// General-purpose exception for XML-related errors.
///
/// Port of `ghidra.xml.XmlException`.
#[derive(Debug, Clone)]
pub(crate) struct XmlException {
    message: String,
    cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
}

impl XmlException {
    /// Creates a new `XmlException` with no message or cause.
    pub(crate) fn new() -> Self {
        Self { message: String::new(), cause: None }
    }

    /// Creates a new `XmlException` with the given detail message.
    pub(crate) fn with_message(message: impl Into<String>) -> Self {
        Self { message: message.into(), cause: None }
    }

    /// Creates a new `XmlException` with a root cause.
    pub(crate) fn with_cause(
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { message: String::new(), cause: Some(Arc::new(cause)) }
    }

    /// Creates a new `XmlException` with a detail message and a root cause.
    pub(crate) fn with_message_and_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { message: message.into(), cause: Some(Arc::new(cause)) }
    }

    /// Returns the detail message.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl Default for XmlException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for XmlException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for XmlException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_creates_empty_exception() {
        let e = XmlException::new();
        assert_eq!(e.message(), "");
        assert!(e.source().is_none());
    }

    #[test]
    fn default_creates_empty_exception() {
        let e = XmlException::default();
        assert_eq!(e.message(), "");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_message_stores_message() {
        let e = XmlException::with_message("test error");
        assert_eq!(e.message(), "test error");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_message_display_shows_message() {
        let e = XmlException::with_message("bad xml");
        assert_eq!(e.to_string(), "bad xml");
    }

    #[test]
    fn with_cause_stores_cause() {
        let inner = XmlException::with_message("root cause");
        let outer = XmlException::with_cause(inner);
        assert_eq!(outer.message(), "");
        assert!(outer.source().is_some());
        assert_eq!(outer.source().unwrap().to_string(), "root cause");
    }

    #[test]
    fn with_message_and_cause_stores_both() {
        let inner = XmlException::with_message("root error");
        let outer = XmlException::with_message_and_cause("wrapper message", inner);
        assert_eq!(outer.message(), "wrapper message");
        assert!(outer.source().is_some());
        assert_eq!(outer.source().unwrap().to_string(), "root error");
    }

    #[test]
    fn clone_preserves_message() {
        let e1 = XmlException::with_message("original");
        let e2 = e1.clone();
        assert_eq!(e1.message(), e2.message());
    }

    #[test]
    fn clone_preserves_cause() {
        let inner = XmlException::with_message("cause");
        let outer = XmlException::with_message_and_cause("outer", inner);
        let cloned = outer.clone();
        assert!(cloned.source().is_some());
        assert_eq!(cloned.source().unwrap().to_string(), "cause");
    }

    #[test]
    fn debug_representation_includes_message() {
        let e = XmlException::with_message("test");
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn empty_message_roundtrips() {
        let e = XmlException::new();
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn exception_is_error() {
        let e = XmlException::with_message("test");
        let _err: &dyn std::error::Error = &e;
    }
}

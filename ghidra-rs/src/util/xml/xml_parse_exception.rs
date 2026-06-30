use std::fmt;
use std::sync::Arc;

/// Error thrown when there is a problem parsing XML.
///
/// Port of `ghidra.xml.XmlParseException`.
#[derive(Debug, Clone)]
pub(crate) struct XmlParseException {
    message: String,
    cause: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
}

impl XmlParseException {
    /// Creates a new `XmlParseException` with the given detail message.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), cause: None }
    }

    /// Creates a new `XmlParseException` with a detail message and a root cause.
    pub(crate) fn with_cause(
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

impl fmt::Display for XmlParseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for XmlParseException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shows_message() {
        let e = XmlParseException::new("unexpected token '<'");
        assert_eq!(e.to_string(), "unexpected token '<'");
    }

    #[test]
    fn message_accessor_matches_display() {
        let e = XmlParseException::new("malformed XML");
        assert_eq!(e.message(), e.to_string());
    }

    #[test]
    fn debug_contains_message() {
        let e = XmlParseException::new("bad xml");
        let s = format!("{:?}", e);
        assert!(s.contains("bad xml"));
    }

    #[test]
    fn clone_has_same_message() {
        let e = XmlParseException::new("xml error");
        let e2 = e.clone();
        assert_eq!(e.message(), e2.message());
    }

    #[test]
    fn no_source_without_cause() {
        use std::error::Error;
        let e = XmlParseException::new("lonely error");
        assert!(e.source().is_none());
    }

    #[test]
    fn source_present_with_cause() {
        use std::error::Error;
        let inner = XmlParseException::new("inner cause");
        let outer = XmlParseException::with_cause("outer error", inner);
        assert!(outer.source().is_some());
        assert_eq!(outer.source().unwrap().to_string(), "inner cause");
    }

    #[test]
    fn empty_message_roundtrips() {
        let e = XmlParseException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn clone_with_cause_preserves_source() {
        use std::error::Error;
        let inner = XmlParseException::new("root");
        let outer = XmlParseException::with_cause("wrapper", inner);
        let cloned = outer.clone();
        assert!(cloned.source().is_some());
        assert_eq!(cloned.source().unwrap().to_string(), "root");
    }
}

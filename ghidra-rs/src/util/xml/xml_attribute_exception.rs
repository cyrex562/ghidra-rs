use std::fmt;

/// Error thrown when an invalid or missing XML attribute is encountered.
///
/// Port of `ghidra.util.xml.XmlAttributeException`.
#[derive(Debug, Clone)]
pub(crate) struct XmlAttributeException {
    message: String,
}

impl XmlAttributeException {
    /// Creates a new `XmlAttributeException` with the given detail message.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the detail message.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for XmlAttributeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for XmlAttributeException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shows_message() {
        let e = XmlAttributeException::new("missing attribute 'foo'");
        assert_eq!(e.to_string(), "missing attribute 'foo'");
    }

    #[test]
    fn message_accessor_matches_display() {
        let e = XmlAttributeException::new("invalid value");
        assert_eq!(e.message(), e.to_string());
    }

    #[test]
    fn debug_contains_message() {
        let e = XmlAttributeException::new("bad attr");
        let s = format!("{:?}", e);
        assert!(s.contains("bad attr"));
    }

    #[test]
    fn clone_has_same_message() {
        let e = XmlAttributeException::new("attr error");
        let e2 = e.clone();
        assert_eq!(e.message(), e2.message());
    }

    #[test]
    fn no_source_cause() {
        use std::error::Error;
        let e = XmlAttributeException::new("lonely error");
        assert!(e.source().is_none());
    }

    #[test]
    fn empty_message_roundtrips() {
        let e = XmlAttributeException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

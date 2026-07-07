/// Exception thrown when an unsupported floating-point format is encountered.
///
/// Mirrors `ghidra.pcode.floatformat.UnsupportedFloatFormatException`.
#[derive(Debug)]
pub struct UnsupportedFloatFormatException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl UnsupportedFloatFormatException {
    /// Constructs an `UnsupportedFloatFormatException` with the given detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs an `UnsupportedFloatFormatException` for an unsupported float format size.
    pub fn with_format_size(format_size: i32) -> Self {
        Self::new(format!("Unsupported float format size: {}", format_size))
    }

    /// Constructs an `UnsupportedFloatFormatException` with the given detail message and a cause.
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

impl std::fmt::Display for UnsupportedFloatFormatException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for UnsupportedFloatFormatException {
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
        let e = UnsupportedFloatFormatException::new("unsupported format");
        assert_eq!(e.message(), "unsupported format");
    }

    #[test]
    fn new_source_is_none() {
        let e = UnsupportedFloatFormatException::new("bad format");
        assert!(e.source().is_none());
    }

    #[test]
    fn display_matches_message() {
        let e = UnsupportedFloatFormatException::new("unknown format");
        assert_eq!(e.to_string(), "unknown format");
    }

    #[test]
    fn debug_is_implemented() {
        let e = UnsupportedFloatFormatException::new("oops");
        assert!(format!("{:?}", e).contains("oops"));
    }

    #[test]
    fn implements_error_trait() {
        let e = UnsupportedFloatFormatException::new("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn with_format_size_constructs_message() {
        let e = UnsupportedFloatFormatException::with_format_size(7);
        assert_eq!(e.message(), "Unsupported float format size: 7");
    }

    #[test]
    fn with_format_size_zero() {
        let e = UnsupportedFloatFormatException::with_format_size(0);
        assert_eq!(e.message(), "Unsupported float format size: 0");
    }

    #[test]
    fn with_format_size_large_value() {
        let e = UnsupportedFloatFormatException::with_format_size(2147483647);
        assert_eq!(
            e.message(),
            "Unsupported float format size: 2147483647"
        );
    }

    #[test]
    fn with_cause_stores_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "io error");
        let e = UnsupportedFloatFormatException::with_cause("format error", cause);
        assert_eq!(e.message(), "format error");
    }

    #[test]
    fn with_cause_exposes_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = UnsupportedFloatFormatException::with_cause("wrapper", cause);
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "root cause");
    }

    #[test]
    fn with_cause_display_matches_message_not_cause() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "io cause");
        let e = UnsupportedFloatFormatException::with_cause("float format error", cause);
        assert_eq!(e.to_string(), "float format error");
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned message");
        let e = UnsupportedFloatFormatException::new(msg);
        assert_eq!(e.message(), "owned message");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = UnsupportedFloatFormatException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

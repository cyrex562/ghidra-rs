use std::fmt;

/// Exception raised when a PNG file fails format validation.
///
/// Mirrors `ghidra.file.formats.ios.png.PNGFormatException`.
#[derive(Debug)]
pub enum PngFormatException {
    /// No message or cause.
    Empty,
    /// Format error with an explanatory message.
    Message(String),
    /// Format error wrapping an underlying cause.
    Cause(Box<dyn std::error::Error + Send + Sync>),
}

impl PngFormatException {
    /// Constructs a `PngFormatException` with no message or cause.
    ///
    /// Mirrors `PNGFormatException()`.
    pub fn new() -> Self {
        Self::Empty
    }

    /// Constructs a `PngFormatException` with a descriptive message.
    ///
    /// Mirrors `PNGFormatException(String msg)`.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }

    /// Constructs a `PngFormatException` wrapping an underlying cause.
    ///
    /// Mirrors `PNGFormatException(Exception cause)`.
    pub fn with_cause(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Cause(Box::new(cause))
    }
}

impl Default for PngFormatException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PngFormatException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "PNG format exception"),
            Self::Message(msg) => write!(f, "{}", msg),
            Self::Cause(cause) => write!(f, "{}", cause),
        }
    }
}

impl std::error::Error for PngFormatException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cause(cause) => Some(cause.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_variant_has_no_source() {
        let e = PngFormatException::new();
        assert!(e.source().is_none());
    }

    #[test]
    fn empty_variant_display_is_nonempty() {
        let e = PngFormatException::new();
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn default_is_empty_variant() {
        let e = PngFormatException::default();
        assert!(matches!(e, PngFormatException::Empty));
    }

    #[test]
    fn message_variant_displays_message() {
        let e = PngFormatException::with_message("invalid PNG header");
        assert_eq!(e.to_string(), "invalid PNG header");
    }

    #[test]
    fn message_variant_empty_string() {
        let e = PngFormatException::with_message("");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn message_variant_has_no_source() {
        let e = PngFormatException::with_message("bad chunk");
        assert!(e.source().is_none());
    }

    #[test]
    fn cause_variant_exposes_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt data");
        let e = PngFormatException::with_cause(cause);
        assert!(e.source().is_some());
    }

    #[test]
    fn cause_variant_display_matches_cause() {
        let cause = std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt data");
        let e = PngFormatException::with_cause(cause);
        assert!(e.to_string().contains("corrupt data"));
    }

    #[test]
    fn implements_error_trait() {
        let e = PngFormatException::new();
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn debug_format_includes_type_name() {
        let e = PngFormatException::with_message("test");
        assert!(format!("{:?}", e).contains("Message"));
    }
}

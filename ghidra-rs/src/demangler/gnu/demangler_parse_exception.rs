use std::fmt;

/// Error signalling a problem parsing a demangled string.
///
/// Mirrors `ghidra.app.util.demangler.gnu.DemanglerParseException`, which is a
/// [`RuntimeException`](https://docs.oracle.com/en/java/docs/api/java.base/java/lang/RuntimeException.html)
/// with a single string-message constructor.
#[derive(Debug)]
pub struct DemanglerParseException {
    message: String,
}

impl DemanglerParseException {
    /// Creates a new [`DemanglerParseException`] with the given message.
    ///
    /// Mirrors `new DemanglerParseException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DemanglerParseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DemanglerParseException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let ex = DemanglerParseException::new("unexpected token");
        assert_eq!(ex.message(), "unexpected token");
        assert_eq!(ex.to_string(), "unexpected token");
    }

    #[test]
    fn display_matches_message() {
        let msg = "parse error at position 5";
        let ex = DemanglerParseException::new(msg);
        assert_eq!(format!("{}", ex), msg);
    }

    #[test]
    fn into_string_conversion() {
        let ex = DemanglerParseException::new(String::from("owned message"));
        assert_eq!(ex.message(), "owned message");
    }

    #[test]
    fn debug_is_available() {
        let ex = DemanglerParseException::new("debug test");
        let _ = format!("{:?}", ex);
    }

    #[test]
    fn implements_std_error() {
        fn takes_error(_: &dyn Error) {}
        let ex = DemanglerParseException::new("test");
        takes_error(&ex);
    }

    #[test]
    fn no_source_error() {
        let ex = DemanglerParseException::new("some error");
        assert!(ex.source().is_none());
    }

    #[test]
    fn empty_message() {
        let ex = DemanglerParseException::new("");
        assert_eq!(ex.message(), "");
        assert_eq!(ex.to_string(), "");
    }
}

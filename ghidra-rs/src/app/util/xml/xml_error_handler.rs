//! SAX-style XML error handler that re-raises parse exceptions to prevent
//! the parser from silently suppressing them.

use thiserror::Error;

/// A parse exception carrying line number and description, analogous to
/// `org.xml.sax.SAXParseException`.
#[derive(Debug, Clone)]
pub struct XmlParseException {
    line_number: u64,
    message: String,
}

impl XmlParseException {
    /// Creates a new `XmlParseException` with the given line number and message.
    pub fn new(line_number: u64, message: impl Into<String>) -> Self {
        Self {
            line_number,
            message: message.into(),
        }
    }

    /// Returns the line number where the parse error occurred.
    pub fn line_number(&self) -> u64 {
        self.line_number
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Error produced by [`XmlErrorHandler`], analogous to `org.xml.sax.SAXException`.
#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct XmlError {
    message: String,
}

impl XmlError {
    /// Creates a new `XmlError` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// An implementation of the basic SAX error-handler contract.
///
/// Each severity level (warning, error, fatal error) formats a message that
/// includes the line number from the parse exception and returns it as an
/// [`XmlError`], preventing the parser from suppressing parse exceptions.
///
/// Java peer: `ghidra.app.util.xml.XMLErrorHandler`
#[derive(Debug, Default, Clone)]
pub struct XmlErrorHandler;

impl XmlErrorHandler {
    /// Creates a new `XmlErrorHandler`.
    pub fn new() -> Self {
        Self
    }

    /// Handles a parse warning by converting it to an [`XmlError`].
    pub fn warning(&self, exception: &XmlParseException) -> Result<(), XmlError> {
        let msg = format!(
            "Warning on line {}: {}",
            exception.line_number(),
            exception.message()
        );
        Err(XmlError::new(msg))
    }

    /// Handles a parse error by converting it to an [`XmlError`].
    pub fn error(&self, exception: &XmlParseException) -> Result<(), XmlError> {
        let msg = format!(
            "Error on line {}: {}",
            exception.line_number(),
            exception.message()
        );
        Err(XmlError::new(msg))
    }

    /// Handles a fatal parse error by converting it to an [`XmlError`].
    pub fn fatal_error(&self, exception: &XmlParseException) -> Result<(), XmlError> {
        let msg = format!(
            "Fatal error on line {}: {}",
            exception.line_number(),
            exception.message()
        );
        Err(XmlError::new(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exception(line: u64, msg: &str) -> XmlParseException {
        XmlParseException::new(line, msg)
    }

    #[test]
    fn warning_formats_message_with_line() {
        let handler = XmlErrorHandler::new();
        let exc = make_exception(5, "unexpected token");
        let err = handler.warning(&exc).unwrap_err();
        assert_eq!(err.message(), "Warning on line 5: unexpected token");
        assert_eq!(err.to_string(), "Warning on line 5: unexpected token");
    }

    #[test]
    fn error_formats_message_with_line() {
        let handler = XmlErrorHandler::new();
        let exc = make_exception(42, "missing closing tag");
        let err = handler.error(&exc).unwrap_err();
        assert_eq!(err.message(), "Error on line 42: missing closing tag");
    }

    #[test]
    fn fatal_error_formats_message_with_line() {
        let handler = XmlErrorHandler::new();
        let exc = make_exception(1, "document is empty");
        let err = handler.fatal_error(&exc).unwrap_err();
        assert_eq!(err.message(), "Fatal error on line 1: document is empty");
    }

    #[test]
    fn all_methods_always_return_err() {
        let handler = XmlErrorHandler::new();
        let exc = make_exception(10, "msg");
        assert!(handler.warning(&exc).is_err());
        assert!(handler.error(&exc).is_err());
        assert!(handler.fatal_error(&exc).is_err());
    }

    #[test]
    fn parse_exception_accessors() {
        let exc = XmlParseException::new(99, "some error");
        assert_eq!(exc.line_number(), 99);
        assert_eq!(exc.message(), "some error");
    }

    #[test]
    fn default_and_clone() {
        let handler = XmlErrorHandler::default();
        let cloned = handler.clone();
        let exc = make_exception(3, "test");
        let err1 = handler.warning(&exc).unwrap_err();
        let err2 = cloned.warning(&exc).unwrap_err();
        assert_eq!(err1.message(), err2.message());
    }

    #[test]
    fn xml_error_clone() {
        let err = XmlError::new("some error");
        let cloned = err.clone();
        assert_eq!(err.message(), cloned.message());
    }

    #[test]
    fn line_number_zero() {
        let handler = XmlErrorHandler::new();
        let exc = make_exception(0, "start");
        let err = handler.error(&exc).unwrap_err();
        assert_eq!(err.message(), "Error on line 0: start");
    }
}

use std::error::Error;

/// Collects and formats errors that occur during version-tracking operations.
///
/// Corresponds to Java's `ErrorStatus` class. Provides methods to accumulate
/// exceptions and format them for display in UI or logs.
pub struct ErrorStatus {
    exceptions: Vec<Box<dyn Error + Send + Sync + 'static>>,
}

impl ErrorStatus {
    /// Creates a new `ErrorStatus` with no exceptions.
    pub fn new() -> Self {
        Self {
            exceptions: Vec::new(),
        }
    }

    /// Returns whether any exceptions have been recorded.
    fn has_errors(&self) -> bool {
        !self.exceptions.is_empty()
    }

    /// Formats all recorded exception messages as HTML.
    ///
    /// Each exception message is separated by an HTML line break (`<br>`).
    ///
    /// # Returns
    ///
    /// A string containing HTML markup with the format `<html>message<br>...`.
    pub fn print_message(&self) -> String {
        let mut builder = String::from("<html>");
        for exception in &self.exceptions {
            builder.push_str(&exception.to_string());
            builder.push_str("<br>");
        }
        builder
    }

    /// Formats all recorded exception messages as plain text for logging.
    ///
    /// Each exception message is followed by a newline.
    ///
    /// # Returns
    ///
    /// A string containing the exception messages, each followed by a newline.
    pub fn print_log_message(&self) -> String {
        let mut builder = String::new();
        for exception in &self.exceptions {
            builder.push_str(&exception.to_string());
            builder.push('\n');
        }
        builder
    }

    /// Adds an exception to the collection.
    ///
    /// # Arguments
    ///
    /// * `e` - An error that implements `Error + Send + Sync + 'static`.
    pub fn add_exception<E: Error + Send + Sync + 'static>(&mut self, e: E) {
        self.exceptions.push(Box::new(e));
    }

    /// Returns a reference to the collected exceptions.
    ///
    /// # Returns
    ///
    /// A slice of the exceptions stored in this `ErrorStatus`.
    pub fn get_exceptions(&self) -> &[Box<dyn Error + Send + Sync + 'static>] {
        &self.exceptions
    }
}

impl Default for ErrorStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug)]
    struct TestError(String);

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Error for TestError {}

    #[test]
    fn new_has_no_errors() {
        let status = ErrorStatus::new();
        assert!(!status.has_errors());
    }

    #[test]
    fn default_has_no_errors() {
        let status = ErrorStatus::default();
        assert!(!status.has_errors());
    }

    #[test]
    fn add_exception_records_error() {
        let mut status = ErrorStatus::new();
        status.add_exception(TestError("test error".to_string()));
        assert!(status.has_errors());
        assert_eq!(status.get_exceptions().len(), 1);
    }

    #[test]
    fn print_message_formats_as_html() {
        let mut status = ErrorStatus::new();
        status.add_exception(TestError("error one".to_string()));
        status.add_exception(TestError("error two".to_string()));

        let msg = status.print_message();
        assert_eq!(msg, "<html>error one<br>error two<br>");
    }

    #[test]
    fn print_message_empty_when_no_errors() {
        let status = ErrorStatus::new();
        let msg = status.print_message();
        assert_eq!(msg, "<html>");
    }

    #[test]
    fn print_log_message_formats_as_plain_text() {
        let mut status = ErrorStatus::new();
        status.add_exception(TestError("error one".to_string()));
        status.add_exception(TestError("error two".to_string()));

        let msg = status.print_log_message();
        assert_eq!(msg, "error one\nerror two\n");
    }

    #[test]
    fn print_log_message_empty_when_no_errors() {
        let status = ErrorStatus::new();
        let msg = status.print_log_message();
        assert!(msg.is_empty());
    }

    #[test]
    fn print_log_message_single_error_with_trailing_newline() {
        let mut status = ErrorStatus::new();
        status.add_exception(TestError("only error".to_string()));

        let msg = status.print_log_message();
        assert_eq!(msg, "only error\n");
    }

    #[test]
    fn get_exceptions_returns_empty_slice_initially() {
        let status = ErrorStatus::new();
        assert_eq!(status.get_exceptions().len(), 0);
    }

    #[test]
    fn get_exceptions_returns_all_added() {
        let mut status = ErrorStatus::new();
        status.add_exception(TestError("error 1".to_string()));
        status.add_exception(TestError("error 2".to_string()));
        status.add_exception(TestError("error 3".to_string()));

        assert_eq!(status.get_exceptions().len(), 3);
    }

    #[test]
    fn multiple_exceptions_preserved_in_order() {
        let mut status = ErrorStatus::new();
        status.add_exception(TestError("first".to_string()));
        status.add_exception(TestError("second".to_string()));
        status.add_exception(TestError("third".to_string()));

        let msg = status.print_message();
        assert!(msg.contains("first<br>"));
        assert!(msg.contains("second<br>"));
        assert!(msg.contains("third<br>"));
    }
}

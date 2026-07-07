use std::fmt::Display;

use crate::util::error_logger::ErrorLogger;

/// Minimal error logger that suppresses debug, info, and warn messages.
///
/// Only error-level messages are printed to stderr.
/// Port of `ghidra.features.bsim.query.MinimalErrorLogger`.
pub struct MinimalErrorLogger;

impl ErrorLogger for MinimalErrorLogger {
    fn trace(&self, _originator: &str, _message: &dyn Display) {}

    fn trace_with_error(
        &self,
        _originator: &str,
        _message: &dyn Display,
        _error: &dyn std::error::Error,
    ) {
    }

    fn debug(&self, _originator: &str, _message: &dyn Display) {}

    fn debug_with_error(
        &self,
        _originator: &str,
        _message: &dyn Display,
        _error: &dyn std::error::Error,
    ) {
    }

    fn info(&self, _originator: &str, _message: &dyn Display) {}

    fn info_with_error(
        &self,
        _originator: &str,
        _message: &dyn Display,
        _error: &dyn std::error::Error,
    ) {
    }

    fn warn(&self, _originator: &str, _message: &dyn Display) {}

    fn warn_with_error(
        &self,
        _originator: &str,
        _message: &dyn Display,
        _error: &dyn std::error::Error,
    ) {
    }

    fn error(&self, _originator: &str, message: &dyn Display) {
        eprintln!("{}", message);
    }

    fn error_with_error(
        &self,
        _originator: &str,
        message: &dyn Display,
        _error: &dyn std::error::Error,
    ) {
        eprintln!("{}", message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_prints_to_stderr() {
        let logger = MinimalErrorLogger;
        logger.error("TestOrigin", &"test error message");
    }

    #[test]
    fn test_error_with_error_prints_message_only() {
        let logger = MinimalErrorLogger;
        let err = std::io::Error::new(std::io::ErrorKind::Other, "underlying error");
        logger.error_with_error("TestOrigin", &"top level error", &err);
    }

    #[test]
    fn test_debug_is_suppressed() {
        let logger = MinimalErrorLogger;
        logger.debug("TestOrigin", &"debug message");
    }

    #[test]
    fn test_debug_with_error_is_suppressed() {
        let logger = MinimalErrorLogger;
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.debug_with_error("TestOrigin", &"debug with error", &err);
    }

    #[test]
    fn test_info_is_suppressed() {
        let logger = MinimalErrorLogger;
        logger.info("TestOrigin", &"info message");
    }

    #[test]
    fn test_info_with_error_is_suppressed() {
        let logger = MinimalErrorLogger;
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.info_with_error("TestOrigin", &"info with error", &err);
    }

    #[test]
    fn test_warn_is_suppressed() {
        let logger = MinimalErrorLogger;
        logger.warn("TestOrigin", &"warn message");
    }

    #[test]
    fn test_warn_with_error_is_suppressed() {
        let logger = MinimalErrorLogger;
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.warn_with_error("TestOrigin", &"warn with error", &err);
    }

    #[test]
    fn test_trace_is_suppressed() {
        let logger = MinimalErrorLogger;
        logger.trace("TestOrigin", &"trace message");
    }

    #[test]
    fn test_trace_with_error_is_suppressed() {
        let logger = MinimalErrorLogger;
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.trace_with_error("TestOrigin", &"trace with error", &err);
    }

    #[test]
    fn test_multiple_errors_all_printed() {
        let logger = MinimalErrorLogger;
        logger.error("Origin1", &"first error");
        logger.error("Origin2", &"second error");
        logger.error("Origin3", &"third error");
    }

    #[test]
    fn test_error_with_dynamic_message() {
        let logger = MinimalErrorLogger;
        let msg = String::from("dynamic error message");
        logger.error("TestOrigin", &msg);
    }

    #[test]
    fn test_error_with_format() {
        let logger = MinimalErrorLogger;
        logger.error("TestOrigin", &format!("error code: {}", 42));
    }
}

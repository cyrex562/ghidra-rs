//! Error logger backed by the `tracing` crate (this project's log4j equivalent).

use std::fmt::Display;

use crate::util::error_logger::ErrorLogger;

/// Port of `ghidra.framework.Log4jErrorLogger`.
///
/// The original dispatches to a log4j `Logger` resolved from the `originator`
/// (a `Class`, `Logger`, `String`, or `null`). In this port `originator` is
/// already a plain `&str`, so that resolution collapses to simply tagging
/// each event with it and delegating to `tracing`.
pub struct Log4jErrorLogger;

impl ErrorLogger for Log4jErrorLogger {
    fn trace(&self, originator: &str, message: &dyn Display) {
        tracing::trace!(originator = %originator, %message);
    }

    fn trace_with_error(
        &self,
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        tracing::trace!(originator = %originator, %message, error = %error);
    }

    fn debug(&self, originator: &str, message: &dyn Display) {
        tracing::debug!(originator = %originator, %message);
    }

    fn debug_with_error(
        &self,
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        tracing::debug!(originator = %originator, %message, error = %error);
    }

    fn info(&self, originator: &str, message: &dyn Display) {
        tracing::info!(originator = %originator, %message);
    }

    fn info_with_error(
        &self,
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        tracing::info!(originator = %originator, %message, error = %error);
    }

    fn warn(&self, originator: &str, message: &dyn Display) {
        tracing::warn!(originator = %originator, %message);
    }

    fn warn_with_error(
        &self,
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        tracing::warn!(originator = %originator, %message, error = %error);
    }

    fn error(&self, originator: &str, message: &dyn Display) {
        tracing::error!(originator = %originator, %message);
    }

    fn error_with_error(
        &self,
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        tracing::error!(originator = %originator, %message, error = %error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_logs_without_panicking() {
        let logger = Log4jErrorLogger;
        logger.trace("TestOrigin", &"trace message");
    }

    #[test]
    fn test_debug_logs_without_panicking() {
        let logger = Log4jErrorLogger;
        logger.debug("TestOrigin", &"debug message");
    }

    #[test]
    fn test_info_logs_without_panicking() {
        let logger = Log4jErrorLogger;
        logger.info("TestOrigin", &"info message");
    }

    #[test]
    fn test_warn_logs_without_panicking() {
        let logger = Log4jErrorLogger;
        logger.warn("TestOrigin", &"warn message");
    }

    #[test]
    fn test_error_logs_without_panicking() {
        let logger = Log4jErrorLogger;
        logger.error("TestOrigin", &"error message");
    }

    #[test]
    fn test_error_with_error_logs_without_panicking() {
        let logger = Log4jErrorLogger;
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.error_with_error("TestOrigin", &"error message", &err);
    }

    #[test]
    fn test_warn_with_error_logs_without_panicking() {
        let logger = Log4jErrorLogger;
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.warn_with_error("TestOrigin", &"warn message", &err);
    }

    #[test]
    fn test_info_with_error_logs_without_panicking() {
        let logger = Log4jErrorLogger;
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.info_with_error("TestOrigin", &"info message", &err);
    }

    #[test]
    fn test_debug_with_error_logs_without_panicking() {
        let logger = Log4jErrorLogger;
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.debug_with_error("TestOrigin", &"debug message", &err);
    }

    #[test]
    fn test_trace_with_error_logs_without_panicking() {
        let logger = Log4jErrorLogger;
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.trace_with_error("TestOrigin", &"trace message", &err);
    }
}

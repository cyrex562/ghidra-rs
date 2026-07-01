use std::fmt::Display;

pub trait ErrorLogger: Send + Sync {
    fn trace(&self, originator: &str, message: &dyn Display);
    fn trace_with_error(
        &self,
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    );

    fn debug(&self, originator: &str, message: &dyn Display);
    fn debug_with_error(
        &self,
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    );

    fn info(&self, originator: &str, message: &dyn Display);
    fn info_with_error(
        &self,
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    );

    fn warn(&self, originator: &str, message: &dyn Display);
    fn warn_with_error(
        &self,
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    );

    fn error(&self, originator: &str, message: &dyn Display);
    fn error_with_error(
        &self,
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    );
}

/// Default implementation of ErrorLogger that delegates to the tracing crate.
///
/// Port of `ghidra.util.DefaultErrorLogger`.
pub struct DefaultErrorLogger;

impl ErrorLogger for DefaultErrorLogger {
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
    use std::sync::{Arc, Mutex};

    struct MockErrorLogger {
        logs: Arc<Mutex<Vec<(String, String, bool)>>>,
    }

    impl MockErrorLogger {
        fn new() -> Self {
            MockErrorLogger {
                logs: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn log(&self, level: String, originator: String, message: String) {
            let mut logs = self.logs.lock().unwrap();
            logs.push((level, originator, message));
        }

        fn get_logs(&self) -> Vec<(String, String, String)> {
            self.logs.lock().unwrap().clone()
        }
    }

    impl ErrorLogger for MockErrorLogger {
        fn trace(&self, originator: &str, message: &dyn Display) {
            self.log("TRACE".to_string(), originator.to_string(), message.to_string());
        }

        fn trace_with_error(
            &self,
            originator: &str,
            message: &dyn Display,
            error: &dyn std::error::Error,
        ) {
            self.log(
                "TRACE_ERROR".to_string(),
                originator.to_string(),
                format!("{}: {}", message, error),
            );
        }

        fn debug(&self, originator: &str, message: &dyn Display) {
            self.log("DEBUG".to_string(), originator.to_string(), message.to_string());
        }

        fn debug_with_error(
            &self,
            originator: &str,
            message: &dyn Display,
            error: &dyn std::error::Error,
        ) {
            self.log(
                "DEBUG_ERROR".to_string(),
                originator.to_string(),
                format!("{}: {}", message, error),
            );
        }

        fn info(&self, originator: &str, message: &dyn Display) {
            self.log("INFO".to_string(), originator.to_string(), message.to_string());
        }

        fn info_with_error(
            &self,
            originator: &str,
            message: &dyn Display,
            error: &dyn std::error::Error,
        ) {
            self.log(
                "INFO_ERROR".to_string(),
                originator.to_string(),
                format!("{}: {}", message, error),
            );
        }

        fn warn(&self, originator: &str, message: &dyn Display) {
            self.log("WARN".to_string(), originator.to_string(), message.to_string());
        }

        fn warn_with_error(
            &self,
            originator: &str,
            message: &dyn Display,
            error: &dyn std::error::Error,
        ) {
            self.log(
                "WARN_ERROR".to_string(),
                originator.to_string(),
                format!("{}: {}", message, error),
            );
        }

        fn error(&self, originator: &str, message: &dyn Display) {
            self.log("ERROR".to_string(), originator.to_string(), message.to_string());
        }

        fn error_with_error(
            &self,
            originator: &str,
            message: &dyn Display,
            error: &dyn std::error::Error,
        ) {
            self.log(
                "ERROR_ERROR".to_string(),
                originator.to_string(),
                format!("{}: {}", message, error),
            );
        }
    }

    #[test]
    fn test_trace_message() {
        let logger = MockErrorLogger::new();
        logger.trace("TestOrigin", &"trace message");
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "TRACE");
        assert_eq!(logs[0].1, "TestOrigin");
        assert_eq!(logs[0].2, "trace message");
    }

    #[test]
    fn test_debug_message() {
        let logger = MockErrorLogger::new();
        logger.debug("Origin", &"debug message");
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "DEBUG");
        assert_eq!(logs[0].1, "Origin");
    }

    #[test]
    fn test_info_message() {
        let logger = MockErrorLogger::new();
        logger.info("Origin", &"info message");
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "INFO");
    }

    #[test]
    fn test_warn_message() {
        let logger = MockErrorLogger::new();
        logger.warn("Origin", &"warn message");
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "WARN");
    }

    #[test]
    fn test_error_message() {
        let logger = MockErrorLogger::new();
        logger.error("Origin", &"error message");
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "ERROR");
    }

    #[test]
    fn test_trace_with_error() {
        let logger = MockErrorLogger::new();
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.trace_with_error("Origin", &"trace with error", &err);
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "TRACE_ERROR");
        assert_eq!(logs[0].1, "Origin");
        assert!(logs[0].2.contains("trace with error"));
        assert!(logs[0].2.contains("test error"));
    }

    #[test]
    fn test_debug_with_error() {
        let logger = MockErrorLogger::new();
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.debug_with_error("Origin", &"debug with error", &err);
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "DEBUG_ERROR");
    }

    #[test]
    fn test_info_with_error() {
        let logger = MockErrorLogger::new();
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.info_with_error("Origin", &"info with error", &err);
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "INFO_ERROR");
    }

    #[test]
    fn test_warn_with_error() {
        let logger = MockErrorLogger::new();
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.warn_with_error("Origin", &"warn with error", &err);
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "WARN_ERROR");
    }

    #[test]
    fn test_error_with_error() {
        let logger = MockErrorLogger::new();
        let err = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        logger.error_with_error("Origin", &"error with error", &err);
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "ERROR_ERROR");
    }

    #[test]
    fn test_multiple_log_calls() {
        let logger = MockErrorLogger::new();
        logger.trace("Origin1", &"msg1");
        logger.debug("Origin2", &"msg2");
        logger.info("Origin3", &"msg3");
        let logs = logger.get_logs();
        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0].0, "TRACE");
        assert_eq!(logs[1].0, "DEBUG");
        assert_eq!(logs[2].0, "INFO");
    }

    #[test]
    fn test_default_error_logger_logs_info() {
        let logger = DefaultErrorLogger;
        logger.info("Origin", &"test message");
    }

    #[test]
    fn test_display_trait_with_string() {
        let logger = MockErrorLogger::new();
        let msg = String::from("dynamic message");
        logger.info("Origin", &msg);
        let logs = logger.get_logs();
        assert_eq!(logs[0].2, "dynamic message");
    }

    #[test]
    fn test_display_trait_with_format() {
        let logger = MockErrorLogger::new();
        logger.warn("Origin", &format!("value: {}", 42));
        let logs = logger.get_logs();
        assert_eq!(logs[0].2, "value: 42");
    }
}

#[cfg(test)]
mod trait_assertions {
    use super::*;

    #[allow(dead_code)]
    const fn assert_send<T: Send>() {}

    #[allow(dead_code)]
    const fn assert_sync<T: Sync>() {}

    #[allow(dead_code)]
    fn check_bounds() {
        assert_send::<DefaultErrorLogger>();
        assert_sync::<DefaultErrorLogger>();
    }
}

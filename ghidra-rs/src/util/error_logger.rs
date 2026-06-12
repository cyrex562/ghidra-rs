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

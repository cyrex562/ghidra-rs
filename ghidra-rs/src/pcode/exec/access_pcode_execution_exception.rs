//! An exception thrown when there is an issue accessing the executor's state.
//!
//! Corresponds to `ghidra.pcode.exec.AccessPcodeExecutionException`.
//!
//! There was an issue accessing the executor's state, i.e., memory or register values. Following
//! this crate's composition-over-inheritance convention, this wraps a [`PcodeExecutionException`]
//! instead of extending it.

use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;
use crate::pcode::exec::pcode_frame::PcodeFrame;

/// An exception thrown when there is an issue accessing the executor's state.
#[derive(Debug)]
pub struct AccessPcodeExecutionException {
    inner: PcodeExecutionException,
}

impl AccessPcodeExecutionException {
    /// Construct the exception with a message, a frame, and a cause.
    ///
    /// Port of `AccessPcodeExecutionException(String message, PcodeFrame frame, Throwable
    /// cause)`.
    pub fn with_frame_and_cause(
        message: impl Into<String>,
        frame: PcodeFrame,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { inner: PcodeExecutionException::with_frame_and_cause(message, frame, cause) }
    }

    /// Construct the exception with a message and a cause.
    ///
    /// Port of `AccessPcodeExecutionException(String message, Exception cause)`.
    pub fn with_cause(message: impl Into<String>, cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self { inner: PcodeExecutionException::with_cause(message, cause) }
    }

    /// Construct the exception with only a message.
    ///
    /// Port of `AccessPcodeExecutionException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { inner: PcodeExecutionException::with_message(message) }
    }

    /// The wrapped execution exception, standing in for Java's `super`.
    pub fn as_execution_exception(&self) -> &PcodeExecutionException {
        &self.inner
    }

    /// Consume this exception and return the wrapped execution exception.
    pub fn into_execution_exception(self) -> PcodeExecutionException {
        self.inner
    }

    /// Stands in for the inherited `Throwable.getMessage()`.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Stands in for the inherited `PcodeExecutionException.getFrame()`.
    pub fn frame(&self) -> Option<&PcodeFrame> {
        self.inner.frame()
    }
}

impl std::fmt::Display for AccessPcodeExecutionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for AccessPcodeExecutionException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_program::testing::NullLanguage;
    use std::sync::Arc;

    fn frame() -> PcodeFrame {
        PcodeFrame::new(Arc::new(NullLanguage), vec![], std::collections::HashMap::new())
    }

    #[test]
    fn message_only_constructor_has_no_frame_or_cause() {
        let e = AccessPcodeExecutionException::new("could not read memory");
        assert_eq!(e.message(), "could not read memory");
        assert!(e.frame().is_none());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn message_and_cause_constructor_exposes_source_but_no_frame() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "short read");
        let e = AccessPcodeExecutionException::with_cause("could not read memory", cause);
        assert_eq!(e.message(), "could not read memory");
        assert!(e.frame().is_none());
        let dyn_err: &dyn std::error::Error = &e;
        assert_eq!(dyn_err.source().unwrap().to_string(), "short read");
    }

    #[test]
    fn message_frame_and_cause_constructor_carries_all_three() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "permission denied");
        let e = AccessPcodeExecutionException::with_frame_and_cause(
            "could not write register",
            frame(),
            cause,
        );
        assert_eq!(e.message(), "could not write register");
        assert!(e.frame().is_some());
        let dyn_err: &dyn std::error::Error = &e;
        assert_eq!(dyn_err.source().unwrap().to_string(), "permission denied");
    }

    #[test]
    fn display_matches_message() {
        let e = AccessPcodeExecutionException::new("oops");
        assert_eq!(e.to_string(), "oops");
    }
}

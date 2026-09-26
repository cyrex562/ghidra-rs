//! A p-code execution exception related to system simulation.
//!
//! Port of `ghidra.pcode.emu.sys.EmuSystemException`.
//!
//! Following this crate's composition-over-inheritance convention, this wraps a
//! [`PcodeExecutionException`] instead of extending it (the same treatment
//! [`AccessPcodeExecutionException`](crate::pcode::exec::access_pcode_execution_exception::AccessPcodeExecutionException)
//! gives its own base class).

use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;
use crate::pcode::exec::pcode_frame::PcodeFrame;

/// A p-code execution exception related to system simulation.
///
/// Port of `ghidra.pcode.emu.sys.EmuSystemException`.
#[derive(Debug)]
pub struct EmuSystemException {
    inner: PcodeExecutionException,
}

impl EmuSystemException {
    /// Construct the exception with only a message.
    ///
    /// Port of `EmuSystemException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { inner: PcodeExecutionException::with_message(message) }
    }

    /// Construct the exception with a message and a frame.
    ///
    /// Port of `EmuSystemException(String message, PcodeFrame frame)`.
    pub fn with_frame(message: impl Into<String>, frame: PcodeFrame) -> Self {
        Self { inner: PcodeExecutionException::with_frame(message, frame) }
    }

    /// Construct the exception with a message and a cause, but no frame.
    ///
    /// Port of `EmuSystemException(String message, PcodeFrame frame, Throwable cause)` called
    /// with a `null` frame -- the combination
    /// [`EmuInvalidSystemCallException`](crate::pcode::emu::sys::emu_invalid_system_call_exception::EmuInvalidSystemCallException)'s
    /// `(String, Throwable)` constructor needs (`super(message, null, cause)`), but that no Java
    /// caller of `EmuSystemException` itself needed until now.
    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { inner: PcodeExecutionException::with_cause(message, cause) }
    }

    /// Construct the exception with a message, a frame, and a cause.
    ///
    /// Port of `EmuSystemException(String message, PcodeFrame frame, Throwable cause)`.
    pub fn with_frame_and_cause(
        message: impl Into<String>,
        frame: PcodeFrame,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { inner: PcodeExecutionException::with_frame_and_cause(message, frame, cause) }
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

impl std::fmt::Display for EmuSystemException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for EmuSystemException {
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
        let e = EmuSystemException::new("syscall not supported");
        assert_eq!(e.message(), "syscall not supported");
        assert!(e.frame().is_none());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn message_and_frame_constructor_has_no_cause() {
        let e = EmuSystemException::with_frame("bad syscall number", frame());
        assert_eq!(e.message(), "bad syscall number");
        assert!(e.frame().is_some());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn message_and_cause_constructor_has_no_frame() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "underlying I/O failure");
        let e = EmuSystemException::with_cause("bad syscall", cause);
        assert_eq!(e.message(), "bad syscall");
        assert!(e.frame().is_none());
        let dyn_err: &dyn std::error::Error = &e;
        assert_eq!(dyn_err.source().unwrap().to_string(), "underlying I/O failure");
    }

    #[test]
    fn message_frame_and_cause_constructor_carries_all_three() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "underlying I/O failure");
        let e = EmuSystemException::with_frame_and_cause("syscall failed", frame(), cause);
        assert_eq!(e.message(), "syscall failed");
        assert!(e.frame().is_some());
        let dyn_err: &dyn std::error::Error = &e;
        assert_eq!(dyn_err.source().unwrap().to_string(), "underlying I/O failure");
    }

    #[test]
    fn display_matches_message() {
        let e = EmuSystemException::new("oops");
        assert_eq!(e.to_string(), "oops");
    }

    #[test]
    fn into_execution_exception_preserves_state() {
        let e = EmuSystemException::with_frame("exit", frame());
        let inner = e.into_execution_exception();
        assert_eq!(inner.message(), "exit");
        assert!(inner.frame().is_some());
    }
}

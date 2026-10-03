//! The simulated system interrupted with an I/O error.
//!
//! Port of `ghidra.pcode.emu.sys.EmuIOException`.
//!
//! This exception is for I/O errors within the simulated system. If the host implementation
//! causes a real I/O error, it should *not* be wrapped in this exception unless, e.g., a
//! simulated file system intends to proxy the real file system.
//!
//! Following this crate's composition-over-inheritance convention, this wraps an
//! [`EmuInvalidSystemCallException`] instead of extending it -- the same treatment
//! [`EmuInvalidSystemCallException`] itself gives
//! [`EmuSystemException`](crate::pcode::emu::sys::emu_system_exception::EmuSystemException).

use crate::pcode::emu::sys::emu_invalid_system_call_exception::EmuInvalidSystemCallException;

/// The simulated system interrupted with an I/O error.
///
/// Port of `ghidra.pcode.emu.sys.EmuIOException`.
#[derive(Debug)]
pub struct EmuIOException {
    inner: EmuInvalidSystemCallException,
}

impl EmuIOException {
    /// Construct the exception with a message and a cause.
    ///
    /// Port of `EmuIOException(String message, Throwable cause)`.
    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { inner: EmuInvalidSystemCallException::with_cause(message, cause) }
    }

    /// Construct the exception with only a message.
    ///
    /// Port of `EmuIOException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { inner: EmuInvalidSystemCallException::new(message) }
    }

    /// The wrapped invalid-system-call exception, standing in for Java's `super`.
    pub fn as_invalid_system_call_exception(&self) -> &EmuInvalidSystemCallException {
        &self.inner
    }

    /// Consume this exception and return the wrapped invalid-system-call exception.
    pub fn into_invalid_system_call_exception(self) -> EmuInvalidSystemCallException {
        self.inner
    }

    /// Stands in for the inherited `Throwable.getMessage()`.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Stands in for the inherited `PcodeExecutionException.getFrame()`.
    pub fn frame(&self) -> Option<&crate::pcode::exec::pcode_frame::PcodeFrame> {
        self.inner.frame()
    }
}

impl std::fmt::Display for EmuIOException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for EmuIOException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_only_constructor_has_no_cause() {
        let e = EmuIOException::new("disk read failed");
        assert_eq!(e.message(), "disk read failed");
        assert!(e.frame().is_none());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn message_and_cause_constructor_carries_the_cause_with_no_frame() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "underlying I/O failure");
        let e = EmuIOException::with_cause("simulated file system I/O error", cause);
        assert_eq!(e.message(), "simulated file system I/O error");
        assert!(e.frame().is_none());
        let dyn_err: &dyn std::error::Error = &e;
        assert_eq!(dyn_err.source().unwrap().to_string(), "underlying I/O failure");
    }

    #[test]
    fn display_matches_message() {
        let e = EmuIOException::new("oops");
        assert_eq!(e.to_string(), "oops");
    }

    #[test]
    fn into_invalid_system_call_exception_preserves_state() {
        let e = EmuIOException::new("bad handle");
        let inner = e.into_invalid_system_call_exception();
        assert_eq!(inner.message(), "bad handle");
    }

    /// The wrapped exception is, in turn, a wrapper around an
    /// [`EmuSystemException`](crate::pcode::emu::sys::emu_system_exception::EmuSystemException),
    /// which itself wraps a
    /// [`PcodeExecutionException`](crate::pcode::exec::pcode_execution_exception::PcodeExecutionException) --
    /// matching the full four-level Java hierarchy this composes over
    /// (`EmuIOException` extends `EmuInvalidSystemCallException` extends `EmuSystemException`
    /// extends `PcodeExecutionException`).
    #[test]
    fn as_invalid_system_call_exception_reaches_the_wrapped_system_exception() {
        let e = EmuIOException::new("bad handle");
        let invalid_call = e.as_invalid_system_call_exception();
        let sys = invalid_call.as_system_exception();
        let exec = sys.as_execution_exception();
        assert_eq!(exec.message(), "bad handle");
    }
}

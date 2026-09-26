//! The emulated program invoked a system call incorrectly.
//!
//! Port of `ghidra.pcode.emu.sys.EmuInvalidSystemCallException`.
//!
//! Following this crate's composition-over-inheritance convention, this wraps an
//! [`EmuSystemException`] instead of extending it -- the same treatment
//! [`EmuSystemException`] itself gives [`PcodeExecutionException`].

use crate::pcode::emu::sys::emu_system_exception::EmuSystemException;
use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;

/// The emulated program invoked a system call incorrectly.
///
/// Port of `ghidra.pcode.emu.sys.EmuInvalidSystemCallException`.
#[derive(Debug)]
pub struct EmuInvalidSystemCallException {
    inner: EmuSystemException,
}

impl EmuInvalidSystemCallException {
    /// Construct the exception for an invalid system call number.
    ///
    /// Port of `EmuInvalidSystemCallException(long number)`, which delegates to the
    /// message-only constructor with `"Invalid system call number: " + number`.
    pub fn for_number(number: i64) -> Self {
        Self::new(format!("Invalid system call number: {number}"))
    }

    /// Construct the exception with only a message.
    ///
    /// Port of `EmuInvalidSystemCallException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { inner: EmuSystemException::new(message) }
    }

    /// Construct the exception with a message and a cause.
    ///
    /// Port of `EmuInvalidSystemCallException(String message, Throwable cause)`, which forwards to
    /// `EmuSystemException(String, PcodeFrame, Throwable)` with a `null` frame.
    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { inner: EmuSystemException::with_cause(message, cause) }
    }

    /// The wrapped system exception, standing in for Java's `super`.
    pub fn as_system_exception(&self) -> &EmuSystemException {
        &self.inner
    }

    /// Consume this exception and return the wrapped system exception.
    pub fn into_system_exception(self) -> EmuSystemException {
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

impl std::fmt::Display for EmuInvalidSystemCallException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for EmuInvalidSystemCallException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_number_formats_the_invalid_number_message() {
        let e = EmuInvalidSystemCallException::for_number(1234);
        assert_eq!(e.message(), "Invalid system call number: 1234");
        assert!(e.frame().is_none());
    }

    #[test]
    fn for_number_matches_the_equivalent_message_constructor() {
        let by_number = EmuInvalidSystemCallException::for_number(7);
        let by_message = EmuInvalidSystemCallException::new("Invalid system call number: 7");
        assert_eq!(by_number.to_string(), by_message.to_string());
    }

    #[test]
    fn message_only_constructor_has_no_cause() {
        let e = EmuInvalidSystemCallException::new("syscall not supported");
        assert_eq!(e.message(), "syscall not supported");
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn message_and_cause_constructor_carries_the_cause_with_no_frame() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "underlying I/O failure");
        let e = EmuInvalidSystemCallException::with_cause("syscall failed", cause);
        assert_eq!(e.message(), "syscall failed");
        assert!(e.frame().is_none());
        let dyn_err: &dyn std::error::Error = &e;
        assert_eq!(dyn_err.source().unwrap().to_string(), "underlying I/O failure");
    }

    #[test]
    fn display_matches_message() {
        let e = EmuInvalidSystemCallException::new("oops");
        assert_eq!(e.to_string(), "oops");
    }

    #[test]
    fn into_system_exception_preserves_state() {
        let e = EmuInvalidSystemCallException::for_number(42);
        let inner: EmuSystemException = e.into_system_exception();
        assert_eq!(inner.message(), "Invalid system call number: 42");
    }

    /// The wrapped exception is, in turn, a wrapper around a
    /// [`PcodeExecutionException`](crate::pcode::exec::pcode_execution_exception::PcodeExecutionException),
    /// matching the full three-level Java hierarchy this composes over.
    #[test]
    fn as_system_exception_reaches_the_wrapped_execution_exception() {
        let e = EmuInvalidSystemCallException::new("bad syscall");
        let sys: &EmuSystemException = e.as_system_exception();
        let exec: &PcodeExecutionException = sys.as_execution_exception();
        assert_eq!(exec.message(), "bad syscall");
    }
}

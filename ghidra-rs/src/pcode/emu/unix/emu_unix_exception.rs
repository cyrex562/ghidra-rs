//! An exception for errors within UNIX system call libraries.
//!
//! Port of `ghidra.pcode.emu.unix.EmuUnixException`.
//!
//! Following this crate's composition-over-inheritance convention, this wraps an
//! [`EmuSystemException`] instead of extending it -- the same treatment
//! [`EmuIOException`](crate::pcode::emu::sys::emu_io_exception::EmuIOException) gives its own
//! wrapped base.

use crate::pcode::emu::sys::emu_system_exception::EmuSystemException;
use crate::pcode::exec::pcode_frame::PcodeFrame;

/// An exception for errors within UNIX system call libraries.
///
/// Port of `ghidra.pcode.emu.unix.EmuUnixException`.
#[derive(Debug)]
pub struct EmuUnixException {
    inner: EmuSystemException,
    errno: Option<i32>,
}

impl EmuUnixException {
    /// Construct the exception with only a message.
    ///
    /// Port of `EmuUnixException(String message)`, which delegates to
    /// `this(message, null, null)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { inner: EmuSystemException::new(message), errno: None }
    }

    /// Construct the exception with a message and a cause, but no errno.
    ///
    /// Port of `EmuUnixException(String message, Throwable e)`, which delegates to
    /// `this(message, null, e)`.
    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { inner: EmuSystemException::with_cause(message, cause), errno: None }
    }

    /// Construct the exception with a message and an errno, but no cause.
    ///
    /// Port of `EmuUnixException(String message, Integer errno)`, which delegates to
    /// `this(message, errno, null)`.
    pub fn with_errno(message: impl Into<String>, errno: i32) -> Self {
        Self { inner: EmuSystemException::new(message), errno: Some(errno) }
    }

    /// Construct a new exception with an optional errno and cause.
    ///
    /// Port of the primary `EmuUnixException(String message, Integer errno, Throwable e)`
    /// constructor, which the other three delegate into with `null` in place of whichever
    /// arguments they omit.
    ///
    /// Providing an errno allows the system call dispatcher to automatically communicate errno to
    /// the target program. If provided, the exception will not interrupt the emulator, because
    /// the target program is expected to handle it. If omitted, the dispatcher simply allows the
    /// exception to interrupt the emulator.
    ///
    /// # Arguments
    /// * `message` - the message
    /// * `errno` - the errno, or `None`
    /// * `cause` - the cause of this exception
    pub fn with_errno_and_cause(
        message: impl Into<String>,
        errno: Option<i32>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { inner: EmuSystemException::with_cause(message, cause), errno }
    }

    /// Get the errno associated with this exception.
    ///
    /// Port of `getErrno()`.
    pub fn errno(&self) -> Option<i32> {
        self.errno
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
    pub fn frame(&self) -> Option<&PcodeFrame> {
        self.inner.frame()
    }
}

impl std::fmt::Display for EmuUnixException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for EmuUnixException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_only_constructor_has_no_errno_or_cause() {
        let e = EmuUnixException::new("unix call failed");
        assert_eq!(e.message(), "unix call failed");
        assert!(e.errno().is_none());
        assert!(e.frame().is_none());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn message_and_cause_constructor_has_no_errno() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "underlying I/O failure");
        let e = EmuUnixException::with_cause("read failed", cause);
        assert_eq!(e.message(), "read failed");
        assert!(e.errno().is_none());
        let dyn_err: &dyn std::error::Error = &e;
        assert_eq!(dyn_err.source().unwrap().to_string(), "underlying I/O failure");
    }

    #[test]
    fn message_and_errno_constructor_has_no_cause() {
        let e = EmuUnixException::with_errno("no such file or directory", 2);
        assert_eq!(e.message(), "no such file or directory");
        assert_eq!(e.errno(), Some(2));
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn message_errno_and_cause_constructor_carries_all_three() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "underlying I/O failure");
        let e = EmuUnixException::with_errno_and_cause("permission denied", Some(13), cause);
        assert_eq!(e.message(), "permission denied");
        assert_eq!(e.errno(), Some(13));
        let dyn_err: &dyn std::error::Error = &e;
        assert_eq!(dyn_err.source().unwrap().to_string(), "underlying I/O failure");
    }

    #[test]
    fn with_errno_and_cause_accepts_a_none_errno() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "underlying I/O failure");
        let e = EmuUnixException::with_errno_and_cause("some failure", None, cause);
        assert!(e.errno().is_none());
    }

    #[test]
    fn display_matches_message() {
        let e = EmuUnixException::new("oops");
        assert_eq!(e.to_string(), "oops");
    }

    #[test]
    fn into_system_exception_preserves_state() {
        let e = EmuUnixException::with_errno("bad fd", 9);
        let inner = e.into_system_exception();
        assert_eq!(inner.message(), "bad fd");
    }

    /// The wrapped exception is, in turn, a wrapper around a
    /// [`PcodeExecutionException`](crate::pcode::exec::pcode_execution_exception::PcodeExecutionException),
    /// matching the full three-level Java hierarchy this composes over (`EmuUnixException`
    /// extends `EmuSystemException` extends `PcodeExecutionException`).
    #[test]
    fn as_system_exception_reaches_the_wrapped_execution_exception() {
        let e = EmuUnixException::new("bad handle");
        let sys = e.as_system_exception();
        let exec = sys.as_execution_exception();
        assert_eq!(exec.message(), "bad handle");
    }
}

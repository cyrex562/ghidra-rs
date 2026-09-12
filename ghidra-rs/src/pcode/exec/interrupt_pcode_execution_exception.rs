//! An exception thrown when execution hits a breakpoint.
//!
//! Corresponds to `ghidra.pcode.exec.InterruptPcodeExecutionException`.
//!
//! Java's class extends [`PcodeExecutionException`] with a fixed message, thrown by
//! `PcodeEmulationLibrary.emu_swi()`, a p-code userop exported by emulators for implementing
//! breakpoints. Following this crate's composition-over-inheritance convention, this wraps a
//! [`PcodeExecutionException`] instead of extending it.

use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;
use crate::pcode::exec::pcode_frame::PcodeFrame;

/// An exception thrown when execution hits a breakpoint.
#[derive(Debug)]
pub struct InterruptPcodeExecutionException {
    inner: PcodeExecutionException,
}

impl InterruptPcodeExecutionException {
    /// The fixed message every instance carries, matching Java's hard-coded `super(...)` call.
    pub const MESSAGE: &'static str = "Execution hit breakpoint";

    /// Construct the exception with the given frame and no cause.
    ///
    /// Port of `InterruptPcodeExecutionException(PcodeFrame frame, Throwable cause)` for a `null`
    /// cause, which every current caller passes.
    pub fn new(frame: PcodeFrame) -> Self {
        Self { inner: PcodeExecutionException::with_frame(Self::MESSAGE, frame) }
    }

    /// Construct the exception with the given frame and cause.
    ///
    /// Port of `InterruptPcodeExecutionException(PcodeFrame frame, Throwable cause)`.
    pub fn with_cause(frame: PcodeFrame, cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self { inner: PcodeExecutionException::with_frame_and_cause(Self::MESSAGE, frame, cause) }
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

impl std::fmt::Display for InterruptPcodeExecutionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for InterruptPcodeExecutionException {
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
    fn message_is_fixed() {
        let e = InterruptPcodeExecutionException::new(frame());
        assert_eq!(e.message(), "Execution hit breakpoint");
        assert_eq!(e.to_string(), "Execution hit breakpoint");
    }

    #[test]
    fn carries_the_given_frame() {
        let e = InterruptPcodeExecutionException::new(frame());
        assert!(e.frame().is_some());
    }

    #[test]
    fn with_cause_exposes_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "breakpoint hook failed");
        let e = InterruptPcodeExecutionException::with_cause(frame(), cause);
        assert_eq!(e.message(), "Execution hit breakpoint");
        let dyn_err: &dyn std::error::Error = &e;
        assert_eq!(dyn_err.source().unwrap().to_string(), "breakpoint hook failed");
    }

    #[test]
    fn into_execution_exception_preserves_message_and_frame() {
        let e = InterruptPcodeExecutionException::new(frame());
        let inner = e.into_execution_exception();
        assert_eq!(inner.message(), "Execution hit breakpoint");
        assert!(inner.frame().is_some());
    }
}

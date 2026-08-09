use crate::pcode::exec::pcode_frame::PcodeFrame;

/// Exception thrown during p-code execution.
///
/// Port of `ghidra.pcode.exec.PcodeExecutionException`.
///
/// The base exception for all p-code execution errors. Exceptions caught by the executor that are
/// not of this type are typically caught and wrapped, so that the frame can be recovered. The
/// frame is important for diagnosing the error, because it records what the executor was doing. It
/// essentially serves as the "line number" of the p-code program within the greater stack.
/// Additionally, if execution of p-code is to resume, the frame must be recovered, and possibly
/// stepped back one.
pub struct PcodeExecutionException {
    message: String,
    frame: Option<Box<PcodeFrame>>,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl std::fmt::Debug for PcodeExecutionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcodeExecutionException")
            .field("message", &self.message)
            .field("frame", &self.frame.as_ref().map(|_| "..."))
            .field("source", &self.source.as_ref().map(|_| "..."))
            .finish()
    }
}

impl PcodeExecutionException {
    /// Construct an execution exception with only a message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            frame: None,
            source: None,
        }
    }

    /// Construct an execution exception with a message and a cause.
    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            frame: None,
            source: Some(Box::new(cause)),
        }
    }

    /// Construct an execution exception with a message and a frame.
    pub fn with_frame(message: impl Into<String>, frame: PcodeFrame) -> Self {
        Self {
            message: message.into(),
            frame: Some(Box::new(frame)),
            source: None,
        }
    }

    /// Construct an execution exception with a message, frame, and a cause.
    pub fn with_frame_and_cause(
        message: impl Into<String>,
        frame: PcodeFrame,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            frame: Some(Box::new(frame)),
            source: Some(Box::new(cause)),
        }
    }

    /// Get the message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the frame at the time of the exception, if available.
    ///
    /// Note that the frame counter is advanced *before* execution of the p-code op. Thus, the
    /// counter often points to the op following the one which caused the exception. For a frame to
    /// be present and meaningful, the executor must intervene between the throw and the catch. In
    /// other words, if you're invoking the executor, you should always expect to see a frame. If you
    /// are implementing, e.g., a userop, then it is possible to catch an exception without frame
    /// information populated. You might instead retrieve the frame from the executor, if you have a
    /// handle to it.
    pub fn frame(&self) -> Option<&PcodeFrame> {
        self.frame.as_deref()
    }

    /// Consume this exception and return the frame, if available.
    pub fn into_frame(self) -> Option<Box<PcodeFrame>> {
        self.frame
    }
}

impl std::fmt::Display for PcodeExecutionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PcodeExecutionException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn with_message_stores_message() {
        let e = PcodeExecutionException::with_message("execution failed");
        assert_eq!(e.message(), "execution failed");
    }

    #[test]
    fn with_message_frame_is_none() {
        let e = PcodeExecutionException::with_message("error");
        assert!(e.frame().is_none());
    }

    #[test]
    fn with_message_source_is_none() {
        let e = PcodeExecutionException::with_message("error");
        assert!(e.source().is_none());
    }

    #[test]
    fn display_matches_message() {
        let e = PcodeExecutionException::with_message("bad op");
        assert_eq!(e.to_string(), "bad op");
    }

    #[test]
    fn debug_is_implemented() {
        let e = PcodeExecutionException::with_message("oops");
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("oops"));
    }

    #[test]
    fn implements_error_trait() {
        let e = PcodeExecutionException::with_message("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn with_cause_stores_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root");
        let e = PcodeExecutionException::with_cause("pcode failed", cause);
        assert_eq!(e.message(), "pcode failed");
    }

    #[test]
    fn with_cause_exposes_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = PcodeExecutionException::with_cause("wrapper", cause);
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "root cause");
    }

    #[test]
    fn with_cause_frame_is_none() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "cause");
        let e = PcodeExecutionException::with_cause("message", cause);
        assert!(e.frame().is_none());
    }

    #[test]
    fn display_does_not_include_cause() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "cause message");
        let e = PcodeExecutionException::with_cause("main message", cause);
        assert_eq!(e.to_string(), "main message");
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned message");
        let e = PcodeExecutionException::with_message(msg);
        assert_eq!(e.message(), "owned message");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = PcodeExecutionException::with_message("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn into_frame_returns_none_when_no_frame() {
        let e = PcodeExecutionException::with_message("no frame");
        let maybe_frame = e.into_frame();
        assert!(maybe_frame.is_none());
    }
}

/// An error raised when bad or incomplete data is encountered during decompilation.
///
/// Corresponds to `ghidra.pcodeCPort.translate.BadDataError`.
use crate::decompiler::error::LowlevelError;

pub struct BadDataError {
    inner: LowlevelError,
}

impl BadDataError {
    /// Constructs a `BadDataError` with the given detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            inner: LowlevelError::with_message(message),
        }
    }

    /// Returns the underlying `LowlevelError`.
    pub fn inner(&self) -> &LowlevelError {
        &self.inner
    }

    /// Consumes this error and returns the underlying `LowlevelError`.
    pub fn into_inner(self) -> LowlevelError {
        self.inner
    }
}

impl std::fmt::Debug for BadDataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::fmt::Display for BadDataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::error::Error for BadDataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

impl From<LowlevelError> for BadDataError {
    fn from(error: LowlevelError) -> Self {
        Self { inner: error }
    }
}

impl From<BadDataError> for LowlevelError {
    fn from(error: BadDataError) -> Self {
        error.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_message_stores_message() {
        let e = BadDataError::with_message("incomplete instruction");
        assert_eq!(e.inner().message(), "incomplete instruction");
    }

    #[test]
    fn with_message_source_is_none() {
        let e = BadDataError::with_message("bad data");
        assert!(e.inner().source().is_none());
    }

    #[test]
    fn display_matches_message() {
        let e = BadDataError::with_message("invalid opcode");
        assert_eq!(e.to_string(), "invalid opcode");
    }

    #[test]
    fn debug_is_implemented() {
        let e = BadDataError::with_message("oops");
        assert!(!format!("{:?}", e).is_empty());
    }

    #[test]
    fn from_lowlevel_error() {
        let lowlevel = LowlevelError::with_message("test error");
        let bad_data: BadDataError = lowlevel.into();
        assert_eq!(bad_data.inner().message(), "test error");
    }

    #[test]
    fn into_lowlevel_error() {
        let bad_data = BadDataError::with_message("test error");
        let lowlevel: LowlevelError = bad_data.into();
        assert_eq!(lowlevel.message(), "test error");
    }

    #[test]
    fn implements_error_trait() {
        use std::error::Error;
        let e = BadDataError::with_message("err");
        let _: &dyn Error = &e;
    }
}

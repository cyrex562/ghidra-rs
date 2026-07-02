/// An error raised when an unimplemented instruction is encountered during decompilation.
///
/// Corresponds to `ghidra.pcodeCPort.translate.UnimplError`.
use crate::decompiler::error::LowlevelError;

pub struct UnimplError {
    inner: LowlevelError,
    instruction_length: u32,
}

impl UnimplError {
    /// Constructs an `UnimplError` with the given detail message and instruction length.
    pub fn with_message(message: impl Into<String>, instruction_length: u32) -> Self {
        Self {
            inner: LowlevelError::with_message(message),
            instruction_length,
        }
    }

    /// Returns the instruction length in bytes.
    pub fn instruction_length(&self) -> u32 {
        self.instruction_length
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

impl std::fmt::Debug for UnimplError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnimplError")
            .field("inner", &self.inner)
            .field("instruction_length", &self.instruction_length)
            .finish()
    }
}

impl std::fmt::Display for UnimplError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::error::Error for UnimplError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

impl From<LowlevelError> for UnimplError {
    fn from(error: LowlevelError) -> Self {
        Self {
            inner: error,
            instruction_length: 0,
        }
    }
}

impl From<UnimplError> for LowlevelError {
    fn from(error: UnimplError) -> Self {
        error.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_message_stores_message_and_length() {
        let e = UnimplError::with_message("unimplemented opcode", 4);
        assert_eq!(e.inner().message(), "unimplemented opcode");
        assert_eq!(e.instruction_length(), 4);
    }

    #[test]
    fn with_message_stores_zero_length() {
        let e = UnimplError::with_message("unknown instruction", 0);
        assert_eq!(e.instruction_length(), 0);
    }

    #[test]
    fn with_message_stores_large_length() {
        let e = UnimplError::with_message("extended instruction", u32::MAX);
        assert_eq!(e.instruction_length(), u32::MAX);
    }

    #[test]
    fn inner_returns_reference() {
        let e = UnimplError::with_message("test error", 2);
        assert_eq!(e.inner().message(), "test error");
        assert!(e.inner().source().is_none());
    }

    #[test]
    fn display_matches_message() {
        let e = UnimplError::with_message("unimplemented", 8);
        assert_eq!(e.to_string(), "unimplemented");
    }

    #[test]
    fn debug_includes_all_fields() {
        let e = UnimplError::with_message("oops", 3);
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("UnimplError"));
        assert!(debug_str.contains("3"));
    }

    #[test]
    fn from_lowlevel_error() {
        let lowlevel = LowlevelError::with_message("test error");
        let unimpl: UnimplError = lowlevel.into();
        assert_eq!(unimpl.inner().message(), "test error");
        assert_eq!(unimpl.instruction_length(), 0);
    }

    #[test]
    fn into_lowlevel_error() {
        let unimpl = UnimplError::with_message("test error", 5);
        let lowlevel: LowlevelError = unimpl.into();
        assert_eq!(lowlevel.message(), "test error");
    }

    #[test]
    fn implements_error_trait() {
        use std::error::Error;
        let e = UnimplError::with_message("err", 1);
        let _: &dyn Error = &e;
    }
}

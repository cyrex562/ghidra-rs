use std::fmt;

/// Error codes from the ISF protocol (`isf.proto`, `ghidra.dbg.isf.protocol.Isf.ErrorCode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Unknown = 0,
    BadRequest = 1,
    NotSupported = 2,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::Unknown => f.write_str("EC_UNKNOWN"),
            ErrorCode::BadRequest => f.write_str("EC_BAD_REQUEST"),
            ErrorCode::NotSupported => f.write_str("EC_NOT_SUPPORTED"),
        }
    }
}

/// Runtime error carrying an ISF protocol error code and message.
///
/// Corresponds to `ghidra.dbg.isf.IsfErrorException`. The display message is
/// formatted as `"{code}: {message}"` to match the Java constructor's `super(code + ": " + message)`.
#[derive(Debug)]
pub struct IsfErrorException {
    code: ErrorCode,
    message: String,
}

impl IsfErrorException {
    /// Creates a new `IsfErrorException` with the given error code and detail message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let detail = message.into();
        let message = format!("{}: {}", code, detail);
        Self { code, message }
    }

    /// Returns the protocol error code.
    pub fn code(&self) -> ErrorCode {
        self.code
    }
}

impl fmt::Display for IsfErrorException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IsfErrorException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_formats_code_colon_text() {
        let err = IsfErrorException::new(ErrorCode::BadRequest, "invalid field");
        assert_eq!(err.to_string(), "EC_BAD_REQUEST: invalid field");
    }

    #[test]
    fn code_getter_returns_stored_code() {
        let err = IsfErrorException::new(ErrorCode::NotSupported, "not implemented");
        assert_eq!(err.code(), ErrorCode::NotSupported);
    }

    #[test]
    fn unknown_code_formats_correctly() {
        let err = IsfErrorException::new(ErrorCode::Unknown, "mystery");
        assert_eq!(err.to_string(), "EC_UNKNOWN: mystery");
    }

    #[test]
    fn not_supported_code_formats_correctly() {
        let err = IsfErrorException::new(ErrorCode::NotSupported, "op");
        assert_eq!(err.to_string(), "EC_NOT_SUPPORTED: op");
    }

    #[test]
    fn implements_error_trait() {
        let err = IsfErrorException::new(ErrorCode::BadRequest, "test");
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn debug_output_contains_struct_name() {
        let err = IsfErrorException::new(ErrorCode::Unknown, "dbg");
        assert!(format!("{:?}", err).contains("IsfErrorException"));
    }
}

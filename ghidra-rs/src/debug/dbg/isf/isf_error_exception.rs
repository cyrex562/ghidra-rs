use std::fmt;

use super::protocol::ErrorCode;

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
        // Java's `code + ": " + message`: an enum constant prints as its proto name.
        let message = format!("{}: {}", code.as_str_name(), detail);
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
        let err = IsfErrorException::new(ErrorCode::EcBadRequest, "invalid field");
        assert_eq!(err.to_string(), "EC_BAD_REQUEST: invalid field");
    }

    #[test]
    fn code_getter_returns_stored_code() {
        let err = IsfErrorException::new(ErrorCode::EcNotSupported, "not implemented");
        assert_eq!(err.code(), ErrorCode::EcNotSupported);
    }

    #[test]
    fn unknown_code_formats_correctly() {
        let err = IsfErrorException::new(ErrorCode::EcUnknown, "mystery");
        assert_eq!(err.to_string(), "EC_UNKNOWN: mystery");
    }

    #[test]
    fn not_supported_code_formats_correctly() {
        let err = IsfErrorException::new(ErrorCode::EcNotSupported, "op");
        assert_eq!(err.to_string(), "EC_NOT_SUPPORTED: op");
    }

    #[test]
    fn implements_error_trait() {
        let err = IsfErrorException::new(ErrorCode::EcBadRequest, "test");
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn debug_output_contains_struct_name() {
        let err = IsfErrorException::new(ErrorCode::EcUnknown, "dbg");
        assert!(format!("{:?}", err).contains("IsfErrorException"));
    }
}

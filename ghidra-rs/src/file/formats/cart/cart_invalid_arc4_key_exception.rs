/// Exception for apparent ARC4 key errors; for instance, when decrypted data does not meet
/// the expected format.
///
/// Mirrors `ghidra.file.formats.cart.CartInvalidARC4KeyException`.
#[derive(Debug)]
pub struct CartInvalidARC4KeyException {
    message: String,
}

impl CartInvalidARC4KeyException {
    /// Constructs a `CartInvalidARC4KeyException` with the given reason message.
    ///
    /// Mirrors `CartInvalidARC4KeyException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CartInvalidARC4KeyException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CartInvalidARC4KeyException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_preserved() {
        let e = CartInvalidARC4KeyException::new("ARC4 key decryption failed");
        assert_eq!(e.to_string(), "ARC4 key decryption failed");
    }

    #[test]
    fn empty_message() {
        let e = CartInvalidARC4KeyException::new("");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn implements_error_trait() {
        let e = CartInvalidARC4KeyException::new("invalid key format");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn debug_format() {
        let e = CartInvalidARC4KeyException::new("decrypted data invalid");
        assert!(format!("{:?}", e).contains("CartInvalidARC4KeyException"));
    }
}

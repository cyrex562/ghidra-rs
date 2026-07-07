/// Exception for apparent CaRT configuration errors, such as an ARC4 key that
/// is not valid base64-encoded data.
///
/// Mirrors `ghidra.file.formats.cart.CartConfigurationException`.
#[derive(Debug)]
pub struct CartConfigurationException {
    message: String,
}

impl CartConfigurationException {
    /// Constructs a `CartConfigurationException` with the given reason message.
    ///
    /// Mirrors `CartConfigurationException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CartConfigurationException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CartConfigurationException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_preserved() {
        let e = CartConfigurationException::new("ARC4 key is not valid base64");
        assert_eq!(e.to_string(), "ARC4 key is not valid base64");
    }

    #[test]
    fn empty_message() {
        let e = CartConfigurationException::new("");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn implements_error_trait() {
        let e = CartConfigurationException::new("config error");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn debug_format() {
        let e = CartConfigurationException::new("bad key");
        assert!(format!("{:?}", e).contains("CartConfigurationException"));
    }
}

/// Exception for general CaRT format or access errors.
///
/// Mirrors `ghidra.file.formats.cart.CartInvalidCartException`.
#[derive(Debug)]
pub struct CartInvalidCartException {
    message: String,
}

impl CartInvalidCartException {
    /// Constructs a `CartInvalidCartException` with the given reason message.
    ///
    /// Mirrors `CartInvalidCartException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CartInvalidCartException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CartInvalidCartException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_preserved() {
        let e = CartInvalidCartException::new("invalid CaRT format");
        assert_eq!(e.to_string(), "invalid CaRT format");
    }

    #[test]
    fn empty_message() {
        let e = CartInvalidCartException::new("");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn implements_error_trait() {
        let e = CartInvalidCartException::new("bad cart");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn debug_format() {
        let e = CartInvalidCartException::new("corrupt header");
        assert!(format!("{:?}", e).contains("CartInvalidCartException"));
    }
}

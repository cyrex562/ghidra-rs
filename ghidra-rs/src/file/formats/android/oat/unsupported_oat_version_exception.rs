/// Error indicating an unsupported OAT file version.
///
/// Mirrors `ghidra.file.formats.android.oat.UnsupportedOatVersionException`.
#[derive(Debug)]
pub struct UnsupportedOatVersionException {
    message: String,
}

impl UnsupportedOatVersionException {
    /// Creates an error for an unsupported OAT version identified by `magic` and `version`.
    ///
    /// Mirrors `UnsupportedOatVersionException(String magic, String version)`.
    pub fn new(magic: &str, version: &str) -> Self {
        Self {
            message: format!("Unsupported OAT ({}) for version: {}", magic.trim(), version),
        }
    }

    /// Creates an error with a custom message.
    ///
    /// Mirrors `UnsupportedOatVersionException(String message)`.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for UnsupportedOatVersionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for UnsupportedOatVersionException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_formats_message() {
        let e = UnsupportedOatVersionException::new("oat\n", "007");
        assert_eq!(e.to_string(), "Unsupported OAT (oat) for version: 007");
    }

    #[test]
    fn new_trims_magic_whitespace() {
        let e = UnsupportedOatVersionException::new("  oat  ", "010");
        assert_eq!(e.to_string(), "Unsupported OAT (oat) for version: 010");
    }

    #[test]
    fn with_message_preserves_text() {
        let e = UnsupportedOatVersionException::with_message("custom error");
        assert_eq!(e.to_string(), "custom error");
    }

    #[test]
    fn implements_error_trait() {
        let e = UnsupportedOatVersionException::new("oat", "001");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn debug_format() {
        let e = UnsupportedOatVersionException::new("oat", "001");
        assert!(format!("{:?}", e).contains("UnsupportedOatVersionException"));
    }
}

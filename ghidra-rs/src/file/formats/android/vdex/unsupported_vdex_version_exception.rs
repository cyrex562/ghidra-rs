/// Error indicating an unsupported VDEX file version.
///
/// Mirrors `ghidra.file.formats.android.vdex.UnsupportedVdexVersionException`.
#[derive(Debug)]
pub struct UnsupportedVdexVersionException {
    message: String,
}

impl UnsupportedVdexVersionException {
    /// Creates an error for an unsupported VDEX version.
    ///
    /// `magic` is accepted for API parity with the Java source but is not included in the
    /// message — the original constructor passes only `version` to `super()`.
    ///
    /// Mirrors `UnsupportedVdexVersionException(String magic, String version)`.
    pub fn new(_magic: &str, version: &str) -> Self {
        Self {
            message: format!("Unsupported VDEX version: {}", version),
        }
    }

    /// Creates an error with a custom message.
    ///
    /// Mirrors `UnsupportedVdexVersionException(String message)`.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for UnsupportedVdexVersionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for UnsupportedVdexVersionException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_formats_message_with_version_only() {
        let e = UnsupportedVdexVersionException::new("vdex", "006");
        assert_eq!(e.to_string(), "Unsupported VDEX version: 006");
    }

    #[test]
    fn new_magic_is_ignored_in_message() {
        let e = UnsupportedVdexVersionException::new("ignored_magic", "019");
        assert_eq!(e.to_string(), "Unsupported VDEX version: 019");
    }

    #[test]
    fn with_message_preserves_text() {
        let e = UnsupportedVdexVersionException::with_message("custom error");
        assert_eq!(e.to_string(), "custom error");
    }

    #[test]
    fn implements_error_trait() {
        let e = UnsupportedVdexVersionException::new("vdex", "001");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn debug_format() {
        let e = UnsupportedVdexVersionException::new("vdex", "001");
        assert!(format!("{:?}", e).contains("UnsupportedVdexVersionException"));
    }
}

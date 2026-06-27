use std::fmt;

/// Error type indicating a problem parsing an OMF record.
///
/// Mirrors Ghidra's `OmfException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfException {
    message: String,
}

impl OmfException {
    /// Creates a new [`OmfException`] with the given detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for OmfException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OmfException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message() {
        let e = OmfException::new("bad OMF record");
        assert_eq!(e.message(), "bad OMF record");
    }

    #[test]
    fn display_equals_message() {
        let e = OmfException::new("unexpected end of record");
        assert_eq!(e.to_string(), "unexpected end of record");
    }

    #[test]
    fn implements_error() {
        let e = OmfException::new("test");
        let _: &dyn std::error::Error = &e;
    }
}

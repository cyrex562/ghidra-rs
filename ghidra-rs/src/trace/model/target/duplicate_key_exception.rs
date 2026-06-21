use std::fmt;

/// Thrown when two value entries with the same parent and key have overlapping lifespans,
/// and the `ConflictResolution::Deny` strategy is in effect.
///
/// This mirrors Ghidra's `ghidra.trace.model.target.DuplicateKeyException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateKeyException {
    key: String,
}

impl DuplicateKeyException {
    /// Constructs a new exception for the given conflicting key.
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    /// Returns the conflicting key.
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl fmt::Display for DuplicateKeyException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key)
    }
}

impl std::error::Error for DuplicateKeyException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_key() {
        let e = DuplicateKeyException::new("myKey");
        assert_eq!(e.key(), "myKey");
    }

    #[test]
    fn display_matches_key() {
        let e = DuplicateKeyException::new("myKey");
        assert_eq!(e.to_string(), "myKey");
    }

    #[test]
    fn empty_key_is_accepted() {
        let e = DuplicateKeyException::new("");
        assert_eq!(e.key(), "");
    }

    #[test]
    fn implements_error_trait() {
        let e: Box<dyn std::error::Error> = Box::new(DuplicateKeyException::new("conflict"));
        assert_eq!(e.to_string(), "conflict");
    }

    #[test]
    fn equality_on_same_key() {
        let a = DuplicateKeyException::new("k");
        let b = DuplicateKeyException::new("k");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_on_different_keys() {
        let a = DuplicateKeyException::new("k1");
        let b = DuplicateKeyException::new("k2");
        assert_ne!(a, b);
    }
}

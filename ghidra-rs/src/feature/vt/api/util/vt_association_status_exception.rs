use std::fmt;

/// An exception that signals an attempt to add `VTMarkupItem`s to an
/// `UNAVAILABLE` association.
///
/// Port of `ghidra.feature.vt.api.util.VTAssociationStatusException`, which extends `Exception`
/// with a single message-only constructor (no cause-carrying overload exists in the Java class).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VTAssociationStatusException {
    message: String,
}

impl VTAssociationStatusException {
    /// Mirrors `VTAssociationStatusException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for VTAssociationStatusException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VTAssociationStatusException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message() {
        let ex = VTAssociationStatusException::new("association is UNAVAILABLE");
        assert_eq!(ex.message(), "association is UNAVAILABLE");
    }

    #[test]
    fn display_shows_message() {
        let ex = VTAssociationStatusException::new("cannot add markup item");
        assert_eq!(ex.to_string(), "cannot add markup item");
    }

    #[test]
    fn equality_compares_by_message() {
        let a = VTAssociationStatusException::new("same");
        let b = VTAssociationStatusException::new("same");
        let c = VTAssociationStatusException::new("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn implements_std_error() {
        let ex = VTAssociationStatusException::new("boom");
        let as_error: &dyn std::error::Error = &ex;
        assert_eq!(as_error.to_string(), "boom");
    }

    #[test]
    fn clone_preserves_message() {
        let ex = VTAssociationStatusException::new("clone me");
        let cloned = ex.clone();
        assert_eq!(ex, cloned);
    }
}

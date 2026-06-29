use thiserror::Error;

/// Signals that a PDB-related error occurred during parsing or processing.
#[derive(Error, Debug)]
#[error("{message}")]
pub struct PdbError {
    message: String,
}

impl PdbError {
    /// Constructs a new error with the given detail message.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let err = PdbError::new("pdb parse failed");
        assert_eq!(err.message(), "pdb parse failed");
        assert_eq!(err.to_string(), "pdb parse failed");
    }

    #[test]
    fn display_matches_message() {
        let err = PdbError::new("bad pdb header");
        assert_eq!(format!("{}", err), "bad pdb header");
    }

    #[test]
    fn no_source_cause() {
        let err = PdbError::new("standalone error");
        assert!(err.source().is_none());
    }

    #[test]
    fn empty_message_is_valid() {
        let err = PdbError::new("");
        assert_eq!(err.message(), "");
    }
}

/// Error thrown when a programmer selects an improper instruction during assembly.
///
/// Mirrors `ghidra.app.plugin.assembler.AssemblySelectionError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblySelectionError {
    message: String,
}

impl AssemblySelectionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for AssemblySelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AssemblySelectionError {}

impl From<AssemblySelectionError> for super::AssemblyError {
    fn from(err: AssemblySelectionError) -> Self {
        super::AssemblyError::new(err.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let e = AssemblySelectionError::new("improper instruction selected");
        assert_eq!(e.message(), "improper instruction selected");
    }

    #[test]
    fn display_matches_message() {
        let e = AssemblySelectionError::new("bad selection");
        assert_eq!(e.to_string(), "bad selection");
    }

    #[test]
    fn debug_contains_message() {
        let e = AssemblySelectionError::new("selection error");
        let s = format!("{:?}", e);
        assert!(s.contains("selection error"));
    }

    #[test]
    fn implements_error_trait() {
        let e = AssemblySelectionError::new("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn error_source_is_none() {
        let e = AssemblySelectionError::new("err");
        assert!(e.source().is_none());
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = AssemblySelectionError::new("msg");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_messages() {
        let a = AssemblySelectionError::new("alpha");
        let b = AssemblySelectionError::new("beta");
        assert_ne!(a, b);
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned");
        let e = AssemblySelectionError::new(msg);
        assert_eq!(e.message(), "owned");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = AssemblySelectionError::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn converts_to_assembly_error() {
        let selection_err = AssemblySelectionError::new("test message");
        let assembly_err: super::AssemblyError = selection_err.into();
        assert_eq!(assembly_err.message(), "test message");
    }
}

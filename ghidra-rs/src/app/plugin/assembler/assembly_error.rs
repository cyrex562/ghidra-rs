/// Error for programmer mistakes regarding an assembler.
///
/// Mirrors `ghidra.app.plugin.assembler.AssemblyError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyError {
    message: String,
}

impl AssemblyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AssemblyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let e = AssemblyError::new("bad opcode");
        assert_eq!(e.message(), "bad opcode");
    }

    #[test]
    fn display_matches_message() {
        let e = AssemblyError::new("invalid register");
        assert_eq!(e.to_string(), "invalid register");
    }

    #[test]
    fn debug_contains_message() {
        let e = AssemblyError::new("oops");
        let s = format!("{:?}", e);
        assert!(s.contains("oops"));
    }

    #[test]
    fn implements_error_trait() {
        let e = AssemblyError::new("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn error_source_is_none() {
        let e = AssemblyError::new("err");
        assert!(e.source().is_none());
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = AssemblyError::new("msg");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_messages() {
        let a = AssemblyError::new("alpha");
        let b = AssemblyError::new("beta");
        assert_ne!(a, b);
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned");
        let e = AssemblyError::new(msg);
        assert_eq!(e.message(), "owned");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = AssemblyError::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

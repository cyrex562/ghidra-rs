/// Error returned when an operation cannot be performed because the tool has
/// background tasks running.
///
/// Mirrors `ghidra.framework.plugintool.BusyToolException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusyToolException {
    message: String,
}

impl BusyToolException {
    /// Construct a new exception.
    ///
    /// `message` – reason the tool is busy.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the reason for the exception.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for BusyToolException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BusyToolException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let e = BusyToolException::new("tool is busy");
        assert_eq!(e.message(), "tool is busy");
    }

    #[test]
    fn display_matches_message() {
        let e = BusyToolException::new("background tasks running");
        assert_eq!(e.to_string(), "background tasks running");
    }

    #[test]
    fn debug_contains_message() {
        let e = BusyToolException::new("busy");
        let s = format!("{:?}", e);
        assert!(s.contains("busy"));
    }

    #[test]
    fn implements_error_trait() {
        let e = BusyToolException::new("busy");
        let _: &dyn Error = &e;
    }

    #[test]
    fn error_source_is_none() {
        let e = BusyToolException::new("busy");
        assert!(e.source().is_none());
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = BusyToolException::new("busy");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_holds_for_same_message() {
        let a = BusyToolException::new("msg");
        let b = BusyToolException::new("msg");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_messages() {
        let a = BusyToolException::new("alpha");
        let b = BusyToolException::new("beta");
        assert_ne!(a, b);
    }

    #[test]
    fn accepts_string_owned() {
        let msg = String::from("owned");
        let e = BusyToolException::new(msg);
        assert_eq!(e.message(), "owned");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = BusyToolException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

use std::fmt;

/// Error thrown when an error occurs when attempting to merge two datatypes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTypeMergeException {
    message: String,
}

impl DataTypeMergeException {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DataTypeMergeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DataTypeMergeException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_message() {
        let e = DataTypeMergeException::new("merge failed");
        assert_eq!(e.message(), "merge failed");
    }

    #[test]
    fn display_returns_message() {
        let e = DataTypeMergeException::new("conflict detected");
        assert_eq!(e.to_string(), "conflict detected");
    }

    #[test]
    fn debug_contains_message() {
        let e = DataTypeMergeException::new("bad merge");
        assert!(format!("{:?}", e).contains("bad merge"));
    }

    #[test]
    fn clone_equals_original() {
        let e = DataTypeMergeException::new("clone test");
        assert_eq!(e.clone(), e);
    }

    #[test]
    fn implements_error_trait() {
        let e = DataTypeMergeException::new("error trait");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn empty_message_allowed() {
        let e = DataTypeMergeException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}

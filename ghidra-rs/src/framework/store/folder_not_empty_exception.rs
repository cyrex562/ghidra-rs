use std::fmt;

/// Raised when an attempt is made to remove a Folder which is not empty.
///
/// Mirrors `ghidra.framework.store.FolderNotEmptyException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderNotEmptyException {
    message: String,
}

impl FolderNotEmptyException {
    /// Creates a new `FolderNotEmptyException` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for FolderNotEmptyException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FolderNotEmptyException {}

impl From<FolderNotEmptyException> for std::io::Error {
    fn from(e: FolderNotEmptyException) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_with_message() {
        let e = FolderNotEmptyException::new("folder not empty");
        assert_eq!(e.message(), "folder not empty");
    }

    #[test]
    fn display_shows_message() {
        let e = FolderNotEmptyException::new("cannot remove non-empty folder");
        assert_eq!(format!("{}", e), "cannot remove non-empty folder");
    }

    #[test]
    fn from_string() {
        let msg = String::from("folder has children");
        let e = FolderNotEmptyException::new(msg);
        assert_eq!(e.message(), "folder has children");
    }

    #[test]
    fn clone_equality() {
        let a = FolderNotEmptyException::new("msg");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_message() {
        let a = FolderNotEmptyException::new("msg1");
        let b = FolderNotEmptyException::new("msg2");
        assert_ne!(a, b);
    }

    #[test]
    fn implements_error_trait() {
        let e = FolderNotEmptyException::new("error");
        let _: &dyn Error = &e;
    }

    #[test]
    fn error_source_is_none() {
        let e = FolderNotEmptyException::new("error");
        assert!(e.source().is_none());
    }

    #[test]
    fn debug_format_includes_type() {
        let e = FolderNotEmptyException::new("test");
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("FolderNotEmptyException"));
    }

    #[test]
    fn into_io_error() {
        let e = FolderNotEmptyException::new("folder not empty");
        let io_err: std::io::Error = e.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::Other);
        assert!(io_err.to_string().contains("folder not empty"));
    }

    #[test]
    fn message_accessor_returns_full_text() {
        let e = FolderNotEmptyException::new("detailed error message");
        let msg = e.message();
        assert_eq!(msg, "detailed error message");
    }
}

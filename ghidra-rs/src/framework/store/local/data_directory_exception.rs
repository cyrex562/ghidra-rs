use std::fmt;
use std::path::{Path, PathBuf};

/// Raised when a folder item cannot be created because its associated data directory
/// already exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirectoryException {
    message: String,
    dir: PathBuf,
}

impl DataDirectoryException {
    /// Creates a new `DataDirectoryException`.
    ///
    /// - `message`: human-readable error description
    /// - `dir`: the data directory that already exists
    pub fn new(message: impl Into<String>, dir: impl Into<PathBuf>) -> Self {
        Self {
            message: message.into(),
            dir: dir.into(),
        }
    }

    /// Returns the existing data directory.
    pub fn data_directory(&self) -> &Path {
        &self.dir
    }
}

impl fmt::Display for DataDirectoryException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DataDirectoryException {}

impl From<DataDirectoryException> for std::io::Error {
    fn from(e: DataDirectoryException) -> Self {
        std::io::Error::new(std::io::ErrorKind::AlreadyExists, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_accessors() {
        let dir = PathBuf::from("/tmp/mydata");
        let e = DataDirectoryException::new("data dir exists", dir.clone());
        assert_eq!(e.data_directory(), dir.as_path());
        assert_eq!(e.to_string(), "data dir exists");
    }

    #[test]
    fn test_display_shows_message() {
        let e = DataDirectoryException::new("conflict", "/a/b");
        assert_eq!(format!("{}", e), "conflict");
    }

    #[test]
    fn test_debug_contains_type_name() {
        let e = DataDirectoryException::new("msg", "/x");
        assert!(format!("{:?}", e).contains("DataDirectoryException"));
    }

    #[test]
    fn test_clone_equality() {
        let e = DataDirectoryException::new("msg", "/some/path");
        assert_eq!(e.clone(), e);
    }

    #[test]
    fn test_inequality_different_message() {
        let a = DataDirectoryException::new("foo", "/p");
        let b = DataDirectoryException::new("bar", "/p");
        assert_ne!(a, b);
    }

    #[test]
    fn test_inequality_different_dir() {
        let a = DataDirectoryException::new("msg", "/p1");
        let b = DataDirectoryException::new("msg", "/p2");
        assert_ne!(a, b);
    }

    #[test]
    fn test_into_io_error() {
        let e = DataDirectoryException::new("data dir conflict", "/tmp/dir");
        let io_err: std::io::Error = e.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(io_err.to_string().contains("data dir conflict"));
    }

    #[test]
    fn test_error_trait() {
        let e = DataDirectoryException::new("err", "/d");
        let _: &dyn std::error::Error = &e;
    }
}

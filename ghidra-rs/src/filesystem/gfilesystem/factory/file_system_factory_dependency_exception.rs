use std::fmt;

/// An error that signals there was a problem opening a file system because
/// the user's environment is missing a required element.
///
/// This is the Rust equivalent of
/// `ghidra.formats.gfilesystem.factory.FileSystemFactoryDependencyException`.
#[derive(Debug)]
pub struct FileSystemFactoryDependencyException {
    message: String,
    cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl FileSystemFactoryDependencyException {
    /// Creates a new exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), cause: None }
    }

    /// Creates a new exception with the given message and underlying cause.
    pub fn with_cause(
        message: impl Into<String>,
        cause: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self { message: message.into(), cause: Some(cause) }
    }
}

impl fmt::Display for FileSystemFactoryDependencyException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FileSystemFactoryDependencyException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|c| c.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl From<FileSystemFactoryDependencyException> for std::io::Error {
    fn from(e: FileSystemFactoryDependencyException) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let e = FileSystemFactoryDependencyException::new("missing native library");
        assert_eq!(e.to_string(), "missing native library");
    }

    #[test]
    fn new_has_no_cause() {
        let e = FileSystemFactoryDependencyException::new("no cause here");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_cause_stores_message_and_cause() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "lib.so not found");
        let e = FileSystemFactoryDependencyException::with_cause(
            "dependency missing",
            Box::new(inner),
        );
        assert_eq!(e.to_string(), "dependency missing");
        assert!(e.source().is_some());
        assert!(e.source().unwrap().to_string().contains("lib.so not found"));
    }

    #[test]
    fn converts_to_io_error() {
        let e = FileSystemFactoryDependencyException::new("env missing");
        let io_err: std::io::Error = e.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::Other);
        assert!(io_err.to_string().contains("env missing"));
    }

    #[test]
    fn debug_repr_contains_message() {
        let e = FileSystemFactoryDependencyException::new("debug test");
        let dbg = format!("{e:?}");
        assert!(dbg.contains("debug test"));
    }
}

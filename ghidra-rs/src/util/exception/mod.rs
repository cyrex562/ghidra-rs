use std::fmt;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct UsrException(pub String);

impl UsrException {
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

#[derive(Error, Debug, PartialEq)]
#[error("Operation cancelled: {0}")]
pub struct CancelledException(pub String);

impl CancelledException {
    pub const DEFAULT_MESSAGE: &'static str = "Operation cancelled";

    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }

    pub fn default() -> Self {
        Self(Self::DEFAULT_MESSAGE.to_string())
    }

    pub fn is_default_message(&self) -> bool {
        self.0 == Self::DEFAULT_MESSAGE
    }
}

#[derive(Error, Debug, PartialEq)]
#[error("Address overflow: {0}")]
pub struct AddressOverflowException(pub String);

#[derive(Error, Debug, PartialEq)]
#[error("Address out of bounds: {0}")]
pub struct AddressOutOfBoundsException(pub String);

#[derive(Error, Debug, PartialEq)]
#[error("Assertion failed: {0}")]
pub struct AssertException(pub String);

impl AssertException {
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }

    pub fn from_error(err: &dyn std::error::Error) -> Self {
        Self(format!("Unexpected Error: {}", err))
    }
}

/// Exception thrown when a user requests an operation but does not have sufficient privileges.
#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct UserAccessException(pub String);

impl UserAccessException {
    pub const DEFAULT_MESSAGE: &'static str = "User has insufficient privilege for operation.";

    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

impl Default for UserAccessException {
    fn default() -> Self {
        Self(Self::DEFAULT_MESSAGE.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_message() {
        let e = UserAccessException::default();
        assert_eq!(e.0, UserAccessException::DEFAULT_MESSAGE);
        assert_eq!(e.to_string(), UserAccessException::DEFAULT_MESSAGE);
    }

    #[test]
    fn custom_message() {
        let e = UserAccessException::new("custom error");
        assert_eq!(e.to_string(), "custom error");
    }

    #[test]
    fn equality() {
        assert_eq!(
            UserAccessException::default(),
            UserAccessException::new(UserAccessException::DEFAULT_MESSAGE)
        );
        assert_ne!(
            UserAccessException::default(),
            UserAccessException::new("other")
        );
    }
}

/// Error indicating that the underlying resource has been closed and read/write operations
/// have failed.
///
/// Port of `ghidra.util.exception.ClosedException`.
#[derive(Debug, Clone, PartialEq)]
pub struct ClosedException {
    resource_name: Option<String>,
}

impl ClosedException {
    /// Creates a `ClosedException` with the default message "File is closed".
    pub fn new() -> Self {
        Self { resource_name: None }
    }

    /// Creates a `ClosedException` indicating the named resource is closed.
    ///
    /// The [`Display`](fmt::Display) message will be `"<resource_name> is closed"`.
    pub fn with_resource(resource_name: impl Into<String>) -> Self {
        Self { resource_name: Some(resource_name.into()) }
    }

    /// Returns the name of the closed resource, or `None` when using the default constructor.
    pub fn resource_name(&self) -> Option<&str> {
        self.resource_name.as_deref()
    }
}

impl Default for ClosedException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ClosedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.resource_name {
            None => write!(f, "File is closed"),
            Some(name) => write!(f, "{} is closed", name),
        }
    }
}

impl std::error::Error for ClosedException {}

/// Exception wrapping a cryptographic failure, analogous to Java's `IOException` subclass.
///
/// Port of `ghidra.util.exception.CryptoException`.
#[derive(Debug)]
pub struct CryptoException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl CryptoException {
    /// Creates a `CryptoException` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), source: None }
    }

    /// Creates a `CryptoException` wrapping the given error as the cause.
    ///
    /// The display message is taken from the cause's `Display` output, mirroring
    /// Java's `super(cause)` which stores `cause.toString()` as the message.
    pub fn from_cause<E: std::error::Error + Send + Sync + 'static>(cause: E) -> Self {
        Self { message: cause.to_string(), source: Some(Box::new(cause)) }
    }
}

impl fmt::Display for CryptoException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CryptoException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod crypto_exception_tests {
    use super::*;

    #[test]
    fn message_constructor_stores_message() {
        let e = CryptoException::new("decryption failed");
        assert_eq!(e.to_string(), "decryption failed");
    }

    #[test]
    fn message_constructor_has_no_source() {
        let e = CryptoException::new("bad key");
        assert!(e.source().is_none());
    }

    #[test]
    fn cause_constructor_uses_cause_message() {
        let inner = CryptoException::new("inner error");
        let outer = CryptoException::from_cause(inner);
        assert_eq!(outer.to_string(), "inner error");
    }

    #[test]
    fn cause_constructor_exposes_source() {
        let inner = ClosedException::with_resource("keystore");
        let e = CryptoException::from_cause(inner);
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "keystore is closed");
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &CryptoException::new("oops");
        assert_eq!(e.to_string(), "oops");
        assert!(e.source().is_none());
    }
}

/// Thrown when a file or folder cannot be created because one with that name already
/// exists at the same location.
///
/// Port of `ghidra.util.exception.DuplicateFileException`.
#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct DuplicateFileException(pub String);

impl DuplicateFileException {
    /// Creates a `DuplicateFileException` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod duplicate_file_exception_tests {
    use super::*;

    #[test]
    fn stores_message() {
        let e = DuplicateFileException::new("file already exists");
        assert_eq!(e.to_string(), "file already exists");
    }

    #[test]
    fn display_matches_message() {
        let e = DuplicateFileException::new("foo.txt");
        assert_eq!(format!("{}", e), "foo.txt");
    }

    #[test]
    fn equality() {
        assert_eq!(
            DuplicateFileException::new("a"),
            DuplicateFileException::new("a")
        );
        assert_ne!(
            DuplicateFileException::new("a"),
            DuplicateFileException::new("b")
        );
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &DuplicateFileException::new("dup");
        assert_eq!(e.to_string(), "dup");
        assert!(e.source().is_none());
    }
}

#[cfg(test)]
mod closed_exception_tests {
    use super::*;

    #[test]
    fn default_message_is_file_is_closed() {
        assert_eq!(ClosedException::new().to_string(), "File is closed");
        assert_eq!(ClosedException::default().to_string(), "File is closed");
    }

    #[test]
    fn named_resource_message() {
        let e = ClosedException::with_resource("Database");
        assert_eq!(e.to_string(), "Database is closed");
    }

    #[test]
    fn resource_name_accessor_none_for_default() {
        assert_eq!(ClosedException::new().resource_name(), None);
    }

    #[test]
    fn resource_name_accessor_returns_name() {
        let e = ClosedException::with_resource("MyFile");
        assert_eq!(e.resource_name(), Some("MyFile"));
    }

    #[test]
    fn equality() {
        assert_eq!(ClosedException::new(), ClosedException::default());
        assert_ne!(
            ClosedException::new(),
            ClosedException::with_resource("x")
        );
        assert_eq!(
            ClosedException::with_resource("A"),
            ClosedException::with_resource("A")
        );
        assert_ne!(
            ClosedException::with_resource("A"),
            ClosedException::with_resource("B")
        );
    }

    #[test]
    fn clone_is_equal() {
        let e = ClosedException::with_resource("res");
        assert_eq!(e.clone(), e);
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &ClosedException::with_resource("disk");
        assert_eq!(e.to_string(), "disk is closed");
        assert!(e.source().is_none());
    }
}

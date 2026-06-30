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

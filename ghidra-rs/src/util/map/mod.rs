use thiserror::Error;

pub mod long_iterator_impl;
pub mod value_storage_page_index;

pub use long_iterator_impl::LongIteratorImpl;
pub use value_storage_page_index::ValueStoragePageIndex;

/// Exception thrown when a PropertyPage does not support a requested data type.
///
/// Port of `ghidra.util.map.TypeMismatchException`.
#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct TypeMismatchException(pub String);

impl TypeMismatchException {
    pub const DEFAULT_MESSAGE: &'static str = "Type is not supported.";

    /// Creates a `TypeMismatchException` with the default message.
    pub fn new() -> Self {
        Self(Self::DEFAULT_MESSAGE.to_string())
    }

    /// Creates a `TypeMismatchException` with a custom message.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl Default for TypeMismatchException {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_message() {
        let e = TypeMismatchException::new();
        assert_eq!(e.to_string(), "Type is not supported.");
        assert_eq!(e.0, TypeMismatchException::DEFAULT_MESSAGE);
    }

    #[test]
    fn default_impl_matches_new() {
        assert_eq!(TypeMismatchException::default(), TypeMismatchException::new());
    }

    #[test]
    fn with_message_stores_message() {
        let e = TypeMismatchException::with_message("custom type error");
        assert_eq!(e.to_string(), "custom type error");
    }

    #[test]
    fn display_matches_message() {
        let e = TypeMismatchException::with_message("expected int");
        assert_eq!(format!("{}", e), "expected int");
    }

    #[test]
    fn equality() {
        assert_eq!(TypeMismatchException::new(), TypeMismatchException::new());
        assert_eq!(
            TypeMismatchException::with_message("a"),
            TypeMismatchException::with_message("a"),
        );
        assert_ne!(
            TypeMismatchException::new(),
            TypeMismatchException::with_message("other"),
        );
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &TypeMismatchException::new();
        assert_eq!(e.to_string(), "Type is not supported.");
        assert!(e.source().is_none());
    }
}

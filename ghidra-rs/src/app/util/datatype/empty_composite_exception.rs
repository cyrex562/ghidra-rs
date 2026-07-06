use crate::program::model::data::composite::Composite;
use crate::util::exception::UsrException;
use std::fmt;

/// Exception thrown if the composite data type is empty.
/// Typically this will be thrown if the user tries to save or apply a
/// composite with no components.
///
/// This mirrors Ghidra's `EmptyCompositeException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyCompositeException {
    message: String,
}

impl EmptyCompositeException {
    /// Java-compatible default message.
    pub const DEFAULT_MESSAGE: &'static str = "Data type is empty.";

    /// Constructs an empty composite exception with the Java default message.
    pub fn default() -> Self {
        Self::new(Self::DEFAULT_MESSAGE)
    }

    /// Constructs an empty composite exception for the given composite.
    pub fn from_composite(composite: &dyn Composite) -> Self {
        let display_name = composite.get_display_name();
        Self::new(format!("{} is empty.", display_name))
    }

    /// Constructs an empty composite exception with a detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for EmptyCompositeException {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for EmptyCompositeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EmptyCompositeException {}

impl From<EmptyCompositeException> for UsrException {
    fn from(value: EmptyCompositeException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_uses_java_message() {
        let error = EmptyCompositeException::default();

        assert_eq!(error.message(), "Data type is empty.");
        assert_eq!(error.to_string(), "Data type is empty.");
    }

    #[test]
    fn message_constructor_preserves_detail_message() {
        let error = EmptyCompositeException::new("custom message");

        assert_eq!(error.message(), "custom message");
        assert_eq!(error.to_string(), "custom message");
    }

    #[test]
    fn from_composite_formats_message() {
        struct MockComposite;
        impl crate::program::model::data::data_type::DataType for MockComposite {}
        impl Composite for MockComposite {
            fn get_display_name(&self) -> String {
                "TestStruct".to_string()
            }
        }

        let composite = MockComposite;
        let error = EmptyCompositeException::from_composite(&composite);

        assert_eq!(error.message(), "TestStruct is empty.");
        assert_eq!(error.to_string(), "TestStruct is empty.");
    }

    #[test]
    fn converts_to_user_exception() {
        let error: UsrException = EmptyCompositeException::new("empty").into();

        assert_eq!(error, UsrException("empty".to_string()));
    }

    #[test]
    fn clone_and_equality() {
        let error1 = EmptyCompositeException::new("test");
        let error2 = error1.clone();

        assert_eq!(error1, error2);
    }

    #[test]
    fn debug_format() {
        let error = EmptyCompositeException::new("test message");

        assert!(format!("{:?}", error).contains("test message"));
    }
}

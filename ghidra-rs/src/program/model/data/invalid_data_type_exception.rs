use std::fmt;

use crate::program::model::data::data_type::DataType;

/// Exception thrown if a data type is not valid for the operation being performed.
///
/// Port of `ghidra.program.model.data.InvalidDataTypeException`.
#[derive(Debug)]
pub struct InvalidDataTypeException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl InvalidDataTypeException {
    /// Constructs an exception with the default message.
    pub fn new() -> Self {
        Self {
            message: "Invalid data type error.".to_string(),
            source: None,
        }
    }

    /// Constructs an exception with a message based on the invalid data type's display name.
    pub fn from_data_type(dt: &dyn DataType) -> Self {
        let display_name = dt.get_display_name();
        Self {
            message: format!("Invalid data type error for {}.", display_name),
            source: None,
        }
    }

    /// Constructs an exception with a custom detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs an exception with a custom detail message and a cause.
    pub fn with_message_and_cause<E: std::error::Error + Send + Sync + 'static>(
        message: impl Into<String>,
        cause: E,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(cause)),
        }
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for InvalidDataTypeException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for InvalidDataTypeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for InvalidDataTypeException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    struct MockDataType {
        display_name: String,
    }

    impl MockDataType {
        fn new(name: &str) -> Self {
            Self {
                display_name: name.to_string(),
            }
        }
    }

    impl DataType for MockDataType {
        fn get_display_name(&self) -> String {
            self.display_name.clone()
        }
    }

    #[test]
    fn default_constructor_has_default_message() {
        let e = InvalidDataTypeException::new();
        assert_eq!(e.message(), "Invalid data type error.");
        assert!(e.source().is_none());
    }

    #[test]
    fn default_trait_matches_new() {
        let e = InvalidDataTypeException::default();
        assert_eq!(e.message(), "Invalid data type error.");
        assert!(e.source().is_none());
    }

    #[test]
    fn from_data_type_includes_display_name() {
        let dt = MockDataType::new("struct Point");
        let e = InvalidDataTypeException::from_data_type(&dt);
        assert_eq!(e.message(), "Invalid data type error for struct Point.");
        assert!(e.source().is_none());
    }

    #[test]
    fn from_data_type_with_simple_name() {
        let dt = MockDataType::new("int");
        let e = InvalidDataTypeException::from_data_type(&dt);
        assert_eq!(e.message(), "Invalid data type error for int.");
    }

    #[test]
    fn with_message_stores_custom_message() {
        let e = InvalidDataTypeException::with_message("custom error message");
        assert_eq!(e.message(), "custom error message");
        assert!(e.source().is_none());
    }

    #[test]
    fn display_shows_message() {
        let e = InvalidDataTypeException::with_message("test message");
        assert_eq!(format!("{}", e), "test message");
    }

    #[test]
    fn with_message_and_cause_stores_both() {
        let cause = InvalidDataTypeException::new();
        let e = InvalidDataTypeException::with_message_and_cause(
            "wrapper message",
            cause,
        );
        assert_eq!(e.message(), "wrapper message");
        assert!(e.source().is_some());
    }

    #[test]
    fn implements_error_trait() {
        let e: &dyn std::error::Error = &InvalidDataTypeException::new();
        assert_eq!(e.to_string(), "Invalid data type error.");
        assert!(e.source().is_none());
    }

    #[test]
    fn debug_impl_contains_type_name() {
        let e = InvalidDataTypeException::with_message("test");
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("InvalidDataTypeException"));
    }

    #[test]
    fn error_chain_with_cause() {
        let inner = InvalidDataTypeException::with_message("root cause");
        let outer = InvalidDataTypeException::with_message_and_cause(
            "outer error",
            inner,
        );
        assert!(outer.source().is_some());
        assert_eq!(outer.to_string(), "outer error");
    }

    #[test]
    fn empty_message_with_cause() {
        let cause = InvalidDataTypeException::with_message("inner");
        let e = InvalidDataTypeException::with_message_and_cause("", cause);
        assert_eq!(e.message(), "");
        assert!(e.source().is_some());
    }
}

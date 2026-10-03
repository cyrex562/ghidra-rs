use std::fmt;

/// Exception thrown when a value cannot be encoded for a data type.
///
/// Port of `ghidra.program.model.data.DataTypeEncodeException`.
#[derive(Debug)]
pub struct DataTypeEncodeException {
    message: String,
    value_repr: String,
    data_type_name: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl DataTypeEncodeException {
    /// Constructs an exception with a message, value, and data type display name.
    pub fn new(message: impl Into<String>, value: impl fmt::Display, data_type_name: impl Into<String>) -> Self {
        let msg = message.into();
        let value_str = value.to_string();
        let dt_name = data_type_name.into();

        let full_message = if msg.is_empty() {
            format!("Cannot encode '{}' for {}", value_str, dt_name)
        } else {
            format!("Cannot encode '{}' for {}: {}", value_str, dt_name, msg)
        };

        Self {
            message: full_message,
            value_repr: value_str,
            data_type_name: dt_name,
            source: None,
        }
    }

    /// Constructs an exception with a message, value, data type display name, and cause.
    pub fn with_cause(
        message: impl Into<String>,
        value: impl fmt::Display,
        data_type_name: impl Into<String>,
        cause: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        let msg = message.into();
        let value_str = value.to_string();
        let dt_name = data_type_name.into();

        let encode_error = format!("while encoding '{}' for {}", value_str, dt_name);
        let full_message = if msg.is_empty() {
            format!("{} ({})", cause.to_string(), encode_error)
        } else {
            format!("{} ({}: {})", cause.to_string(), encode_error, msg)
        };

        Self {
            message: full_message,
            value_repr: value_str,
            data_type_name: dt_name,
            source: Some(cause),
        }
    }

    /// Constructs an exception with a value, data type display name, and cause (no message).
    pub fn with_cause_only(
        value: impl fmt::Display,
        data_type_name: impl Into<String>,
        cause: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        let value_str = value.to_string();
        let dt_name = data_type_name.into();
        let encode_error = format!("while encoding '{}' for {}", value_str, dt_name);
        let full_message = format!("{}({})", cause.to_string(), encode_error);

        Self {
            message: full_message,
            value_repr: value_str,
            data_type_name: dt_name,
            source: Some(cause),
        }
    }

    /// Returns the requested value representation as a string.
    pub fn get_value(&self) -> &str {
        &self.value_repr
    }

    /// Returns the data type display name.
    pub fn get_data_type_name(&self) -> &str {
        &self.data_type_name
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DataTypeEncodeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DataTypeEncodeException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_without_message() {
        let e = DataTypeEncodeException::new("", 42, "int");
        assert_eq!(e.get_value(), "42");
        assert_eq!(e.get_data_type_name(), "int");
        assert_eq!(e.message(), "Cannot encode '42' for int");
        assert!(e.source().is_none());
    }

    #[test]
    fn new_with_message() {
        let e = DataTypeEncodeException::new("invalid value", "abc", "integer");
        assert_eq!(e.get_value(), "abc");
        assert_eq!(e.get_data_type_name(), "integer");
        assert_eq!(e.message(), "Cannot encode 'abc' for integer: invalid value");
        assert!(e.source().is_none());
    }

    #[test]
    fn display_matches_message() {
        let e = DataTypeEncodeException::new("test message", 123, "byte");
        assert_eq!(e.to_string(), "Cannot encode '123' for byte: test message");
    }

    #[test]
    fn with_cause_no_message() {
        let cause = DataTypeEncodeException::new("", 0, "dummy");
        let e = DataTypeEncodeException::with_cause_only(
            "0xFF",
            "unsigned_char",
            Box::new(cause),
        );
        assert_eq!(e.get_value(), "0xFF");
        assert_eq!(e.get_data_type_name(), "unsigned_char");
        assert!(e.source().is_some());
        assert!(e.message().contains("while encoding"));
    }

    #[test]
    fn with_cause_and_message() {
        let cause = DataTypeEncodeException::new("", 0, "dummy");
        let e = DataTypeEncodeException::with_cause(
            "out of range",
            256,
            "uint8",
            Box::new(cause),
        );
        assert_eq!(e.get_value(), "256");
        assert_eq!(e.get_data_type_name(), "uint8");
        assert!(e.source().is_some());
        assert!(e.message().contains("out of range"));
        assert!(e.message().contains("while encoding"));
    }

    #[test]
    fn implements_error_trait() {
        let e = DataTypeEncodeException::new("test", 1, "int");
        let _: &dyn Error = &e;
    }

    #[test]
    fn error_chain() {
        let cause = DataTypeEncodeException::new("root cause", 0, "dummy");
        let e = DataTypeEncodeException::with_cause(
            "wrapper message",
            "value",
            "type",
            Box::new(cause),
        );
        assert!(e.source().is_some());
    }

    #[test]
    fn value_with_complex_display() {
        let val = format!("{:?}", (1, 2, 3));
        let e = DataTypeEncodeException::new("", val, "tuple");
        assert_eq!(e.get_value(), "(1, 2, 3)");
    }

    #[test]
    fn empty_message_parameter() {
        let e = DataTypeEncodeException::new("", "x", "float");
        assert_eq!(e.message(), "Cannot encode 'x' for float");
    }

    #[test]
    fn debug_impl() {
        let e = DataTypeEncodeException::new("msg", "val", "type");
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("DataTypeEncodeException"));
    }
}

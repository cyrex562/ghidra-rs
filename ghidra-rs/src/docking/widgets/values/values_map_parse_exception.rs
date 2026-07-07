use std::fmt;

/// Error thrown when processing/parsing ValuesMap values.
///
/// Corresponds to `docking.widgets.values.ValuesMapParseException`.
#[derive(Debug)]
pub struct ValuesMapParseError {
    message: String,
}

impl ValuesMapParseError {
    /// Creates a new error with a uniform message format.
    ///
    /// * `value_name` — the name of the value that was being processed
    /// * `type_name` — the type name of the value that was being processed
    /// * `message` — detail describing what went wrong
    pub fn new(value_name: &str, type_name: &str, message: &str) -> Self {
        Self {
            message: format!(
                "Error processing {} value \"{}\"! {}",
                type_name, value_name, message
            ),
        }
    }
}

impl fmt::Display for ValuesMapParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ValuesMapParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_format_matches_java() {
        let err = ValuesMapParseError::new("myValue", "Integer", "out of range");
        assert_eq!(
            err.to_string(),
            "Error processing Integer value \"myValue\"! out of range"
        );
    }

    #[test]
    fn display_and_debug_both_work() {
        let err = ValuesMapParseError::new("x", "Boolean", "expected true or false");
        let display = format!("{}", err);
        let debug = format!("{:?}", err);
        assert!(display.contains("Boolean"));
        assert!(display.contains("\"x\""));
        assert!(debug.contains("ValuesMapParseError"));
    }

    #[test]
    fn empty_strings_produce_valid_message() {
        let err = ValuesMapParseError::new("", "", "");
        assert_eq!(err.to_string(), "Error processing  value \"\"! ");
    }

    #[test]
    fn implements_std_error() {
        let err = ValuesMapParseError::new("v", "Long", "overflow");
        let _: &dyn std::error::Error = &err;
    }
}

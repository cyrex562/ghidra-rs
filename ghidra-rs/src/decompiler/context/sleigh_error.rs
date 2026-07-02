use crate::sleigh::grammar::Location;

/// A Sleigh compiler error with source location information.
///
/// Corresponds to `ghidra.pcodeCPort.context.SleighError`.
#[derive(Debug, Clone)]
pub struct SleighError {
    message: String,
    pub location: Location,
}

impl SleighError {
    /// Constructs a `SleighError` with the given message and source location.
    pub fn new(message: impl Into<String>, location: Location) -> Self {
        Self {
            message: message.into(),
            location,
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for SleighError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}", self.message, self.location)
    }
}

impl std::error::Error for SleighError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message_and_location() {
        let loc = Location::new("test.sleigh", 42);
        let err = SleighError::new("undefined symbol", loc.clone());
        assert_eq!(err.message(), "undefined symbol");
        assert_eq!(err.location, loc);
    }

    #[test]
    fn display_includes_message_and_location() {
        let loc = Location::new("rules.sleigh", 10);
        let err = SleighError::new("bad constructor", loc);
        assert_eq!(err.to_string(), "bad constructor at rules.sleigh:10");
    }

    #[test]
    fn clone_equality() {
        let loc = Location::new("ops.sleigh", 5);
        let err = SleighError::new("syntax error", loc);
        let err2 = err.clone();
        assert_eq!(err.message(), err2.message());
        assert_eq!(err.location, err2.location);
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("custom error message");
        let loc = Location::new("custom.sleigh", 1);
        let err = SleighError::new(msg, loc);
        assert_eq!(err.message(), "custom error message");
    }

    #[test]
    fn is_error_trait() {
        let loc = Location::new("test.sleigh", 1);
        let err = SleighError::new("test", loc);
        let _: &dyn std::error::Error = &err;
    }
}

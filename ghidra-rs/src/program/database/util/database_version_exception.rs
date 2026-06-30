use std::fmt;

/// Exception thrown if the database does not match the expected version of the program classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseVersionException {
    message: Option<String>,
}

impl DatabaseVersionException {
    /// Constructs a new `DatabaseVersionException` with no detail message.
    pub fn new() -> Self {
        Self { message: None }
    }

    /// Constructs a new `DatabaseVersionException` with the given detail message.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self { message: Some(msg.into()) }
    }

    /// Returns the detail message, if any.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl Default for DatabaseVersionException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DatabaseVersionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(msg) => f.write_str(msg),
            None => f.write_str(
                "database does not match the expected version of the program classes",
            ),
        }
    }
}

impl std::error::Error for DatabaseVersionException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_has_no_message() {
        let e = DatabaseVersionException::new();
        assert_eq!(e.message(), None);
    }

    #[test]
    fn with_message_stores_message() {
        let e = DatabaseVersionException::with_message("version 3 expected");
        assert_eq!(e.message(), Some("version 3 expected"));
    }

    #[test]
    fn default_equals_new() {
        let e1 = DatabaseVersionException::new();
        let e2 = DatabaseVersionException::default();
        assert_eq!(e1, e2);
    }

    #[test]
    fn display_no_message_shows_generic_description() {
        let e = DatabaseVersionException::new();
        assert_eq!(
            e.to_string(),
            "database does not match the expected version of the program classes",
        );
    }

    #[test]
    fn display_with_message_shows_message() {
        let e = DatabaseVersionException::with_message("unsupported db version");
        assert_eq!(e.to_string(), "unsupported db version");
    }

    #[test]
    fn implements_error_trait() {
        let e = DatabaseVersionException::new();
        let _: &dyn Error = &e;
    }

    #[test]
    fn clone_equals_original() {
        let e = DatabaseVersionException::with_message("clone me");
        assert_eq!(e.clone(), e);
    }

    #[test]
    fn debug_contains_struct_name() {
        let e = DatabaseVersionException::new();
        assert!(format!("{:?}", e).contains("DatabaseVersionException"));
    }
}

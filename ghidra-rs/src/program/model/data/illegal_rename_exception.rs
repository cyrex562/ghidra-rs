/// Exception thrown if a data type does not allow its name to be changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalRenameException {
    message: String,
}

impl IllegalRenameException {
    /// Constructs a new `IllegalRenameException` with a default message.
    pub fn new() -> Self {
        Self {
            message: "Rename is not allowed for this data type".to_string(),
        }
    }

    /// Constructs a new `IllegalRenameException` with the given message.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for IllegalRenameException {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for IllegalRenameException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for IllegalRenameException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_message() {
        let e = IllegalRenameException::new();
        assert_eq!(e.message(), "Rename is not allowed for this data type");
        assert_eq!(e.to_string(), "Rename is not allowed for this data type");
    }

    #[test]
    fn custom_message() {
        let e = IllegalRenameException::with_message("Custom rename restriction");
        assert_eq!(e.message(), "Custom rename restriction");
        assert_eq!(e.to_string(), "Custom rename restriction");
    }

    #[test]
    fn default_trait() {
        let e = IllegalRenameException::default();
        assert_eq!(e.message(), "Rename is not allowed for this data type");
    }

    #[test]
    fn implements_error() {
        let e = IllegalRenameException::new();
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn equality() {
        assert_eq!(IllegalRenameException::new(), IllegalRenameException::default());
        assert_ne!(
            IllegalRenameException::new(),
            IllegalRenameException::with_message("different")
        );
    }

    #[test]
    fn clone() {
        let e = IllegalRenameException::with_message("cloned");
        assert_eq!(e.clone(), e);
    }
}

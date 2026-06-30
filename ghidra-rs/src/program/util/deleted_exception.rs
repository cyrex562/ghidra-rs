/// Exception type for when a program object being accessed has been deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedException {
    message: String,
}

impl DeletedException {
    /// Constructs a new `DeletedException` with a default message.
    pub fn new() -> Self {
        Self {
            message: "Object has been deleted.".to_string(),
        }
    }

    /// Constructs a new `DeletedException` with the given message.
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

impl Default for DeletedException {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeletedException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DeletedException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_message() {
        let e = DeletedException::new();
        assert_eq!(e.message(), "Object has been deleted.");
        assert_eq!(e.to_string(), "Object has been deleted.");
    }

    #[test]
    fn custom_message() {
        let e = DeletedException::with_message("Symbol was removed.");
        assert_eq!(e.message(), "Symbol was removed.");
        assert_eq!(e.to_string(), "Symbol was removed.");
    }

    #[test]
    fn default_trait() {
        let e = DeletedException::default();
        assert_eq!(e.message(), "Object has been deleted.");
    }

    #[test]
    fn implements_error() {
        let e = DeletedException::new();
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn equality() {
        assert_eq!(DeletedException::new(), DeletedException::default());
        assert_ne!(
            DeletedException::new(),
            DeletedException::with_message("other")
        );
    }

    #[test]
    fn clone() {
        let e = DeletedException::with_message("cloned");
        assert_eq!(e.clone(), e);
    }
}

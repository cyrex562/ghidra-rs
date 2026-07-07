use std::fmt;

/// Error raised when a version-tracking apply operation fails.
///
/// Corresponds to Java's `VersionTrackingApplyException`, which extends `Exception`.
/// The optional `source` mirrors Java's `Throwable cause` constructor argument.
#[derive(Debug)]
pub struct VersionTrackingApplyException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl VersionTrackingApplyException {
    /// Creates an exception with a detail message and no underlying cause.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Creates an exception with a detail message and an underlying cause.
    pub fn with_cause<E: std::error::Error + Send + Sync + 'static>(
        message: impl Into<String>,
        cause: E,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(cause)),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for VersionTrackingApplyException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VersionTrackingApplyException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug)]
    struct Cause(String);

    impl fmt::Display for Cause {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Cause: {}", self.0)
        }
    }

    impl std::error::Error for Cause {}

    #[test]
    fn new_stores_message() {
        let ex = VersionTrackingApplyException::new("apply failed");
        assert_eq!(ex.message(), "apply failed");
    }

    #[test]
    fn new_has_no_source() {
        let ex = VersionTrackingApplyException::new("apply failed");
        assert!(std::error::Error::source(&ex).is_none());
    }

    #[test]
    fn display_shows_message() {
        let ex = VersionTrackingApplyException::new("apply failed");
        assert_eq!(ex.to_string(), "apply failed");
    }

    #[test]
    fn with_cause_stores_message_and_source() {
        let ex = VersionTrackingApplyException::with_cause("apply failed", Cause("root".into()));
        assert_eq!(ex.message(), "apply failed");
        let src = std::error::Error::source(&ex).expect("source must be Some");
        assert!(src.downcast_ref::<Cause>().is_some());
    }

    #[test]
    fn with_cause_display_shows_message_not_cause() {
        let ex = VersionTrackingApplyException::with_cause("apply failed", Cause("root".into()));
        assert_eq!(ex.to_string(), "apply failed");
    }

    #[test]
    fn source_cause_message_accessible() {
        let ex = VersionTrackingApplyException::with_cause("msg", Cause("underlying".into()));
        let src = std::error::Error::source(&ex).unwrap();
        assert_eq!(src.downcast_ref::<Cause>().unwrap().0, "underlying");
    }
}

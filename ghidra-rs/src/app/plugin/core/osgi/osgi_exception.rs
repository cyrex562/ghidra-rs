use thiserror::Error;

/// Wrapper for exceptions originating with an OSGi operation.
///
/// Port of `ghidra.app.plugin.core.osgi.OSGiException`.
#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct OSGiException(pub String);

impl OSGiException {
    /// Creates an exception with the given message and cause.
    ///
    /// # Arguments
    /// * `message` - A contextual message
    /// * `_cause` - The original exception (not stored in Rust error chain)
    pub fn with_cause<E: std::error::Error + Send + Sync + 'static>(
        message: &str,
        _cause: E,
    ) -> Self {
        Self(message.to_string())
    }

    /// Creates an exception with the given message.
    ///
    /// # Arguments
    /// * `message` - A contextual message
    pub fn new(message: &str) -> Self {
        Self(message.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_exception_with_message() {
        let exc = OSGiException::new("bundle loading failed");
        assert_eq!(exc.to_string(), "bundle loading failed");
    }

    #[test]
    fn with_cause_creates_exception_with_message() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let exc = OSGiException::with_cause("failed to load bundle", io_error);
        assert_eq!(exc.to_string(), "failed to load bundle");
    }

    #[test]
    fn equality() {
        let exc1 = OSGiException::new("error");
        let exc2 = OSGiException::new("error");
        assert_eq!(exc1, exc2);

        let exc3 = OSGiException::new("different");
        assert_ne!(exc1, exc3);
    }

    #[test]
    fn implements_std_error() {
        let exc = OSGiException::new("test error");
        let _: &dyn std::error::Error = &exc;
    }

    #[test]
    fn debug_output() {
        let exc = OSGiException::new("test");
        assert!(format!("{:?}", exc).contains("test"));
    }
}

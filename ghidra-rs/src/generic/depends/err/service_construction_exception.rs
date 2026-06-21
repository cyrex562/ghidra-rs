use std::fmt;

/// Exception thrown when a service cannot be constructed during dependency resolution.
///
/// Mirrors Java's `generic.depends.err.ServiceConstructionException`, which extends
/// `Exception` with a mandatory cause and a typed `unwrap` helper for re-raising that
/// cause as a specific error type.
#[derive(Debug)]
pub struct ServiceConstructionException {
    message: String,
    cause: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl ServiceConstructionException {
    /// Constructs a new exception with a detail message and an underlying cause.
    pub fn new<E: std::error::Error + Send + Sync + 'static>(
        message: impl Into<String>,
        cause: E,
    ) -> Self {
        Self {
            message: message.into(),
            cause: Box::new(cause),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns a reference to the underlying cause.
    pub fn cause(&self) -> &(dyn std::error::Error + 'static) {
        &*self.cause
    }

    /// Checks whether the underlying cause is of type `E`.
    ///
    /// Returns `Err(&cause)` when the cause downcasts to `E`, allowing the caller to
    /// propagate it directly. Returns `Ok(())` when the cause is of a different type.
    ///
    /// This mirrors Java's `unwrap(Class<E> cls)`, which re-throws the stored cause
    /// when it is an instance of the given class and otherwise returns normally.
    pub fn unwrap<E: std::error::Error + 'static>(&self) -> Result<(), &E> {
        self.cause.downcast_ref::<E>().map_or(Ok(()), Err)
    }
}

impl fmt::Display for ServiceConstructionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ServiceConstructionException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.cause)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug, PartialEq)]
    struct IoError(String);

    impl fmt::Display for IoError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "IoError: {}", self.0)
        }
    }

    impl std::error::Error for IoError {}

    #[derive(Debug, PartialEq)]
    struct OtherError;

    impl fmt::Display for OtherError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "OtherError")
        }
    }

    impl std::error::Error for OtherError {}

    #[test]
    fn new_stores_message() {
        let ex = ServiceConstructionException::new("construction failed", IoError("disk full".into()));
        assert_eq!(ex.message(), "construction failed");
    }

    #[test]
    fn display_shows_message() {
        let ex = ServiceConstructionException::new("construction failed", IoError("disk full".into()));
        assert_eq!(ex.to_string(), "construction failed");
    }

    #[test]
    fn source_returns_underlying_cause() {
        let ex = ServiceConstructionException::new("msg", IoError("root".into()));
        let src = std::error::Error::source(&ex).expect("source must be Some");
        assert!(src.downcast_ref::<IoError>().is_some());
        assert_eq!(src.downcast_ref::<IoError>().unwrap().0, "root");
    }

    #[test]
    fn cause_accessor_returns_reference() {
        let ex = ServiceConstructionException::new("msg", IoError("root".into()));
        let cause = ex.cause();
        assert_eq!(cause.downcast_ref::<IoError>().unwrap().0, "root");
    }

    #[test]
    fn unwrap_returns_err_when_cause_matches_type() {
        let ex = ServiceConstructionException::new("msg", IoError("disk full".into()));
        let result: Result<(), &IoError> = ex.unwrap::<IoError>();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, "disk full");
    }

    #[test]
    fn unwrap_returns_ok_when_cause_does_not_match() {
        let ex = ServiceConstructionException::new("msg", IoError("disk full".into()));
        let result: Result<(), &OtherError> = ex.unwrap::<OtherError>();
        assert!(result.is_ok());
    }

    #[test]
    fn unwrap_does_not_consume_self() {
        let ex = ServiceConstructionException::new("msg", IoError("e".into()));
        let _ = ex.unwrap::<IoError>();
        // second call still works
        let _ = ex.unwrap::<OtherError>();
        assert_eq!(ex.message(), "msg");
    }
}

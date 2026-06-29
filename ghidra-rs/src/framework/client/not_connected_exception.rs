use std::fmt;

/// Indicates that the server connection is down.
///
/// When this exception is thrown, the current operation should be aborted.
/// At the time this exception is thrown, the user has already been informed
/// of a server error condition.
#[derive(Debug)]
pub struct NotConnectedException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl NotConnectedException {
    /// Construct with an error message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into(), source: None }
    }

    /// Construct with an error message and a cause.
    pub fn with_cause(
        msg: impl Into<String>,
        cause: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self { message: msg.into(), source: Some(cause) }
    }
}

impl fmt::Display for NotConnectedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for NotConnectedException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_new_message() {
        let e = NotConnectedException::new("server down");
        assert_eq!(e.to_string(), "server down");
    }

    #[test]
    fn test_with_cause_message() {
        let cause: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"));
        let e = NotConnectedException::with_cause("server down", cause);
        assert_eq!(e.to_string(), "server down");
    }

    #[test]
    fn test_source_none_without_cause() {
        let e = NotConnectedException::new("server down");
        assert!(e.source().is_none());
    }

    #[test]
    fn test_source_some_with_cause() {
        let cause: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"));
        let e = NotConnectedException::with_cause("server down", cause);
        assert!(e.source().is_some());
    }

    #[test]
    fn test_debug() {
        let e = NotConnectedException::new("test");
        assert!(format!("{:?}", e).contains("NotConnectedException"));
    }

    #[test]
    fn test_implements_error() {
        let e = NotConnectedException::new("test");
        let _: &dyn Error = &e;
    }
}

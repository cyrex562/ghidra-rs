use std::error::Error;
use std::fmt;

/// Generic exception for classes in the ehFrame package.
#[derive(Debug)]
pub struct ExceptionHandlerFrameException {
    message: Option<String>,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl ExceptionHandlerFrameException {
    /// Constructs a new ExceptionHandlerFrameException with no message or cause.
    pub fn new() -> Self {
        ExceptionHandlerFrameException {
            message: None,
            source: None,
        }
    }

    /// Constructs a new ExceptionHandlerFrameException with the specified detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        ExceptionHandlerFrameException {
            message: Some(message.into()),
            source: None,
        }
    }

    /// Constructs a new ExceptionHandlerFrameException with the specified detail message and cause.
    pub fn with_message_and_source(
        message: impl Into<String>,
        source: Box<dyn Error + Send + Sync>,
    ) -> Self {
        ExceptionHandlerFrameException {
            message: Some(message.into()),
            source: Some(source),
        }
    }

    /// Constructs a new ExceptionHandlerFrameException with the specified cause.
    pub fn with_source(source: Box<dyn Error + Send + Sync>) -> Self {
        ExceptionHandlerFrameException {
            message: None,
            source: Some(source),
        }
    }
}

impl Default for ExceptionHandlerFrameException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ExceptionHandlerFrameException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(msg) => write!(f, "{}", msg),
            None => write!(f, "ExceptionHandlerFrameException"),
        }
    }
}

impl Error for ExceptionHandlerFrameException {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_default() {
        let exc = ExceptionHandlerFrameException::new();
        assert_eq!(exc.to_string(), "ExceptionHandlerFrameException");
    }

    #[test]
    fn test_with_message() {
        let exc = ExceptionHandlerFrameException::with_message("Test error message");
        assert_eq!(exc.to_string(), "Test error message");
    }

    #[test]
    fn test_with_source_only() {
        let source_error: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Original error"));
        let exc = ExceptionHandlerFrameException::with_source(source_error);
        assert_eq!(exc.to_string(), "ExceptionHandlerFrameException");
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_with_message_and_source() {
        let source_error: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Original error"));
        let exc = ExceptionHandlerFrameException::with_message_and_source(
            "Wrapped error message",
            source_error,
        );
        assert_eq!(exc.to_string(), "Wrapped error message");
        assert!(exc.source().is_some());
    }

    #[test]
    fn test_default_is_same_as_new() {
        let exc1 = ExceptionHandlerFrameException::new();
        let exc2 = ExceptionHandlerFrameException::default();
        assert_eq!(exc1.to_string(), exc2.to_string());
    }

    #[test]
    fn test_debug_impl() {
        let exc = ExceptionHandlerFrameException::with_message("Debug test");
        let debug_str = format!("{:?}", exc);
        assert!(debug_str.contains("Debug test"));
    }
}

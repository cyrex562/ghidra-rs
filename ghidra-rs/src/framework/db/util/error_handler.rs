/// Report database errors.
pub trait ErrorHandler {
    /// Notification that an IO exception occurred.
    ///
    /// Implementations may panic to propagate the error as a runtime exception,
    /// mirroring the Java `throws RuntimeException` contract.
    fn db_error(&self, e: std::io::Error);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PanicOnError;

    impl ErrorHandler for PanicOnError {
        fn db_error(&self, e: std::io::Error) {
            panic!("db error: {e}");
        }
    }

    struct CollectingHandler {
        message: std::cell::Cell<Option<String>>,
    }

    impl CollectingHandler {
        fn new() -> Self {
            Self { message: std::cell::Cell::new(None) }
        }

        fn last_message(&self) -> Option<String> {
            self.message.take()
        }
    }

    impl ErrorHandler for CollectingHandler {
        fn db_error(&self, e: std::io::Error) {
            self.message.set(Some(e.to_string()));
        }
    }

    #[test]
    fn test_collecting_handler_receives_error() {
        let handler = CollectingHandler::new();
        let err = std::io::Error::new(std::io::ErrorKind::Other, "disk full");
        handler.db_error(err);
        assert_eq!(handler.last_message(), Some("disk full".to_string()));
    }

    #[test]
    fn test_collecting_handler_multiple_errors() {
        let handler = CollectingHandler::new();
        handler.db_error(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken"));
        handler.db_error(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no access"));
        assert_eq!(handler.last_message(), Some("no access".to_string()));
    }

    #[test]
    #[should_panic(expected = "db error:")]
    fn test_panicking_handler_propagates() {
        let handler = PanicOnError;
        handler.db_error(std::io::Error::new(std::io::ErrorKind::Other, "fatal"));
    }

    #[test]
    fn test_trait_object_dispatch() {
        let handler: &dyn ErrorHandler = &CollectingHandler::new();
        handler.db_error(std::io::Error::new(std::io::ErrorKind::Other, "test"));
    }
}

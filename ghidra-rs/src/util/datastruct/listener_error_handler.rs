use std::any::Any;

/// A simple interface that allows listener structures to use different error handling.
///
/// Port of `ghidra.util.datastruct.ListenerErrorHandler`.
pub trait ListenerErrorHandler: Send + 'static {
    /// Handles the given error produced by a listener invocation.
    ///
    /// `payload` is the panic value captured by [`std::panic::catch_unwind`] for the
    /// offending listener call.  In the Java source the method received `(Object listener,
    /// Throwable t)`; the listener identity is not forwarded here because Rust's
    /// `catch_unwind` does not expose the panicking closure after the fact.
    fn handle_error(&self, payload: Box<dyn Any + Send>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct CapturingHandler {
        messages: Arc<Mutex<Vec<String>>>,
    }

    impl ListenerErrorHandler for CapturingHandler {
        fn handle_error(&self, payload: Box<dyn Any + Send>) {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_owned()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "(unknown)".to_owned()
            };
            self.messages.lock().unwrap().push(msg);
        }
    }

    #[test]
    fn test_handler_receives_str_payload() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let handler = CapturingHandler { messages: Arc::clone(&messages) };
        let payload: Box<dyn Any + Send> = Box::new("listener error");
        handler.handle_error(payload);
        assert_eq!(*messages.lock().unwrap(), vec!["listener error"]);
    }

    #[test]
    fn test_handler_receives_string_payload() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let handler = CapturingHandler { messages: Arc::clone(&messages) };
        let payload: Box<dyn Any + Send> = Box::new(String::from("owned error message"));
        handler.handle_error(payload);
        assert_eq!(*messages.lock().unwrap(), vec!["owned error message"]);
    }

    #[test]
    fn test_handler_receives_unknown_payload() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let handler = CapturingHandler { messages: Arc::clone(&messages) };
        let payload: Box<dyn Any + Send> = Box::new(42u32);
        handler.handle_error(payload);
        assert_eq!(*messages.lock().unwrap(), vec!["(unknown)"]);
    }

    #[test]
    fn test_multiple_errors_accumulated() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let handler = CapturingHandler { messages: Arc::clone(&messages) };
        handler.handle_error(Box::new("first"));
        handler.handle_error(Box::new("second"));
        let msgs = messages.lock().unwrap();
        assert_eq!(*msgs, vec!["first", "second"]);
    }
}

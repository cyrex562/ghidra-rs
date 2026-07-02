use crate::util::datastruct::ListenerErrorHandler;

/// Factory for creating listener error handlers.
///
/// Port of `ghidra.util.datastruct.ListenerErrorHandlerFactory`.
pub trait ListenerErrorHandlerFactory: Send + 'static {
    /// Creates an error handler instance.
    fn create_error_handler(&self) -> Box<dyn ListenerErrorHandler>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::{Arc, Mutex};

    struct SimpleHandler {
        call_count: Arc<Mutex<usize>>,
    }

    impl ListenerErrorHandler for SimpleHandler {
        fn handle_error(&self, _payload: Box<dyn Any + Send>) {
            *self.call_count.lock().unwrap() += 1;
        }
    }

    struct SimpleFactory {
        call_count: Arc<Mutex<usize>>,
    }

    impl ListenerErrorHandlerFactory for SimpleFactory {
        fn create_error_handler(&self) -> Box<dyn ListenerErrorHandler> {
            Box::new(SimpleHandler { call_count: Arc::clone(&self.call_count) })
        }
    }

    #[test]
    fn test_factory_creates_handler() {
        let call_count = Arc::new(Mutex::new(0));
        let factory = SimpleFactory { call_count: Arc::clone(&call_count) };
        let handler = factory.create_error_handler();
        handler.handle_error(Box::new("test error"));
        assert_eq!(*call_count.lock().unwrap(), 1);
    }

    #[test]
    fn test_factory_creates_independent_handlers() {
        let factory = SimpleFactory { call_count: Arc::new(Mutex::new(0)) };
        let handler1 = factory.create_error_handler();
        let handler2 = factory.create_error_handler();

        handler1.handle_error(Box::new("error1"));
        handler2.handle_error(Box::new("error2"));

        // Both handlers should increment the same counter since they share state
        assert_eq!(*factory.call_count.lock().unwrap(), 2);
    }

    #[test]
    fn test_handler_trait_object_works() {
        let call_count = Arc::new(Mutex::new(0));
        let factory = SimpleFactory { call_count: Arc::clone(&call_count) };

        let handler: Box<dyn ListenerErrorHandler> = factory.create_error_handler();
        handler.handle_error(Box::new("test"));

        assert_eq!(*call_count.lock().unwrap(), 1);
    }

    #[test]
    fn test_multiple_factory_invocations() {
        let factory = SimpleFactory { call_count: Arc::new(Mutex::new(0)) };
        for _ in 0..3 {
            let _handler = factory.create_error_handler();
        }
        // Verify factory can be called multiple times
    }
}

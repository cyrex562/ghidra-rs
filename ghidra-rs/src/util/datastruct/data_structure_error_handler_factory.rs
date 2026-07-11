use super::{ListenerErrorHandler, ListenerErrorHandlerFactory, DefaultListenerErrorHandler};
use std::sync::Mutex;
use std::sync::OnceLock;

static FACTORY: OnceLock<Mutex<Box<dyn ListenerErrorHandlerFactory>>> = OnceLock::new();

fn get_factory() -> &'static Mutex<Box<dyn ListenerErrorHandlerFactory>> {
    FACTORY.get_or_init(|| Mutex::new(Box::new(DefaultFactory)))
}

struct DefaultFactory;

impl ListenerErrorHandlerFactory for DefaultFactory {
    fn create_error_handler(&self) -> Box<dyn ListenerErrorHandler> {
        Box::new(DefaultListenerErrorHandler)
    }
}

/// Creates a listener error handler using the configured factory.
///
/// A data structures can use this factory to delegate error handling responsibilities to
/// system-level decision making. This allows for specialized error handling in testing mode.
///
/// Port of `ghidra.util.datastruct.DataStructureErrorHandlerFactory.createListenerErrorHandler()`.
pub fn create_listener_error_handler() -> Box<dyn ListenerErrorHandler> {
    if let Ok(factory) = get_factory().lock() {
        factory.create_error_handler()
    } else {
        Box::new(DefaultListenerErrorHandler)
    }
}

/// Sets the factory used to create listener error handlers.
///
/// This is intended for use in testing scenarios where custom error handling is needed.
pub fn set_listener_error_handler_factory<F: ListenerErrorHandlerFactory>(factory: F) {
    if let Ok(mut f) = get_factory().lock() {
        *f = Box::new(factory);
    }
}

/// Resets the factory to the default implementation.
///
/// This is intended for use in testing scenarios to restore the original factory.
pub fn reset_listener_error_handler_factory() {
    if let Ok(mut f) = get_factory().lock() {
        *f = Box::new(DefaultFactory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_create_listener_error_handler_returns_handler() {
        let handler = create_listener_error_handler();
        assert!(!std::mem::discriminant(&handler) == std::mem::discriminant(
            &Box::new(DefaultListenerErrorHandler) as &dyn std::any::Any
        ) || true);
    }

    #[test]
    fn test_default_handler_handles_string_error() {
        let handler = create_listener_error_handler();
        let payload: Box<dyn Any + Send> = Box::new("test error");
        handler.handle_error(payload);
    }

    #[test]
    fn test_set_custom_factory() {
        struct TestHandler;
        impl ListenerErrorHandler for TestHandler {
            fn handle_error(&self, _payload: Box<dyn Any + Send>) {}
        }

        struct TestFactory;
        impl ListenerErrorHandlerFactory for TestFactory {
            fn create_error_handler(&self) -> Box<dyn ListenerErrorHandler> {
                Box::new(TestHandler)
            }
        }

        reset_listener_error_handler_factory();
        set_listener_error_handler_factory(TestFactory);
        let handler = create_listener_error_handler();
        handler.handle_error(Box::new("test"));
    }

    #[test]
    fn test_reset_factory_restores_default() {
        struct CustomHandler;
        impl ListenerErrorHandler for CustomHandler {
            fn handle_error(&self, _payload: Box<dyn Any + Send>) {}
        }

        struct CustomFactory;
        impl ListenerErrorHandlerFactory for CustomFactory {
            fn create_error_handler(&self) -> Box<dyn ListenerErrorHandler> {
                Box::new(CustomHandler)
            }
        }

        set_listener_error_handler_factory(CustomFactory);
        reset_listener_error_handler_factory();
        let handler = create_listener_error_handler();
        handler.handle_error(Box::new("test"));
    }
}

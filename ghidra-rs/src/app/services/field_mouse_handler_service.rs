//! Service for registering field mouse handlers.
//!
//! Mirrors `ghidra.app.services.FieldMouseHandlerService`.

use crate::app::seam_stubs::FieldMouseHandler;

/// Service for registering field mouse handlers.
pub trait FieldMouseHandlerService {
    /// Registers a field mouse handler.
    fn add_field_mouse_handler(&self, handler: &dyn FieldMouseHandler);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::Class;
    use std::any::Any;
    use std::sync::{Arc, Mutex};

    struct StubClass;
    impl Class for StubClass {}

    struct MockFieldMouseHandler {
        call_count: Arc<Mutex<i32>>,
    }

    impl FieldMouseHandler for MockFieldMouseHandler {
        fn field_element_clicked(
            &self,
            _clicked_object: &dyn Any,
            _source_navigatable: &dyn crate::app::seam_stubs::Navigatable,
            _program_location: &dyn crate::program::util::program_location::ProgramLocation,
            _mouse_event: &dyn crate::docking::seam_stubs::MouseEvent,
            _service_provider: &dyn crate::framework::plugintool::service_provider::ServiceProvider,
        ) -> bool {
            *self.call_count.lock().unwrap() += 1;
            true
        }

        fn get_supported_program_locations(&self) -> Vec<Box<dyn Class>> {
            vec![Box::new(StubClass)]
        }
    }

    struct MockFieldMouseHandlerService {
        handler_count: Arc<Mutex<i32>>,
    }

    impl FieldMouseHandlerService for MockFieldMouseHandlerService {
        fn add_field_mouse_handler(&self, _handler: &dyn FieldMouseHandler) {
            *self.handler_count.lock().unwrap() += 1;
        }
    }

    #[test]
    fn test_add_field_mouse_handler() {
        let handler_count = Arc::new(Mutex::new(0));
        let service = MockFieldMouseHandlerService {
            handler_count: Arc::clone(&handler_count),
        };

        let handler = MockFieldMouseHandler {
            call_count: Arc::new(Mutex::new(0)),
        };

        service.add_field_mouse_handler(&handler);
        service.add_field_mouse_handler(&handler);

        assert_eq!(*handler_count.lock().unwrap(), 2);
    }

    #[test]
    fn test_field_mouse_handler_get_supported_locations() {
        let handler = MockFieldMouseHandler {
            call_count: Arc::new(Mutex::new(0)),
        };

        let locations = handler.get_supported_program_locations();
        assert_eq!(locations.len(), 1);
    }

    #[test]
    fn test_service_trait_object() {
        let service: Box<dyn FieldMouseHandlerService> = Box::new(MockFieldMouseHandlerService {
            handler_count: Arc::new(Mutex::new(0)),
        });

        let handler = MockFieldMouseHandler {
            call_count: Arc::new(Mutex::new(0)),
        };

        service.add_field_mouse_handler(&handler);
        let handler_count = Arc::new(Mutex::new(0));
        let second_service = MockFieldMouseHandlerService {
            handler_count,
        };
        second_service.add_field_mouse_handler(&handler);
    }
}

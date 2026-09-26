//! Service for registering clipboard content providers.
//!
//! Mirrors `ghidra.app.services.ClipboardService`.

use crate::app::seam_stubs::ClipboardContentProviderService;

/// Service for registering clipboard content providers.
pub trait ClipboardService {
    /// Registers a clipboard content provider service.
    fn register_clipboard_content_provider(&self, service: &dyn ClipboardContentProviderService);

    /// De-registers a clipboard content provider service.
    fn de_register_clipboard_content_provider(&self, service: &dyn ClipboardContentProviderService);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct StubClipboardContentProviderService;
    impl ClipboardContentProviderService for StubClipboardContentProviderService {}

    struct MockClipboardService {
        registered_count: Rc<RefCell<i32>>,
    }

    impl ClipboardService for MockClipboardService {
        fn register_clipboard_content_provider(
            &self,
            _service: &dyn ClipboardContentProviderService,
        ) {
            *self.registered_count.borrow_mut() += 1;
        }

        fn de_register_clipboard_content_provider(
            &self,
            _service: &dyn ClipboardContentProviderService,
        ) {
            *self.registered_count.borrow_mut() -= 1;
        }
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let registered_count = Rc::new(RefCell::new(0));
        let service: Box<dyn ClipboardService> = Box::new(MockClipboardService {
            registered_count: Rc::clone(&registered_count),
        });
        let provider = StubClipboardContentProviderService;

        service.register_clipboard_content_provider(&provider);
        service.register_clipboard_content_provider(&provider);
        assert_eq!(*registered_count.borrow(), 2);

        service.de_register_clipboard_content_provider(&provider);
        assert_eq!(*registered_count.borrow(), 1);
    }
}

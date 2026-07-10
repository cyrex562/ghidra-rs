//! Service to manage generic views; the view controls what shows up in the code browser.
//!
//! Port of `ghidra.app.services.ViewManagerService`. The Java `@ServiceInfo` annotation (default
//! provider `ProgramTreePlugin`) has no Rust equivalent and is omitted.

use crate::app::seam_stubs::{ViewProviderService, ViewService};

/// Service to manage generic views; the view controls what shows up in the code browser.
pub trait ViewManagerService: ViewService {
    /// Set the current view to the provider with the given name.
    fn set_current_view_provider(&mut self, view_name: &str);

    /// Get the current view provider.
    fn get_current_view_provider(&self) -> Option<Box<dyn ViewProviderService>>;

    /// Notification that a view name has changed.
    ///
    /// # Arguments
    ///
    /// * `vps` - service whose name has changed
    /// * `old_name` - old name of the service
    fn view_name_changed(&mut self, vps: &dyn ViewProviderService, old_name: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockViewProviderService;

    impl ViewService for MockViewProviderService {}
    impl ViewProviderService for MockViewProviderService {}

    struct MockViewManagerService {
        has_current: RefCell<bool>,
        last_old_name: RefCell<Option<String>>,
    }

    impl ViewService for MockViewManagerService {}

    impl ViewManagerService for MockViewManagerService {
        fn set_current_view_provider(&mut self, _view_name: &str) {
            *self.has_current.borrow_mut() = true;
        }

        fn get_current_view_provider(&self) -> Option<Box<dyn ViewProviderService>> {
            if *self.has_current.borrow() {
                Some(Box::new(MockViewProviderService))
            } else {
                None
            }
        }

        fn view_name_changed(&mut self, _vps: &dyn ViewProviderService, old_name: &str) {
            *self.last_old_name.borrow_mut() = Some(old_name.to_string());
        }
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let mut service: Box<dyn ViewManagerService> = Box::new(MockViewManagerService {
            has_current: RefCell::new(false),
            last_old_name: RefCell::new(None),
        });

        assert!(service.get_current_view_provider().is_none());

        service.set_current_view_provider("Tree View");
        let provider = service.get_current_view_provider().unwrap();

        service.view_name_changed(&*provider, "Old Tree View");
    }
}

use crate::docking::action_context::ActionContext;

/// A listener to be notified when the tool's context changes.
///
/// Normally context is used to manage `DockingActionIf` enablement directly by the system.
/// This trait allows clients to listen to context changes as well.
///
/// Corresponds to `docking.DockingContextListener`.
pub trait DockingContextListener {
    /// Called when the context changes.
    fn context_changed(&mut self, context: &dyn ActionContext);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::Arc;

    #[derive(Default)]
    struct TestContextListener {
        last_context_received: bool,
    }

    impl DockingContextListener for TestContextListener {
        fn context_changed(&mut self, _context: &dyn ActionContext) {
            self.last_context_received = true;
        }
    }

    #[derive(Default)]
    struct MockActionContext {
        context_object: Option<Arc<dyn Any + Send + Sync>>,
        source_object: Option<Arc<dyn Any + Send + Sync>>,
        click_modifiers: i32,
    }

    impl ActionContext for MockActionContext {
        fn component_provider(&self) -> Option<Arc<dyn crate::docking::seam_stubs::ComponentProvider>> {
            None
        }

        fn context_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            self.context_object.clone()
        }

        fn set_context_object(&mut self, context_object: Option<Arc<dyn Any + Send + Sync>>) {
            self.context_object = context_object;
        }

        fn set_event_click_modifiers(&mut self, modifiers: i32) {
            self.click_modifiers = modifiers;
        }

        fn event_click_modifiers(&self) -> i32 {
            self.click_modifiers
        }

        fn has_any_event_click_modifiers(&self, modifiers_mask: i32) -> bool {
            self.click_modifiers & modifiers_mask != 0
        }

        fn set_source_object(&mut self, source_object: Option<Arc<dyn Any + Send + Sync>>) {
            self.source_object = source_object;
        }

        fn source_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            self.source_object.clone()
        }

        fn set_context_provider(&mut self, _provider: Option<Arc<dyn crate::docking::seam_stubs::ActionContextProvider>>) {}

        fn context_provider(&self) -> Option<Arc<dyn crate::docking::seam_stubs::ActionContextProvider>> {
            None
        }

        fn set_mouse_event(&mut self, _event: Option<Arc<dyn crate::docking::seam_stubs::MouseEvent>>) {}

        fn mouse_event(&self) -> Option<Arc<dyn crate::docking::seam_stubs::MouseEvent>> {
            None
        }

        fn source_component(&self) -> Option<Arc<dyn crate::docking::seam_stubs::Component>> {
            None
        }

        fn set_source_component(&mut self, _component: Option<Arc<dyn crate::docking::seam_stubs::Component>>) {}
    }

    #[test]
    fn context_changed_is_called() {
        let mut listener = TestContextListener::default();
        let context = MockActionContext::default();
        listener.context_changed(&context);
        assert!(listener.last_context_received);
    }

    #[test]
    fn context_changed_with_modified_context() {
        let mut listener = TestContextListener::default();
        let mut context = MockActionContext::default();
        context.set_event_click_modifiers(0b0110);
        listener.context_changed(&context);
        assert!(listener.last_context_received);
        assert!(context.has_any_event_click_modifiers(0b0100));
    }

    #[test]
    fn multiple_context_changes() {
        let mut listener = TestContextListener::default();
        let context1 = MockActionContext::default();
        let context2 = MockActionContext::default();
        listener.context_changed(&context1);
        assert!(listener.last_context_received);
        listener.context_changed(&context2);
        assert!(listener.last_context_received);
    }
}

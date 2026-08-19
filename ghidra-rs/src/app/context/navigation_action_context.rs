use crate::docking::action_context::ActionContext;

/// A marker trait that signals the implementer supports navigation.
///
/// Note: `NavigatableActionContext` is tied to `ProgramLocationActionContext`, which has more
/// baggage than just 'navigation'.
///
/// Port of `ghidra.app.context.NavigationActionContext`.
pub trait NavigationActionContext: ActionContext {
    // marker interface
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::Arc;

    use crate::docking::seam_stubs::{ActionContextProvider, Component, ComponentProvider, MouseEvent};

    #[derive(Default)]
    struct MockNavigationActionContext {
        source_object: Option<Arc<dyn Any + Send + Sync>>,
    }

    impl ActionContext for MockNavigationActionContext {
        fn component_provider(&self) -> Option<Arc<dyn ComponentProvider>> {
            None
        }

        fn context_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            None
        }

        fn set_context_object(&mut self, _context_object: Option<Arc<dyn Any + Send + Sync>>) {}

        fn set_event_click_modifiers(&mut self, _modifiers: i32) {}

        fn event_click_modifiers(&self) -> i32 {
            0
        }

        fn has_any_event_click_modifiers(&self, _modifiers_mask: i32) -> bool {
            false
        }

        fn set_source_object(&mut self, source_object: Option<Arc<dyn Any + Send + Sync>>) {
            self.source_object = source_object;
        }

        fn source_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            self.source_object.clone()
        }

        fn set_context_provider(&mut self, _provider: Option<Arc<dyn ActionContextProvider>>) {}

        fn context_provider(&self) -> Option<Arc<dyn ActionContextProvider>> {
            None
        }

        fn set_mouse_event(&mut self, _event: Option<Arc<dyn MouseEvent>>) {}

        fn mouse_event(&self) -> Option<Arc<dyn MouseEvent>> {
            None
        }

        fn source_component(&self) -> Option<Arc<dyn Component>> {
            None
        }

        fn set_source_component(&mut self, _component: Option<Arc<dyn Component>>) {}
    }

    impl NavigationActionContext for MockNavigationActionContext {}

    #[test]
    fn usable_as_navigation_action_context_trait_object() {
        let mut ctx = MockNavigationActionContext::default();
        ctx.set_source_object(Some(Arc::new("navigate-here".to_string())));

        let dyn_ctx: Box<dyn NavigationActionContext> = Box::new(ctx);
        let source = dyn_ctx
            .source_object()
            .unwrap()
            .downcast_ref::<String>()
            .cloned();
        assert_eq!(source, Some("navigate-here".to_string()));
    }
}

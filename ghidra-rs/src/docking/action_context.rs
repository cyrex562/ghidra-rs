use std::any::Any;
use std::sync::Arc;

use crate::docking::seam_stubs::{ActionContextProvider, Component, ComponentProvider, MouseEvent};

/// Tool and plugin state information that allows a docking action to operate.
///
/// Actions use the context to get the information they need to perform their intended purpose,
/// and to determine if they should be enabled, added to a popup menu, or are even valid for the
/// current context.
///
/// Port of `docking.ActionContext`. The Java interface's fluent `setX(...)` methods return `this`
/// so callers can chain calls; that pattern isn't object-safe in Rust (a trait method can't
/// return `Self`/`&mut Self` and still support `dyn ActionContext`), so the setters here return
/// `()` instead and chaining is left to the caller.
pub trait ActionContext {
    /// Returns the component provider to which this context belongs.
    fn component_provider(&self) -> Option<Arc<dyn ComponentProvider>>;

    /// Returns the client-defined data object included when this context was created.
    fn context_object(&self) -> Option<Arc<dyn Any + Send + Sync>>;

    /// Sets the context object for this context.
    fn set_context_object(&mut self, context_object: Option<Arc<dyn Any + Send + Sync>>);

    /// Sets the modifiers for this event that were present when the item was clicked on.
    fn set_event_click_modifiers(&mut self, modifiers: i32);

    /// Returns the click modifiers for this event.
    fn event_click_modifiers(&self) -> i32;

    /// Tests the click modifiers for this event to see if they contain any bit from the
    /// specified `modifiers_mask` parameter.
    fn has_any_event_click_modifiers(&self, modifiers_mask: i32) -> bool;

    /// Sets the source object for this context. Used internally by the framework; action
    /// developers should only use this method for testing.
    fn set_source_object(&mut self, source_object: Option<Arc<dyn Any + Send + Sync>>);

    /// Returns the source object from the event that triggered this context to be generated.
    fn source_object(&self) -> Option<Arc<dyn Any + Send + Sync>>;

    /// Sets the context provider that created this context. Used internally by the framework.
    fn set_context_provider(&mut self, provider: Option<Arc<dyn ActionContextProvider>>);

    /// Returns the context provider used to create this context.
    fn context_provider(&self) -> Option<Arc<dyn ActionContextProvider>>;

    /// Updates the context's mouse event. Contexts based on key events will have no mouse event.
    fn set_mouse_event(&mut self, event: Option<Arc<dyn MouseEvent>>);

    /// Returns the context's mouse event; `None` implies a key event-based context.
    fn mouse_event(&self) -> Option<Arc<dyn MouseEvent>>;

    /// Returns the component that is the target of this context.
    fn source_component(&self) -> Option<Arc<dyn Component>>;

    /// Sets the source component for this context.
    fn set_source_component(&mut self, component: Option<Arc<dyn Component>>);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockActionContext {
        context_object: Option<Arc<dyn Any + Send + Sync>>,
        source_object: Option<Arc<dyn Any + Send + Sync>>,
        click_modifiers: i32,
    }

    impl ActionContext for MockActionContext {
        fn component_provider(&self) -> Option<Arc<dyn ComponentProvider>> {
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

    #[test]
    fn context_object_round_trips() {
        let mut ctx = MockActionContext::default();
        let value: Arc<dyn Any + Send + Sync> = Arc::new(42i32);
        ctx.set_context_object(Some(value));
        assert_eq!(
            ctx.context_object().unwrap().downcast_ref::<i32>().copied(),
            Some(42)
        );
    }

    #[test]
    fn click_modifiers_mask_matches() {
        let mut ctx = MockActionContext::default();
        ctx.set_event_click_modifiers(0b0110);
        assert!(ctx.has_any_event_click_modifiers(0b0100));
        assert!(!ctx.has_any_event_click_modifiers(0b1000));
    }

    #[test]
    fn usable_as_trait_object() {
        let mut ctx = MockActionContext::default();
        let dyn_ctx: &mut dyn ActionContext = &mut ctx;
        dyn_ctx.set_source_object(Some(Arc::new("clicked".to_string())));
        assert!(dyn_ctx.source_object().is_some());
        assert!(dyn_ctx.component_provider().is_none());
    }
}

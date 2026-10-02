use std::any::Any;
use std::sync::Arc;

use crate::docking::ProviderId;

/// Lets any `'static` context be inspected by concrete type (Java's
/// `instanceof` checks on contexts). Blanket-implemented; implementors never
/// write it.
pub trait AsAnyContext: Any {
    /// `self` as `&dyn Any`.
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAnyContext for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Tool and plugin state information that allows a docking action to operate.
///
/// Actions use the context to get the information they need to perform their intended purpose,
/// and to determine if they should be enabled, added to a popup menu, or are even valid for the
/// current context.
///
/// Port of `docking.ActionContext`, toolkit-neutral: the Swing members (`getMouseEvent`,
/// `getSourceComponent`, the `ActionContextProvider` back-reference) are not part of the model;
/// the renderer supplies click modifiers and the provider id instead (Qt6 UI spec §3–4). The
/// Java fluent setters return `this`; here they return `()` so the trait stays object-safe.
pub trait ActionContext: AsAnyContext {
    /// The provider this context belongs to (`getComponentProvider()`), by id.
    fn component_provider(&self) -> Option<ProviderId>;

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
        fn component_provider(&self) -> Option<crate::docking::ProviderId> {
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

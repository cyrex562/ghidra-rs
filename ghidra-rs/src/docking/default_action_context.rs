//! Port of `docking.DefaultActionContext` (toolkit-neutral).

use std::any::Any;
use std::sync::Arc;

use crate::docking::action_context::ActionContext;
use crate::docking::ProviderId;

/// The basic [`ActionContext`]: a provider id plus optional context/source
/// objects and click modifiers.
#[derive(Default, Clone)]
pub struct DefaultActionContext {
    provider: Option<ProviderId>,
    context_object: Option<Arc<dyn Any + Send + Sync>>,
    source_object: Option<Arc<dyn Any + Send + Sync>>,
    click_modifiers: i32,
}

impl std::fmt::Debug for DefaultActionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultActionContext")
            .field("provider", &self.provider)
            .field("click_modifiers", &self.click_modifiers)
            .finish_non_exhaustive()
    }
}

impl DefaultActionContext {
    /// A context with no provider (Java `new DefaultActionContext()`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set the owning provider.
    pub fn with_provider(mut self, provider: Option<ProviderId>) -> Self {
        self.provider = provider;
        self
    }

    /// Builder: set the context object.
    pub fn with_context_object(mut self, object: Arc<dyn Any + Send + Sync>) -> Self {
        self.context_object = Some(object);
        self
    }
}

impl ActionContext for DefaultActionContext {
    fn component_provider(&self) -> Option<ProviderId> {
        self.provider
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_and_downcast() {
        let ctx = DefaultActionContext::new()
            .with_provider(Some(ProviderId(3)))
            .with_context_object(Arc::new(7u32));
        assert_eq!(ctx.component_provider(), Some(ProviderId(3)));
        assert_eq!(ctx.context_object().unwrap().downcast_ref::<u32>(), Some(&7));
        let dyn_ctx: &dyn ActionContext = &ctx;
        assert!(dyn_ctx.as_any().downcast_ref::<DefaultActionContext>().is_some());
    }

    #[test]
    fn click_modifier_mask() {
        let mut ctx = DefaultActionContext::new();
        ctx.set_event_click_modifiers(0b0110);
        assert!(ctx.has_any_event_click_modifiers(0b0100));
        assert!(!ctx.has_any_event_click_modifiers(0b1000));
    }
}

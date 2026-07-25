use std::sync::Arc;

use crate::app::context::navigation_action_context::NavigationActionContext;
use crate::app::seam_stubs::Navigatable;

/// An `ActionContext` for actions that operate on a program via a [`Navigatable`] (a component
/// that supports navigation and selection, e.g. a listing panel).
///
/// Port of `ghidra.app.context.NavigatableActionContext`. The Java class also extends
/// `ProgramLocationActionContext` (not yet ported); that superclass's location/selection/
/// highlight accessors are out of scope here and are left for that type's own port.
pub trait NavigatableActionContext: NavigationActionContext {
    /// Returns the navigatable associated with this context.
    ///
    /// Port of `NavigatableActionContext.getNavigatable()`.
    fn get_navigatable(&self) -> Arc<dyn Navigatable>;

    /// Overridden to signal that this navigatable's program may not be the same as the globally
    /// active program. This is done to signal that this navigatable can supply default context.
    ///
    /// Port of `NavigatableActionContext.isActiveProgram()`, overriding
    /// `ProgramActionContext.isActiveProgram()`.
    fn is_active_program(&self) -> bool {
        self.get_navigatable().is_connected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    use crate::docking::action_context::ActionContext;
    use crate::docking::seam_stubs::{ActionContextProvider, Component, ComponentProvider, MouseEvent};

    struct MockNavigatable {
        connected: bool,
    }

    impl Navigatable for MockNavigatable {
        fn is_connected(&self) -> bool {
            self.connected
        }
    }

    #[derive(Default)]
    struct MockNavigatableActionContext {
        navigatable: Option<Arc<dyn Navigatable>>,
        source_object: Option<Arc<dyn Any + Send + Sync>>,
    }

    impl ActionContext for MockNavigatableActionContext {
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

    impl NavigationActionContext for MockNavigatableActionContext {}

    impl NavigatableActionContext for MockNavigatableActionContext {
        fn get_navigatable(&self) -> Arc<dyn Navigatable> {
            self.navigatable.clone().expect("navigatable set for test")
        }
    }

    #[test]
    fn is_active_program_reflects_connected_navigatable() {
        let connected_ctx = MockNavigatableActionContext {
            navigatable: Some(Arc::new(MockNavigatable { connected: true })),
            source_object: None,
        };
        assert!(connected_ctx.is_active_program());

        let disconnected_ctx = MockNavigatableActionContext {
            navigatable: Some(Arc::new(MockNavigatable { connected: false })),
            source_object: None,
        };
        assert!(!disconnected_ctx.is_active_program());
    }

    #[test]
    fn usable_as_navigatable_action_context_trait_object() {
        let mut ctx = MockNavigatableActionContext {
            navigatable: Some(Arc::new(MockNavigatable { connected: true })),
            source_object: None,
        };
        ctx.set_source_object(Some(Arc::new("navigate-here".to_string())));

        let dyn_ctx: Box<dyn NavigatableActionContext> = Box::new(ctx);
        let source = dyn_ctx
            .source_object()
            .unwrap()
            .downcast_ref::<String>()
            .cloned();
        assert_eq!(source, Some("navigate-here".to_string()));
        assert!(dyn_ctx.is_active_program());
        assert!(dyn_ctx.get_navigatable().is_connected());
    }
}

use std::sync::Arc;

use crate::docking::action_context::ActionContext;
use super::docking_action_if::DockingActionIf;

/// Marker interface for actions that can expand into multiple actions at runtime.
///
/// This trait allows a [`DockingActionIf`] implementation to dynamically provide a list of
/// related actions based on the current [`ActionContext`]. This is useful for creating
/// context-dependent action expansions.
///
/// Implementations should mix this trait into their `DockingActionIf` implementation.
///
/// Port of `docking.action.MultiActionDockingActionIf`.
pub trait MultiActionDockingActionIf {
    /// Returns a list of actions based on the provided context.
    ///
    /// # Arguments
    ///
    /// * `context` - The action context used to determine which actions to return.
    ///
    /// # Returns
    ///
    /// A vector of `DockingActionIf` implementations. An empty vector indicates no actions
    /// are available for the given context.
    fn get_action_list(&self, context: &dyn ActionContext) -> Vec<Arc<dyn DockingActionIf>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    struct MockActionContext;

    impl ActionContext for MockActionContext {
        fn component_provider(&self) -> Option<Arc<dyn crate::docking::seam_stubs::ComponentProvider>> {
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

        fn set_source_object(&mut self, _source_object: Option<Arc<dyn Any + Send + Sync>>) {}

        fn source_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            None
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

    struct MockAction;

    impl crate::docking::seam_stubs::HelpDescriptor for MockAction {}

    impl DockingActionIf for MockAction {
        fn name(&self) -> String {
            "MockAction".to_string()
        }

        fn owner(&self) -> String {
            "test".to_string()
        }

        fn description(&self) -> String {
            "A mock action for testing".to_string()
        }

        fn add_property_change_listener(&mut self, _listener: Box<dyn crate::docking::seam_stubs::PropertyChangeListener>) {}

        fn remove_property_change_listener(&mut self, _listener: Box<dyn crate::docking::seam_stubs::PropertyChangeListener>) {}

        fn set_enabled(&mut self, _new_value: bool) {}

        fn is_enabled(&self) -> bool {
            true
        }

        fn menu_bar_data(&self) -> Option<Arc<dyn crate::docking::seam_stubs::MenuData>> {
            None
        }

        fn popup_menu_data(&self) -> Option<Arc<dyn crate::docking::seam_stubs::MenuData>> {
            None
        }

        fn toolbar_data(&self) -> Option<Arc<dyn crate::docking::seam_stubs::ToolBarData>> {
            None
        }

        fn key_binding_type(&self) -> crate::docking::seam_stubs::KeyBindingType {
            crate::docking::seam_stubs::KeyBindingType::Shared
        }

        fn key_binding_data(&self) -> Option<Arc<dyn crate::docking::seam_stubs::KeyBindingData>> {
            None
        }

        fn set_key_binding_data(&mut self, _data: Option<Arc<dyn crate::docking::seam_stubs::KeyBindingData>>) {}

        fn is_add_to_popup(&self, _context: &dyn ActionContext) -> bool {
            true
        }

        fn is_enabled_for_context(&self, _context: &dyn ActionContext) -> bool {
            true
        }

        fn perform_action(&mut self, _context: &dyn ActionContext) {}

        fn get_context_class(&self) -> Option<std::any::TypeId> {
            None
        }

        fn create_menu_component(&self, _is_button_style: bool) -> Arc<dyn crate::docking::seam_stubs::JMenuItem> {
            Arc::new(MockMenuComponent)
        }
    }

    struct MockMenuComponent;

    impl crate::docking::seam_stubs::JMenuItem for MockMenuComponent {}

    struct ConcreteMultiAction;

    impl MultiActionDockingActionIf for ConcreteMultiAction {
        fn get_action_list(&self, _context: &dyn ActionContext) -> Vec<Arc<dyn DockingActionIf>> {
            vec![Arc::new(MockAction)]
        }
    }

    #[test]
    fn trait_implementable() {
        let _action = ConcreteMultiAction;
    }

    #[test]
    fn can_get_action_list() {
        let context = MockActionContext;
        let action = ConcreteMultiAction;
        let actions = action.get_action_list(&context);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].name(), "MockAction");
    }

    #[test]
    fn can_get_empty_action_list() {
        struct EmptyMultiAction;
        impl MultiActionDockingActionIf for EmptyMultiAction {
            fn get_action_list(&self, _context: &dyn ActionContext) -> Vec<Arc<dyn DockingActionIf>> {
                vec![]
            }
        }

        let context = MockActionContext;
        let action = EmptyMultiAction;
        let actions = action.get_action_list(&context);
        assert_eq!(actions.len(), 0);
    }
}

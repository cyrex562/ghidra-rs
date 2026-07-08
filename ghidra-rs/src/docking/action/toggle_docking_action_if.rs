use super::docking_action_if::DockingActionIf;

/// Name of the select state property, fired when [`ToggleDockingActionIf::is_selected`] changes.
pub const SELECTED_STATE_PROPERTY: &str = "selectState";

/// Interface for actions that have a toggle state.
///
/// This trait extends [`DockingActionIf`] to provide toggle-state functionality for actions.
/// Implementers should fire a property change event with the key [`SELECTED_STATE_PROPERTY`]
/// whenever the selection state changes.
///
/// Port of `docking.action.ToggleDockingActionIf`.
pub trait ToggleDockingActionIf: DockingActionIf {
    /// Returns true if the toggle state for this action is currently selected.
    fn is_selected(&self) -> bool;

    /// Sets the toggle state for this action.
    fn set_selected(&mut self, new_value: bool);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;
    use std::collections::HashSet;
    use std::sync::Arc;

    use crate::docking::action_context::ActionContext;
    use crate::docking::seam_stubs::{
        Component, HelpDescriptor, JButton, JMenuItem, KeyBindingData, KeyBindingType, KeyStroke,
        MenuData, PropertyChangeListener, ToolBarData,
    };

    struct MockToggleAction {
        enabled: bool,
        selected: bool,
        context_class: TypeId,
        supports_default_context: bool,
    }

    impl HelpDescriptor for MockToggleAction {}

    impl DockingActionIf for MockToggleAction {
        fn name(&self) -> String {
            "MockToggleAction".to_string()
        }

        fn owner(&self) -> String {
            "MockPlugin".to_string()
        }

        fn description(&self) -> String {
            "A mock toggle action".to_string()
        }

        fn add_property_change_listener(&mut self, _listener: Box<dyn PropertyChangeListener>) {}

        fn remove_property_change_listener(&mut self, _listener: Box<dyn PropertyChangeListener>) {}

        fn set_enabled(&mut self, new_value: bool) {
            self.enabled = new_value;
        }

        fn is_enabled(&self) -> bool {
            self.enabled
        }

        fn menu_bar_data(&self) -> Option<Arc<dyn MenuData>> {
            None
        }

        fn popup_menu_data(&self) -> Option<Arc<dyn MenuData>> {
            None
        }

        fn tool_bar_data(&self) -> Option<Arc<dyn ToolBarData>> {
            None
        }

        fn key_binding_data(&self) -> Option<Arc<dyn KeyBindingData>> {
            None
        }

        fn default_key_binding_data(&self) -> Option<Arc<dyn KeyBindingData>> {
            None
        }

        fn key_binding(&self) -> Option<Arc<dyn KeyStroke>> {
            None
        }

        fn full_name(&self) -> String {
            format!("{} - {}", self.name(), self.owner())
        }

        fn action_performed(&mut self, _context: &dyn ActionContext) {}

        fn is_add_to_popup(&self, context: &dyn ActionContext) -> bool {
            self.is_enabled_for_context(context)
        }

        fn is_valid_context(&self, _context: &dyn ActionContext) -> bool {
            true
        }

        fn is_enabled_for_context(&self, _context: &dyn ActionContext) -> bool {
            self.enabled
        }

        fn inception_information(&self) -> String {
            "MockToggleAction.java:1".to_string()
        }

        fn create_button(&self) -> Option<Arc<dyn JButton>> {
            None
        }

        fn create_menu_item(&self, _is_popup: bool) -> Arc<dyn JMenuItem> {
            struct MockMenuItem;
            impl JMenuItem for MockMenuItem {}
            Arc::new(MockMenuItem)
        }

        fn create_menu_component(&self, _is_popup: bool) -> Arc<dyn Component> {
            struct MockComponent;
            impl Component for MockComponent {}
            Arc::new(MockComponent)
        }

        fn should_add_to_window(
            &self,
            is_main_window: bool,
            _context_types: &HashSet<TypeId>,
        ) -> bool {
            is_main_window
        }

        fn key_binding_type(&self) -> Arc<dyn KeyBindingType> {
            struct Individual;
            impl KeyBindingType for Individual {}
            Arc::new(Individual)
        }

        fn set_key_binding_data(&mut self, _key_binding_data: Option<Arc<dyn KeyBindingData>>) {}

        fn set_unvalidated_key_binding_data(
            &mut self,
            _new_key_binding_data: Option<Arc<dyn KeyBindingData>>,
        ) {
        }

        fn dispose(&mut self) {}

        fn context_class(&self) -> TypeId {
            self.context_class
        }

        fn supports_default_context(&self) -> bool {
            self.supports_default_context
        }

        fn set_context_class(&mut self, context_type: TypeId, supports_default_context: bool) {
            self.context_class = context_type;
            self.supports_default_context = supports_default_context;
        }
    }

    impl ToggleDockingActionIf for MockToggleAction {
        fn is_selected(&self) -> bool {
            self.selected
        }

        fn set_selected(&mut self, new_value: bool) {
            self.selected = new_value;
        }
    }

    fn mock_toggle_action() -> MockToggleAction {
        MockToggleAction {
            enabled: true,
            selected: false,
            context_class: TypeId::of::<dyn ActionContext>(),
            supports_default_context: false,
        }
    }

    #[test]
    fn selected_state_property_constant_exists() {
        assert_eq!(SELECTED_STATE_PROPERTY, "selectState");
    }

    #[test]
    fn is_selected_returns_false_by_default() {
        let action = mock_toggle_action();
        assert!(!action.is_selected());
    }

    #[test]
    fn set_selected_changes_state() {
        let mut action = mock_toggle_action();
        assert!(!action.is_selected());
        action.set_selected(true);
        assert!(action.is_selected());
    }

    #[test]
    fn set_selected_toggles_back_to_false() {
        let mut action = mock_toggle_action();
        action.set_selected(true);
        assert!(action.is_selected());
        action.set_selected(false);
        assert!(!action.is_selected());
    }

    #[test]
    fn toggle_action_is_trait_object() {
        let mut action = mock_toggle_action();
        let dyn_toggle: &mut dyn ToggleDockingActionIf = &mut action;

        assert!(!dyn_toggle.is_selected());
        dyn_toggle.set_selected(true);
        assert!(dyn_toggle.is_selected());
    }

    #[test]
    fn toggle_action_inherits_docking_action_methods() {
        let mut action = mock_toggle_action();
        let dyn_action: &mut dyn ToggleDockingActionIf = &mut action;

        assert_eq!(dyn_action.name(), "MockToggleAction");
        assert_eq!(dyn_action.owner(), "MockPlugin");
        assert!(dyn_action.is_enabled());

        dyn_action.set_enabled(false);
        assert!(!dyn_action.is_enabled());
    }
}

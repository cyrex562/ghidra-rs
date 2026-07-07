use std::any::TypeId;
use std::collections::HashSet;
use std::sync::Arc;

use crate::docking::action_context::ActionContext;
use crate::docking::seam_stubs::{
    Component, HelpDescriptor, JButton, JMenuItem, KeyBindingData, KeyBindingType, KeyStroke,
    MenuData, PropertyChangeListener, ToolBarData,
};

/// Name of the enablement property, fired when [`DockingActionIf::is_enabled`] changes.
pub const ENABLEMENT_PROPERTY: &str = "enabled";
/// Name of the global-context property.
pub const GLOBALCONTEXT_PROPERTY: &str = "globalContext";
/// Name of the description property.
pub const DESCRIPTION_PROPERTY: &str = "description";
/// Name of the key binding data property.
pub const KEYBINDING_DATA_PROPERTY: &str = "KeyBindings";
/// Name of the menu bar data property.
pub const MENUBAR_DATA_PROPERTY: &str = "MenuBar";
/// Name of the popup menu data property.
pub const POPUP_MENU_DATA_PROPERTY: &str = "PopupMenu";
/// Name of the toolbar data property.
pub const TOOLBAR_DATA_PROPERTY: &str = "ToolBar";

/// The base interface for clients that wish to create commands to be registered with a tool.
///
/// An action may appear in a primary menu, a popup menu or a toolbar. Further, an action may
/// have a key binding assigned. [`ActionContext`] is a key concept for tool actions so that they
/// can be context sensitive: it provides a consistent way for plugins and components to share
/// tool state with actions, which actions use to decide whether they should be enabled or added
/// to a popup menu, and to perform their work when invoked.
///
/// Port of `docking.action.DockingActionIf`.
///
/// `MenuData`, `ToolBarData`, `KeyBindingData`, `KeyBindingType`, `PropertyChangeListener`,
/// `JButton` and `JMenuItem` are not yet ported; this trait references minimal placeholder
/// traits for them from [`crate::docking::seam_stubs`] that carry no members because
/// `DockingActionIf` only ever passes them through as opaque values. Because those placeholders
/// can't manufacture a concrete instance, [`Self::key_binding_type`] and
/// [`Self::create_menu_component`] are required methods here even though their Java
/// counterparts have default implementations.
///
/// `Class<? extends ActionContext>` is represented as [`TypeId`] since Rust has no runtime
/// `Class` object; this mirrors how `getDomainObjectClass` was ported for `DomainFile`.
pub trait DockingActionIf: HelpDescriptor {
    /// Returns the name of the action.
    fn name(&self) -> String;

    /// Returns the owner of this action.
    fn owner(&self) -> String;

    /// Returns a description of this action's owner. For most actions this will return the same
    /// value as [`Self::owner`].
    fn owner_description(&self) -> String {
        self.owner()
    }

    /// Returns a short description of this action. Generally used for a tooltip.
    fn description(&self) -> String;

    /// Adds a listener to be notified if any property changes.
    fn add_property_change_listener(&mut self, listener: Box<dyn PropertyChangeListener>);

    /// Removes a listener to be notified of property changes.
    fn remove_property_change_listener(&mut self, listener: Box<dyn PropertyChangeListener>);

    /// Enables or disables the action.
    fn set_enabled(&mut self, new_value: bool);

    /// Returns true if the action is enabled.
    fn is_enabled(&self) -> bool;

    /// Returns the [`MenuData`] to be used to put this action in the menu bar, or `None` if the
    /// action is not set to be in the menu bar.
    fn menu_bar_data(&self) -> Option<Arc<dyn MenuData>>;

    /// Returns the [`MenuData`] to be used to put this action in a popup menu, or `None` if the
    /// action is not set to be in a popup menu.
    fn popup_menu_data(&self) -> Option<Arc<dyn MenuData>>;

    /// Returns the [`ToolBarData`] to be used to put this action in a toolbar, or `None` if the
    /// action is not set to be in a toolbar.
    fn tool_bar_data(&self) -> Option<Arc<dyn ToolBarData>>;

    /// Returns the [`KeyBindingData`] to be used to assign this action to a key binding, or
    /// `None` if the action has no key binding.
    fn key_binding_data(&self) -> Option<Arc<dyn KeyBindingData>>;

    /// Returns the default [`KeyBindingData`] set via [`Self::set_key_binding_data`], or `None`
    /// if the action has no key binding.
    fn default_key_binding_data(&self) -> Option<Arc<dyn KeyBindingData>>;

    /// Convenience method for getting the keybinding for this action.
    fn key_binding(&self) -> Option<Arc<dyn KeyStroke>>;

    /// Returns the full name (the action name combined with the owner name).
    fn full_name(&self) -> String;

    /// Performs the action logic for this action.
    fn action_performed(&mut self, context: &dyn ActionContext);

    /// Determines if this action should be displayed on the current popup. Only called if the
    /// action has popup menu data set.
    fn is_add_to_popup(&self, context: &dyn ActionContext) -> bool;

    /// Determines if this action is valid for the given context (local or global).
    fn is_valid_context(&self, context: &dyn ActionContext) -> bool;

    /// Determines if this action should be enabled for the given context.
    fn is_enabled_for_context(&self, context: &dyn ActionContext) -> bool;

    /// Returns a string that includes source file and line number information of where this
    /// action was created.
    fn inception_information(&self) -> String;

    /// Returns a button suitable for this action, or `None` if the action does not have toolbar
    /// data set.
    fn create_button(&self) -> Option<Arc<dyn JButton>>;

    /// Returns a menu item suitable for this action.
    ///
    /// * `is_popup` - true if the action should use its popup menu data, else it uses the menu
    ///   bar menu data.
    fn create_menu_item(&self, is_popup: bool) -> Arc<dyn JMenuItem>;

    /// Returns a component to represent this action in the menu. Typically this is the menu item
    /// that triggers the action, though some actions may use other components.
    fn create_menu_component(&self, is_popup: bool) -> Arc<dyn Component>;

    /// Determines whether this action should be added to a window (the main window or a
    /// secondary detached window).
    ///
    /// * `is_main_window` - true if the window in question is the main window.
    /// * `context_types` - the context types (in Java, `Class` objects; here, [`TypeId`]s) based
    ///   on the providers currently in the window.
    fn should_add_to_window(&self, is_main_window: bool, context_types: &HashSet<TypeId>) -> bool;

    /// Returns this action's level of support for key binding accelerator keys.
    fn key_binding_type(&self) -> Arc<dyn KeyBindingType>;

    /// Sets the [`KeyBindingData`] on an action to either assign a keybinding or remove one
    /// (`None`).
    fn set_key_binding_data(&mut self, key_binding_data: Option<Arc<dyn KeyBindingData>>);

    /// Bypasses the validation of [`Self::set_key_binding_data`] so that keybindings are set
    /// exactly as given (such as when set by the user and not by the programmer).
    fn set_unvalidated_key_binding_data(
        &mut self,
        new_key_binding_data: Option<Arc<dyn KeyBindingData>>,
    );

    /// Called when the action's owner is removed from the tool.
    fn dispose(&mut self);

    /// Returns the specific [`ActionContext`] type that this action requires to operate.
    fn context_class(&self) -> TypeId;

    /// Returns true if this action also supports operating on a default context other than the
    /// active (focused) provider's context.
    fn supports_default_context(&self) -> bool;

    /// Sets the specific action context type that this action works on and whether the action
    /// supports default context.
    fn set_context_class(&mut self, context_type: TypeId, supports_default_context: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAction {
        enabled: bool,
        context_class: TypeId,
        supports_default_context: bool,
    }

    impl crate::docking::seam_stubs::HelpDescriptor for MockAction {}

    impl DockingActionIf for MockAction {
        fn name(&self) -> String {
            "MockAction".to_string()
        }

        fn owner(&self) -> String {
            "MockPlugin".to_string()
        }

        fn description(&self) -> String {
            "A mock action".to_string()
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
            "MockAction.java:1".to_string()
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

        fn should_add_to_window(&self, is_main_window: bool, _context_types: &HashSet<TypeId>) -> bool {
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

    fn mock_action() -> MockAction {
        MockAction {
            enabled: true,
            context_class: TypeId::of::<dyn ActionContext>(),
            supports_default_context: false,
        }
    }

    #[test]
    fn owner_description_defaults_to_owner() {
        let action = mock_action();
        assert_eq!(action.owner_description(), action.owner());
    }

    #[test]
    fn usable_as_trait_object() {
        let mut action = mock_action();
        let dyn_action: &mut dyn DockingActionIf = &mut action;

        assert_eq!(dyn_action.name(), "MockAction");
        assert!(dyn_action.is_enabled());

        dyn_action.set_enabled(false);
        assert!(!dyn_action.is_enabled());

        dyn_action.set_context_class(TypeId::of::<i32>(), true);
        assert_eq!(dyn_action.context_class(), TypeId::of::<i32>());
        assert!(dyn_action.supports_default_context());

        assert!(dyn_action.menu_bar_data().is_none());
        let _menu_item = dyn_action.create_menu_item(false);
        let _menu_component = dyn_action.create_menu_component(false);
        let _key_binding_type = dyn_action.key_binding_type();
    }
}

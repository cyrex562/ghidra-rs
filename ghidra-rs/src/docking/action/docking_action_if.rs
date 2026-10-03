//! Port of `docking.action.DockingActionIf`, toolkit-neutral.
//!
//! Every action owns a [`DockingAction`] state (name, owner, menu/toolbar/
//! key-binding data, predicates) and supplies its behaviour by implementing
//! this trait. Accessors forward to the state; the context checks default to
//! Java's `DockingAction` behaviour (predicates first, then enablement).
//! Swing members (`createButton`, `createMenuItem`, property-change listener
//! registration) are not part of the model: the renderer builds widgets from
//! the state and the tool drains [`ActionChange`]s instead (Qt6 UI spec §4).

use crate::docking::action::docking_action::{ActionChange, DockingAction};
use crate::docking::action::{KeyBindingData, KeyBindingType, MenuData, ToolBarData};
use crate::docking::action_context::ActionContext;
use crate::util::awt::KeyStroke;

/// `ENABLEMENT_PROPERTY`
pub const ENABLEMENT_PROPERTY: &str = "enabled";
/// `GLOBALCONTEXT_PROPERTY`
pub const GLOBALCONTEXT_PROPERTY: &str = "globalContext";
/// `DESCRIPTION_PROPERTY`
pub const DESCRIPTION_PROPERTY: &str = "description";
/// `KEYBINDING_DATA_PROPERTY`
pub const KEYBINDING_DATA_PROPERTY: &str = "KeyBindings";
/// `MENUBAR_DATA_PROPERTY`
pub const MENUBAR_DATA_PROPERTY: &str = "MenuBar";
/// `POPUP_MENU_DATA_PROPERTY`
pub const POPUP_MENU_DATA_PROPERTY: &str = "PopupMenu";
/// `TOOLBAR_DATA_PROPERTY`
pub const TOOLBAR_DATA_PROPERTY: &str = "ToolBar";

/// A docking action: state plus behaviour.
pub trait DockingActionIf: Send {
    /// The action's shared state.
    fn state(&self) -> &DockingAction;

    /// Mutable access to the action's shared state.
    fn state_mut(&mut self) -> &mut DockingAction;

    /// `actionPerformed(context)`.
    fn action_performed(&mut self, context: &dyn ActionContext);

    /// `isEnabledForContext`: the `enabledWhen` predicate if set, else `isEnabled()`.
    fn is_enabled_for_context(&self, context: &dyn ActionContext) -> bool {
        match self.state().enabled_predicate() {
            Some(p) => p(context),
            None => self.state().is_enabled(),
        }
    }

    /// `isValidContext`: the `validContextWhen` predicate if set; otherwise
    /// the declared context type must match (Java's `setContextClass`
    /// installs exactly that predicate); otherwise `true`.
    fn is_valid_context(&self, context: &dyn ActionContext) -> bool {
        match self.state().valid_context_predicate() {
            Some(p) => p(context),
            None => super::is_context_applicable(self.state(), context),
        }
    }

    /// `isAddToPopup`: the `popupWhen` predicate if set, else `isEnabledForContext`.
    fn is_add_to_popup(&self, context: &dyn ActionContext) -> bool {
        match self.state().popup_predicate() {
            Some(p) => p(context),
            None => self.is_enabled_for_context(context),
        }
    }

    /// `getName()`
    fn name(&self) -> &str {
        self.state().name()
    }

    /// `getOwner()`
    fn owner(&self) -> &str {
        self.state().owner()
    }

    /// `getFullName()`
    fn full_name(&self) -> String {
        self.state().full_name()
    }

    /// `isEnabled()`
    fn is_enabled(&self) -> bool {
        self.state().is_enabled()
    }

    /// `getKeyBinding()`
    fn key_binding(&self) -> Option<KeyStroke> {
        self.state().key_binding()
    }

    /// `getKeyBindingData()`
    fn key_binding_data(&self) -> Option<&KeyBindingData> {
        self.state().key_binding_data()
    }

    /// `getKeyBindingType()`
    fn key_binding_type(&self) -> KeyBindingType {
        self.state().key_binding_type()
    }

    /// `getMenuBarData()`
    fn menu_bar_data(&self) -> Option<&MenuData> {
        self.state().menu_bar_data()
    }

    /// `getPopupMenuData()`
    fn popup_menu_data(&self) -> Option<&MenuData> {
        self.state().popup_menu_data()
    }

    /// `getToolBarData()`
    fn tool_bar_data(&self) -> Option<&ToolBarData> {
        self.state().tool_bar_data()
    }

    /// This action as a toggle action, if it is one (Java
    /// `instanceof ToggleDockingActionIf`).
    fn as_toggle(&self) -> Option<&dyn super::ToggleDockingActionIf> {
        None
    }

    /// Drains recorded state changes (replaces property-change events).
    fn take_changes(&mut self) -> Vec<ActionChange> {
        self.state_mut().take_changes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::DefaultActionContext;

    struct Noop(DockingAction);
    impl DockingActionIf for Noop {
        fn state(&self) -> &DockingAction {
            &self.0
        }
        fn state_mut(&mut self) -> &mut DockingAction {
            &mut self.0
        }
        fn action_performed(&mut self, _c: &dyn ActionContext) {}
    }

    #[test]
    fn accessors_forward_to_state() {
        let mut a = Noop(DockingAction::new("Copy", "Clipboard"));
        a.state_mut().set_menu_bar_data(Some(MenuData::new(&["Edit", "&Copy"]).unwrap()));
        assert_eq!(a.name(), "Copy");
        assert_eq!(a.owner(), "Clipboard");
        assert_eq!(a.menu_bar_data().unwrap().menu_item_name(), "Copy");
        assert_eq!(a.key_binding_type(), KeyBindingType::Individual);
        assert_eq!(a.take_changes(), vec![ActionChange::MenuBarData]);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut boxed: Box<dyn DockingActionIf> = Box::new(Noop(DockingAction::new("A", "B")));
        boxed.action_performed(&DefaultActionContext::new());
        assert_eq!(boxed.full_name(), "A (B)");
    }
}

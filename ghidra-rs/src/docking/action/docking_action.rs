//! Port of `docking.action.DockingAction`: the shared state every action
//! carries (R11 shared-state struct; behaviour lives on [`DockingActionIf`]).
//!
//! Java fires `PropertyChangeEvent`s to registered listeners; here the state
//! records an [`ActionChange`] whenever a value actually changes, and the
//! tool's action registry drains them (`take_changes`) into UI events. Swing
//! members (`createButton`, `createMenuItem`) are not part of the model — the
//! renderer builds widgets from this data (Qt6 UI spec §4).

use std::any::TypeId;
use std::fmt;

use crate::docking::action::{KeyBindingData, KeyBindingType, MenuData, ToolBarData};
use crate::docking::action_context::ActionContext;
use crate::docking::KeyBindingPrecedence;
use crate::util::awt::KeyStroke;

/// Which part of an action changed (Java's property-change property names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionChange {
    /// `ENABLEMENT_PROPERTY`
    Enabled,
    /// `MENUBAR_DATA_PROPERTY`
    MenuBarData,
    /// `POPUP_MENU_DATA_PROPERTY`
    PopupMenuData,
    /// `TOOLBAR_DATA_PROPERTY`
    ToolBarData,
    /// `KEYBINDING_DATA_PROPERTY`
    KeyBindingData,
    /// `DESCRIPTION_PROPERTY`
    Description,
    /// `ToggleDockingActionIf.SELECTED_STATE_PROPERTY`
    Selected,
}

/// Identifies an action registered with a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ActionId(pub u64);

/// Context predicate (`enabledWhen` / `popupWhen` / `validContextWhen`).
pub type ContextPredicate = Box<dyn Fn(&dyn ActionContext) -> bool + Send + Sync>;

/// Marker for "any context type" (Java's default `ActionContext.class`).
struct AnyContext;

/// Shared state of a docking action.
pub struct DockingAction {
    name: String,
    owner: String,
    description: String,
    enabled: bool,
    help_location: Option<String>,
    key_binding_type: KeyBindingType,
    key_binding_data: Option<KeyBindingData>,
    default_key_binding_data: Option<KeyBindingData>,
    menu_bar_data: Option<MenuData>,
    popup_menu_data: Option<MenuData>,
    tool_bar_data: Option<ToolBarData>,
    enabled_predicate: Option<ContextPredicate>,
    popup_predicate: Option<ContextPredicate>,
    valid_context_predicate: Option<ContextPredicate>,
    add_to_all_windows: bool,
    add_to_window_when_context: Option<TypeId>,
    context_type: TypeId,
    supports_default_context: bool,
    pending: Vec<ActionChange>,
}

impl fmt::Debug for DockingAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DockingAction")
            .field("name", &self.name)
            .field("owner", &self.owner)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl DockingAction {
    /// `new DockingAction(name, owner)`: enabled, individually key-bindable.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self::with_key_binding_type(name, owner, KeyBindingType::Individual)
    }

    /// `new DockingAction(name, owner, kbType)`.
    pub fn with_key_binding_type(name: impl Into<String>, owner: impl Into<String>, kb_type: KeyBindingType) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            description: String::new(),
            enabled: true,
            help_location: None,
            key_binding_type: kb_type,
            key_binding_data: None,
            default_key_binding_data: None,
            menu_bar_data: None,
            popup_menu_data: None,
            tool_bar_data: None,
            enabled_predicate: None,
            popup_predicate: None,
            valid_context_predicate: None,
            add_to_all_windows: false,
            add_to_window_when_context: None,
            context_type: TypeId::of::<AnyContext>(),
            supports_default_context: false,
            pending: Vec::new(),
        }
    }

    fn changed(&mut self, c: ActionChange) {
        if !self.pending.contains(&c) {
            self.pending.push(c);
        }
    }

    /// Records a change made outside this struct (e.g. a toggle action's
    /// selection via [`ToggleState`](super::ToggleState)).
    pub fn record_change(&mut self, c: ActionChange) {
        self.changed(c);
    }

    /// Drains the recorded changes (oldest first, each kind once).
    pub fn take_changes(&mut self) -> Vec<ActionChange> {
        std::mem::take(&mut self.pending)
    }

    /// `getName()`
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `getOwner()`
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// `getFullName()`: `"name (owner)"`.
    pub fn full_name(&self) -> String {
        format!("{} ({})", self.name, self.owner)
    }

    /// `getDescription()`
    pub fn description(&self) -> &str {
        &self.description
    }

    /// `setDescription`
    pub fn set_description(&mut self, description: impl Into<String>) {
        let d = description.into();
        if d != self.description {
            self.description = d;
            self.changed(ActionChange::Description);
        }
    }

    /// `isEnabled()`
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// `setEnabled`
    pub fn set_enabled(&mut self, enabled: bool) {
        if enabled != self.enabled {
            self.enabled = enabled;
            self.changed(ActionChange::Enabled);
        }
    }

    /// `getHelpLocation()` (as a help-location string).
    pub fn help_location(&self) -> Option<&str> {
        self.help_location.as_deref()
    }

    /// `setHelpLocation`
    pub fn set_help_location(&mut self, location: Option<String>) {
        self.help_location = location;
    }

    /// `getKeyBindingType()`
    pub fn key_binding_type(&self) -> KeyBindingType {
        self.key_binding_type
    }

    /// `getKeyBinding()`
    pub fn key_binding(&self) -> Option<KeyStroke> {
        self.key_binding_data.as_ref().and_then(KeyBindingData::key_binding)
    }

    /// `getKeyBindingData()`
    pub fn key_binding_data(&self) -> Option<&KeyBindingData> {
        self.key_binding_data.as_ref()
    }

    /// `getDefaultKeyBindingData()`
    pub fn default_key_binding_data(&self) -> Option<&KeyBindingData> {
        self.default_key_binding_data.as_ref()
    }

    fn supports_key_binding(&self, data: Option<&KeyBindingData>) -> bool {
        if self.key_binding_type.supports_key_bindings() {
            return true;
        }
        if data.map(KeyBindingData::precedence) == Some(KeyBindingPrecedence::SystemActionsLevel) {
            return true; // system actions are special
        }
        tracing::error!("Action does not support key bindings: {}", self.full_name());
        false
    }

    /// `setKeyBindingData`: ignored (with an error log) when the action does
    /// not support key bindings; the first value set also becomes the default.
    pub fn set_key_binding_data(&mut self, data: Option<KeyBindingData>) {
        if !self.supports_key_binding(data.as_ref()) {
            return;
        }
        let changed = data != self.key_binding_data;
        self.key_binding_data = data;
        if self.default_key_binding_data.is_none() {
            self.default_key_binding_data = self.key_binding_data.clone();
        }
        if changed {
            self.changed(ActionChange::KeyBindingData);
        }
    }

    /// `setUnvalidatedKeyBindingData`: no support check, no default update.
    pub fn set_unvalidated_key_binding_data(&mut self, data: Option<KeyBindingData>) {
        if data != self.key_binding_data {
            self.key_binding_data = data;
            self.changed(ActionChange::KeyBindingData);
        }
    }

    /// `getMenuBarData()`
    pub fn menu_bar_data(&self) -> Option<&MenuData> {
        self.menu_bar_data.as_ref()
    }

    /// `setMenuBarData`
    pub fn set_menu_bar_data(&mut self, data: Option<MenuData>) {
        if data != self.menu_bar_data {
            self.menu_bar_data = data;
            self.changed(ActionChange::MenuBarData);
        }
    }

    /// Edits the menu-bar data in place (Java mutating the `MenuBarData` the
    /// action owns); records a change only if it actually changed.
    pub fn update_menu_bar_data(&mut self, f: impl FnOnce(&mut MenuData)) {
        if let Some(mut data) = self.menu_bar_data.clone() {
            f(&mut data);
            self.set_menu_bar_data(Some(data));
        }
    }

    /// `getPopupMenuData()`
    pub fn popup_menu_data(&self) -> Option<&MenuData> {
        self.popup_menu_data.as_ref()
    }

    /// `setPopupMenuData`
    pub fn set_popup_menu_data(&mut self, data: Option<MenuData>) {
        if data != self.popup_menu_data {
            self.popup_menu_data = data;
            self.changed(ActionChange::PopupMenuData);
        }
    }

    /// In-place edit of the popup data; see [`Self::update_menu_bar_data`].
    pub fn update_popup_menu_data(&mut self, f: impl FnOnce(&mut MenuData)) {
        if let Some(mut data) = self.popup_menu_data.clone() {
            f(&mut data);
            self.set_popup_menu_data(Some(data));
        }
    }

    /// `getToolBarData()`
    pub fn tool_bar_data(&self) -> Option<&ToolBarData> {
        self.tool_bar_data.as_ref()
    }

    /// `setToolBarData`
    pub fn set_tool_bar_data(&mut self, data: Option<ToolBarData>) {
        if data != self.tool_bar_data {
            self.tool_bar_data = data;
            self.changed(ActionChange::ToolBarData);
        }
    }

    /// In-place edit of the toolbar data; see [`Self::update_menu_bar_data`].
    pub fn update_tool_bar_data(&mut self, f: impl FnOnce(&mut ToolBarData)) {
        if let Some(mut data) = self.tool_bar_data.clone() {
            f(&mut data);
            self.set_tool_bar_data(Some(data));
        }
    }

    /// `enabledWhen`
    pub fn enabled_when(&mut self, p: ContextPredicate) {
        self.enabled_predicate = Some(p);
    }

    /// `popupWhen`
    pub fn popup_when(&mut self, p: ContextPredicate) {
        self.popup_predicate = Some(p);
    }

    /// `validContextWhen`
    pub fn valid_context_when(&mut self, p: ContextPredicate) {
        self.valid_context_predicate = Some(p);
    }

    /// `setAddToAllWindows`
    pub fn set_add_to_all_windows(&mut self, b: bool) {
        self.add_to_all_windows = b;
    }

    /// `addToWindowWhen(Class)`
    pub fn add_to_window_when(&mut self, context_type: TypeId) {
        self.add_to_window_when_context = Some(context_type);
    }

    /// `shouldAddToWindow(isMainWindow, contextTypes)`.
    pub fn should_add_to_window(&self, is_main_window: bool, context_types: &[TypeId]) -> bool {
        if self.menu_bar_data.is_none() && self.tool_bar_data.is_none() {
            return false;
        }
        if self.add_to_all_windows {
            return true;
        }
        match self.add_to_window_when_context {
            // Java: once a window context type is declared, only that decides
            Some(t) => context_types.contains(&t),
            // default: only the main window
            None => is_main_window,
        }
    }

    /// `getContextClass()`
    pub fn context_type(&self) -> TypeId {
        self.context_type
    }

    /// Whether this action accepts any context type (Java `ActionContext.class`).
    pub fn accepts_any_context(&self) -> bool {
        self.context_type == TypeId::of::<AnyContext>()
    }

    /// `supportsDefaultContext()`
    pub fn supports_default_context(&self) -> bool {
        self.supports_default_context
    }

    /// `setContextClass(type, supportsDefaultContext)`
    pub fn set_context_type(&mut self, context_type: TypeId, supports_default_context: bool) {
        self.context_type = context_type;
        self.supports_default_context = supports_default_context;
    }

    pub(crate) fn enabled_predicate(&self) -> Option<&ContextPredicate> {
        self.enabled_predicate.as_ref()
    }

    pub(crate) fn popup_predicate(&self) -> Option<&ContextPredicate> {
        self.popup_predicate.as_ref()
    }

    pub(crate) fn valid_context_predicate(&self) -> Option<&ContextPredicate> {
        self.valid_context_predicate.as_ref()
    }
}

/// Whether `ctx` is of the action's declared context type (Java
/// `contextClass.isInstance(ctx)`, installed as the valid-context predicate by
/// `setContextClass`). Exact type match: Rust has no subtype test.
pub fn is_context_applicable(s: &DockingAction, ctx: &dyn ActionContext) -> bool {
    s.accepts_any_context() || ctx.as_any().type_id() == s.context_type()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::action::DockingActionIf;
    use crate::docking::DefaultActionContext;

    struct Counter {
        state: DockingAction,
        hits: u32,
    }
    impl DockingActionIf for Counter {
        fn state(&self) -> &DockingAction {
            &self.state
        }
        fn state_mut(&mut self) -> &mut DockingAction {
            &mut self.state
        }
        fn action_performed(&mut self, _ctx: &dyn ActionContext) {
            self.hits += 1;
        }
    }

    fn action() -> Counter {
        Counter { state: DockingAction::new("Rename", "LabelPlugin"), hits: 0 }
    }

    #[test]
    fn full_name_is_name_then_owner() {
        assert_eq!(action().full_name(), "Rename (LabelPlugin)");
    }

    #[test]
    fn setting_same_value_records_no_change() {
        let mut a = action();
        a.state_mut().set_enabled(true); // already enabled by default
        assert!(a.state_mut().take_changes().is_empty());
        a.state_mut().set_enabled(false);
        assert_eq!(a.state_mut().take_changes(), vec![ActionChange::Enabled]);
    }

    #[test]
    fn updating_menu_data_in_place_records_change_only_when_different() {
        let mut a = action();
        a.state_mut().set_menu_bar_data(Some(MenuData::new(&["Edit", "Rename"]).unwrap()));
        a.state_mut().take_changes();
        a.state_mut().update_menu_bar_data(|m| m.set_menu_group(Some("g")));
        assert_eq!(a.state_mut().take_changes(), vec![ActionChange::MenuBarData]);
        a.state_mut().update_menu_bar_data(|m| m.set_menu_group(Some("g")));
        assert!(a.state_mut().take_changes().is_empty());
    }

    #[test]
    fn default_enablement_follows_is_enabled_like_java() {
        let mut a = action();
        let ctx = DefaultActionContext::new();
        assert!(a.is_enabled_for_context(&ctx));
        assert!(a.is_add_to_popup(&ctx));
        a.state_mut().set_enabled(false);
        assert!(!a.is_enabled_for_context(&ctx));
        assert!(!a.is_add_to_popup(&ctx));
        assert!(a.is_valid_context(&ctx));
    }

    #[test]
    fn predicates_override_defaults() {
        let mut a = action();
        a.state_mut().enabled_when(Box::new(|c| c.event_click_modifiers() == 1));
        a.state_mut().valid_context_when(Box::new(|_| false));
        let mut ctx = DefaultActionContext::new();
        assert!(!a.is_enabled_for_context(&ctx));
        ctx.set_event_click_modifiers(1);
        assert!(a.is_enabled_for_context(&ctx));
        assert!(!a.is_valid_context(&ctx));
    }

    #[test]
    fn context_type_gates_applicability() {
        struct Special;
        let mut a = action();
        assert!(is_context_applicable(a.state(), &DefaultActionContext::new()));
        a.state_mut().set_context_type(TypeId::of::<Special>(), false);
        assert!(!is_context_applicable(a.state(), &DefaultActionContext::new()));
        a.state_mut().set_context_type(TypeId::of::<Special>(), true);
        // supporting a default context does not make a foreign context valid
        assert!(!is_context_applicable(a.state(), &DefaultActionContext::new()));
        assert!(!a.is_valid_context(&DefaultActionContext::new()));
        a.state_mut().set_context_type(TypeId::of::<DefaultActionContext>(), false);
        assert!(is_context_applicable(a.state(), &DefaultActionContext::new()));
    }

    #[test]
    fn first_key_binding_becomes_default_and_unsupported_type_rejects() {
        use crate::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};
        let ks = KeyStroke::new(vk::G, CTRL_DOWN_MASK);
        let mut a = action();
        a.state_mut().set_key_binding_data(Some(KeyBindingData::new(ks)));
        assert_eq!(a.state().default_key_binding_data().and_then(|d| d.key_binding()), Some(ks));
        a.state_mut().set_key_binding_data(None);
        assert_eq!(a.state().key_binding(), None);
        assert!(a.state().default_key_binding_data().is_some());

        let mut u = DockingAction::with_key_binding_type("U", "O", KeyBindingType::Unsupported);
        u.set_key_binding_data(Some(KeyBindingData::new(ks)));
        assert_eq!(u.key_binding(), None);
        u.set_key_binding_data(Some(KeyBindingData::system(ks)));
        assert_eq!(u.key_binding(), Some(ks));
    }

    #[test]
    fn should_add_to_window_rules() {
        let mut a = DockingAction::new("A", "O");
        assert!(!a.should_add_to_window(true, &[]));
        a.set_menu_bar_data(Some(MenuData::new(&["File", "A"]).unwrap()));
        assert!(a.should_add_to_window(true, &[]));
        assert!(!a.should_add_to_window(false, &[]));
        a.add_to_window_when(TypeId::of::<u8>());
        assert!(a.should_add_to_window(false, &[TypeId::of::<u8>()]));
        assert!(!a.should_add_to_window(true, &[])); // declared type overrides main-window default
        a.set_add_to_all_windows(true);
        assert!(a.should_add_to_window(false, &[]));
    }

    #[test]
    fn performing_runs_behaviour() {
        let mut a = action();
        a.action_performed(&DefaultActionContext::new());
        assert_eq!(a.hits, 1);
    }
}

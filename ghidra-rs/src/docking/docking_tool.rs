//! A toolkit-neutral docking tool: its providers, actions and layout
//! (the model half of Ghidra's `AbstractDockingTool` + `DockingWindowManager`).

use std::any::TypeId;
use std::collections::{BTreeMap, HashMap};

use crate::docking::action::{ActionId, DispatchResult, DockingActionIf, KeyBindingsManager};
use crate::docking::action_context::ActionContext;
use crate::docking::actions::ToolActions;
use crate::docking::dock_layout::{DockLayout, LayoutEntry};
use crate::docking::menu::MenuGroupMap;
use crate::docking::{ComponentProvider, DefaultActionContext, ProviderId};
use crate::framework::options::SaveState;
use crate::util::awt::KeyStroke;

/// A docking tool's model: providers, actions and layout.
pub struct DockingTool {
    name: String,
    next_provider: u64,
    providers: BTreeMap<ProviderId, Box<dyn ComponentProvider>>,
    actions: ToolActions,
    layout: DockLayout,
    menu_groups: MenuGroupMap,
    default_contexts: HashMap<TypeId, DefaultContextFactory>,
}

/// Builds the tool's default context for one context type
/// (`DockingWindowManager.getDefaultActionContextMap`).
pub type DefaultContextFactory = Box<dyn Fn() -> Box<dyn ActionContext> + Send>;

impl DockingTool {
    /// An empty tool.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            next_provider: 0,
            providers: BTreeMap::new(),
            actions: ToolActions::new(),
            layout: DockLayout::default(),
            menu_groups: MenuGroupMap::default(),
            default_contexts: HashMap::new(),
        }
    }

    /// The tool name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Adds a provider, assigning its id. If the layout already knows this
    /// provider (restored earlier) its saved visibility wins; otherwise a
    /// layout entry is created from the provider's defaults and `show`.
    pub fn add_provider(&mut self, mut provider: Box<dyn ComponentProvider>, show: bool) -> ProviderId {
        self.next_provider += 1;
        let id = ProviderId(self.next_provider);
        provider.state_mut().set_id(id);
        let key = provider.state().layout_key();
        let visible = match self.layout.entry(&key) {
            Some(e) => e.visible,
            None => {
                let s = provider.state();
                self.layout.set_entry(
                    key.clone(),
                    LayoutEntry { visible: show, position: s.default_position(), group: s.window_group().to_owned() },
                );
                show
            }
        };
        provider.state_mut().set_visible(visible);
        self.providers.insert(id, provider);
        id
    }

    /// Removes a provider and its local actions. Its layout entry is kept so
    /// re-adding it restores its placement (Java placeholders behave alike).
    pub fn remove_provider(&mut self, id: ProviderId) -> Option<Box<dyn ComponentProvider>> {
        self.actions.remove_provider_actions(id);
        self.providers.remove(&id)
    }

    /// Shows or hides a provider.
    pub fn show_provider(&mut self, id: ProviderId, visible: bool) {
        let Some(p) = self.providers.get_mut(&id) else { return };
        p.state_mut().set_visible(visible);
        if visible {
            p.component_shown();
        } else {
            p.component_hidden();
        }
        let key = p.state().layout_key();
        if let Some(e) = self.layout.entry(&key).cloned() {
            self.layout.set_entry(key, LayoutEntry { visible, ..e });
        }
    }

    /// The provider, if present.
    pub fn provider(&self, id: ProviderId) -> Option<&dyn ComponentProvider> {
        self.providers.get(&id).map(|p| p.as_ref())
    }

    /// Mutable access to the provider, if present.
    pub fn provider_mut(&mut self, id: ProviderId) -> Option<&mut (dyn ComponentProvider + 'static)> {
        self.providers.get_mut(&id).map(|p| p.as_mut())
    }

    /// All provider ids.
    pub fn provider_ids(&self) -> impl Iterator<Item = ProviderId> + '_ {
        self.providers.keys().copied()
    }

    /// Finds a provider by owner and name.
    pub fn find_provider(&self, owner: &str, name: &str) -> Option<ProviderId> {
        self.providers
            .iter()
            .find(|(_, p)| p.state().owner() == owner && p.state().name() == name)
            .map(|(id, _)| *id)
    }

    /// Adds a global action.
    pub fn add_action(&mut self, action: Box<dyn DockingActionIf>) -> ActionId {
        self.actions.add_global(action)
    }

    /// Adds an action local to `provider`.
    pub fn add_local_action(&mut self, provider: ProviderId, action: Box<dyn DockingActionIf>) -> ActionId {
        self.actions.add_local(provider, action)
    }

    /// The action registry.
    pub fn actions(&self) -> &ToolActions {
        &self.actions
    }

    /// Mutable action registry.
    pub fn actions_mut(&mut self) -> &mut ToolActions {
        &mut self.actions
    }

    /// Preferred menu groups (`PluginTool.setMenuGroup`).
    pub fn menu_groups(&self) -> &MenuGroupMap {
        &self.menu_groups
    }

    /// `setMenuGroup(menuPath, group, menuSubGroup)`.
    pub fn set_menu_group(&mut self, path: &[&str], group: Option<&str>, sub_group: Option<&str>) {
        self.menu_groups.set_menu_group(path, group, sub_group);
    }

    /// The layout.
    pub fn layout(&self) -> &DockLayout {
        &self.layout
    }

    /// Mutable layout (the renderer stores its geometry here).
    pub fn layout_mut(&mut self) -> &mut DockLayout {
        &mut self.layout
    }

    /// The context for a provider (or the tool's default context).
    pub fn action_context(&self, provider: Option<ProviderId>) -> Box<dyn ActionContext> {
        match provider.and_then(|id| self.providers.get(&id)) {
            Some(p) => p.action_context(),
            None => Box::new(DefaultActionContext::new()),
        }
    }

    /// Registers the default context for actions of `context_type` that
    /// support a default context (`ComponentProvider.registerDefaultContext`).
    pub fn set_default_context(&mut self, context_type: TypeId, factory: DefaultContextFactory) {
        self.default_contexts.insert(context_type, factory);
    }

    /// Dispatches a key stroke given the focused provider.
    pub fn dispatch_key(&mut self, ks: KeyStroke, focused: Option<ProviderId>) -> DispatchResult {
        let providers = &self.providers;
        let defaults = &self.default_contexts;
        let ctx_for = |p: Option<ProviderId>| -> Box<dyn ActionContext> {
            match p.and_then(|id| providers.get(&id)) {
                Some(pr) => pr.action_context(),
                None => Box::new(DefaultActionContext::new()),
            }
        };
        let default_ctx = |t: TypeId| defaults.get(&t).map(|f| f());
        KeyBindingsManager::dispatch(&mut self.actions, ks, focused, &ctx_for, &default_ctx)
    }

    /// Saves the layout; transient providers are omitted.
    pub fn save_layout(&self) -> SaveState {
        let mut layout = self.layout.clone();
        for p in self.providers.values() {
            if p.state().is_transient() {
                layout.remove_entry(&p.state().layout_key());
            }
        }
        layout.to_save_state()
    }

    /// Restores a saved layout. Entries for current providers are applied
    /// (visibility, position, group); providers missing from the save keep
    /// their current entry; entries for providers not present are **kept**
    /// unapplied and written back on save, like Java's `PlaceholderManager`
    /// keeps placeholders — so a plugin loaded later (or a newer build's
    /// config) does not lose its placement.
    pub fn restore_layout(&mut self, saved: &SaveState) {
        let restored = DockLayout::from_save_state(saved);
        let mut layout = restored.clone();
        for p in self.providers.values_mut() {
            let key = p.state().layout_key();
            match restored.entry(&key).cloned() {
                Some(e) => {
                    let was = p.state().is_visible();
                    p.state_mut().set_visible(e.visible);
                    if was != e.visible {
                        if e.visible {
                            p.component_shown();
                        } else {
                            p.component_hidden();
                        }
                    }
                }
                None => {
                    if let Some(e) = self.layout.entry(&key).cloned() {
                        layout.set_entry(key, e);
                    }
                }
            }
        }
        self.layout = layout;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::action::tests_support::noop_action;
    use crate::docking::{ComponentProviderState, ProviderViewKind, WindowPosition};

    struct P(ComponentProviderState);
    impl ComponentProvider for P {
        fn state(&self) -> &ComponentProviderState {
            &self.0
        }
        fn state_mut(&mut self) -> &mut ComponentProviderState {
            &mut self.0
        }
    }
    fn p(name: &str, pos: WindowPosition) -> Box<dyn ComponentProvider> {
        let mut s = ComponentProviderState::new(name, "Owner", ProviderViewKind::Table);
        s.set_default_position(pos);
        Box::new(P(s))
    }

    #[test]
    fn layout_round_trips_visibility_position_and_geometry() {
        let mut t = DockingTool::new("CodeBrowser");
        t.add_provider(p("A", WindowPosition::Left), true);
        t.add_provider(p("B", WindowPosition::Bottom), false);
        t.layout_mut().set_geometry(Some(vec![1, 2, 3]));
        let saved = t.save_layout();

        let mut t2 = DockingTool::new("CodeBrowser");
        let a2 = t2.add_provider(p("A", WindowPosition::Right), false); // different default
        let b2 = t2.add_provider(p("B", WindowPosition::Bottom), true);
        t2.restore_layout(&saved);
        assert!(t2.provider(a2).unwrap().state().is_visible());
        assert!(!t2.provider(b2).unwrap().state().is_visible());
        assert_eq!(t2.layout().entry("Owner.A").unwrap().position, WindowPosition::Left);
        assert_eq!(t2.layout().geometry(), Some(&[1u8, 2, 3][..]));
    }

    #[test]
    fn restore_ignores_unknown_and_defaults_new_providers() {
        let mut old = DockingTool::new("T");
        old.add_provider(p("Gone", WindowPosition::Top), true);
        let saved = old.save_layout();

        let mut t = DockingTool::new("T");
        let n = t.add_provider(p("New", WindowPosition::Right), true);
        t.restore_layout(&saved); // must not error on "Owner.Gone"
        assert!(t.provider(n).unwrap().state().is_visible());
        assert_eq!(t.layout().entry("Owner.New").unwrap().position, WindowPosition::Right);
        // the absent provider's placement survives a load/save cycle
        assert_eq!(t.layout().entry("Owner.Gone").unwrap().position, WindowPosition::Top);
        let resaved = DockLayout::from_save_state(&t.save_layout());
        assert!(resaved.entry("Owner.Gone").is_some());
        // and is applied when that provider is added later
        let g = t.add_provider(p("Gone", WindowPosition::Bottom), false);
        assert!(t.provider(g).unwrap().state().is_visible());
    }

    #[test]
    fn transient_providers_are_not_saved() {
        let mut t = DockingTool::new("T");
        let mut s = ComponentProviderState::new("Search Results", "Owner", ProviderViewKind::Table);
        s.set_transient();
        t.add_provider(Box::new(P(s)), true);
        let restored = DockLayout::from_save_state(&t.save_layout());
        assert!(restored.entry("Owner.Search Results").is_none());
    }

    #[test]
    fn removing_a_provider_removes_its_local_actions() {
        let mut t = DockingTool::new("T");
        let id = t.add_provider(p("A", WindowPosition::Left), true);
        t.add_local_action(id, Box::new(noop_action("X")));
        assert_eq!(t.actions().local_actions(id).count(), 1);
        t.remove_provider(id);
        assert_eq!(t.actions().local_actions(id).count(), 0);
        assert!(t.provider(id).is_none());
    }

    #[test]
    fn find_and_show_provider() {
        let mut t = DockingTool::new("T");
        let id = t.add_provider(p("A", WindowPosition::Left), false);
        assert_eq!(t.find_provider("Owner", "A"), Some(id));
        t.show_provider(id, true);
        assert!(t.provider(id).unwrap().state().is_visible());
        assert!(t.layout().entry("Owner.A").unwrap().visible);
    }
}

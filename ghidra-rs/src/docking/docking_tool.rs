//! A toolkit-neutral docking tool: its providers, actions and layout
//! (the model half of Ghidra's `AbstractDockingTool` + `DockingWindowManager`).

use std::any::TypeId;
use std::collections::{BTreeMap, HashMap};

use crate::docking::action::{ActionId, DispatchResult, DockingActionIf, KeyBindingsManager};
use crate::docking::action_context::ActionContext;
use crate::docking::actions::ToolActions;
use crate::docking::dock_layout::{DockLayout, LayoutEntry};
use crate::docking::menu::MenuGroupMap;
use crate::docking::action::{KeyBindingData, KeyBindingType};
use crate::docking::show_component_action::{ShowComponentAction, ToolRequest, ToolRequests, MENU_WINDOW};
use crate::framework::options::option_type::OptionType;
use crate::framework::options::SharedOptionsListener;
use crate::framework::options::option_type::OptionValue;
use crate::framework::options::ToolOptions;
use crate::framework::options::action_trigger::ActionTrigger;
use std::sync::Arc;

/// Java `DockingToolConstants.KEY_BINDINGS`.
pub const KEY_BINDINGS: &str = "Key Bindings";
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
    requests: ToolRequests,
    window_actions: Vec<ActionId>,
    key_binding_options: Arc<ToolOptions>,
    /// ToolOptions holds listeners weakly; the tool keeps its own alive.
    _key_binding_listener: SharedOptionsListener,
}

/// Java `ToolActions.optionsChanged`: a key-binding option changed — queue
/// the re-binding for the tool (listeners cannot reach it).
struct KeyBindingListener(ToolRequests);

impl crate::framework::options::options_change_listener::OptionsChangeListener for KeyBindingListener {
    fn options_changed(
        &mut self,
        _options: &dyn crate::framework::seam_stubs::ToolOptions,
        option_name: &str,
        _old_value: Option<&dyn std::any::Any>,
        new_value: Option<&dyn std::any::Any>,
    ) -> Result<(), Box<dyn crate::framework::seam_stubs::OptionsVetoException>> {
        let trigger = match new_value.and_then(|v| v.downcast_ref::<OptionValue>()) {
            Some(OptionValue::ActionTrigger(t)) => Some(t.clone()),
            _ => None,
        };
        self.0.push(ToolRequest::SetActionTrigger(option_name.to_owned(), trigger));
        Ok(())
    }
}

/// Builds the tool's default context for one context type
/// (`DockingWindowManager.getDefaultActionContextMap`).
pub type DefaultContextFactory = Box<dyn Fn() -> Box<dyn ActionContext> + Send>;

impl DockingTool {
    /// An empty tool.
    pub fn new(name: impl Into<String>) -> Self {
        let requests = ToolRequests::default();
        let key_binding_options = Arc::new(ToolOptions::new(KEY_BINDINGS));
        let listener: SharedOptionsListener = Arc::new(std::sync::Mutex::new(KeyBindingListener(requests.clone())));
        key_binding_options.add_options_change_listener(&listener);
        Self {
            name: name.into(),
            next_provider: 0,
            providers: BTreeMap::new(),
            actions: ToolActions::new(),
            layout: DockLayout::default(),
            menu_groups: MenuGroupMap::default(),
            default_contexts: HashMap::new(),
            requests: requests.clone(),
            window_actions: Vec::new(),
            key_binding_options,
            _key_binding_listener: listener,
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
        self.rebuild_window_menu();
        id
    }

    /// Removes a provider and its local actions. Its layout entry is kept so
    /// re-adding it restores its placement (Java placeholders behave alike).
    pub fn remove_provider(&mut self, id: ProviderId) -> Option<Box<dyn ComponentProvider>> {
        self.actions.remove_provider_actions(id);
        let removed = self.providers.remove(&id);
        self.rebuild_window_menu();
        removed
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
        let id = self.actions.add_global(action);
        self.register_key_binding(id);
        id
    }

    /// Adds an action local to `provider`.
    pub fn add_local_action(&mut self, provider: ProviderId, action: Box<dyn DockingActionIf>) -> ActionId {
        let id = self.actions.add_local(provider, action);
        self.register_key_binding(id);
        id
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

    /// The tool's "Key Bindings" options: one `ActionTrigger` option per
    /// action with an individual key binding (Java `ToolActions` +
    /// `DockingToolConstants.KEY_BINDINGS`).
    pub fn key_binding_options(&self) -> &Arc<ToolOptions> {
        &self.key_binding_options
    }

    /// Java `ToolActions.loadKeyBindingFromOptions`: an individual-binding
    /// action registers its option and takes the option's value.
    fn register_key_binding(&mut self, id: ActionId) {
        let Some(a) = self.actions.get(id) else { return };
        if a.state().key_binding_type() != KeyBindingType::Individual {
            return;
        }
        let full = a.state().full_name();
        let default = a.state().key_binding_data().map(|k| k.action_trigger());
        let _ = self.key_binding_options.register_option_with_type(
            &full,
            OptionType::ActionTrigger,
            default.clone().map(OptionValue::ActionTrigger),
            None,
            Some(&format!("Key Binding for {full}")),
            None,
        );
        let trigger = match self.key_binding_options.get_object(&full, default.clone().map(OptionValue::ActionTrigger)) {
            Ok(Some(OptionValue::ActionTrigger(t))) => Some(t),
            Ok(_) => None,
            Err(_) => default,
        };
        let existing = self.actions.get(id).and_then(|a| a.state().key_binding_data().cloned());
        self.actions.set_key_binding(id, KeyBindingData::update(existing.as_ref(), trigger.as_ref()));
    }

    fn set_action_trigger(&mut self, full_name: &str, trigger: Option<&ActionTrigger>) {
        let ids: Vec<ActionId> = self
            .actions
            .all_actions()
            .filter(|&id| {
                self.actions
                    .get(id)
                    .is_some_and(|a| a.state().key_binding_type() == KeyBindingType::Individual && a.state().full_name() == full_name)
            })
            .collect();
        for id in ids {
            let existing = self.actions.get(id).and_then(|a| a.state().key_binding_data().cloned());
            self.actions.set_key_binding(id, KeyBindingData::update(existing.as_ref(), trigger));
        }
    }

    /// Recreates the Window menu: one [`ShowComponentAction`] per provider,
    /// sub-menus for window menu groups with two or more providers (single
    /// ones are promoted), plus "Show All" per sub-menu
    /// (Java `DockingWindowManager.updateComponentMenus`).
    pub fn rebuild_window_menu(&mut self) {
        for id in self.window_actions.drain(..) {
            self.actions.remove(id);
        }
        let mut by_group: BTreeMap<Option<String>, Vec<ProviderId>> = BTreeMap::new();
        for (id, p) in &self.providers {
            by_group.entry(p.state().window_menu_group().map(str::to_owned)).or_default().push(*id);
        }
        // promoteSingleMenuGroups: a sub-menu of one is just a top-level entry
        let singles: Vec<Option<String>> =
            by_group.iter().filter(|(g, ids)| g.is_some() && ids.len() == 1).map(|(g, _)| g.clone()).collect();
        for g in singles {
            let ids = by_group.remove(&g).unwrap_or_default();
            by_group.entry(None).or_default().extend(ids);
        }
        let mut entries = Vec::new();
        for (group, ids) in &by_group {
            for id in ids {
                let st = self.providers[id].state();
                let full_title = match st.sub_title().filter(|s| !s.trim().is_empty()) {
                    Some(sub) => format!("{} - {sub}", st.title()),
                    None => st.title().to_owned(),
                };
                entries.push(ShowComponentAction::for_provider(
                    st.name(),
                    st.title(),
                    &full_title,
                    group.as_deref(),
                    *id,
                    self.requests.clone(),
                ));
            }
            if let Some(g) = group {
                entries.push(ShowComponentAction::show_all(g, ids.clone(), self.requests.clone()));
                self.menu_groups.set_menu_group(&[MENU_WINDOW, g], Some("Permanent"), None);
            }
        }
        for e in entries {
            let id = self.actions.add_global(Box::new(e));
            self.window_actions.push(id);
        }
    }

    /// Applies show requests made by actions since the last call; returns the
    /// providers that were shown, in request order.
    pub fn apply_requests(&mut self) -> Vec<ProviderId> {
        let mut shown = Vec::new();
        for request in self.requests.take() {
            match request {
                ToolRequest::Show(id) if self.providers.contains_key(&id) => {
                    self.show_provider(id, true);
                    shown.push(id);
                }
                ToolRequest::Show(_) => {}
                ToolRequest::SetActionTrigger(name, trigger) => self.set_action_trigger(&name, trigger.as_ref()),
            }
        }
        shown
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

    fn bound(name: &str, key: KeyStroke) -> Box<dyn DockingActionIf> {
        let mut a = crate::docking::action::ClosureAction::new(name, "Owner", |_| {});
        a.state_mut().set_key_binding_data(Some(crate::docking::action::KeyBindingData::new(key)));
        Box::new(a)
    }

    fn trigger(key: &str) -> OptionValue {
        OptionValue::ActionTrigger(ActionTrigger::new(KeyStroke::parse(key), None).unwrap())
    }

    fn binding(t: &DockingTool, id: ActionId) -> Option<String> {
        t.actions().get(id).unwrap().state().key_binding_data().and_then(|k| k.key_binding()).map(|k| format!("{k:?}"))
    }

    #[test]
    fn individual_actions_get_a_key_binding_option() {
        let mut t = DockingTool::new("T");
        t.add_action(bound("Find", KeyStroke::parse("ctrl F").unwrap()));
        let o = t.key_binding_options();
        assert_eq!(o.get_name(), KEY_BINDINGS);
        let e = o.find_option("Find (Owner)").expect("Find (Owner) registered");
        assert_eq!(e.description(), "Key Binding for Find (Owner)");
        assert!(matches!(e.default_value(), Some(OptionValue::ActionTrigger(_))));
    }

    #[test]
    fn changing_the_option_rebinds_every_action_with_that_name() {
        let mut t = DockingTool::new("T");
        let p = t.add_provider(p("A", WindowPosition::Left), true);
        let g = t.add_action(bound("Find", KeyStroke::parse("ctrl F").unwrap()));
        let l = t.add_local_action(p, bound("Find", KeyStroke::parse("ctrl F").unwrap()));
        t.key_binding_options().put_object("Find (Owner)", Some(trigger("ctrl J"))).unwrap();
        t.apply_requests();
        assert_eq!(binding(&t, g), binding(&t, l));
        assert_eq!(binding(&t, g).unwrap(), format!("{:?}", KeyStroke::parse("ctrl J").unwrap()));
        t.key_binding_options().set_action_trigger("Find (Owner)", None).unwrap(); // cleared (Java KeyBindingsModel)
        t.apply_requests();
        assert_eq!(binding(&t, g), None);
    }

    #[test]
    fn a_stored_binding_applies_when_its_action_registers() {
        let mut t = DockingTool::new("T");
        t.key_binding_options().put_object("Late (Owner)", Some(trigger("ctrl K"))).unwrap();
        let id = t.add_action(bound("Late", KeyStroke::parse("ctrl L").unwrap()));
        assert_eq!(binding(&t, id).unwrap(), format!("{:?}", KeyStroke::parse("ctrl K").unwrap()));
    }

    #[test]
    fn window_menu_entries_get_no_key_binding_option() {
        let mut t = DockingTool::new("T");
        t.add_provider(p("A", WindowPosition::Left), true);
        assert!(t.key_binding_options().get_option_names().iter().all(|n| !n.ends_with("(DockingWindows)")), "{:?}", t.key_binding_options().get_option_names());
    }

    fn window_menu(t: &DockingTool) -> Vec<String> {
        let mut paths: Vec<String> = t
            .actions()
            .global_actions()
            .filter_map(|id| t.actions().get(id))
            .filter(|a| a.state().owner() == crate::docking::show_component_action::DOCKING_WINDOWS_OWNER)
            .filter_map(|a| a.state().menu_bar_data().map(|m| m.menu_path()[1..].join(" > ")))
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn the_window_menu_lists_providers_with_sub_menus_for_groups() {
        let mut t = DockingTool::new("T");
        let mut grouped = |name: &str, group: Option<&str>| {
            let mut b = p(name, WindowPosition::Left);
            b.state_mut().set_window_menu_group(group.map(str::to_owned));
            b
        };
        let (a, b, c, d) = (grouped("A", Some("G")), grouped("B", Some("G")), grouped("C", None), grouped("D", Some("H")));
        for x in [a, b, c, d] {
            t.add_provider(x, true);
        }
        assert_eq!(window_menu(&t), vec!["C", "D", "G > A", "G > B", "G > Show All"]);
        let c_id = t.find_provider("Owner", "C").unwrap();
        t.remove_provider(c_id);
        assert_eq!(window_menu(&t), vec!["D", "G > A", "G > B", "G > Show All"]);
    }

    #[test]
    fn a_window_entry_shows_its_hidden_provider() {
        let mut t = DockingTool::new("T");
        let a = t.add_provider(p("A", WindowPosition::Left), false);
        assert!(!t.provider(a).unwrap().state().is_visible());
        let entry = t
            .actions()
            .global_actions()
            .find(|&id| t.actions().get(id).is_some_and(|x| x.state().owner() == crate::docking::show_component_action::DOCKING_WINDOWS_OWNER))
            .unwrap();
        let ctx = DefaultActionContext::new();
        t.actions_mut().get_mut(entry).unwrap().action_performed(&ctx);
        assert_eq!(t.apply_requests(), vec![a]);
        assert!(t.provider(a).unwrap().state().is_visible());
        assert!(t.layout().entry("Owner.A").unwrap().visible);
        assert!(t.apply_requests().is_empty());
    }
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

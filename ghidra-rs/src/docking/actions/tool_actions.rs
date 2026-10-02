//! The tool's action registry (the registry/key-index part of
//! `docking.actions.ToolActions`): global and provider-local actions, by id,
//! with an index from key stroke to bound actions.

use std::collections::BTreeMap;

use crate::docking::action::{ActionChange, ActionId, DockingActionIf, KeyBindingData};
use crate::docking::ProviderId;
use crate::util::awt::KeyStroke;

/// Where an action lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionScope {
    /// A tool-level action (menu bar, toolbar, global key binding).
    Global,
    /// An action local to one provider.
    Local(ProviderId),
}

struct Entry {
    action: Box<dyn DockingActionIf>,
    scope: ActionScope,
}

/// Registry of a tool's actions.
#[derive(Default)]
pub struct ToolActions {
    next_id: u64,
    entries: BTreeMap<ActionId, Entry>,
}

impl ToolActions {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, action: Box<dyn DockingActionIf>, scope: ActionScope) -> ActionId {
        self.next_id += 1;
        let id = ActionId(self.next_id);
        self.entries.insert(id, Entry { action, scope });
        id
    }

    /// Adds a global (tool-level) action.
    pub fn add_global(&mut self, action: Box<dyn DockingActionIf>) -> ActionId {
        self.insert(action, ActionScope::Global)
    }

    /// Adds an action local to `provider`.
    pub fn add_local(&mut self, provider: ProviderId, action: Box<dyn DockingActionIf>) -> ActionId {
        self.insert(action, ActionScope::Local(provider))
    }

    /// Removes an action, returning it.
    pub fn remove(&mut self, id: ActionId) -> Option<Box<dyn DockingActionIf>> {
        self.entries.remove(&id).map(|e| e.action)
    }

    /// Removes every action local to `provider`.
    pub fn remove_provider_actions(&mut self, provider: ProviderId) {
        let ids: Vec<ActionId> = self.local_actions(provider).collect();
        for id in ids {
            self.remove(id);
        }
    }

    /// The action, if registered.
    pub fn get(&self, id: ActionId) -> Option<&dyn DockingActionIf> {
        self.entries.get(&id).map(|e| e.action.as_ref())
    }

    /// Mutable access to the action, if registered.
    pub fn get_mut(&mut self, id: ActionId) -> Option<&mut (dyn DockingActionIf + 'static)> {
        self.entries.get_mut(&id).map(|e| e.action.as_mut())
    }

    /// Where the action lives.
    pub fn scope(&self, id: ActionId) -> Option<ActionScope> {
        self.entries.get(&id).map(|e| e.scope)
    }

    /// Actions currently bound to `ks`, in registration order. Computed from
    /// the actions' live key bindings, so rebinding through `state_mut()` (or
    /// an action rebinding itself) can never leave a stale entry.
    pub fn actions_for_key(&self, ks: KeyStroke) -> Vec<ActionId> {
        self.entries.iter().filter(|(_, e)| e.action.key_binding() == Some(ks)).map(|(id, _)| *id).collect()
    }

    /// All global actions.
    pub fn global_actions(&self) -> impl Iterator<Item = ActionId> + '_ {
        self.entries.iter().filter(|(_, e)| e.scope == ActionScope::Global).map(|(id, _)| *id)
    }

    /// Actions local to `provider`.
    pub fn local_actions(&self, provider: ProviderId) -> impl Iterator<Item = ActionId> + '_ {
        self.entries
            .iter()
            .filter(move |(_, e)| e.scope == ActionScope::Local(provider))
            .map(|(id, _)| *id)
    }

    /// Re-binds an action.
    pub fn set_key_binding(&mut self, id: ActionId, data: Option<KeyBindingData>) {
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.action.state_mut().set_key_binding_data(data);
        }
    }

    /// Drains every action's recorded changes.
    pub fn take_all_changes(&mut self) -> Vec<(ActionId, ActionChange)> {
        let mut out = Vec::new();
        for (id, e) in self.entries.iter_mut() {
            out.extend(e.action.take_changes().into_iter().map(|c| (*id, c)));
        }
        out
    }
}

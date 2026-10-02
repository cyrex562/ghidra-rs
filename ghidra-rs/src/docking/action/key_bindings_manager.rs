//! Port of the key-dispatch rules of `docking.action.KeyBindingsManager` and
//! `MultipleKeyAction`: which action a key stroke fires, given the focused
//! provider. Toolkit-neutral — the renderer forwards unconsumed key presses
//! here (Qt6 UI spec §4) and passes `NotHandled` keys on.

use crate::docking::action::{is_context_applicable, ActionId, DockingActionIf};
use crate::docking::action_context::ActionContext;
use crate::docking::actions::ToolActions;
use crate::docking::ProviderId;
use crate::util::awt::KeyStroke;

/// Outcome of dispatching a key stroke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchResult {
    /// The single valid, enabled action ran.
    Performed(ActionId),
    /// One valid action matched but is disabled for the context (Java beeps).
    Disabled(ActionId),
    /// Several valid, enabled actions matched; the renderer shows Ghidra's
    /// action chooser and invokes the chosen one.
    Ambiguous(Vec<ActionId>),
    /// No action is bound to this key for the current focus.
    NotHandled,
}

/// Context-sensitive key dispatch.
pub struct KeyBindingsManager;

impl KeyBindingsManager {
    /// Resolves and runs the action bound to `ks`.
    ///
    /// Rules (Java `MultipleKeyAction.getValidContextActions`): actions local
    /// to the focused provider are checked first against that provider's
    /// context; only if none is valid are global actions checked. Within the
    /// chosen set, candidates are ordered by [`KeyBindingPrecedence`](crate::docking::KeyBindingPrecedence)
    /// and only the best precedence level competes.
    pub fn dispatch(
        actions: &mut ToolActions,
        ks: KeyStroke,
        focused: Option<ProviderId>,
        ctx_for: &dyn Fn(Option<ProviderId>) -> Box<dyn ActionContext>,
    ) -> DispatchResult {
        let bound = actions.actions_for_key(ks);
        if bound.is_empty() {
            return DispatchResult::NotHandled;
        }
        let ctx = ctx_for(focused);
        let valid_in = |ids: &[ActionId], actions: &ToolActions| -> Vec<ActionId> {
            ids.iter()
                .copied()
                .filter(|id| {
                    actions.get(*id).is_some_and(|a| is_context_applicable(a, ctx.as_ref()) && a.is_valid_context(ctx.as_ref()))
                })
                .collect()
        };
        let local: Vec<ActionId> = match focused {
            Some(p) => bound.iter().copied().filter(|id| actions.scope(*id) == Some(crate::docking::actions::ActionScope::Local(p))).collect(),
            None => Vec::new(),
        };
        let mut candidates = valid_in(&local, actions);
        if candidates.is_empty() {
            let global: Vec<ActionId> =
                bound.iter().copied().filter(|id| actions.scope(*id) == Some(crate::docking::actions::ActionScope::Global)).collect();
            candidates = valid_in(&global, actions);
        }
        if candidates.is_empty() {
            return DispatchResult::NotHandled;
        }
        // Only the best (lowest) precedence level competes.
        let precedence = |id: &ActionId| {
            actions.get(*id).and_then(|a| a.key_binding_data()).map(|d| d.precedence())
        };
        let best = candidates.iter().filter_map(precedence).min();
        candidates.retain(|id| precedence(id) == best);

        let enabled: Vec<ActionId> =
            candidates.iter().copied().filter(|id| actions.get(*id).is_some_and(|a| a.is_enabled_for_context(ctx.as_ref()))).collect();
        match enabled.len() {
            0 => DispatchResult::Disabled(candidates[0]),
            1 => {
                let id = enabled[0];
                if let Some(a) = actions.get_mut(id) {
                    a.action_performed(ctx.as_ref());
                }
                DispatchResult::Performed(id)
            }
            _ => DispatchResult::Ambiguous(enabled),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use crate::docking::action::{DockingAction, KeyBindingData};
    use crate::docking::DefaultActionContext;
    use crate::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};

    struct A {
        s: DockingAction,
        hits: Arc<AtomicU32>,
        valid: bool,
        enabled: bool,
    }
    impl DockingActionIf for A {
        fn state(&self) -> &DockingAction {
            &self.s
        }
        fn state_mut(&mut self) -> &mut DockingAction {
            &mut self.s
        }
        fn action_performed(&mut self, _c: &dyn ActionContext) {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
        fn is_valid_context(&self, _c: &dyn ActionContext) -> bool {
            self.valid
        }
        fn is_enabled_for_context(&self, _c: &dyn ActionContext) -> bool {
            self.enabled
        }
    }
    fn ctrl_g() -> KeyStroke {
        KeyStroke::new(vk::G, CTRL_DOWN_MASK)
    }
    fn act(name: &str, valid: bool, enabled: bool) -> (Box<A>, Arc<AtomicU32>) {
        let hits = Arc::new(AtomicU32::new(0));
        let mut s = DockingAction::new(name, "T");
        s.set_key_binding_data(Some(KeyBindingData::new(ctrl_g())));
        (Box::new(A { s, hits: hits.clone(), valid, enabled }), hits)
    }
    fn ctx(p: Option<ProviderId>) -> Box<dyn ActionContext> {
        Box::new(DefaultActionContext::new().with_provider(p))
    }
    fn hits(h: &Arc<AtomicU32>) -> u32 {
        h.load(Ordering::SeqCst)
    }

    #[test]
    fn focused_provider_local_action_beats_global() {
        let mut t = ToolActions::new();
        let (g, g_hits) = act("Global", true, true);
        let (l, l_hits) = act("Local", true, true);
        t.add_global(g);
        let lid = t.add_local(ProviderId(1), l);
        let r = KeyBindingsManager::dispatch(&mut t, ctrl_g(), Some(ProviderId(1)), &ctx);
        assert_eq!(r, DispatchResult::Performed(lid));
        assert_eq!((hits(&l_hits), hits(&g_hits)), (1, 0));
    }

    #[test]
    fn global_fires_when_no_local_is_valid() {
        let mut t = ToolActions::new();
        let (g, g_hits) = act("Global", true, true);
        let (l, _) = act("Local", false, true);
        let gid = t.add_global(g);
        t.add_local(ProviderId(1), l);
        assert_eq!(
            KeyBindingsManager::dispatch(&mut t, ctrl_g(), Some(ProviderId(1)), &ctx),
            DispatchResult::Performed(gid)
        );
        assert_eq!(hits(&g_hits), 1);
    }

    #[test]
    fn other_providers_local_actions_are_ignored() {
        let mut t = ToolActions::new();
        let (l, h) = act("Local", true, true);
        t.add_local(ProviderId(2), l);
        assert_eq!(
            KeyBindingsManager::dispatch(&mut t, ctrl_g(), Some(ProviderId(1)), &ctx),
            DispatchResult::NotHandled
        );
        assert_eq!(hits(&h), 0);
    }

    #[test]
    fn valid_but_disabled_reports_disabled() {
        let mut t = ToolActions::new();
        let (g, h) = act("Global", true, false);
        let gid = t.add_global(g);
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx), DispatchResult::Disabled(gid));
        assert_eq!(hits(&h), 0);
    }

    #[test]
    fn two_valid_enabled_globals_are_ambiguous() {
        let mut t = ToolActions::new();
        let (a, _) = act("A", true, true);
        let (b, _) = act("B", true, true);
        let ia = t.add_global(a);
        let ib = t.add_global(b);
        match KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx) {
            DispatchResult::Ambiguous(mut ids) => {
                ids.sort();
                assert_eq!(ids, vec![ia, ib]);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn unbound_key_is_not_handled_and_rebinding_updates_index() {
        let mut t = ToolActions::new();
        let (a, _) = act("A", true, true);
        let id = t.add_global(a);
        let ctrl_h = KeyStroke::new(vk::H, CTRL_DOWN_MASK);
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_h, None, &ctx), DispatchResult::NotHandled);
        t.set_key_binding(id, Some(KeyBindingData::new(ctrl_h)));
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_h, None, &ctx), DispatchResult::Performed(id));
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx), DispatchResult::NotHandled);
    }

    #[test]
    fn removing_actions_clears_the_key_index() {
        let mut t = ToolActions::new();
        let (a, _) = act("A", true, true);
        let (l, _) = act("L", true, true);
        let id = t.add_global(a);
        t.add_local(ProviderId(4), l);
        assert!(t.remove(id).is_some());
        t.remove_provider_actions(ProviderId(4));
        assert!(t.actions_for_key(ctrl_g()).is_empty());
        assert_eq!(t.local_actions(ProviderId(4)).count(), 0);
    }
}

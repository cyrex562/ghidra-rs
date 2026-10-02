//! Port of the key-dispatch rules of `docking.action.KeyBindingsManager` and
//! `MultipleKeyAction`: which action a key stroke fires, given the focused
//! provider. Toolkit-neutral — the renderer forwards unconsumed key presses
//! here (Qt6 UI spec §4) and passes `NotHandled` keys on.

use std::any::TypeId;

use crate::docking::action::{ActionId, DockingActionIf};
use crate::docking::action_context::ActionContext;
use crate::docking::actions::{ActionScope, ToolActions};
use crate::docking::ProviderId;
use crate::util::awt::KeyStroke;

/// Outcome of dispatching a key stroke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchResult {
    /// The single valid, enabled action ran.
    Performed(ActionId),
    /// Valid actions matched but none is enabled for the context (Java beeps).
    Disabled(ActionId),
    /// Several valid, enabled actions matched; the renderer shows Ghidra's
    /// action chooser and invokes the chosen one.
    Ambiguous(Vec<ActionId>),
    /// No action is bound to this key for the current focus.
    NotHandled,
}

/// Context-sensitive key dispatch.
pub struct KeyBindingsManager;

/// Valid and enabled candidates found at one resolution step, with the
/// context they were evaluated in.
struct Step {
    valid: Vec<ActionId>,
    enabled: Vec<ActionId>,
    context: Option<Box<dyn ActionContext>>,
}

impl KeyBindingsManager {
    /// Resolves and runs the action bound to `ks`, following Java
    /// `MultipleKeyAction.createNonDialogExecutableAction`: the first step that
    /// yields a *valid* action wins (even if that action is disabled):
    /// 1. actions local to the focused provider, in the focused context;
    /// 2. global actions, in the focused context;
    /// 3. global actions that support a default context, each in the tool's
    ///    default context for its declared type (`default_ctx`).
    pub fn dispatch(
        actions: &mut ToolActions,
        ks: KeyStroke,
        focused: Option<ProviderId>,
        ctx_for: &dyn Fn(Option<ProviderId>) -> Box<dyn ActionContext>,
        default_ctx: &dyn Fn(TypeId) -> Option<Box<dyn ActionContext>>,
    ) -> DispatchResult {
        let bound = actions.actions_for_key(ks);
        if bound.is_empty() {
            return DispatchResult::NotHandled;
        }
        let local_ctx = ctx_for(focused);
        let in_ctx = |ids: Vec<ActionId>, ctx: &dyn ActionContext, actions: &ToolActions| -> (Vec<ActionId>, Vec<ActionId>) {
            let valid: Vec<ActionId> =
                ids.into_iter().filter(|id| actions.get(*id).is_some_and(|a| a.is_valid_context(ctx))).collect();
            let enabled = valid.iter().copied().filter(|id| actions.get(*id).is_some_and(|a| a.is_enabled_for_context(ctx))).collect();
            (valid, enabled)
        };

        let scoped = |scope: ActionScope| -> Vec<ActionId> {
            bound.iter().copied().filter(|id| actions.scope(*id) == Some(scope)).collect()
        };

        let mut step = Step { valid: Vec::new(), enabled: Vec::new(), context: None };
        if let Some(p) = focused {
            let (valid, enabled) = in_ctx(scoped(ActionScope::Local(p)), local_ctx.as_ref(), actions);
            step = Step { valid, enabled, context: None };
        }
        if step.valid.is_empty() {
            let (valid, enabled) = in_ctx(scoped(ActionScope::Global), local_ctx.as_ref(), actions);
            step = Step { valid, enabled, context: None };
        }
        if step.valid.is_empty() {
            // Step 3: default contexts, evaluated per action type.
            for id in scoped(ActionScope::Global) {
                let Some(a) = actions.get(id) else { continue };
                if !a.state().supports_default_context() {
                    continue;
                }
                let Some(ctx) = default_ctx(a.state().context_type()) else { continue };
                if !a.is_valid_context(ctx.as_ref()) {
                    continue;
                }
                step.valid.push(id);
                if a.is_enabled_for_context(ctx.as_ref()) {
                    step.enabled.push(id);
                    step.context = Some(ctx);
                }
            }
        }
        if step.valid.is_empty() {
            return DispatchResult::NotHandled;
        }
        match step.enabled.len() {
            0 => DispatchResult::Disabled(step.valid[0]),
            1 => {
                let id = step.enabled[0];
                let ctx = step.context.unwrap_or(local_ctx);
                if let Some(a) = actions.get_mut(id) {
                    a.action_performed(ctx.as_ref());
                }
                DispatchResult::Performed(id)
            }
            _ => DispatchResult::Ambiguous(step.enabled),
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
    fn no_default(_t: std::any::TypeId) -> Option<Box<dyn ActionContext>> {
        None
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
        let r = KeyBindingsManager::dispatch(&mut t, ctrl_g(), Some(ProviderId(1)), &ctx, &no_default);
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
            KeyBindingsManager::dispatch(&mut t, ctrl_g(), Some(ProviderId(1)), &ctx, &no_default),
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
            KeyBindingsManager::dispatch(&mut t, ctrl_g(), Some(ProviderId(1)), &ctx, &no_default),
            DispatchResult::NotHandled
        );
        assert_eq!(hits(&h), 0);
    }

    #[test]
    fn valid_but_disabled_reports_disabled() {
        let mut t = ToolActions::new();
        let (g, h) = act("Global", true, false);
        let gid = t.add_global(g);
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx, &no_default), DispatchResult::Disabled(gid));
        assert_eq!(hits(&h), 0);
    }

    #[test]
    fn two_valid_enabled_globals_are_ambiguous() {
        let mut t = ToolActions::new();
        let (a, _) = act("A", true, true);
        let (b, _) = act("B", true, true);
        let ia = t.add_global(a);
        let ib = t.add_global(b);
        match KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx, &no_default) {
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
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_h, None, &ctx, &no_default), DispatchResult::NotHandled);
        t.set_key_binding(id, Some(KeyBindingData::new(ctrl_h)));
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_h, None, &ctx, &no_default), DispatchResult::Performed(id));
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx, &no_default), DispatchResult::NotHandled);
    }

    /// A context type distinct from DefaultActionContext.
    #[derive(Default)]
    struct MarkerCtx(DefaultActionContext);
    impl ActionContext for MarkerCtx {
        fn component_provider(&self) -> Option<ProviderId> {
            self.0.component_provider()
        }
        fn context_object(&self) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
            self.0.context_object()
        }
        fn set_context_object(&mut self, o: Option<Arc<dyn std::any::Any + Send + Sync>>) {
            self.0.set_context_object(o)
        }
        fn set_event_click_modifiers(&mut self, m: i32) {
            self.0.set_event_click_modifiers(m)
        }
        fn event_click_modifiers(&self) -> i32 {
            self.0.event_click_modifiers()
        }
        fn has_any_event_click_modifiers(&self, m: i32) -> bool {
            self.0.has_any_event_click_modifiers(m)
        }
        fn set_source_object(&mut self, o: Option<Arc<dyn std::any::Any + Send + Sync>>) {
            self.0.set_source_object(o)
        }
        fn source_object(&self) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
            self.0.source_object()
        }
    }

    /// An action with Java's default (type-checked) validity.
    struct Typed {
        s: DockingAction,
        hits: Arc<AtomicU32>,
        saw_marker: Arc<AtomicU32>,
    }
    impl DockingActionIf for Typed {
        fn state(&self) -> &DockingAction {
            &self.s
        }
        fn state_mut(&mut self) -> &mut DockingAction {
            &mut self.s
        }
        fn action_performed(&mut self, c: &dyn ActionContext) {
            self.hits.fetch_add(1, Ordering::SeqCst);
            if c.as_any().downcast_ref::<MarkerCtx>().is_some() {
                self.saw_marker.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[test]
    fn typed_global_with_default_context_runs_in_that_context_not_the_focused_one() {
        let mut t = ToolActions::new();
        let hits = Arc::new(AtomicU32::new(0));
        let saw = Arc::new(AtomicU32::new(0));
        let mut s = DockingAction::new("Typed", "T");
        s.set_key_binding_data(Some(KeyBindingData::new(ctrl_g())));
        s.set_context_type(std::any::TypeId::of::<MarkerCtx>(), true);
        let gid = t.add_global(Box::new(Typed { s, hits: hits.clone(), saw_marker: saw.clone() }));
        // The focused context is a DefaultActionContext: not valid at steps 1-2,
        // and with no default context registered nothing runs.
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx, &no_default), DispatchResult::NotHandled);
        let with_default = |tid: std::any::TypeId| -> Option<Box<dyn ActionContext>> {
            (tid == std::any::TypeId::of::<MarkerCtx>()).then(|| Box::new(MarkerCtx::default()) as Box<dyn ActionContext>)
        };
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx, &with_default), DispatchResult::Performed(gid));
        assert_eq!((hits.load(Ordering::SeqCst), saw.load(Ordering::SeqCst)), (1, 1));
    }

    #[test]
    fn rebinding_through_state_is_seen_by_dispatch() {
        let mut t = ToolActions::new();
        let (a, _) = act("A", true, true);
        let id = t.add_global(a);
        let ctrl_h = KeyStroke::new(vk::H, CTRL_DOWN_MASK);
        t.get_mut(id).unwrap().state_mut().set_key_binding_data(Some(KeyBindingData::new(ctrl_h)));
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_h, None, &ctx, &no_default), DispatchResult::Performed(id));
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx, &no_default), DispatchResult::NotHandled);
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

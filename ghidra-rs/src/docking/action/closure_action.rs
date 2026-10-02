//! An action whose behaviour is a closure: the Rust form of Java's anonymous
//! `new DockingAction(name, owner) { actionPerformed(...) {...} }` subclasses
//! (and of `ActionBuilder`). Enablement/popup/validity overrides go through
//! the state's `enabled_when`/`popup_when`/`valid_context_when` predicates.

use crate::docking::action::{DockingAction, DockingActionIf};
use crate::docking::action_context::ActionContext;

/// Closure invoked by [`ClosureAction::action_performed`].
pub type PerformFn = Box<dyn FnMut(&dyn ActionContext) + Send>;

/// A docking action backed by a closure.
pub struct ClosureAction {
    state: DockingAction,
    perform: PerformFn,
}

impl ClosureAction {
    /// An action named `name`, owned by `owner`, running `perform`.
    pub fn new(name: impl Into<String>, owner: impl Into<String>, perform: impl FnMut(&dyn ActionContext) + Send + 'static) -> Self {
        Self { state: DockingAction::new(name, owner), perform: Box::new(perform) }
    }
}

impl DockingActionIf for ClosureAction {
    fn state(&self) -> &DockingAction {
        &self.state
    }
    fn state_mut(&mut self) -> &mut DockingAction {
        &mut self.state
    }
    fn action_performed(&mut self, context: &dyn ActionContext) {
        (self.perform)(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::DefaultActionContext;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn runs_closure_and_honours_predicates() {
        let n = Arc::new(AtomicU32::new(0));
        let n2 = n.clone();
        let mut a = ClosureAction::new("Go", "T", move |_| {
            n2.fetch_add(1, Ordering::SeqCst);
        });
        a.state_mut().enabled_when(Box::new(|_| false));
        a.state_mut().popup_when(Box::new(|_| true));
        let ctx = DefaultActionContext::new();
        assert!(!a.is_enabled_for_context(&ctx));
        assert!(a.is_add_to_popup(&ctx));
        a.action_performed(&ctx);
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }
}

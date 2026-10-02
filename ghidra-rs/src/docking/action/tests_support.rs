//! Shared test doubles for docking actions.

use crate::docking::action::{DockingAction, DockingActionIf};
use crate::docking::action_context::ActionContext;

/// An action that does nothing when performed.
pub(crate) struct NoopAction(pub DockingAction);

impl DockingActionIf for NoopAction {
    fn state(&self) -> &DockingAction {
        &self.0
    }
    fn state_mut(&mut self) -> &mut DockingAction {
        &mut self.0
    }
    fn action_performed(&mut self, _c: &dyn ActionContext) {}
}

/// A no-op action named `name` owned by `"Test"`.
pub(crate) fn noop_action(name: &str) -> NoopAction {
    NoopAction(DockingAction::new(name, "Test"))
}

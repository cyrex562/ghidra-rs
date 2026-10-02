use std::sync::Arc;

use crate::docking::action_context::ActionContext;
use super::docking_action_if::DockingActionIf;

/// Marker interface for actions that can expand into multiple actions at runtime.
///
/// This trait allows a [`DockingActionIf`] implementation to dynamically provide a list of
/// related actions based on the current [`ActionContext`]. This is useful for creating
/// context-dependent action expansions.
///
/// Implementations should mix this trait into their `DockingActionIf` implementation.
///
/// Port of `docking.action.MultiActionDockingActionIf`.
pub trait MultiActionDockingActionIf {
    /// Returns a list of actions based on the provided context.
    ///
    /// # Arguments
    ///
    /// * `context` - The action context used to determine which actions to return.
    ///
    /// # Returns
    ///
    /// A vector of `DockingActionIf` implementations. An empty vector indicates no actions
    /// are available for the given context.
    fn get_action_list(&self, context: &dyn ActionContext) -> Vec<Arc<dyn DockingActionIf>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::action::docking_action::DockingAction;
    use crate::docking::DefaultActionContext;

    struct Leaf(DockingAction);
    impl DockingActionIf for Leaf {
        fn state(&self) -> &DockingAction {
            &self.0
        }
        fn state_mut(&mut self) -> &mut DockingAction {
            &mut self.0
        }
        fn action_performed(&mut self, _c: &dyn ActionContext) {}
    }

    struct Multi;
    impl MultiActionDockingActionIf for Multi {
        fn get_action_list(&self, context: &dyn ActionContext) -> Vec<Arc<dyn DockingActionIf>> {
            if context.event_click_modifiers() == 0 {
                vec![Arc::new(Leaf(DockingAction::new("One", "M"))), Arc::new(Leaf(DockingAction::new("Two", "M")))]
            } else {
                Vec::new()
            }
        }
    }

    #[test]
    fn list_depends_on_context() {
        let names: Vec<String> =
            Multi.get_action_list(&DefaultActionContext::new()).iter().map(|a| a.name().to_owned()).collect();
        assert_eq!(names, vec!["One", "Two"]);
        let mut ctx = DefaultActionContext::new();
        ctx.set_event_click_modifiers(1);
        assert!(Multi.get_action_list(&ctx).is_empty());
    }
}

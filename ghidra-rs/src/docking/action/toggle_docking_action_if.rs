use super::docking_action::ActionChange;
use super::docking_action_if::DockingActionIf;

/// Name of the select state property, fired when [`ToggleDockingActionIf::is_selected`] changes.
pub const SELECTED_STATE_PROPERTY: &str = "selectState";

/// Interface for actions that have a toggle state.
///
/// Port of `docking.action.ToggleDockingActionIf`; selection changes are
/// recorded as [`ActionChange::Selected`] on the action's state.
pub trait ToggleDockingActionIf: DockingActionIf {
    /// Returns true if the toggle state for this action is currently selected.
    fn is_selected(&self) -> bool;

    /// Sets the toggle state for this action.
    fn set_selected(&mut self, new_value: bool);
}

/// Port of `docking.action.ToggleDockingAction`'s selection bookkeeping: embed
/// in a toggle action and forward `is_selected`/`set_selected` to it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ToggleState {
    selected: bool,
}

impl ToggleState {
    /// Current selection.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Sets the selection; returns the change to record if it changed.
    pub fn set_selected(&mut self, selected: bool) -> Option<ActionChange> {
        if selected == self.selected {
            return None;
        }
        self.selected = selected;
        Some(ActionChange::Selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::action::docking_action::DockingAction;
    use crate::docking::action_context::ActionContext;

    struct Toggle {
        state: DockingAction,
        toggle: ToggleState,
    }
    impl DockingActionIf for Toggle {
        fn state(&self) -> &DockingAction {
            &self.state
        }
        fn state_mut(&mut self) -> &mut DockingAction {
            &mut self.state
        }
        fn action_performed(&mut self, _c: &dyn ActionContext) {
            let s = !self.is_selected();
            self.set_selected(s);
        }
    }
    impl ToggleDockingActionIf for Toggle {
        fn is_selected(&self) -> bool {
            self.toggle.is_selected()
        }
        fn set_selected(&mut self, v: bool) {
            self.toggle.set_selected(v);
        }
    }

    #[test]
    fn performing_flips_selection() {
        let mut t = Toggle { state: DockingAction::new("Wrap", "Listing"), toggle: ToggleState::default() };
        assert!(!t.is_selected());
        t.action_performed(&crate::docking::DefaultActionContext::new());
        assert!(t.is_selected());
        let dyn_toggle: &mut dyn ToggleDockingActionIf = &mut t;
        dyn_toggle.set_selected(false);
        assert!(!dyn_toggle.is_selected());
    }

    #[test]
    fn toggle_state_reports_change_only_on_flip() {
        let mut s = ToggleState::default();
        assert_eq!(s.set_selected(false), None);
        assert_eq!(s.set_selected(true), Some(ActionChange::Selected));
    }
}

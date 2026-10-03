//! Listener interface for notifications when the program selection changes.

use crate::app::seam_stubs::ProgramSelection;
use crate::docking::widgets::event_trigger::EventTrigger;

/// Notified whenever the program selection changes.
///
/// Corresponds to Java `ghidra.app.util.viewer.listingpanel.ProgramSelectionListener`.
pub trait ProgramSelectionListener {
    /// Called whenever the program selection changes.
    ///
    /// # Arguments
    ///
    /// * `selection` - The new program selection.
    /// * `trigger` - The cause of the change (user action, API call, model change, or internal).
    fn program_selection_changed(&mut self, selection: &dyn ProgramSelection, trigger: EventTrigger);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProgramSelection {
        is_empty: bool,
    }

    impl ProgramSelection for MockProgramSelection {
        fn is_empty(&self) -> bool {
            self.is_empty
        }
    }

    struct RecordingListener {
        calls: Vec<(bool, EventTrigger)>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
            }
        }
    }

    impl ProgramSelectionListener for RecordingListener {
        fn program_selection_changed(&mut self, selection: &dyn ProgramSelection, trigger: EventTrigger) {
            self.calls.push((selection.is_empty(), trigger));
        }
    }

    #[test]
    fn test_program_selection_changed_called() {
        let mut listener = RecordingListener::new();
        let selection = MockProgramSelection { is_empty: false };
        listener.program_selection_changed(&selection, EventTrigger::GuiAction);
        assert_eq!(listener.calls.len(), 1);
        assert_eq!(listener.calls[0], (false, EventTrigger::GuiAction));
    }

    #[test]
    fn test_program_selection_changed_empty_selection() {
        let mut listener = RecordingListener::new();
        let selection = MockProgramSelection { is_empty: true };
        listener.program_selection_changed(&selection, EventTrigger::ApiCall);
        assert_eq!(listener.calls.len(), 1);
        assert_eq!(listener.calls[0], (true, EventTrigger::ApiCall));
    }

    #[test]
    fn test_program_selection_changed_multiple_triggers() {
        let mut listener = RecordingListener::new();
        let selection1 = MockProgramSelection { is_empty: false };
        let selection2 = MockProgramSelection { is_empty: true };
        listener.program_selection_changed(&selection1, EventTrigger::GuiAction);
        listener.program_selection_changed(&selection2, EventTrigger::ModelChange);
        listener.program_selection_changed(&selection1, EventTrigger::ApiCall);
        assert_eq!(listener.calls.len(), 3);
        assert_eq!(listener.calls[0], (false, EventTrigger::GuiAction));
        assert_eq!(listener.calls[1], (true, EventTrigger::ModelChange));
        assert_eq!(listener.calls[2], (false, EventTrigger::ApiCall));
    }

    #[test]
    fn test_trait_object_dispatch() {
        let mut listener: Box<dyn ProgramSelectionListener> = Box::new(RecordingListener::new());
        let selection = MockProgramSelection { is_empty: false };
        listener.program_selection_changed(&selection, EventTrigger::InternalOnly);
    }
}

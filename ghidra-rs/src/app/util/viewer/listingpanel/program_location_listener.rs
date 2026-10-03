//! Listener interface for notifications when the program location changes.

use crate::docking::widgets::event_trigger::EventTrigger;
use crate::program::util::program_location::ProgramLocation;

/// Notified when the program location changes.
///
/// Corresponds to Java `ghidra.app.util.viewer.listingpanel.ProgramLocationListener`.
pub trait ProgramLocationListener {
    /// Called whenever the program location changes.
    ///
    /// # Arguments
    ///
    /// * `loc` - The new program location.
    /// * `trigger` - The cause of the change (user action, API call, model change, or internal).
    fn program_location_changed(&mut self, loc: &dyn ProgramLocation, trigger: EventTrigger);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockProgramLocation;

    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            panic!("Not implemented for mock");
        }

        fn get_address(&self) -> crate::program::model::address::Address {
            panic!("Not implemented for mock");
        }

        fn get_byte_address(&self) -> crate::program::model::address::Address {
            panic!("Not implemented for mock");
        }

        fn get_ref_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }

        fn get_component_path(&self) -> Option<&[i32]> {
            None
        }

        fn get_row(&self) -> i32 {
            0
        }

        fn get_column(&self) -> i32 {
            0
        }

        fn get_char_offset(&self) -> i32 {
            0
        }

        fn is_valid(&self, _test_program: &dyn crate::program::model::listing::Program) -> bool {
            true
        }
    }

    struct RecordingListener {
        calls: Vec<EventTrigger>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
            }
        }
    }

    impl ProgramLocationListener for RecordingListener {
        fn program_location_changed(&mut self, _loc: &dyn ProgramLocation, trigger: EventTrigger) {
            self.calls.push(trigger);
        }
    }

    #[test]
    fn test_program_location_changed_called() {
        let mut listener = RecordingListener::new();
        let loc = MockProgramLocation;
        listener.program_location_changed(&loc, EventTrigger::GuiAction);
        assert_eq!(listener.calls.len(), 1);
        assert_eq!(listener.calls[0], EventTrigger::GuiAction);
    }

    #[test]
    fn test_program_location_changed_multiple_triggers() {
        let mut listener = RecordingListener::new();
        let loc = MockProgramLocation;
        listener.program_location_changed(&loc, EventTrigger::GuiAction);
        listener.program_location_changed(&loc, EventTrigger::ApiCall);
        listener.program_location_changed(&loc, EventTrigger::ModelChange);
        assert_eq!(listener.calls.len(), 3);
        assert_eq!(listener.calls[0], EventTrigger::GuiAction);
        assert_eq!(listener.calls[1], EventTrigger::ApiCall);
        assert_eq!(listener.calls[2], EventTrigger::ModelChange);
    }

    #[test]
    fn test_trait_object_dispatch() {
        let mut listener: Box<dyn ProgramLocationListener> = Box::new(RecordingListener::new());
        let loc = MockProgramLocation;
        listener.program_location_changed(&loc, EventTrigger::ApiCall);
    }
}

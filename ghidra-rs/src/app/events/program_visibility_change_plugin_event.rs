use crate::framework::plugintool::PluginEvent;
use crate::program::model::listing::Program;
use std::sync::Weak;

const NAME: &str = "Open Program";

/// Event for telling a tool to open or close a program.
///
/// Mirrors `ghidra.app.events.ProgramVisibilityChangePluginEvent`.
pub struct ProgramVisibilityChangePluginEvent {
    event: PluginEvent,
    program_ref: Weak<dyn Program>,
    is_visible: bool,
}

impl ProgramVisibilityChangePluginEvent {
    /// Creates a new program visibility change event.
    ///
    /// # Arguments
    ///
    /// * `source` - Name of the plugin that created this event
    /// * `program` - The program associated with this event (wrapped in Arc)
    /// * `is_visible` - True if the program is becoming visible, false if it's closing
    pub fn new(
        source: impl Into<String>,
        program: std::sync::Arc<dyn Program>,
        is_visible: bool,
    ) -> Self {
        let program_ref = std::sync::Arc::downgrade(&program);

        Self {
            event: PluginEvent::new(source, NAME),
            program_ref,
            is_visible,
        }
    }

    /// Returns the program associated with this event, or `None` if the program has been closed.
    ///
    /// In the original Java, this can return null when the program is no longer in use.
    ///
    /// Mirrors `getProgram()`.
    pub fn get_program(&self) -> Option<std::sync::Arc<dyn Program>> {
        self.program_ref.upgrade()
    }

    /// Returns true if the program is currently in a visible state.
    ///
    /// Mirrors `isProgramVisible()`.
    pub fn is_program_visible(&self) -> bool {
        self.is_visible
    }

    /// Returns a reference to the underlying `PluginEvent`.
    pub fn event(&self) -> &PluginEvent {
        &self.event
    }

    /// Returns a mutable reference to the underlying `PluginEvent`.
    pub fn event_mut(&mut self) -> &mut PluginEvent {
        &mut self.event
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "MockProgram".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
    }

    #[test]
    fn new_stores_source() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramVisibilityChangePluginEvent::new("TestPlugin", program, true);

        assert_eq!(event.event().source_name(), "TestPlugin");
    }

    #[test]
    fn new_stores_visibility() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramVisibilityChangePluginEvent::new("TestPlugin", program, true);

        assert!(event.is_program_visible());
    }

    #[test]
    fn new_stores_program() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramVisibilityChangePluginEvent::new("TestPlugin", program.clone(), true);

        assert!(event.get_program().is_some());
    }

    #[test]
    fn event_name_is_correct() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramVisibilityChangePluginEvent::new("TestPlugin", program, true);

        assert_eq!(event.event().event_name(), "Open Program");
    }

    #[test]
    fn get_program_returns_program_while_arc_alive() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramVisibilityChangePluginEvent::new("TestPlugin", program.clone(), true);

        assert!(event.get_program().is_some());
    }

    #[test]
    fn get_program_returns_none_after_arc_dropped() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramVisibilityChangePluginEvent::new("TestPlugin", program.clone(), true);

        drop(program);

        assert!(event.get_program().is_none());
    }

    #[test]
    fn visibility_false_indicates_closing() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramVisibilityChangePluginEvent::new("TestPlugin", program, false);

        assert!(!event.is_program_visible());
    }

    #[test]
    fn event_mut_allows_modification() {
        let program = std::sync::Arc::new(MockProgram);
        let mut event = ProgramVisibilityChangePluginEvent::new("TestPlugin", program, true);

        event.event_mut().set_source_name("NewSource");
        assert_eq!(event.event().source_name(), "NewSource");
    }

    #[test]
    fn name_constant_is_correct() {
        assert_eq!(NAME, "Open Program");
    }
}

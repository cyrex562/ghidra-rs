use crate::framework::plugintool::PluginEvent;
use crate::program::model::listing::Program;
use std::sync::Weak;

const NAME: &str = "Program Closed";

/// Event for notification of a program being closed.
///
/// Mirrors `ghidra.app.events.ProgramClosedPluginEvent`.
pub struct ProgramClosedPluginEvent {
    event: PluginEvent,
    program_ref: Weak<dyn Program>,
}

impl ProgramClosedPluginEvent {
    /// Creates a new program closed event.
    ///
    /// # Arguments
    ///
    /// * `source` - Name of the plugin that created this event
    /// * `program` - The program associated with this event (wrapped in Arc)
    pub fn new(source: impl Into<String>, program: std::sync::Arc<dyn Program>) -> Self {
        let program_ref = std::sync::Arc::downgrade(&program);

        Self {
            event: PluginEvent::new(source, NAME),
            program_ref,
        }
    }

    /// Returns the program that has just been closed, or `None` if it has been dropped.
    ///
    /// Mirrors `getProgram()`.
    pub fn get_program(&self) -> Option<std::sync::Arc<dyn Program>> {
        self.program_ref.upgrade()
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
        let event = ProgramClosedPluginEvent::new("TestPlugin", program);

        assert_eq!(event.event().source_name(), "TestPlugin");
    }

    #[test]
    fn new_stores_program() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramClosedPluginEvent::new("TestPlugin", program.clone());

        assert!(event.get_program().is_some());
    }

    #[test]
    fn event_name_is_correct() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramClosedPluginEvent::new("TestPlugin", program);

        assert_eq!(event.event().event_name(), "Program Closed");
    }

    #[test]
    fn get_program_returns_program_while_arc_alive() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramClosedPluginEvent::new("TestPlugin", program.clone());

        assert!(event.get_program().is_some());
    }

    #[test]
    fn get_program_returns_none_after_arc_dropped() {
        let program = std::sync::Arc::new(MockProgram);
        let event = ProgramClosedPluginEvent::new("TestPlugin", program.clone());

        drop(program);

        assert!(event.get_program().is_none());
    }

    #[test]
    fn event_mut_allows_modification() {
        let program = std::sync::Arc::new(MockProgram);
        let mut event = ProgramClosedPluginEvent::new("TestPlugin", program);

        event.event_mut().set_source_name("NewSource");
        assert_eq!(event.event().source_name(), "NewSource");
    }

    #[test]
    fn name_constant_is_correct() {
        assert_eq!(NAME, "Program Closed");
    }
}

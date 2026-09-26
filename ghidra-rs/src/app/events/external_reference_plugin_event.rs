use crate::framework::plugintool::PluginEvent;
use crate::program::model::symbol::ExternalLocation;
use std::sync::Arc;

const NAME: &str = "ExternalReference";

/// Event for navigating to a location in another program when following an external reference.
///
/// Mirrors `ghidra.app.events.ExternalReferencePluginEvent`.
pub struct ExternalReferencePluginEvent {
    event: PluginEvent,
    external_location: Arc<dyn ExternalLocation>,
    program_path: String,
}

impl ExternalReferencePluginEvent {
    /// Creates a new external reference event.
    ///
    /// # Arguments
    ///
    /// * `source` - Name of the plugin that created this event
    /// * `external_location` - The external location to follow
    /// * `program_path` - The ghidra path name of the program file to go to
    pub fn new(
        source: impl Into<String>,
        external_location: Arc<dyn ExternalLocation>,
        program_path: impl Into<String>,
    ) -> Self {
        Self {
            event: PluginEvent::new(source, NAME),
            external_location,
            program_path: program_path.into(),
        }
    }

    /// Returns the external location associated with this event.
    ///
    /// Mirrors `getExternalLocation()`.
    pub fn get_external_location(&self) -> Arc<dyn ExternalLocation> {
        Arc::clone(&self.external_location)
    }

    /// Returns the program path name.
    ///
    /// Mirrors `getProgramPath()`.
    pub fn get_program_path(&self) -> &str {
        &self.program_path
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

    struct MockExternalLocation;

    impl ExternalLocation for MockExternalLocation {}

    #[test]
    fn new_stores_source() {
        let ext_loc = Arc::new(MockExternalLocation) as Arc<dyn ExternalLocation>;
        let event = ExternalReferencePluginEvent::new("TestPlugin", ext_loc, "/path/to/program");

        assert_eq!(event.event().source_name(), "TestPlugin");
    }

    #[test]
    fn new_stores_external_location() {
        let ext_loc = Arc::new(MockExternalLocation) as Arc<dyn ExternalLocation>;
        let event = ExternalReferencePluginEvent::new("TestPlugin", ext_loc.clone(), "/path/to/program");

        assert!(Arc::ptr_eq(&event.get_external_location(), &ext_loc));
    }

    #[test]
    fn event_name_is_correct() {
        let ext_loc = Arc::new(MockExternalLocation) as Arc<dyn ExternalLocation>;
        let event = ExternalReferencePluginEvent::new("TestPlugin", ext_loc, "/path/to/program");

        assert_eq!(event.event().event_name(), "ExternalReference");
    }

    #[test]
    fn get_program_path_returns_stored_path() {
        let ext_loc = Arc::new(MockExternalLocation) as Arc<dyn ExternalLocation>;
        let program_path = "/path/to/program.ghidra";
        let event = ExternalReferencePluginEvent::new("TestPlugin", ext_loc, program_path);

        assert_eq!(event.get_program_path(), program_path);
    }

    #[test]
    fn event_mut_allows_modification() {
        let ext_loc = Arc::new(MockExternalLocation) as Arc<dyn ExternalLocation>;
        let mut event = ExternalReferencePluginEvent::new("TestPlugin", ext_loc, "/path/to/program");

        event.event_mut().set_source_name("NewSource");
        assert_eq!(event.event().source_name(), "NewSource");
    }

    #[test]
    fn multiple_clones_of_external_location_are_same() {
        let ext_loc = Arc::new(MockExternalLocation) as Arc<dyn ExternalLocation>;
        let event = ExternalReferencePluginEvent::new("TestPlugin", ext_loc.clone(), "/path/to/program");

        let cloned = event.get_external_location();
        assert!(Arc::ptr_eq(&ext_loc, &cloned));
    }

    #[test]
    fn name_constant_is_correct() {
        assert_eq!(NAME, "ExternalReference");
    }
}

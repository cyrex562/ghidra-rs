use std::sync::Arc;

use super::abstract_location_plugin_event::AbstractLocationPluginEvent;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

/// The name of this plugin event.
///
/// Mirrors `ProgramLocationPluginEvent.NAME`.
pub const NAME: &str = "ProgramLocationChange";

/// This plugin event class provides program location information.
///
/// The event is fired when a plugin's program location has changed. Typically, a plugin does
/// not actually generate the event unless it is processing some user action, e.g., the user
/// mouse clicks somewhere on a plugin component to cause the program location to change.
///
/// Port of `ghidra.app.events.ProgramLocationPluginEvent`, a `final` class extending
/// `AbstractLocationPluginEvent`. Rust has no inheritance, so this struct composes
/// [`AbstractLocationPluginEvent`] the same way that struct composes
/// [`PluginEvent`](crate::framework::plugintool::PluginEvent).
pub struct ProgramLocationPluginEvent {
    base: AbstractLocationPluginEvent,
}

impl ProgramLocationPluginEvent {
    /// Construct a new `ProgramLocationPluginEvent`.
    ///
    /// Mirrors `ProgramLocationPluginEvent(String src, ProgramLocation loc, Program program)`,
    /// which forwards to `super(src, NAME, loc, program)`. That superclass constructor does not
    /// reject a `None` location; see
    /// [`AbstractLocationPluginEvent::new`] for the faithfully-reproduced quirk this inherits.
    ///
    /// # Arguments
    ///
    /// * `src` - the name of the plugin that generated this event.
    /// * `loc` - the `ProgramLocation` that contains the new location.
    /// * `program` - the `Program` for which `loc` refers.
    pub fn new(
        src: impl Into<String>,
        loc: Option<Arc<dyn ProgramLocation + Send + Sync>>,
        program: &Arc<dyn Program>,
    ) -> Self {
        Self {
            base: AbstractLocationPluginEvent::new(src, NAME, loc, program),
        }
    }

    /// Get the location stored in this event.
    ///
    /// Mirrors the inherited `getLocation()`.
    pub fn get_location(&self) -> Option<Arc<dyn ProgramLocation + Send + Sync>> {
        self.base.get_location()
    }

    /// Get the program that the location refers to, or `None` if it has since been closed and
    /// dropped.
    ///
    /// Mirrors the inherited `getProgram()`.
    pub fn get_program(&self) -> Option<Arc<dyn Program>> {
        self.base.get_program()
    }

    /// Returns a reference to the underlying [`AbstractLocationPluginEvent`].
    pub fn base(&self) -> &AbstractLocationPluginEvent {
        &self.base
    }

    /// Returns a mutable reference to the underlying [`AbstractLocationPluginEvent`].
    pub fn base_mut(&mut self) -> &mut AbstractLocationPluginEvent {
        &mut self.base
    }

    /// Returns a reference to the underlying `PluginEvent`.
    pub fn event(&self) -> &crate::framework::plugintool::PluginEvent {
        self.base.event()
    }

    /// Returns a mutable reference to the underlying `PluginEvent`.
    pub fn event_mut(&mut self) -> &mut crate::framework::plugintool::PluginEvent {
        self.base.event_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

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

    struct MockLocation {
        address: Address,
    }

    impl ProgramLocation for MockLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    fn mock_location(offset: i64) -> Arc<dyn ProgramLocation + Send + Sync> {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Arc::new(MockLocation {
            address: Address::new(space, offset),
        })
    }

    #[test]
    fn name_constant_matches_java() {
        assert_eq!(NAME, "ProgramLocationChange");
    }

    #[test]
    fn new_stores_source_and_fixed_event_name() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event =
            ProgramLocationPluginEvent::new("MyPlugin", Some(mock_location(0x400)), &program);
        assert_eq!(event.event().source_name(), "MyPlugin");
        assert_eq!(event.event().event_name(), NAME);
    }

    #[test]
    fn get_location_returns_the_stored_location() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let location = mock_location(0x1234);
        let event = ProgramLocationPluginEvent::new("P", Some(location.clone()), &program);
        let got = event.get_location().expect("location should be present");
        assert_eq!(got.get_address(), location.get_address());
    }

    #[test]
    fn get_program_returns_program_while_arc_alive() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = ProgramLocationPluginEvent::new("P", Some(mock_location(0x10)), &program);
        assert!(event.get_program().is_some());
    }

    #[test]
    fn get_program_returns_none_after_program_dropped() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = ProgramLocationPluginEvent::new("P", Some(mock_location(0x10)), &program);
        drop(program);
        assert!(event.get_program().is_none());
    }

    #[test]
    fn details_include_the_address_when_location_is_set() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = ProgramLocationPluginEvent::new("P", Some(mock_location(0x400)), &program);
        let display = event.event().to_string();
        assert!(display.contains("Details:"));
        assert!(display.contains("addr==>"));
    }

    /// Faithful reproduction of the quirk inherited from `AbstractLocationPluginEvent`: a
    /// `None` location does not fail construction (Java's constructor merely logs an error via
    /// `Msg.showError`, never throws). The event still constructs and `get_location()` is
    /// `None`.
    #[test]
    fn none_location_still_constructs_a_valid_event() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = ProgramLocationPluginEvent::new("P", None, &program);
        assert!(event.get_location().is_none());
        assert!(!event.event().to_string().contains("Details:"));
    }

    #[test]
    fn event_mut_allows_modification() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let mut event = ProgramLocationPluginEvent::new("Orig", Some(mock_location(0x1)), &program);
        event.event_mut().set_source_name("Updated");
        assert_eq!(event.event().source_name(), "Updated");
    }

    #[test]
    fn base_and_base_mut_expose_the_composed_abstract_event() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let mut event = ProgramLocationPluginEvent::new("P", Some(mock_location(0x1)), &program);
        assert!(event.base().get_location().is_some());
        event.base_mut().event_mut().set_source_name("ViaBase");
        assert_eq!(event.event().source_name(), "ViaBase");
    }
}

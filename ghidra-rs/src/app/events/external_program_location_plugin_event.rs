use std::sync::{Arc, Weak};

use crate::framework::plugintool::tool_event_name::ToolEventName;
use crate::framework::plugintool::{PluginEvent, PluginEventBehavior};
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

/// The name of this plugin event.
///
/// Mirrors `ExternalProgramLocationPluginEvent.NAME`.
pub const NAME: &str = "External Program Location Change";

/// The cross-tool event name this event is published under.
///
/// Mirrors `ExternalProgramLocationPluginEvent.TOOL_EVENT_NAME`, which the class's
/// `@ToolEventName` annotation refers to (`this allows the event to be considered for tool
/// connection`).
pub const TOOL_EVENT_NAME: &str = "Program Location Change";

/// Supplies the `@ToolEventName(ExternalProgramLocationPluginEvent.TOOL_EVENT_NAME)` annotation
/// to the composed [`PluginEvent`]. This event overrides no other `PluginEvent` hook (no
/// `getDetails()` override in the Java source), so `details()` is left at its default.
struct ToolEventNameBehavior {
    tool_event_name: ToolEventName,
}

impl PluginEventBehavior for ToolEventNameBehavior {
    fn tool_event_name(&self) -> Option<&ToolEventName> {
        Some(&self.tool_event_name)
    }
}

/// Plugin event that is generated when a tool receives an external `ProgramLocation` tool
/// event.
///
/// Port of `ghidra.app.events.ExternalProgramLocationPluginEvent`, a `final` class extending
/// `PluginEvent` directly (*not* `AbstractLocationPluginEvent` -- despite the similar name and
/// purpose, the real `extends` clause is `PluginEvent`, and this class keeps its own `loc`/
/// `programRef` fields and accessors rather than delegating to the abstract location base).
/// Rust has no inheritance, so this struct composes a [`PluginEvent`] directly, following the
/// same pattern used by
/// [`ProgramActivatedPluginEvent`](super::program_activated_plugin_event::ProgramActivatedPluginEvent).
pub struct ExternalProgramLocationPluginEvent {
    event: PluginEvent,
    loc: Option<Arc<dyn ProgramLocation + Send + Sync>>,
    program_ref: Weak<dyn Program>,
}

impl ExternalProgramLocationPluginEvent {
    /// Construct a new `ExternalProgramLocationPluginEvent`.
    ///
    /// Mirrors `ExternalProgramLocationPluginEvent(String src, ProgramLocation loc, Program
    /// program)`, which forwards to `super(src, NAME)` and then stores `loc` and a
    /// `WeakReference` to `program` directly, with no null check on either argument (unlike
    /// `AbstractLocationPluginEvent`'s constructor, which logs -- but does not throw -- on a
    /// null location). A `None` location is therefore stored as-is with no side effect.
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
        let behavior = ToolEventNameBehavior {
            tool_event_name: ToolEventName::new(TOOL_EVENT_NAME),
        };
        Self {
            event: PluginEvent::with_behavior(src, NAME, Box::new(behavior)),
            loc,
            program_ref: Arc::downgrade(program),
        }
    }

    /// Returns the `ProgramLocation` stored in this event.
    ///
    /// Mirrors `getLocation()`.
    pub fn get_location(&self) -> Option<Arc<dyn ProgramLocation + Send + Sync>> {
        self.loc.clone()
    }

    /// Returns the `Program` object that the location refers to, or `None` if it has since been
    /// closed and dropped.
    ///
    /// Mirrors `getProgram()`, which reads a `WeakReference`.
    pub fn get_program(&self) -> Option<Arc<dyn Program>> {
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
    fn name_constants_match_java() {
        assert_eq!(NAME, "External Program Location Change");
        assert_eq!(TOOL_EVENT_NAME, "Program Location Change");
    }

    #[test]
    fn new_stores_source_and_fixed_event_name() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = ExternalProgramLocationPluginEvent::new(
            "MyPlugin",
            Some(mock_location(0x400)),
            &program,
        );
        assert_eq!(event.event().source_name(), "MyPlugin");
        assert_eq!(event.event().event_name(), NAME);
    }

    /// Mirrors the effect of the class's `@ToolEventName(TOOL_EVENT_NAME)` annotation: the
    /// event is available for passing between tools via a `ToolConnection`, under the name
    /// `TOOL_EVENT_NAME` (distinct from its own `event_name()`).
    #[test]
    fn tool_event_name_is_set_from_the_annotation_value() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = ExternalProgramLocationPluginEvent::new(
            "MyPlugin",
            Some(mock_location(0x400)),
            &program,
        );
        assert!(event.event().is_tool_event());
        assert_eq!(
            event.event().tool_event_name(),
            Some(&ToolEventName::new(TOOL_EVENT_NAME))
        );
    }

    #[test]
    fn get_location_returns_the_stored_location() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let location = mock_location(0x1234);
        let event =
            ExternalProgramLocationPluginEvent::new("P", Some(location.clone()), &program);
        let got = event.get_location().expect("location should be present");
        assert_eq!(got.get_address(), location.get_address());
    }

    #[test]
    fn get_program_returns_program_while_arc_alive() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event =
            ExternalProgramLocationPluginEvent::new("P", Some(mock_location(0x10)), &program);
        assert!(event.get_program().is_some());
    }

    #[test]
    fn get_program_returns_none_after_program_dropped() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event =
            ExternalProgramLocationPluginEvent::new("P", Some(mock_location(0x10)), &program);
        drop(program);
        assert!(event.get_program().is_none());
    }

    /// Java quirk faithfully reproduced: unlike `AbstractLocationPluginEvent`, this class's
    /// constructor performs no null check on `loc` at all -- no logging, no exception
    /// construction, nothing. A `None` location is simply stored, and `getDetails()` is not
    /// even overridden here (it always returns the `PluginEvent` default of `null`), so there is
    /// no location-dependent behavior to diverge from in the first place.
    #[test]
    fn none_location_is_silently_stored_with_no_details_override() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = ExternalProgramLocationPluginEvent::new("P", None, &program);
        assert!(event.get_location().is_none());
        assert!(!event.event().to_string().contains("Details:"));
    }

    #[test]
    fn event_mut_allows_modification() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let mut event = ExternalProgramLocationPluginEvent::new(
            "Orig",
            Some(mock_location(0x1)),
            &program,
        );
        event.event_mut().set_source_name("Updated");
        assert_eq!(event.event().source_name(), "Updated");
    }
}

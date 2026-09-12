use std::sync::{Arc, Weak};

use crate::framework::plugintool::{PluginEvent, PluginEventBehavior};
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;
use crate::util::msg::Msg;

/// Supplies [`AbstractLocationPluginEvent`]'s `getDetails()` override to the composed
/// [`PluginEvent`], holding a clone of the `location` `Arc` so the details string is recomputed
/// fresh on every call, matching Java re-deriving it from `location` on each `getDetails()` call
/// rather than caching it.
struct LocationDetails {
    location: Option<Arc<dyn ProgramLocation + Send + Sync>>,
}

impl PluginEventBehavior for LocationDetails {
    fn details(&self) -> Option<String> {
        // Mirrors `getDetails()`:
        //   if (location != null) {
        //       return location.getClass().getName() + " addr==> " + location.getAddress() + "\n";
        //   }
        //   return super.getDetails();  // null
        let location = self.location.as_ref()?;
        // Java's `location.getClass().getName()` reflects the concrete subclass at runtime.
        // `ProgramLocation` here is an object-safe cut-point trait (see its own module docs)
        // with no analogous "class name" accessor, and `std::any::type_name_of_val` on a `&dyn
        // Trait` reference reports the *static* trait type (`"dyn ProgramLocation"`), not the
        // concrete implementor -- unlike its use in `pcode_userop_library.rs`, where `self` is
        // statically the concrete monomorphized type. This is therefore an approximation of the
        // Java text, not a faithful reproduction of it.
        Some(format!(
            "{} addr==> {}\n",
            std::any::type_name_of_val(location.as_ref()),
            location.get_address()
        ))
    }
}

/// Base for plugin events describing a location within a program.
///
/// Port of `ghidra.app.events.AbstractLocationPluginEvent`, an abstract class extending
/// `PluginEvent`. Rust has no inheritance, so this struct composes a [`PluginEvent`] the same
/// way [`FirstTimeAnalyzedPluginEvent`](super::first_time_analyzed_plugin_event::FirstTimeAnalyzedPluginEvent)
/// and friends do, and supplies the `getDetails()` override via a private [`LocationDetails`]
/// [`PluginEventBehavior`] handed to [`PluginEvent::with_behavior`] at construction time (a
/// separate struct, rather than `AbstractLocationPluginEvent` implementing the behavior trait
/// itself, since the composed `PluginEvent` would otherwise need to borrow back from its own
/// owner).
///
/// Concrete location events (e.g. the unported `ProgramLocationPluginEvent`) are expected to
/// compose this type the same way this type composes `PluginEvent`.
pub struct AbstractLocationPluginEvent {
    event: PluginEvent,
    location: Option<Arc<dyn ProgramLocation + Send + Sync>>,
    program_ref: Weak<dyn Program>,
}

impl AbstractLocationPluginEvent {
    /// Construct a new event.
    ///
    /// Mirrors `protected AbstractLocationPluginEvent(String sourceName, String eventName,
    /// ProgramLocation location, Program program)`.
    ///
    /// Java quirk faithfully reproduced: passing `location: None` does **not** reject
    /// construction. The real constructor only logs an error via `Msg.showError(...)` (with a
    /// freshly constructed, immediately-discarded `NullPointerException` -- never thrown) and
    /// then proceeds to store the null location anyway, so `getLocation()` afterward returns
    /// null and `getDetails()` falls back to the superclass default (`null`). This port mirrors
    /// that: a `None` location still produces a fully-constructed event whose
    /// [`AbstractLocationPluginEvent::get_location`] is `None`.
    pub fn new(
        source_name: impl Into<String>,
        event_name: impl Into<String>,
        location: Option<Arc<dyn ProgramLocation + Send + Sync>>,
        program: &Arc<dyn Program>,
    ) -> Self {
        if location.is_none() {
            Msg::show_error_with_error(
                "AbstractLocationPluginEvent",
                "Error",
                &"Null LocationEvent being created.  Trace and remove this problem",
                &NullProgramLocationError,
            );
        }
        let behavior = LocationDetails {
            location: location.clone(),
        };
        Self {
            event: PluginEvent::with_behavior(source_name, event_name, Box::new(behavior)),
            location,
            program_ref: Arc::downgrade(program),
        }
    }

    /// Get the location stored in this event.
    ///
    /// Mirrors `getLocation()`.
    pub fn get_location(&self) -> Option<Arc<dyn ProgramLocation + Send + Sync>> {
        self.location.clone()
    }

    /// Get the program that the location refers to, or `None` if it has since been closed and
    /// dropped.
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

/// Stands in for the Java `NullPointerException("Null ProgramLocation passed to create a
/// Plugin event")` constructed (but never thrown) by `AbstractLocationPluginEvent`'s
/// constructor when handed a null location, purely so it has something to pass as the
/// `Throwable` argument to `Msg.showError`.
#[derive(Debug)]
struct NullProgramLocationError;

impl std::fmt::Display for NullProgramLocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Null ProgramLocation passed to create a Plugin event")
    }
}

impl std::error::Error for NullProgramLocationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;

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
    fn new_stores_names() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = AbstractLocationPluginEvent::new(
            "MyPlugin",
            "MyEvent",
            Some(mock_location(0x400)),
            &program,
        );
        assert_eq!(event.event().source_name(), "MyPlugin");
        assert_eq!(event.event().event_name(), "MyEvent");
    }

    #[test]
    fn get_location_returns_the_stored_location() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let location = mock_location(0x1234);
        let event =
            AbstractLocationPluginEvent::new("P", "E", Some(location.clone()), &program);
        let got = event.get_location().expect("location should be present");
        assert_eq!(got.get_address(), location.get_address());
    }

    #[test]
    fn get_program_returns_program_while_arc_alive() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = AbstractLocationPluginEvent::new(
            "P",
            "E",
            Some(mock_location(0x10)),
            &program,
        );
        assert!(event.get_program().is_some());
    }

    #[test]
    fn get_program_returns_none_after_program_dropped() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = AbstractLocationPluginEvent::new(
            "P",
            "E",
            Some(mock_location(0x10)),
            &program,
        );
        drop(program);
        assert!(event.get_program().is_none());
    }

    #[test]
    fn details_are_present_and_include_the_address_when_location_is_set() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = AbstractLocationPluginEvent::new(
            "P",
            "E",
            Some(mock_location(0x400)),
            &program,
        );
        let display = event.event().to_string();
        assert!(display.contains("Details:"));
        assert!(display.contains("addr==>"));
        assert!(display.contains("0x400") || display.contains("400"));
    }

    /// Faithful reproduction of the Java quirk documented on [`AbstractLocationPluginEvent::new`]:
    /// constructing with a null/`None` location does not fail or panic -- the event is still
    /// fully constructed, `get_location()` is `None`, and (since `getDetails()` falls back to
    /// the superclass default) the event's `Display` carries no "Details:" line.
    #[test]
    fn none_location_still_constructs_a_valid_event_with_no_details() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let event = AbstractLocationPluginEvent::new("P", "E", None, &program);
        assert!(event.get_location().is_none());
        assert!(!event.event().to_string().contains("Details:"));
    }

    #[test]
    fn event_mut_allows_modification() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let mut event = AbstractLocationPluginEvent::new(
            "Orig",
            "E",
            Some(mock_location(0x1)),
            &program,
        );
        event.event_mut().set_source_name("Updated");
        assert_eq!(event.event().source_name(), "Updated");
    }
}

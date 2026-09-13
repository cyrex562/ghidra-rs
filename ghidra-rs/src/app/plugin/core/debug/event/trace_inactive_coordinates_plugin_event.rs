use crate::debug::api::tracemgr::DebuggerCoordinates;
use crate::framework::plugintool::PluginEvent;

/// The name of this plugin event.
///
/// Mirrors the package-private `TraceInactiveCoordinatesPluginEvent.NAME` (`static final String
/// NAME`, with no visibility modifier -- Java package-private). It is exported here so sibling
/// modules within this crate can reference it, mirroring same-package Java access.
pub const NAME: &str = "Trace Inactive Location";

/// Event fired when the coordinates of an *inactive* trace view change.
///
/// Port of `ghidra.app.plugin.core.debug.event.TraceInactiveCoordinatesPluginEvent`, a class
/// extending `PluginEvent` directly. Rust has no inheritance, so this struct composes a
/// [`PluginEvent`] the same way
/// [`TraceActivatedPluginEvent`](super::trace_activated_plugin_event::TraceActivatedPluginEvent)
/// does. This class overrides no `PluginEvent` hooks (no `getDetails()` override, no
/// `@ToolEventName` annotation), so the composed event needs no
/// [`PluginEventBehavior`](crate::framework::plugintool::PluginEventBehavior).
pub struct TraceInactiveCoordinatesPluginEvent {
    event: PluginEvent,
    coordinates: DebuggerCoordinates,
}

impl TraceInactiveCoordinatesPluginEvent {
    /// Construct a new `TraceInactiveCoordinatesPluginEvent`.
    ///
    /// Mirrors `TraceInactiveCoordinatesPluginEvent(String source, DebuggerCoordinates
    /// coordinates)`, which forwards to `super(source, NAME)`.
    pub fn new(source: impl Into<String>, coordinates: DebuggerCoordinates) -> Self {
        Self {
            event: PluginEvent::new(source, NAME),
            coordinates,
        }
    }

    /// Returns the (inactive) coordinates carried by this event.
    ///
    /// Mirrors `getCoordinates()`.
    pub fn get_coordinates(&self) -> DebuggerCoordinates {
        self.coordinates.clone()
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

    #[test]
    fn name_constant_matches_java() {
        assert_eq!(NAME, "Trace Inactive Location");
    }

    #[test]
    fn new_stores_source_and_fixed_event_name() {
        let event =
            TraceInactiveCoordinatesPluginEvent::new("MyPlugin", DebuggerCoordinates::nowhere());
        assert_eq!(event.event().source_name(), "MyPlugin");
        assert_eq!(event.event().event_name(), NAME);
    }

    #[test]
    fn get_coordinates_returns_the_stored_coordinates() {
        let coords = DebuggerCoordinates::nowhere();
        let event = TraceInactiveCoordinatesPluginEvent::new("P", coords.clone());
        assert!(event.get_coordinates().is_nowhere());
    }

    #[test]
    fn no_details_and_no_tool_event_by_default() {
        let event =
            TraceInactiveCoordinatesPluginEvent::new("P", DebuggerCoordinates::nowhere());
        assert!(!event.event().is_tool_event());
        assert!(!event.event().to_string().contains("Details:"));
    }

    #[test]
    fn event_mut_allows_modification() {
        let mut event =
            TraceInactiveCoordinatesPluginEvent::new("Orig", DebuggerCoordinates::nowhere());
        event.event_mut().set_source_name("Updated");
        assert_eq!(event.event().source_name(), "Updated");
    }
}

use crate::app::services::debugger_trace_manager_service::ActivationCause;
use crate::debug::api::tracemgr::DebuggerCoordinates;
use crate::framework::plugintool::PluginEvent;

/// The name of this plugin event.
///
/// Mirrors the package-private `TraceActivatedPluginEvent.NAME` (`static final String NAME`,
/// with no visibility modifier -- Java package-private). It is exported here so sibling
/// modules within this crate can reference it, mirroring same-package Java access.
pub const NAME: &str = "Trace Location";

/// Event fired when the active trace/coordinates change in the Debugger UI.
///
/// Port of `ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent`, a class extending
/// `PluginEvent` directly. Rust has no inheritance, so this struct composes a [`PluginEvent`]
/// the same way [`TraceClosedPluginEvent`](super::trace_closed_plugin_event::TraceClosedPluginEvent)
/// and [`TraceOpenedPluginEvent`](super::trace_opened_plugin_event::TraceOpenedPluginEvent) do.
/// This class overrides no `PluginEvent` hooks (no `getDetails()` override, no `@ToolEventName`
/// annotation), so the composed event needs no [`PluginEventBehavior`](crate::framework::plugintool::PluginEventBehavior).
pub struct TraceActivatedPluginEvent {
    event: PluginEvent,
    coordinates: DebuggerCoordinates,
    cause: ActivationCause,
}

impl TraceActivatedPluginEvent {
    /// Construct a new `TraceActivatedPluginEvent`.
    ///
    /// Mirrors `TraceActivatedPluginEvent(String source, DebuggerCoordinates coordinates,
    /// ActivationCause cause)`, which forwards to `super(source, NAME)`.
    pub fn new(
        source: impl Into<String>,
        coordinates: DebuggerCoordinates,
        cause: ActivationCause,
    ) -> Self {
        Self {
            event: PluginEvent::new(source, NAME),
            coordinates,
            cause,
        }
    }

    /// Returns the coordinates that were activated.
    ///
    /// Mirrors `getActiveCoordinates()`.
    pub fn get_active_coordinates(&self) -> DebuggerCoordinates {
        self.coordinates.clone()
    }

    /// Returns the cause of the activation.
    ///
    /// Mirrors `getCause()`.
    pub fn get_cause(&self) -> ActivationCause {
        self.cause
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
        assert_eq!(NAME, "Trace Location");
    }

    #[test]
    fn new_stores_source_and_fixed_event_name() {
        let event = TraceActivatedPluginEvent::new(
            "MyPlugin",
            DebuggerCoordinates::nowhere(),
            ActivationCause::User,
        );
        assert_eq!(event.event().source_name(), "MyPlugin");
        assert_eq!(event.event().event_name(), NAME);
    }

    #[test]
    fn get_active_coordinates_returns_the_stored_coordinates() {
        let coords = DebuggerCoordinates::nowhere();
        let event = TraceActivatedPluginEvent::new("P", coords.clone(), ActivationCause::User);
        assert!(event.get_active_coordinates().is_nowhere());
    }

    #[test]
    fn get_cause_returns_the_stored_cause() {
        let event = TraceActivatedPluginEvent::new(
            "P",
            DebuggerCoordinates::nowhere(),
            ActivationCause::FollowPresent,
        );
        assert_eq!(event.get_cause(), ActivationCause::FollowPresent);
    }

    #[test]
    fn distinct_causes_are_preserved_independently() {
        let e1 = TraceActivatedPluginEvent::new(
            "P",
            DebuggerCoordinates::nowhere(),
            ActivationCause::User,
        );
        let e2 = TraceActivatedPluginEvent::new(
            "P",
            DebuggerCoordinates::nowhere(),
            ActivationCause::SyncModel,
        );
        assert_eq!(e1.get_cause(), ActivationCause::User);
        assert_eq!(e2.get_cause(), ActivationCause::SyncModel);
    }

    #[test]
    fn no_details_and_no_tool_event_by_default() {
        let event = TraceActivatedPluginEvent::new(
            "P",
            DebuggerCoordinates::nowhere(),
            ActivationCause::User,
        );
        assert!(!event.event().is_tool_event());
        assert!(!event.event().to_string().contains("Details:"));
    }

    #[test]
    fn event_mut_allows_modification() {
        let mut event = TraceActivatedPluginEvent::new(
            "Orig",
            DebuggerCoordinates::nowhere(),
            ActivationCause::User,
        );
        event.event_mut().set_source_name("Updated");
        assert_eq!(event.event().source_name(), "Updated");
    }
}

use std::sync::Arc;

use crate::app::events::AbstractLocationPluginEvent;
use crate::framework::plugintool::PluginEvent;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;
use crate::trace::model::program::TraceProgramView;

/// The name of this plugin event.
///
/// Mirrors `TraceLocationPluginEvent.NAME` (`public static final String NAME`).
pub const NAME: &str = "TraceLocation";

/// Event fired when the program location within a trace's program view changes.
///
/// Port of `ghidra.app.plugin.core.debug.event.TraceLocationPluginEvent`, a class extending
/// `AbstractLocationPluginEvent`. Rust has no inheritance, so this struct composes an
/// [`AbstractLocationPluginEvent`] the same way
/// [`ProgramLocationPluginEvent`](crate::app::events::program_location_plugin_event::ProgramLocationPluginEvent)
/// does.
///
/// Java's constructor is `TraceLocationPluginEvent(String src, ProgramLocation loc)`: it derives
/// both the `Program` passed up to `AbstractLocationPluginEvent` *and* this class's own `view`
/// field from a single expression, `loc.getProgram()`, the second time via an explicit downcast
/// to `TraceProgramView`:
/// ```java
/// super(src, NAME, loc, loc.getProgram());
/// this.view = (TraceProgramView) loc.getProgram());
/// ```
/// `ProgramLocation::get_program` in this crate returns `Arc<dyn Program>`, and Rust has no safe
/// way to downcast a `dyn Program` trait object to `dyn TraceProgramView` (no `Any`-based
/// downcasting is wired up for `Program`, unlike Java's checked runtime cast, which would throw
/// `ClassCastException` here if `loc`'s program were not actually a `TraceProgramView`). Rather
/// than reproduce that as a panic against an unrelated invariant, this port instead requires the
/// caller to supply the already-typed `view` directly as a second constructor argument -- pushing
/// the invariant "this view is (the same object as) `loc`'s program" to the type system /
/// call-site, exactly as real Java call sites already hold a `TraceProgramView`-typed value
/// before ever wrapping it in a generic `ProgramLocation`.
///
/// Java's `loc` parameter is a plain (non-`Optional`) `ProgramLocation`, and the constructor
/// dereferences it (`loc.getProgram()`) *before* even calling `super(...)`; passing a null `loc`
/// would throw `NullPointerException` right there, independent of
/// `AbstractLocationPluginEvent`'s own tolerance for a null *location* value. This port mirrors
/// that mandatory-ness by taking `loc` as a plain (non-`Option`) `Arc`, not the
/// `Option<Arc<...>>` that `AbstractLocationPluginEvent::new` itself accepts.
pub struct TraceLocationPluginEvent {
    base: AbstractLocationPluginEvent,
    view: Arc<dyn TraceProgramView>,
}

impl TraceLocationPluginEvent {
    /// Construct a new `TraceLocationPluginEvent`.
    ///
    /// `view` must be (or wrap) the same program `loc.get_program()` would return in Java; see
    /// the struct-level docs for why this port takes it as an explicit argument instead of
    /// downcasting `loc`'s program itself.
    pub fn new(
        src: impl Into<String>,
        loc: Arc<dyn ProgramLocation + Send + Sync>,
        view: Arc<dyn TraceProgramView>,
    ) -> Self {
        // `TraceProgramView: Program`, so this is a trait-upcasting coercion, not a downcast --
        // always sound, unlike Java's runtime-checked cast in the other direction.
        let program: Arc<dyn Program> = view.clone();
        Self {
            base: AbstractLocationPluginEvent::new(src, NAME, Some(loc), &program),
            view,
        }
    }

    /// Returns the trace program view this location refers to.
    ///
    /// Mirrors `getTraceProgramView()`.
    pub fn get_trace_program_view(&self) -> Arc<dyn TraceProgramView> {
        self.view.clone()
    }

    /// Returns the location stored in this event.
    ///
    /// Mirrors the inherited `getLocation()`.
    pub fn get_location(&self) -> Option<Arc<dyn ProgramLocation + Send + Sync>> {
        self.base.get_location()
    }

    /// Returns the program the location refers to, or `None` if it has since been closed and
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
    pub fn event(&self) -> &PluginEvent {
        self.base.event()
    }

    /// Returns a mutable reference to the underlying `PluginEvent`.
    pub fn event_mut(&mut self) -> &mut PluginEvent {
        self.base.event_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_time_viewport::TraceTimeViewport;

    struct MockTraceProgramView;
    impl crate::framework::model::DomainObject for MockTraceProgramView {}
    impl Program for MockTraceProgramView {
        fn get_name(&self) -> String {
            "trace-view".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }
    impl TraceProgramView for MockTraceProgramView {
        fn get_trace_program_view_memory(
            &self,
        ) -> Box<dyn crate::trace::model::program::trace_program_view_memory::TraceProgramViewMemory>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_snap(&self) -> i64 {
            5
        }
        fn get_viewport(&self) -> Box<dyn TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_max_snap(&self) -> Option<i64> {
            None
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

    fn mock_view() -> Arc<dyn TraceProgramView> {
        Arc::new(MockTraceProgramView)
    }

    #[test]
    fn name_constant_matches_java() {
        assert_eq!(NAME, "TraceLocation");
    }

    #[test]
    fn new_stores_source_and_fixed_event_name() {
        let event = TraceLocationPluginEvent::new("MyPlugin", mock_location(0x400), mock_view());
        assert_eq!(event.event().source_name(), "MyPlugin");
        assert_eq!(event.event().event_name(), NAME);
    }

    #[test]
    fn get_trace_program_view_returns_the_stored_view() {
        let view = mock_view();
        let event = TraceLocationPluginEvent::new("P", mock_location(0x10), view.clone());
        assert_eq!(event.get_trace_program_view().get_snap(), view.get_snap());
    }

    #[test]
    fn get_location_returns_the_stored_location() {
        let location = mock_location(0x1234);
        let event = TraceLocationPluginEvent::new("P", location.clone(), mock_view());
        let got = event.get_location().expect("location should be present");
        assert_eq!(got.get_address(), location.get_address());
    }

    #[test]
    fn get_program_returns_the_view_as_a_program() {
        let event = TraceLocationPluginEvent::new("P", mock_location(0x10), mock_view());
        let program = event.get_program().expect("program should be present");
        assert_eq!(Program::get_name(program.as_ref()), "trace-view");
    }

    #[test]
    fn details_include_the_address_since_location_is_always_set() {
        let event = TraceLocationPluginEvent::new("P", mock_location(0x400), mock_view());
        let display = event.event().to_string();
        assert!(display.contains("Details:"));
        assert!(display.contains("addr==>"));
    }

    #[test]
    fn event_mut_allows_modification() {
        let mut event =
            TraceLocationPluginEvent::new("Orig", mock_location(0x1), mock_view());
        event.event_mut().set_source_name("Updated");
        assert_eq!(event.event().source_name(), "Updated");
    }

    #[test]
    fn base_and_base_mut_expose_the_composed_abstract_event() {
        let mut event = TraceLocationPluginEvent::new("P", mock_location(0x1), mock_view());
        assert!(event.base().get_location().is_some());
        event.base_mut().event_mut().set_source_name("ViaBase");
        assert_eq!(event.event().source_name(), "ViaBase");
    }
}

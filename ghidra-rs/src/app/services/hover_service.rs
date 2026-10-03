use std::any::Any;
use std::sync::Arc;

use crate::app::seam_stubs::{Field, FieldLocation};
use crate::program::model::listing::Program;
use crate::program::util::program_location::ProgramLocation;

/// Port of `ghidra.app.services.HoverService`.
///
/// Provides the ability to popup data windows over a field viewer in response to the mouse
/// hovering over a single field.
///
/// # Shape
///
/// Java's `getHoverComponent` returns a Swing `JComponent` to embed in the popup -- an actual
/// UI toolkit dependency baked into the contract, not just into callers. Real popup rendering is
/// out of scope for this port (AGENTS.md descopes Swing/UI work). This trait is a headless
/// stand-in: the registry/dispatch behaviour ports (priority ordering, hover-mode gating,
/// shown/hidden notification), but the popup content is carried type-erased as
/// `Arc<dyn Any + Send + Sync>` rather than as a real widget -- the same type-erasure this
/// crate's plugin-service registry already uses to hand out services
/// ([`registerServiceProvided`](crate::framework::plugintool::Plugin::register_service_provided)
/// keys them by `TypeId`, mirroring Java's `X.class`-keyed lookup). A future UI port can replace
/// the `Any` with a real component type without touching this trait's other four methods.
pub trait HoverService: Send + Sync {
    /// Returns the priority of this hover service. A lower priority is more important.
    fn priority(&self) -> i32;

    /// If this service's window supports scrolling, scroll by the specified amount.
    fn scroll(&self, amount: i32);

    /// Returns whether hover mode is "on".
    fn hover_mode_selected(&self) -> bool;

    /// Returns a component to be shown in a popup window that is relevant to the given
    /// parameters. `None` is returned if there is no appropriate information to display.
    fn hover_component(
        &self,
        program: &dyn Program,
        program_location: &dyn ProgramLocation,
        field_location: &dyn FieldLocation,
        field: &dyn Field,
    ) -> Option<Arc<dyn Any + Send + Sync>>;

    /// Provides notification when this hover component is popped down.
    fn component_hidden(&self);

    /// Provides notification when this hover component is popped up.
    fn component_shown(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    struct MockHoverService {
        priority: i32,
        hover_mode: bool,
        scrolled: Mutex<Vec<i32>>,
        shown: AtomicU32,
        hidden: AtomicU32,
    }

    impl MockHoverService {
        fn new(priority: i32, hover_mode: bool) -> Self {
            MockHoverService {
                priority,
                hover_mode,
                scrolled: Mutex::new(Vec::new()),
                shown: AtomicU32::new(0),
                hidden: AtomicU32::new(0),
            }
        }
    }

    impl HoverService for MockHoverService {
        fn priority(&self) -> i32 {
            self.priority
        }

        fn scroll(&self, amount: i32) {
            self.scrolled.lock().unwrap().push(amount);
        }

        fn hover_mode_selected(&self) -> bool {
            self.hover_mode
        }

        fn hover_component(
            &self,
            _program: &dyn Program,
            _program_location: &dyn ProgramLocation,
            _field_location: &dyn FieldLocation,
            _field: &dyn Field,
        ) -> Option<Arc<dyn Any + Send + Sync>> {
            None
        }

        fn component_hidden(&self) {
            self.hidden.fetch_add(1, Ordering::SeqCst);
        }

        fn component_shown(&self) {
            self.shown.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn priority_and_hover_mode_are_read_through() {
        let svc = MockHoverService::new(3, true);
        assert_eq!(svc.priority(), 3);
        assert!(svc.hover_mode_selected());
    }

    #[test]
    fn hover_mode_off_is_reported() {
        let svc = MockHoverService::new(1, false);
        assert!(!svc.hover_mode_selected());
    }

    #[test]
    fn scroll_records_each_call() {
        let svc = MockHoverService::new(0, true);
        svc.scroll(5);
        svc.scroll(-2);
        assert_eq!(*svc.scrolled.lock().unwrap(), vec![5, -2]);
    }

    #[test]
    fn shown_and_hidden_notifications_count_independently() {
        let svc = MockHoverService::new(0, true);
        svc.component_shown();
        svc.component_shown();
        svc.component_hidden();
        assert_eq!(svc.shown.load(Ordering::SeqCst), 2);
        assert_eq!(svc.hidden.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lower_priority_value_means_more_important() {
        let important = MockHoverService::new(0, true);
        let less_important = MockHoverService::new(10, true);
        assert!(important.priority() < less_important.priority());
    }
}

//! Port of `ghidra.debug.api.listing.DebuggerListing`. `Navigatable` is not yet ported; it is
//! represented by the placeholder trait in [`crate::app::seam_stubs`] (already added for
//! [`MemorySearchService`](crate::app::services::memory_search_service::MemorySearchService)).
//! `LocationTrackingSpec` is not yet ported either, and is represented by a new placeholder trait
//! in [`crate::debug::seam_stubs`].

use crate::app::seam_stubs::Navigatable;
use crate::debug::seam_stubs::LocationTrackingSpec;

/// A debugger listing window: a `CodeViewer`-like component that additionally tracks a debug
/// session's current thread/location.
///
/// Port of `ghidra.debug.api.listing.DebuggerListing`.
pub trait DebuggerListing: Navigatable {
    /// Get the window title of this debugger listing.
    ///
    /// Port of `DebuggerListing.getTitle()`.
    fn title(&self) -> String;

    /// Returns true if this listing is the main debugger listing.
    ///
    /// Port of `DebuggerListing.isMainListing()`.
    fn is_main_listing(&self) -> bool;

    /// Set a custom title.
    ///
    /// Setting the title here prevents future calls to `ComponentProvider.setTitle(String)` from
    /// having any effect. This is done to preserve the custom title.
    ///
    /// Port of `DebuggerListing.setCustomTitle(String)`.
    fn set_custom_title(&mut self, title: &str);

    /// Set if this debugger listing should follow the current thread when displaying.
    ///
    /// Port of `DebuggerListing.setFollowsCurrentThread(boolean)`.
    fn set_follows_current_thread(&mut self, follows: bool);

    /// Set what this debugger listing should track as the user performs actions.
    ///
    /// `spec` describes how/what the listing will track.
    ///
    /// Port of `DebuggerListing.setTrackingSpec(LocationTrackingSpec)`.
    fn set_tracking_spec(&mut self, spec: Box<dyn LocationTrackingSpec>);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockLocationTrackingSpec;
    impl LocationTrackingSpec for MockLocationTrackingSpec {}

    #[derive(Default)]
    struct MockDebuggerListing {
        title: String,
        follows_current_thread: bool,
        tracking_set: bool,
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl crate::program::model::listing::program::Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock".to_string()
        }
    }

    impl Navigatable for MockDebuggerListing {
        fn is_connected(&self) -> bool {
            true
        }

        fn get_program(&self) -> Box<dyn crate::program::model::listing::program::Program> {
            Box::new(MockProgram)
        }
    }

    impl DebuggerListing for MockDebuggerListing {
        fn title(&self) -> String {
            self.title.clone()
        }

        fn is_main_listing(&self) -> bool {
            false
        }

        fn set_custom_title(&mut self, title: &str) {
            self.title = title.to_string();
        }

        fn set_follows_current_thread(&mut self, follows: bool) {
            self.follows_current_thread = follows;
        }

        fn set_tracking_spec(&mut self, _spec: Box<dyn LocationTrackingSpec>) {
            self.tracking_set = true;
        }
    }

    #[test]
    fn setters_mutate_state_and_getters_reflect_it() {
        let mut listing = MockDebuggerListing::default();

        listing.set_custom_title("Dynamic Listing");
        listing.set_follows_current_thread(true);
        listing.set_tracking_spec(Box::new(MockLocationTrackingSpec));

        assert_eq!(listing.title(), "Dynamic Listing");
        assert!(listing.follows_current_thread);
        assert!(listing.tracking_set);
        assert!(!listing.is_main_listing());
    }

    #[test]
    fn usable_as_trait_object_and_inherits_navigatable() {
        let mut listing: Box<dyn DebuggerListing> = Box::new(MockDebuggerListing::default());

        listing.set_custom_title("Main Listing");
        listing.set_tracking_spec(Box::new(MockLocationTrackingSpec));

        assert_eq!(listing.title(), "Main Listing");
        assert!(listing.is_connected());
    }
}

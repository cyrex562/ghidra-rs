//! A service providing access to the main listing panel.
//!
//! Port of `ghidra.app.services.DebuggerListingService`, which extends
//! `ghidra.app.services.CodeViewerService` -- not yet ported, so it is represented here by the
//! empty [`CodeViewerService`](crate::app::seam_stubs::CodeViewerService) placeholder trait,
//! mirroring how [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService)
//! extends the unported `DebuggerAddressTranslator`. The Java `@ServiceInfo` annotation (default
//! provider `DebuggerListingPlugin`) has no Rust equivalent and is omitted.
//!
//! `DebuggerListingService.goTo(Address, boolean)` is distinct from the inherited
//! `CodeViewerService.goTo(ProgramLocation, boolean)` overload (different parameter type); since
//! `CodeViewerService` is currently an empty placeholder, both keep the plain name `go_to` with no
//! ambiguity.

use crate::app::seam_stubs::{
    AutoReadMemorySpec, CodeViewerService, LitIdMode, ListingPanel,
    MultiBlendedListingBackgroundColorModel, ProgramSelection,
};
use crate::debug::api::listing::DebuggerListing;
use crate::debug::seam_stubs::LocationTrackingSpec;
use crate::program::model::address::Address;

/// A listener for changes in location tracking specification.
///
/// Port of `DebuggerListingService.LocationTrackingSpecChangeListener`.
pub trait LocationTrackingSpecChangeListener {
    /// The specification has changed.
    ///
    /// Port of `LocationTrackingSpecChangeListener.locationTrackingSpecChanged(LocationTrackingSpec)`.
    fn location_tracking_spec_changed(&self, spec: &dyn LocationTrackingSpec);
}

/// A service providing access to the main listing panel.
///
/// Port of `ghidra.app.services.DebuggerListingService`.
pub trait DebuggerListingService: CodeViewerService {
    /// Set the tracking specification of the listing. Navigates immediately.
    ///
    /// Port of `DebuggerListingService.setTrackingSpec(LocationTrackingSpec)`.
    fn set_tracking_spec(&mut self, spec: Box<dyn LocationTrackingSpec>);

    /// Get the tracking specification of the main listing.
    ///
    /// Port of `DebuggerListingService.getTrackingSpec()`.
    fn get_tracking_spec(&self) -> Box<dyn LocationTrackingSpec>;

    /// Create a new disconnected debugger listing.
    ///
    /// Port of `DebuggerListingService.createNewListing()`.
    fn create_new_listing(&mut self) -> Box<dyn DebuggerListing>;

    /// Get all debugger listings.
    ///
    /// Port of `DebuggerListingService.getAllListings()`.
    fn get_all_listings(&self) -> Vec<Box<dyn DebuggerListing>>;

    /// Get the auto-read memory specification of the main listing.
    ///
    /// Port of `DebuggerListingService.getAutoReadMemorySpec()`.
    fn get_auto_read_memory_spec(&self) -> Box<dyn AutoReadMemorySpec>;

    /// Add a listener for changes to the tracking specification.
    ///
    /// Port of `DebuggerListingService.addTrackingSpecChangeListener(LocationTrackingSpecChangeListener)`.
    fn add_tracking_spec_change_listener(
        &mut self,
        listener: Box<dyn LocationTrackingSpecChangeListener>,
    );

    /// Remove a listener for changes to the tracking specification.
    ///
    /// Port of `DebuggerListingService.removeTrackingSpecChangeListener(LocationTrackingSpecChangeListener)`.
    fn remove_tracking_spec_change_listener(
        &mut self,
        listener: &dyn LocationTrackingSpecChangeListener,
    );

    /// Set the selection of addresses in this listing.
    ///
    /// Port of `DebuggerListingService.setCurrentSelection(ProgramSelection)`.
    fn set_current_selection(&mut self, selection: &dyn ProgramSelection);

    /// Navigate to the given address.
    ///
    /// Returns true if the request was effective.
    ///
    /// Port of `DebuggerListingService.goTo(Address, boolean)`.
    fn go_to(&mut self, address: &Address, center_on_screen: bool) -> bool;

    /// Set the mode of the Go-to dialog's Sleigh expressions.
    ///
    /// This applies to all Go-to dialogs among the dynamic providers, including listings and
    /// memory (hex byte) views.
    ///
    /// Port of `DebuggerListingService.setGoToSleighMode(LitIdMode)`.
    fn set_go_to_sleigh_mode(&mut self, mode: LitIdMode);

    /// Get the mode of the Go-to dialog's Sleigh expressions.
    ///
    /// Port of `DebuggerListingService.getGoToSleighMode()`.
    fn get_go_to_sleigh_mode(&self) -> LitIdMode;

    /// Obtain a coloring background model suitable for the given listing.
    ///
    /// This may be used, e.g., to style an alternative view in the same manner as listings
    /// managed by this service. Namely, this provides coloring for memory state and the user's
    /// cursor. Coloring for tracked locations and the marker service in general must still be
    /// added separately, since they incorporate additional dependencies.
    ///
    /// Port of `DebuggerListingService.createListingBackgroundColorModel(ListingPanel)`.
    fn create_listing_background_color_model(
        &self,
        listing_panel: &dyn ListingPanel,
    ) -> Box<dyn MultiBlendedListingBackgroundColorModel>;

    /// Get the next custom title for a `DebuggerListing`.
    ///
    /// Port of `DebuggerListingService.findNextCustomTitle()`.
    fn find_next_custom_title(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::Navigatable;
    use std::cell::RefCell;

    struct MockLocationTrackingSpec;
    impl LocationTrackingSpec for MockLocationTrackingSpec {}

    struct MockAutoReadMemorySpec;
    impl AutoReadMemorySpec for MockAutoReadMemorySpec {}

    struct MockMultiBlended;
    impl MultiBlendedListingBackgroundColorModel for MockMultiBlended {}

    struct MockListingPanel;
    impl ListingPanel for MockListingPanel {}

    struct MockProgramSelection;
    impl ProgramSelection for MockProgramSelection {}

    struct MockDebuggerListing {
        title: String,
    }
    impl Navigatable for MockDebuggerListing {
        fn is_connected(&self) -> bool {
            true
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
        fn set_follows_current_thread(&mut self, _follows: bool) {}
        fn set_tracking_spec(&mut self, _spec: Box<dyn LocationTrackingSpec>) {}
    }

    struct MockDebuggerListingService {
        tracking_spec_tag: RefCell<&'static str>,
        listings: RefCell<Vec<String>>,
        sleigh_mode: RefCell<LitIdMode>,
    }

    impl CodeViewerService for MockDebuggerListingService {}

    impl DebuggerListingService for MockDebuggerListingService {
        fn set_tracking_spec(&mut self, _spec: Box<dyn LocationTrackingSpec>) {
            *self.tracking_spec_tag.borrow_mut() = "custom";
        }

        fn get_tracking_spec(&self) -> Box<dyn LocationTrackingSpec> {
            Box::new(MockLocationTrackingSpec)
        }

        fn create_new_listing(&mut self) -> Box<dyn DebuggerListing> {
            let title = format!("Listing {}", self.listings.borrow().len());
            self.listings.borrow_mut().push(title.clone());
            Box::new(MockDebuggerListing { title })
        }

        fn get_all_listings(&self) -> Vec<Box<dyn DebuggerListing>> {
            self.listings
                .borrow()
                .iter()
                .map(|title| Box::new(MockDebuggerListing { title: title.clone() }) as Box<dyn DebuggerListing>)
                .collect()
        }

        fn get_auto_read_memory_spec(&self) -> Box<dyn AutoReadMemorySpec> {
            Box::new(MockAutoReadMemorySpec)
        }

        fn add_tracking_spec_change_listener(
            &mut self,
            _listener: Box<dyn LocationTrackingSpecChangeListener>,
        ) {
        }

        fn remove_tracking_spec_change_listener(
            &mut self,
            _listener: &dyn LocationTrackingSpecChangeListener,
        ) {
        }

        fn set_current_selection(&mut self, _selection: &dyn ProgramSelection) {}

        fn go_to(&mut self, _address: &Address, _center_on_screen: bool) -> bool {
            true
        }

        fn set_go_to_sleigh_mode(&mut self, mode: LitIdMode) {
            *self.sleigh_mode.borrow_mut() = mode;
        }

        fn get_go_to_sleigh_mode(&self) -> LitIdMode {
            *self.sleigh_mode.borrow()
        }

        fn create_listing_background_color_model(
            &self,
            _listing_panel: &dyn ListingPanel,
        ) -> Box<dyn MultiBlendedListingBackgroundColorModel> {
            Box::new(MockMultiBlended)
        }

        fn find_next_custom_title(&self) -> String {
            format!("Listing {}", self.listings.borrow().len())
        }
    }

    fn new_service() -> MockDebuggerListingService {
        MockDebuggerListingService {
            tracking_spec_tag: RefCell::new("default"),
            listings: RefCell::new(Vec::new()),
            sleigh_mode: RefCell::new(LitIdMode::Normal),
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let service: Box<dyn DebuggerListingService> = Box::new(new_service());
        let _ = service;
    }

    #[test]
    fn create_new_listing_grows_all_listings() {
        let mut service = new_service();
        assert!(service.get_all_listings().is_empty());

        let listing = service.create_new_listing();
        assert_eq!(listing.title(), "Listing 0");
        assert_eq!(service.get_all_listings().len(), 1);

        service.create_new_listing();
        assert_eq!(service.get_all_listings().len(), 2);
    }

    #[test]
    fn set_tracking_spec_updates_internal_state() {
        let mut service = new_service();
        assert_eq!(*service.tracking_spec_tag.borrow(), "default");

        service.set_tracking_spec(Box::new(MockLocationTrackingSpec));
        assert_eq!(*service.tracking_spec_tag.borrow(), "custom");

        // The getter still hands back a usable trait object.
        let _spec: Box<dyn LocationTrackingSpec> = service.get_tracking_spec();
    }

    #[test]
    fn go_to_sleigh_mode_round_trips() {
        let mut service = new_service();
        assert_eq!(service.get_go_to_sleigh_mode(), LitIdMode::Normal);
        service.set_go_to_sleigh_mode(LitIdMode::Hex);
        assert_eq!(service.get_go_to_sleigh_mode(), LitIdMode::Hex);
    }

    #[test]
    fn tracking_spec_change_listener_is_object_safe() {
        struct RecordingListener;
        impl LocationTrackingSpecChangeListener for RecordingListener {
            fn location_tracking_spec_changed(&self, _spec: &dyn LocationTrackingSpec) {}
        }
        let listener: Box<dyn LocationTrackingSpecChangeListener> = Box::new(RecordingListener);
        let spec = MockLocationTrackingSpec;
        listener.location_tracking_spec_changed(&spec);
    }

    #[test]
    fn find_next_custom_title_reflects_listing_count() {
        let mut service = new_service();
        assert_eq!(service.find_next_custom_title(), "Listing 0");
        service.create_new_listing();
        assert_eq!(service.find_next_custom_title(), "Listing 1");
    }
}

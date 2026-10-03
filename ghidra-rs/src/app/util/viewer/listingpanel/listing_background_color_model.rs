//! Background color model for the listing panel.

use crate::app::seam_stubs::{BackgroundColorModel, ListingPanel};

/// Background color model for the listing panel.
///
/// This trait extends the [`BackgroundColorModel`] exclusively for background color models used by
/// the listing panel. The [`BackgroundColorModel`] is a general contract for dealing with
/// background colors in a field panel. Listing background color models require additional
/// information such as the address index map and the program so that they can translate indexes
/// to specific addresses and look up information in the program.
///
/// Corresponds to Java `ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel`.
pub trait ListingBackgroundColorModel: BackgroundColorModel {
    /// Called when the address index map or the program changes.
    ///
    /// # Arguments
    ///
    /// * `listing_panel` - The listing panel that changed, from which the new address index map
    ///   and program can be retrieved.
    fn model_data_changed(&self, listing_panel: &dyn ListingPanel);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestColorModel;

    impl BackgroundColorModel for TestColorModel {}

    impl ListingBackgroundColorModel for TestColorModel {
        fn model_data_changed(&self, _listing_panel: &dyn ListingPanel) {
            // Test implementation does nothing
        }
    }

    struct TestListingPanel;

    impl ListingPanel for TestListingPanel {}

    #[test]
    fn test_model_data_changed_called() {
        let model = TestColorModel;
        let panel = TestListingPanel;
        model.model_data_changed(&panel);
    }

    #[test]
    fn test_trait_object_dispatch() {
        let model: Box<dyn ListingBackgroundColorModel> = Box::new(TestColorModel);
        let panel = TestListingPanel;
        model.model_data_changed(&panel);
    }

    #[test]
    fn test_multiple_calls() {
        let model = TestColorModel;
        let panel = TestListingPanel;
        model.model_data_changed(&panel);
        model.model_data_changed(&panel);
        model.model_data_changed(&panel);
        // Test passes if no panic occurs
    }
}

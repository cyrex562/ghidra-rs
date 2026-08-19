//! A service to provide a widget that is designed to appear on the left-hand side of the Code
//! Viewer.
//!
//! Port of `ghidra.app.services.ListingMarginProviderService`.

use crate::app::seam_stubs::ListingMarginProvider;

/// A service to provide a widget that is designed to appear on the left-hand side of the Code
/// Viewer.
pub trait ListingMarginProviderService {
    /// Creates a new margin provider.
    fn create_margin_provider(&self) -> Box<dyn ListingMarginProvider>;

    /// True if this service is the owner of the given provider.
    fn is_owner(&self, provider: &dyn ListingMarginProvider) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider;
    impl ListingMarginProvider for MockProvider {}

    struct MockListingMarginProviderService;

    impl ListingMarginProviderService for MockListingMarginProviderService {
        fn create_margin_provider(&self) -> Box<dyn ListingMarginProvider> {
            Box::new(MockProvider)
        }

        fn is_owner(&self, _provider: &dyn ListingMarginProvider) -> bool {
            true
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let service: Box<dyn ListingMarginProviderService> =
            Box::new(MockListingMarginProviderService);
        let _ = service;
    }

    #[test]
    fn smoke_create_and_is_owner() {
        let service = MockListingMarginProviderService;
        let provider = service.create_margin_provider();
        assert!(service.is_owner(provider.as_ref()));
    }
}

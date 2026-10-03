//! A service to provide an overview of the listing.
//!
//! Port of `ghidra.app.services.ListingOverviewProviderService`.

use crate::app::seam_stubs::ListingOverviewProvider;

/// A service to provide an overview of the listing.
pub trait ListingOverviewProviderService {
    /// Creates a new overview provider.
    fn create_overview_provider(&self) -> Box<dyn ListingOverviewProvider>;

    /// True if this service is the owner of the given provider.
    fn is_owner(&self, provider: &dyn ListingOverviewProvider) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider;
    impl ListingOverviewProvider for MockProvider {}

    struct MockListingOverviewProviderService;

    impl ListingOverviewProviderService for MockListingOverviewProviderService {
        fn create_overview_provider(&self) -> Box<dyn ListingOverviewProvider> {
            Box::new(MockProvider)
        }

        fn is_owner(&self, _provider: &dyn ListingOverviewProvider) -> bool {
            true
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let service: Box<dyn ListingOverviewProviderService> =
            Box::new(MockListingOverviewProviderService);
        let _ = service;
    }

    #[test]
    fn smoke_create_and_is_owner() {
        let service = MockListingOverviewProviderService;
        let provider = service.create_overview_provider();
        assert!(service.is_owner(provider.as_ref()));
    }
}

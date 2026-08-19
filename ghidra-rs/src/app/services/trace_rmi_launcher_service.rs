//! The service for launching Trace RMI targets in the GUI.
//!
//! Port of `ghidra.app.services.TraceRmiLauncherService`. The Java `@ServiceInfo` annotation
//! (default provider `TraceRmiLauncherServicePlugin`) has no Rust equivalent and is omitted.

use crate::app::seam_stubs::TraceRmiLaunchOffer;
use crate::program::model::listing::Program;

/// The service for launching Trace RMI targets in the GUI.
pub trait TraceRmiLauncherService {
    /// Get all offers for the given program.
    fn get_offers(&self, program: &dyn Program) -> Vec<Box<dyn TraceRmiLaunchOffer>>;

    /// Get offers with a saved configuration, ordered by most-recently-saved.
    fn get_saved_offers(&self, program: &dyn Program) -> Vec<Box<dyn TraceRmiLaunchOffer>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockOffer;
    impl TraceRmiLaunchOffer for MockOffer {}

    struct MockTraceRmiLauncherService;

    impl TraceRmiLauncherService for MockTraceRmiLauncherService {
        fn get_offers(&self, _program: &dyn Program) -> Vec<Box<dyn TraceRmiLaunchOffer>> {
            vec![Box::new(MockOffer)]
        }

        fn get_saved_offers(&self, _program: &dyn Program) -> Vec<Box<dyn TraceRmiLaunchOffer>> {
            Vec::new()
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let service: Box<dyn TraceRmiLauncherService> = Box::new(MockTraceRmiLauncherService);
        let _ = service;
    }

    #[test]
    fn smoke_get_offers() {
        use crate::framework::model::DomainObject;
        use crate::program::model::listing::Listing;

        struct MockProgram;
        impl DomainObject for MockProgram {}
        impl Program for MockProgram {
            fn get_name(&self) -> String {
                "mock".to_string()
            }

            fn get_language_id(&self) -> String {
                "mock:LE:64:default".to_string()
            }

            fn get_listing(&mut self) -> Option<&mut dyn Listing> {
                None
            }
        }

        let service = MockTraceRmiLauncherService;
        let program = MockProgram;
        assert_eq!(service.get_offers(&program).len(), 1);
        assert!(service.get_saved_offers(&program).is_empty());
    }
}

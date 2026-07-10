//! The GoToService provides a general service for plugins to generate GoTo events.
//!
//! Port of `ghidra.app.services.GoToService`. The provider of this service takes care of
//! interfacing with any history service that may be available.
//!
//! Java's overloaded `goTo`/`goToExternalLocation`/`goToQuery` methods are each given a distinct
//! Rust name, since Rust traits cannot overload on parameter type/arity alone. `ProgramLocation`
//! and `Navigatable` are not yet ported, so they are represented by placeholder traits in
//! [`crate::app::seam_stubs`] (the former already exists for
//! [`StringTranslationService`](crate::app::services::StringTranslationService), the latter for
//! [`MemorySearchService`](crate::app::services::MemorySearchService)). `GoToOverrideService` is
//! also not yet ported and is added as a new placeholder here.
//!
//! Java documents that all `goTo` calls execute on the Swing thread, blocking if called from any
//! other thread; that threading behavior is a UI-toolkit concern with no equivalent in this
//! trait and is left to implementors.

use std::sync::Arc;

use crate::app::seam_stubs::{GoToOverrideService, Navigatable, ProgramLocation};
use crate::app::services::go_to_service_listener::GoToServiceListener;
use crate::app::services::query_data::QueryData;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::symbol::ExternalLocation;
use crate::util::task::TaskMonitor;

/// Characters that are allowed in words that the GoToService can use. These typically represent
/// library name delimiters.
///
/// Port of `GoToService.VALID_GOTO_CHARS`.
pub const VALID_GOTO_CHARS: [char; 3] = ['.', ':', '*'];

/// The GoToService provides a general service for plugins to generate GoTo events.
///
/// Port of `ghidra.app.services.GoToService`.
pub trait GoToService {
    /// Generates a GoTo event and handles any history state that needs to be saved.
    ///
    /// This method attempts to find the program that contains the given location.
    ///
    /// Returns true if the go to was successful.
    ///
    /// Port of `GoToService.goTo(ProgramLocation)`.
    fn go_to(&self, loc: &dyn ProgramLocation) -> bool;

    /// Generates a GoTo event and handles any history state that needs to be saved, using the
    /// given program as the program within which to perform the GoTo.
    ///
    /// If the given program does not contain the given location, the GoTo will not be performed
    /// and false will be returned.
    ///
    /// Port of `GoToService.goTo(ProgramLocation, Program)`.
    fn go_to_in_program(&self, loc: &dyn ProgramLocation, program: &dyn Program) -> bool;

    /// Generates a GoTo event to the given location in the given program.
    ///
    /// Port of `GoToService.goTo(Navigatable, ProgramLocation, Program)`.
    fn go_to_navigatable_location(
        &self,
        navigatable: &dyn Navigatable,
        loc: &dyn ProgramLocation,
        program: &dyn Program,
    ) -> bool;

    /// Generates a GoTo event to the given address. `ref_address` is used to determine if there
    /// is a specific symbol reference from that reference.
    ///
    /// Port of `GoToService.goTo(Navigatable, Program, Address, Address)`.
    fn go_to_navigatable_address_with_ref(
        &self,
        navigatable: &dyn Navigatable,
        program: &dyn Program,
        address: &Address,
        ref_address: &Address,
    ) -> bool;

    /// Generates a GoTo event to the given address. `from_address` is used to determine if there
    /// is a specific symbol reference from the current address.
    ///
    /// Port of `GoToService.goTo(Address, Address)`.
    fn go_to_from_address(&self, from_address: &Address, address: &Address) -> bool;

    /// Generates a GoTo event to the given address for the specific navigatable.
    ///
    /// Port of `GoToService.goTo(Navigatable, Address)`.
    fn go_to_navigatable_address(&self, navigatable: &dyn Navigatable, go_to_address: &Address) -> bool;

    /// Generates a GoTo event to the given address.
    ///
    /// Port of `GoToService.goTo(Address)`.
    fn go_to_address(&self, go_to_address: &Address) -> bool;

    /// Generates a GoTo event to the given address, using the given program as the program
    /// within which to perform the GoTo.
    ///
    /// If the given program does not contain the given address, the GoTo will not be performed
    /// and false will be returned.
    ///
    /// Port of `GoToService.goTo(Address, Program)`.
    fn go_to_address_in_program(&self, go_to_address: &Address, program: &dyn Program) -> bool;

    /// Navigate to either the external program location or address linkage location.
    ///
    /// If `check_navigation_option` is true, the service navigation option is used to determine
    /// whether to navigate to the external program, or to the external linkage location within
    /// the current program. If false, the implementation's default behavior is performed.
    ///
    /// Returns true if either navigation was completed successfully. Specific behavior may vary
    /// based upon implementation.
    ///
    /// Port of `GoToService.goToExternalLocation(ExternalLocation, boolean)`.
    fn go_to_external_location(
        &self,
        external_loc: &dyn ExternalLocation,
        check_navigation_option: bool,
    ) -> bool;

    /// Navigate to either the external program location or address linkage location for the
    /// given navigatable.
    ///
    /// Port of `GoToService.goToExternalLocation(Navigatable, ExternalLocation, boolean)`.
    fn go_to_navigatable_external_location(
        &self,
        navigatable: &dyn Navigatable,
        external_loc: &dyn ExternalLocation,
        check_navigation_option: bool,
    ) -> bool;

    /// Generates a GoTo event for the given query.
    ///
    /// If the query results in more than one location, a list of locations is displayed. If the
    /// query results in only one location, a goto event is fired (except for a wildcard query, in
    /// which case a list is still displayed). `listener` is notified after the query completes
    /// and indicates the query status.
    ///
    /// Returns true if the queryInput is found or appears to be a wildcard search.
    ///
    /// Port of `GoToService.goToQuery(Address, QueryData, GoToServiceListener, TaskMonitor)`.
    fn go_to_query(
        &self,
        from_addr: &Address,
        query_data: &QueryData,
        listener: &dyn GoToServiceListener,
        monitor: &dyn TaskMonitor,
    ) -> bool;

    /// Generates a GoTo event for the given query, targeting the given navigatable.
    ///
    /// Port of `GoToService.goToQuery(Navigatable, Address, QueryData, GoToServiceListener,
    /// TaskMonitor)`.
    fn go_to_query_navigatable(
        &self,
        navigatable: &dyn Navigatable,
        from_addr: &Address,
        query_data: &QueryData,
        listener: &dyn GoToServiceListener,
        monitor: &dyn TaskMonitor,
    ) -> bool;

    /// Returns the default navigatable that is the destination for GoTo events. This
    /// navigatable will not be `None`.
    ///
    /// Port of `GoToService.getDefaultNavigatable()`.
    fn get_default_navigatable(&self) -> Arc<dyn Navigatable>;

    /// Returns the current override service, if one is set.
    ///
    /// Port of `GoToService.getOverrideService()`.
    #[deprecated(since = "10.2", note = "for removal, per the Java source")]
    fn get_override_service(&self) -> Option<Arc<dyn GoToOverrideService>>;

    /// Sets the override service used to handle GoTo requests before the default handling is
    /// performed.
    ///
    /// Port of `GoToService.setOverrideService(GoToOverrideService)`.
    #[deprecated(since = "10.2", note = "for removal, per the Java source")]
    fn set_override_service(&mut self, override_service: Option<Arc<dyn GoToOverrideService>>);
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockLocation;
    impl ProgramLocation for MockLocation {}

    struct MockNavigatable;
    impl Navigatable for MockNavigatable {}

    struct MockExternalLocation;
    impl ExternalLocation for MockExternalLocation {}

    struct MockOverrideService;
    impl GoToOverrideService for MockOverrideService {}

    struct MockListener;
    impl GoToServiceListener for MockListener {
        fn goto_completed(&self, _query_string: &str, _found_results: bool) {}
        fn goto_failed(&self, _error: &str) {}
    }

    struct MockService {
        override_service: Option<Arc<dyn GoToOverrideService>>,
    }

    impl GoToService for MockService {
        fn go_to(&self, _loc: &dyn ProgramLocation) -> bool {
            true
        }

        fn go_to_in_program(&self, _loc: &dyn ProgramLocation, _program: &dyn Program) -> bool {
            true
        }

        fn go_to_navigatable_location(
            &self,
            _navigatable: &dyn Navigatable,
            _loc: &dyn ProgramLocation,
            _program: &dyn Program,
        ) -> bool {
            true
        }

        fn go_to_navigatable_address_with_ref(
            &self,
            _navigatable: &dyn Navigatable,
            _program: &dyn Program,
            _address: &Address,
            _ref_address: &Address,
        ) -> bool {
            true
        }

        fn go_to_from_address(&self, _from_address: &Address, _address: &Address) -> bool {
            true
        }

        fn go_to_navigatable_address(
            &self,
            _navigatable: &dyn Navigatable,
            _go_to_address: &Address,
        ) -> bool {
            true
        }

        fn go_to_address(&self, _go_to_address: &Address) -> bool {
            true
        }

        fn go_to_address_in_program(&self, _go_to_address: &Address, _program: &dyn Program) -> bool {
            true
        }

        fn go_to_external_location(
            &self,
            _external_loc: &dyn ExternalLocation,
            _check_navigation_option: bool,
        ) -> bool {
            true
        }

        fn go_to_navigatable_external_location(
            &self,
            _navigatable: &dyn Navigatable,
            _external_loc: &dyn ExternalLocation,
            _check_navigation_option: bool,
        ) -> bool {
            true
        }

        fn go_to_query(
            &self,
            _from_addr: &Address,
            _query_data: &QueryData,
            listener: &dyn GoToServiceListener,
            _monitor: &dyn TaskMonitor,
        ) -> bool {
            listener.goto_completed("q", true);
            true
        }

        fn go_to_query_navigatable(
            &self,
            _navigatable: &dyn Navigatable,
            _from_addr: &Address,
            _query_data: &QueryData,
            listener: &dyn GoToServiceListener,
            _monitor: &dyn TaskMonitor,
        ) -> bool {
            listener.goto_completed("q", true);
            true
        }

        fn get_default_navigatable(&self) -> Arc<dyn Navigatable> {
            Arc::new(MockNavigatable)
        }

        fn get_override_service(&self) -> Option<Arc<dyn GoToOverrideService>> {
            self.override_service.clone()
        }

        fn set_override_service(&mut self, override_service: Option<Arc<dyn GoToOverrideService>>) {
            self.override_service = override_service;
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn GoToService> = Box::new(MockService { override_service: None });

        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let addr = Address::new(space, 0x1000);

        assert!(service.go_to(&MockLocation));
        assert!(service.go_to_in_program(&MockLocation, &MockProgram));
        assert!(service.go_to_navigatable_location(&MockNavigatable, &MockLocation, &MockProgram));
        assert!(service.go_to_navigatable_address_with_ref(
            &MockNavigatable,
            &MockProgram,
            &addr,
            &addr
        ));
        assert!(service.go_to_from_address(&addr, &addr));
        assert!(service.go_to_navigatable_address(&MockNavigatable, &addr));
        assert!(service.go_to_address(&addr));
        assert!(service.go_to_address_in_program(&addr, &MockProgram));
        assert!(service.go_to_external_location(&MockExternalLocation, true));
        assert!(service.go_to_navigatable_external_location(
            &MockNavigatable,
            &MockExternalLocation,
            true
        ));

        let query = QueryData::new("foo", false, true);
        let listener = MockListener;
        let monitor = crate::util::task::DummyMonitor;
        assert!(service.go_to_query(&addr, &query, &listener, &monitor));
        assert!(service.go_to_query_navigatable(&MockNavigatable, &addr, &query, &listener, &monitor));

        let _default_nav = service.get_default_navigatable();

        assert!(service.get_override_service().is_none());
        service.set_override_service(Some(Arc::new(MockOverrideService)));
        assert!(service.get_override_service().is_some());
    }

    #[test]
    fn valid_goto_chars_matches_java() {
        assert_eq!(VALID_GOTO_CHARS, ['.', ':', '*']);
    }
}

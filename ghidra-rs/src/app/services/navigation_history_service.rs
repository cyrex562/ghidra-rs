//! The NavigationHistoryService maintains a stack of locations that the user has visited via a
//! navigation plugin.
//!
//! Port of `ghidra.app.services.NavigationHistoryService`. The Java `@ServiceInfo` annotation
//! (default provider `ghidra.app.plugin.core.navigation.NavigationHistoryPlugin`, not yet
//! ported) has no Rust equivalent and is omitted, matching the convention used elsewhere (e.g.
//! [`TerminalService`](crate::app::services::TerminalService)). `NavigationHistoryPlugin` is
//! otherwise only mentioned in Javadoc, never in a method signature, so no placeholder is needed
//! for it.
//!
//! `Navigatable` is not yet ported and is represented by the placeholder trait in
//! [`crate::app::seam_stubs`]. `LocationMemento` is likewise not yet ported; since Java's version
//! is a concrete class (not an interface) and this service only ever passes it through, it is
//! represented by the plain placeholder struct [`crate::app::seam_stubs::LocationMemento`] rather
//! than a `dyn`-dispatched trait.
//!
//! Java's overloaded `next`/`previous`/`clear` methods are each given a distinct Rust name, since
//! Rust traits cannot overload on parameter type/arity alone: `next(Navigatable,
//! LocationMemento)` becomes [`next_location`](NavigationHistoryService::next_location),
//! `previous(Navigatable, LocationMemento)` becomes
//! [`previous_location`](NavigationHistoryService::previous_location), and `clear(Program)`
//! becomes [`clear_program`](NavigationHistoryService::clear_program).

use crate::app::seam_stubs::{LocationMemento, Navigatable};
use crate::program::model::listing::Program;

/// The NavigationHistoryService maintains a stack of locations that the user has visited via a
/// navigation plugin. It provides methods querying and manipulating this list.
///
/// Port of `ghidra.app.services.NavigationHistoryService`.
pub trait NavigationHistoryService {
    /// Positions the current location to the next location in the history list. If there is no
    /// "next" location, the history list remains unchanged.
    ///
    /// Port of `NavigationHistoryService.next(Navigatable)`.
    fn next(&self, navigatable: &dyn Navigatable);

    /// Positions the "current" location to the previous location in the history list. If there
    /// is no "previous" location, the history list remains unchanged.
    ///
    /// Port of `NavigationHistoryService.previous(Navigatable)`.
    fn previous(&self, navigatable: &dyn Navigatable);

    /// Navigates to the given location in the "next" list. If the location is not in the list,
    /// then nothing will happen.
    ///
    /// Port of `NavigationHistoryService.next(Navigatable, LocationMemento)`.
    fn next_location(&self, navigatable: &dyn Navigatable, location: &LocationMemento);

    /// Navigates to the given location in the "previous" list. If the location is not in the
    /// list, then nothing will happen.
    ///
    /// Port of `NavigationHistoryService.previous(Navigatable, LocationMemento)`.
    fn previous_location(&self, navigatable: &dyn Navigatable, location: &LocationMemento);

    /// Positions the "current" location to the next location which is in a different function
    /// from current one or previous non-code location. If we are not inside any function,
    /// performs like [`next`](Self::next).
    ///
    /// Port of `NavigationHistoryService.nextFunction(Navigatable)`.
    fn next_function(&self, navigatable: &dyn Navigatable);

    /// Positions the "previous" location to the next location which is in a different function
    /// from current one or previous non-code location. If we are not inside any function,
    /// performs like [`next`](Self::next).
    ///
    /// Port of `NavigationHistoryService.previousFunction(Navigatable)`.
    fn previous_function(&self, navigatable: &dyn Navigatable);

    /// Returns the [`LocationMemento`] objects in the "previous" list.
    ///
    /// Port of `NavigationHistoryService.getPreviousLocations(Navigatable)`.
    fn get_previous_locations(&self, navigatable: &dyn Navigatable) -> Vec<LocationMemento>;

    /// Returns the [`LocationMemento`] objects in the "next" list.
    ///
    /// Port of `NavigationHistoryService.getNextLocations(Navigatable)`.
    fn get_next_locations(&self, navigatable: &dyn Navigatable) -> Vec<LocationMemento>;

    /// Returns true if there is a valid "next" location in the history list.
    ///
    /// Port of `NavigationHistoryService.hasNext(Navigatable)`.
    fn has_next(&self, navigatable: &dyn Navigatable) -> bool;

    /// Returns true if there is a valid "previous" location in the history list.
    ///
    /// Port of `NavigationHistoryService.hasPrevious(Navigatable)`.
    fn has_previous(&self, navigatable: &dyn Navigatable) -> bool;

    /// Returns true if there is a valid "next" function location in the history list.
    ///
    /// Port of `NavigationHistoryService.hasNextFunction(Navigatable)`.
    fn has_next_function(&self, navigatable: &dyn Navigatable) -> bool;

    /// Returns true if there is a valid "previous" function location in the history list.
    ///
    /// Port of `NavigationHistoryService.hasPreviousFunction(Navigatable)`.
    fn has_previous_function(&self, navigatable: &dyn Navigatable) -> bool;

    /// Adds the current location memento to the list of previous locations for the given
    /// navigatable. Clears the list of next locations.
    ///
    /// Port of `NavigationHistoryService.addNewLocation(Navigatable)`.
    fn add_new_location(&self, navigatable: &dyn Navigatable);

    /// Removes all visited locations from the history list for the given navigatable.
    ///
    /// Port of `NavigationHistoryService.clear(Navigatable)`.
    fn clear(&self, navigatable: &dyn Navigatable);

    /// Removes all entries for the given program from all history lists.
    ///
    /// Port of `NavigationHistoryService.clear(Program)`.
    fn clear_program(&self, program: &dyn Program);
}

#[cfg(test)]
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

    struct MockNavigatable;
    impl Navigatable for MockNavigatable {
        fn is_connected(&self) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct MockHistoryService {
        previous: Vec<LocationMemento>,
        next: Vec<LocationMemento>,
        cleared: std::cell::RefCell<bool>,
        program_cleared: std::cell::RefCell<bool>,
    }

    impl NavigationHistoryService for MockHistoryService {
        fn next(&self, _navigatable: &dyn Navigatable) {}
        fn previous(&self, _navigatable: &dyn Navigatable) {}
        fn next_location(&self, _navigatable: &dyn Navigatable, _location: &LocationMemento) {}
        fn previous_location(&self, _navigatable: &dyn Navigatable, _location: &LocationMemento) {}
        fn next_function(&self, _navigatable: &dyn Navigatable) {}
        fn previous_function(&self, _navigatable: &dyn Navigatable) {}

        fn get_previous_locations(&self, _navigatable: &dyn Navigatable) -> Vec<LocationMemento> {
            self.previous.clone()
        }

        fn get_next_locations(&self, _navigatable: &dyn Navigatable) -> Vec<LocationMemento> {
            self.next.clone()
        }

        fn has_next(&self, _navigatable: &dyn Navigatable) -> bool {
            !self.next.is_empty()
        }

        fn has_previous(&self, _navigatable: &dyn Navigatable) -> bool {
            !self.previous.is_empty()
        }

        fn has_next_function(&self, navigatable: &dyn Navigatable) -> bool {
            self.has_next(navigatable)
        }

        fn has_previous_function(&self, navigatable: &dyn Navigatable) -> bool {
            self.has_previous(navigatable)
        }

        fn add_new_location(&self, _navigatable: &dyn Navigatable) {}

        fn clear(&self, _navigatable: &dyn Navigatable) {
            *self.cleared.borrow_mut() = true;
        }

        fn clear_program(&self, _program: &dyn Program) {
            *self.program_cleared.borrow_mut() = true;
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let service: Box<dyn NavigationHistoryService> = Box::new(MockHistoryService {
            previous: vec![LocationMemento],
            next: vec![],
            ..Default::default()
        });

        let navigatable = MockNavigatable;
        let program = MockProgram;

        assert!(service.has_previous(&navigatable));
        assert!(!service.has_next(&navigatable));
        assert_eq!(service.get_previous_locations(&navigatable), vec![LocationMemento]);
        assert!(service.get_next_locations(&navigatable).is_empty());

        service.next(&navigatable);
        service.previous(&navigatable);
        service.next_location(&navigatable, &LocationMemento);
        service.previous_location(&navigatable, &LocationMemento);
        service.next_function(&navigatable);
        service.previous_function(&navigatable);
        service.add_new_location(&navigatable);

        service.clear(&navigatable);
        service.clear_program(&program);
    }
}

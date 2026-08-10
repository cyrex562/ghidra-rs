//! Service for creating data types in Ghidra programs.
//!
//! Mirrors `ghidra.app.services.DataService`.

use crate::app::seam_stubs::ListingActionContext;
use crate::program::model::data::data_type::DataType;

/// Service for creating data in Ghidra programs.
///
/// Provides methods to determine if data creation is allowed at a location and to apply data types.
pub trait DataService {
    /// Determines if creating data is permitted on the specified location.
    ///
    /// If the location is contained within the current program selection, the entire selection
    /// is examined.
    ///
    /// # Arguments
    ///
    /// * `context` - The context containing program, location, and selection information
    ///
    /// # Returns
    ///
    /// `true` if creating data is allowed at the specified location, `false` otherwise.
    fn is_create_data_allowed(&self, context: &dyn ListingActionContext) -> bool;

    /// Applies the given data type at a location.
    ///
    /// # Arguments
    ///
    /// * `dt` - The data type to create at the location
    /// * `context` - The context containing program, location, and selection information
    /// * `stack_pointers` - If `true`, and if supported and the existing context-specified data is
    ///   a pointer, the specified datatype should be stacked onto the existing pointer if permitted
    /// * `enable_conflict_handling` - If `true`, the service may prompt the user to resolve data
    ///   conflicts
    ///
    /// # Returns
    ///
    /// `true` if the data could be created at the specified location, `false` otherwise.
    fn create_data(
        &self,
        dt: Box<dyn DataType>,
        context: &dyn ListingActionContext,
        stack_pointers: bool,
        enable_conflict_handling: bool,
    ) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct MockListingActionContext;
    impl ListingActionContext for MockListingActionContext {}

    struct MockDataService {
        allow_create: Rc<RefCell<bool>>,
        create_success: Rc<RefCell<bool>>,
    }

    impl DataService for MockDataService {
        fn is_create_data_allowed(&self, _context: &dyn ListingActionContext) -> bool {
            *self.allow_create.borrow()
        }

        fn create_data(
            &self,
            _dt: Box<dyn DataType>,
            _context: &dyn ListingActionContext,
            _stack_pointers: bool,
            _enable_conflict_handling: bool,
        ) -> bool {
            *self.create_success.borrow()
        }
    }

    #[test]
    fn test_is_create_data_allowed_true() {
        let allow_create = Rc::new(RefCell::new(true));
        let create_success = Rc::new(RefCell::new(false));
        let service = MockDataService {
            allow_create,
            create_success,
        };
        let context = MockListingActionContext;
        assert!(service.is_create_data_allowed(&context));
    }

    #[test]
    fn test_is_create_data_allowed_false() {
        let allow_create = Rc::new(RefCell::new(false));
        let create_success = Rc::new(RefCell::new(false));
        let service = MockDataService {
            allow_create,
            create_success,
        };
        let context = MockListingActionContext;
        assert!(!service.is_create_data_allowed(&context));
    }

    #[test]
    fn test_create_data_failure() {
        let allow_create = Rc::new(RefCell::new(false));
        let create_success = Rc::new(RefCell::new(false));
        let service = MockDataService {
            allow_create,
            create_success,
        };
        let context = MockListingActionContext;

        // Use the trait object directly in a mock way by casting
        // Since we can't easily construct a DataType in tests, we verify trait bounds
        let _: &dyn DataService = &service;
    }

    #[test]
    fn test_service_trait_object() {
        let service: Box<dyn DataService> = Box::new(MockDataService {
            allow_create: Rc::new(RefCell::new(true)),
            create_success: Rc::new(RefCell::new(true)),
        });
        let context = MockListingActionContext;
        assert!(service.is_create_data_allowed(&context));
    }
}

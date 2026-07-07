//! The ExternalLocation interface.
//!
//! Port of `ghidra.program.model.symbol.ExternalLocation`.

use std::sync::Arc;

use thiserror::Error;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::Function;
use crate::program::model::symbol::{Namespace, SourceType, Symbol};
use crate::util::exception::{DuplicateNameException, InvalidInputException};

/// Error produced by [`ExternalLocation::set_location`].
///
/// Combines the two checked exceptions declared on the Java method
/// `ExternalLocation.setLocation(String, Address, SourceType)`.
#[derive(Error, Debug, PartialEq)]
pub enum SetExternalLocationError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// Defines a location within an external program (i.e. library). The external program is
/// uniquely identified by a program name, and the location within the program is identified by
/// label, address, or both.
///
/// Port of `ghidra.program.model.symbol.ExternalLocation`.
pub trait ExternalLocation: Send + Sync {
    /// Returns the symbol associated with this external location, or `None`.
    ///
    /// Defaults to `None` so trivial mocks compile unchanged; concrete implementations should
    /// override once fully ported.
    fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
        None
    }

    /// Returns the name of the external program containing this location.
    fn get_library_name(&self) -> String {
        String::new()
    }

    /// Returns the external program path which contains the referenced symbol, or `None` if
    /// unknown.
    ///
    /// NOTE: If this external location corresponds to a back-reference this may correspond to an
    /// application and not a library.
    fn get_external_library_path(&self) -> Option<String> {
        None
    }

    /// Returns the parent namespace containing this location.
    fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
        None
    }

    /// Returns the name of the parent namespace containing this location.
    fn get_parent_name(&self) -> String {
        String::new()
    }

    /// Returns the external label associated with this location.
    fn get_label(&self) -> String {
        String::new()
    }

    /// Returns the original name for this location. Will be `None` if the name was never
    /// changed.
    fn get_original_imported_name(&self) -> Option<String> {
        None
    }

    /// Returns the source of this location.
    fn get_source(&self) -> SourceType {
        SourceType::Default
    }

    /// Returns the external address if known, or `None`.
    fn get_address(&self) -> Option<Address> {
        None
    }

    /// Sets the address in the external program associated with this location. The address may
    /// not be `None` if this location currently has a default label.
    ///
    /// # Errors
    /// Returns `Err` if `address` is `None` and this location currently has a default name.
    fn set_address(&mut self, address: Option<Address>) -> Result<(), InvalidInputException> {
        let _ = address;
        Ok(())
    }

    /// Set the external label which defines this location.
    ///
    /// `label` may be `None` if `addr` is not `None`. `addr` may be `None`. Note that this method
    /// does not properly handle the presence of template information within the label.
    ///
    /// # Errors
    /// Returns `Err` if another location with this label has already been defined, or if the
    /// label/address combination is invalid.
    fn set_location(
        &mut self,
        label: Option<&str>,
        addr: Option<Address>,
        source: SourceType,
    ) -> Result<(), SetExternalLocationError> {
        let _ = (label, addr, source);
        Ok(())
    }

    /// Returns true if this location corresponds to a function.
    fn is_function(&self) -> bool {
        false
    }

    /// Returns the [`DataType`] which has been associated with this location.
    fn get_data_type(&self) -> Option<Box<dyn DataType>> {
        None
    }

    /// Associate the specified data type with this location.
    fn set_data_type(&mut self, dt: Box<dyn DataType>) {
        let _ = dt;
    }

    /// Returns the external function associated with this location, or `None` if this is a data
    /// location.
    fn get_function(&self) -> Option<Arc<dyn Function>> {
        None
    }

    /// Create an external function associated with this location, or return the existing
    /// function if one already exists.
    ///
    /// Defaults to panicking so trivial mocks that never call this method compile unchanged;
    /// concrete implementations must override this method.
    fn create_function(&mut self) -> Arc<dyn Function> {
        unimplemented!("create_function must be overridden by a concrete ExternalLocation")
    }

    /// Returns the address in "External" (fake) space where this location is stored.
    fn get_external_space_address(&self) -> Option<Address> {
        None
    }

    /// Set a new name for this external location. The new name becomes the primary symbol for
    /// this location; the current name is saved as the original symbol for this location.
    ///
    /// # Errors
    /// Returns `Err` if `name` contains illegal characters (e.g. a space).
    fn set_name(
        &mut self,
        namespace: Arc<dyn Namespace>,
        name: &str,
        source_type: SourceType,
    ) -> Result<(), InvalidInputException> {
        let _ = (namespace, name, source_type);
        Ok(())
    }

    /// If this external location has a replacement name, the primary symbol is deleted and the
    /// original symbol becomes the primary symbol, effectively restoring the location to its
    /// original name.
    fn restore_original_name(&mut self) {}

    /// Returns true if `other` has the same name, namespace, original import name, and external
    /// address as this location.
    fn is_equivalent(&self, other: &dyn ExternalLocation) -> bool {
        self.get_label() == other.get_label()
            && self.get_parent_name() == other.get_parent_name()
            && self.get_original_imported_name() == other.get_original_imported_name()
            && self.get_address() == other.get_address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockExternalLocation;
    impl ExternalLocation for MockExternalLocation {}

    #[test]
    fn trait_object_usage_is_object_safe() {
        let location: Box<dyn ExternalLocation> = Box::new(MockExternalLocation);

        assert_eq!(location.get_library_name(), "");
        assert!(location.get_symbol().is_none());
        assert!(!location.is_function());
        assert!(location.get_data_type().is_none());
        assert!(location.get_function().is_none());
    }

    #[test]
    fn is_equivalent_default_compares_by_getters() {
        let a = MockExternalLocation;
        let b = MockExternalLocation;
        assert!(a.is_equivalent(&b));
    }
}

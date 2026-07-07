//! External manager interface. Defines methods for dealing with external programs and locations
//! within those programs.
//!
//! Port of `ghidra.program.model.symbol.ExternalManager`.

use std::sync::Arc;

use thiserror::Error;

use crate::program::model::address::Address;
use crate::program::model::listing::Library;
use crate::program::model::symbol::{
    ExternalLocation, ExternalLocationIterator, Namespace, SourceType, Symbol,
};
use crate::util::exception::{DuplicateNameException, InvalidInputException};

/// Error produced by [`ExternalManager::update_external_library_name`].
#[derive(Error, Debug, PartialEq)]
pub enum UpdateExternalLibraryNameError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// Error produced by [`ExternalManager::add_external_library_name`].
#[derive(Error, Debug, PartialEq)]
pub enum AddExternalLibraryNameError {
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
}

/// Error produced by [`ExternalManager::add_ext_location_in_library`] and
/// [`ExternalManager::add_ext_function_in_library`].
#[derive(Error, Debug, PartialEq)]
pub enum AddExternalLocationInLibraryError {
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
}

/// External manager interface. Defines methods for dealing with external programs and locations
/// within those programs.
///
/// Port of `ghidra.program.model.symbol.ExternalManager`. Java's overloaded `getExternalLocations`
/// / `getUniqueExternalLocation` / `addExtLocation` / `addExtFunction` methods are each given a
/// distinct Rust name, since Rust traits cannot overload on parameter type alone. The
/// `reuseExisting`-boolean overloads of `addExtLocation`/`addExtFunction` become dedicated
/// `*_reuse` methods, with the non-reuse variant provided as a default method that forwards with
/// `reuse_existing: false`, mirroring the Java default of not reusing an existing location.
pub trait ExternalManager: Send + Sync {
    /// Returns the names of all external Libraries sorted by preferred search order.
    /// This order reflects the preferred search order when looking for external symbols
    /// which were not linked to a specific Library.
    ///
    /// NOTE: The `Library::UNKNOWN` library will always be returned as first in the list
    /// but will not have an associated program path and cannot be searched.
    fn get_external_library_names(&self) -> Vec<String>;

    /// Get a list of all external Libraries sorted by preferred search order.
    /// This order reflects the preferred search order when looking for external symbols
    /// which were not linked to a specific Library.
    ///
    /// NOTE: The `Library::UNKNOWN` library will always be returned as first in the list
    /// but will not have an associated program path and cannot be searched.
    fn get_libraries(&self) -> Vec<Arc<dyn Library>>;

    /// Get the Library which corresponds to the specified name, or `None` if not found.
    fn get_external_library(&self, library_name: &str) -> Option<Arc<dyn Library>>;

    /// Removes external name if no associated `ExternalLocation`s exist.
    ///
    /// Returns `true` if removed, `false` if unable to due to associated locations/references.
    fn remove_external_library(&mut self, library_name: &str) -> bool;

    /// Returns the file pathname associated with an external name.
    ///
    /// Returns `None` if either the external name does not exist or a pathname has not been set.
    fn get_external_library_path(&self, library_name: &str) -> Option<String>;

    /// Sets the file pathname associated with an external name.
    /// If the Library namespace/symbol does not already exist it will be created provided
    /// the `library_name` does not conflict with another namespace whose parent is the global
    /// namespace.
    ///
    /// NOTE: Assigning path for the `Library::UNKNOWN` Library will be ignored.
    ///
    /// NOTE: Assigning path to a non-Library namespace will fail silently.
    ///
    /// # Errors
    /// Returns `Err` on invalid input specified.
    fn set_external_path(
        &mut self,
        library_name: &str,
        pathname: Option<&str>,
        user_defined: bool,
    ) -> Result<(), InvalidInputException>;

    /// Returns the ordinal associated with an external library which represents its
    /// sequence within the order list of libraries, or -1 if library name not found.
    fn get_library_ordinal(&self, library_name: &str) -> i32;

    /// Sets the Library search ordinal associated with an external name.
    ///
    /// Assigning ordinal for the `Library::UNKNOWN` Library will fail and return -1.
    /// Assigning ordinal to a non-existing Library will fail and return -1.
    ///
    /// NOTE: The actual ordinal applied may be limited based on placement restrictions.
    ///
    /// Returns the actual ordinal applied or -1 if change failed.
    fn set_library_ordinal(&mut self, library_name: &str, ordinal: i32) -> i32;

    /// Change the name of an existing external name.
    ///
    /// Returns `true` if symbol was found and renamed, `false` if symbol not found.
    ///
    /// # Errors
    /// Returns `Err` if the name conflicts with another symbol, or an invalid/empty name is
    /// specified.
    fn update_external_library_name(
        &mut self,
        old_name: &str,
        new_name: &str,
        source: SourceType,
    ) -> Result<bool, UpdateExternalLibraryNameError>;

    /// Get an iterator over all external locations associated with the specified Library.
    ///
    /// Stands in for the Java overload `getExternalLocations(String)`.
    fn get_external_locations_for_library(
        &self,
        library_name: &str,
    ) -> Box<dyn ExternalLocationIterator>;

    /// Get an iterator over all external locations which have been associated to
    /// the specified memory address.
    ///
    /// Stands in for the Java overload `getExternalLocations(Address)`.
    fn get_external_locations_at_address(
        &self,
        memory_address: &Address,
    ) -> Box<dyn ExternalLocationIterator>;

    /// Returns the external locations matching the given label name in the specified Library.
    /// If searching for an original import name which should not be constrained to a specific
    /// library (e.g., mangled name), `None` may be specified for the `library_name`.
    ///
    /// Stands in for the Java overload `getExternalLocations(String, String)`, with the returned
    /// `Set<ExternalLocation>` modeled as a `Vec` since trait objects have no natural identity
    /// for hashing/equality.
    fn get_external_locations_by_label(
        &self,
        library_name: Option<&str>,
        label: &str,
    ) -> Vec<Arc<dyn ExternalLocation>>;

    /// Returns the external locations matching the given label name in the given Namespace.
    /// If searching for an original import name which should not be constrained to a specific
    /// library (e.g., mangled name), `None` may be specified for the namespace. If a library
    /// sub-namespace is specified the original import name will not be searched.
    ///
    /// Stands in for the Java overload `getExternalLocations(Namespace, String)`, with the
    /// returned `Set<ExternalLocation>` modeled as a `Vec` since trait objects have no natural
    /// identity for hashing/equality.
    fn get_external_locations_in_namespace(
        &self,
        namespace: Option<Arc<dyn Namespace>>,
        label: &str,
    ) -> Vec<Arc<dyn ExternalLocation>>;

    /// Returns the unique external location associated with the given library name and label.
    /// If searching for an original import name which should not be constrained to a specific
    /// library (e.g., mangled name), `None` may be specified for the `library_name`.
    ///
    /// Stands in for the Java overload `getUniqueExternalLocation(String, String)`.
    fn get_unique_external_location(
        &self,
        library_name: Option<&str>,
        label: &str,
    ) -> Option<Arc<dyn ExternalLocation>>;

    /// Returns the unique external location associated with the given namespace and label.
    /// If searching for an original import name which should not be constrained to a specific
    /// library (e.g., mangled name), `None` may be specified for the namespace. If a library
    /// sub-namespace is specified the original import name will not be searched.
    ///
    /// Stands in for the Java overload `getUniqueExternalLocation(Namespace, String)`.
    fn get_unique_external_location_in_namespace(
        &self,
        namespace: Option<Arc<dyn Namespace>>,
        label: &str,
    ) -> Option<Arc<dyn ExternalLocation>>;

    /// Returns the external location associated with the given external symbol, or `None`.
    fn get_external_location(&self, symbol: Arc<dyn Symbol>) -> Option<Arc<dyn ExternalLocation>>;

    /// Determines if the indicated external library name is being managed (exists).
    fn contains(&self, library_name: &str) -> bool;

    /// Adds a new external library name.
    ///
    /// # Errors
    /// Returns `Err` if `library_name` is invalid/empty, or another non-Library namespace already
    /// has the same name.
    fn add_external_library_name(
        &mut self,
        library_name: &str,
        source: SourceType,
    ) -> Result<Arc<dyn Library>, AddExternalLibraryNameError>;

    /// Get or create an external location associated with a library/file named `library_name`
    /// and the location within that file identified by `ext_label` and/or its memory address
    /// `ext_addr`. Either or both `ext_label` or `ext_addr` must be specified.
    ///
    /// Stands in for the Java overload `addExtLocation(String, String, Address, SourceType)`.
    ///
    /// # Errors
    /// Returns `Err` if `library_name` or `ext_label` is invalid, or neither `ext_label` nor
    /// `ext_addr` was specified properly, or another non-Library namespace already has the same
    /// name.
    fn add_ext_location_in_library(
        &mut self,
        library_name: &str,
        ext_label: Option<&str>,
        ext_addr: Option<Address>,
        source_type: SourceType,
    ) -> Result<Arc<dyn ExternalLocation>, AddExternalLocationInLibraryError>;

    /// Create an external location in the indicated external parent namespace and identified by
    /// `ext_label` and/or its memory address `ext_addr`. Either or both `ext_label` or `ext_addr`
    /// must be specified.
    ///
    /// Stands in for the Java overload
    /// `addExtLocation(Namespace, String, Address, SourceType)`. Defaults to forwarding to
    /// [`ExternalManager::add_ext_location_in_namespace_reuse`] with `reuse_existing: false`.
    ///
    /// # Errors
    /// Returns `Err` if `ext_label` is invalid, or neither `ext_label` nor `ext_addr` was
    /// specified properly.
    fn add_ext_location_in_namespace(
        &mut self,
        ext_namespace: Arc<dyn Namespace>,
        ext_label: Option<&str>,
        ext_addr: Option<Address>,
        source_type: SourceType,
    ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException> {
        self.add_ext_location_in_namespace_reuse(
            ext_namespace,
            ext_label,
            ext_addr,
            source_type,
            false,
        )
    }

    /// Get or create an external location in the indicated external parent namespace and
    /// identified by `ext_label` and/or its memory address `ext_addr`. Either or both `ext_label`
    /// or `ext_addr` must be specified.
    ///
    /// Stands in for the Java overload
    /// `addExtLocation(Namespace, String, Address, SourceType, boolean)`. When `reuse_existing` is
    /// `true`, an existing matching external location is returned instead of creating a new one.
    ///
    /// # Errors
    /// Returns `Err` if `ext_label` is invalid, or neither `ext_label` nor `ext_addr` was
    /// specified properly.
    fn add_ext_location_in_namespace_reuse(
        &mut self,
        ext_namespace: Arc<dyn Namespace>,
        ext_label: Option<&str>,
        ext_addr: Option<Address>,
        source_type: SourceType,
        reuse_existing: bool,
    ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException>;

    /// Create an external Function in the external Library namespace `library_name` and
    /// identified by `ext_label` and/or its memory address `ext_addr`. Either or both `ext_label`
    /// or `ext_addr` must be specified.
    ///
    /// Stands in for the Java overload `addExtFunction(String, String, Address, SourceType)`.
    ///
    /// # Errors
    /// Returns `Err` if `library_name` or `ext_label` is invalid, or neither `ext_label` nor
    /// `ext_addr` was specified properly, or another non-Library namespace already has the same
    /// name.
    fn add_ext_function_in_library(
        &mut self,
        library_name: &str,
        ext_label: Option<&str>,
        ext_addr: Option<Address>,
        source_type: SourceType,
    ) -> Result<Arc<dyn ExternalLocation>, AddExternalLocationInLibraryError>;

    /// Create an external Function in the indicated external parent namespace and identified by
    /// `ext_label` and/or its memory address `ext_addr`. Either or both `ext_label` or `ext_addr`
    /// must be specified.
    ///
    /// Stands in for the Java overload `addExtFunction(Namespace, String, Address, SourceType)`.
    /// Defaults to forwarding to [`ExternalManager::add_ext_function_in_namespace_reuse`] with
    /// `reuse_existing: false`.
    ///
    /// # Errors
    /// Returns `Err` if `ext_label` is invalid, or neither `ext_label` nor `ext_addr` was
    /// specified properly.
    fn add_ext_function_in_namespace(
        &mut self,
        ext_namespace: Arc<dyn Namespace>,
        ext_label: Option<&str>,
        ext_addr: Option<Address>,
        source_type: SourceType,
    ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException> {
        self.add_ext_function_in_namespace_reuse(
            ext_namespace,
            ext_label,
            ext_addr,
            source_type,
            false,
        )
    }

    /// Get or create an external Function in the indicated external parent namespace and
    /// identified by `ext_label` and/or its memory address `ext_addr`. Either or both
    /// `ext_label` or `ext_addr` must be specified.
    ///
    /// Stands in for the Java overload
    /// `addExtFunction(Namespace, String, Address, SourceType, boolean)`. When `reuse_existing`
    /// is `true`, an existing matching location is returned instead of creating a new one; when
    /// `false`, a new one is preferred as long as the specified address is not `None` and not
    /// used in an existing location.
    ///
    /// # Errors
    /// Returns `Err` if `ext_label` is invalid, or neither `ext_label` nor `ext_addr` was
    /// specified properly.
    fn add_ext_function_in_namespace_reuse(
        &mut self,
        ext_namespace: Arc<dyn Namespace>,
        ext_label: Option<&str>,
        ext_addr: Option<Address>,
        source_type: SourceType,
        reuse_existing: bool,
    ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::symbol::EmptyExternalLocationIterator;

    struct MockExternalManager;

    impl ExternalManager for MockExternalManager {
        fn get_external_library_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_libraries(&self) -> Vec<Arc<dyn Library>> {
            Vec::new()
        }

        fn get_external_library(&self, _library_name: &str) -> Option<Arc<dyn Library>> {
            None
        }

        fn remove_external_library(&mut self, _library_name: &str) -> bool {
            false
        }

        fn get_external_library_path(&self, _library_name: &str) -> Option<String> {
            None
        }

        fn set_external_path(
            &mut self,
            _library_name: &str,
            _pathname: Option<&str>,
            _user_defined: bool,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn get_library_ordinal(&self, _library_name: &str) -> i32 {
            -1
        }

        fn set_library_ordinal(&mut self, _library_name: &str, _ordinal: i32) -> i32 {
            -1
        }

        fn update_external_library_name(
            &mut self,
            _old_name: &str,
            _new_name: &str,
            _source: SourceType,
        ) -> Result<bool, UpdateExternalLibraryNameError> {
            Ok(false)
        }

        fn get_external_locations_for_library(
            &self,
            _library_name: &str,
        ) -> Box<dyn ExternalLocationIterator> {
            Box::new(EmptyExternalLocationIterator)
        }

        fn get_external_locations_at_address(
            &self,
            _memory_address: &Address,
        ) -> Box<dyn ExternalLocationIterator> {
            Box::new(EmptyExternalLocationIterator)
        }

        fn get_external_locations_by_label(
            &self,
            _library_name: Option<&str>,
            _label: &str,
        ) -> Vec<Arc<dyn ExternalLocation>> {
            Vec::new()
        }

        fn get_external_locations_in_namespace(
            &self,
            _namespace: Option<Arc<dyn Namespace>>,
            _label: &str,
        ) -> Vec<Arc<dyn ExternalLocation>> {
            Vec::new()
        }

        fn get_unique_external_location(
            &self,
            _library_name: Option<&str>,
            _label: &str,
        ) -> Option<Arc<dyn ExternalLocation>> {
            None
        }

        fn get_unique_external_location_in_namespace(
            &self,
            _namespace: Option<Arc<dyn Namespace>>,
            _label: &str,
        ) -> Option<Arc<dyn ExternalLocation>> {
            None
        }

        fn get_external_location(
            &self,
            _symbol: Arc<dyn Symbol>,
        ) -> Option<Arc<dyn ExternalLocation>> {
            None
        }

        fn contains(&self, _library_name: &str) -> bool {
            false
        }

        fn add_external_library_name(
            &mut self,
            _library_name: &str,
            _source: SourceType,
        ) -> Result<Arc<dyn Library>, AddExternalLibraryNameError> {
            unimplemented!("not needed for this smoke test")
        }

        fn add_ext_location_in_library(
            &mut self,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source_type: SourceType,
        ) -> Result<Arc<dyn ExternalLocation>, AddExternalLocationInLibraryError> {
            unimplemented!("not needed for this smoke test")
        }

        fn add_ext_location_in_namespace_reuse(
            &mut self,
            _ext_namespace: Arc<dyn Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source_type: SourceType,
            _reuse_existing: bool,
        ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }

        fn add_ext_function_in_library(
            &mut self,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source_type: SourceType,
        ) -> Result<Arc<dyn ExternalLocation>, AddExternalLocationInLibraryError> {
            unimplemented!("not needed for this smoke test")
        }

        fn add_ext_function_in_namespace_reuse(
            &mut self,
            _ext_namespace: Arc<dyn Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source_type: SourceType,
            _reuse_existing: bool,
        ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }
    }

    #[test]
    fn mock_external_manager_is_object_safe() {
        let mut manager: Box<dyn ExternalManager> = Box::new(MockExternalManager);

        assert!(manager.get_external_library_names().is_empty());
        assert!(manager.get_libraries().is_empty());
        assert!(manager.get_external_library("advapi32.dll").is_none());
        assert!(!manager.remove_external_library("advapi32.dll"));
        assert_eq!(manager.get_library_ordinal("advapi32.dll"), -1);
        assert!(!manager.contains("advapi32.dll"));
        assert!(manager
            .get_external_locations_by_label(None, "CreateFileA")
            .is_empty());
        assert!(!manager
            .get_external_locations_for_library("advapi32.dll")
            .has_next());
    }

    #[test]
    fn default_non_reuse_overloads_forward_with_reuse_existing_false() {
        struct RecordingExternalManager {
            last_reuse_existing: Option<bool>,
        }

        impl ExternalManager for RecordingExternalManager {
            fn get_external_library_names(&self) -> Vec<String> {
                Vec::new()
            }
            fn get_libraries(&self) -> Vec<Arc<dyn Library>> {
                Vec::new()
            }
            fn get_external_library(&self, _library_name: &str) -> Option<Arc<dyn Library>> {
                None
            }
            fn remove_external_library(&mut self, _library_name: &str) -> bool {
                false
            }
            fn get_external_library_path(&self, _library_name: &str) -> Option<String> {
                None
            }
            fn set_external_path(
                &mut self,
                _library_name: &str,
                _pathname: Option<&str>,
                _user_defined: bool,
            ) -> Result<(), InvalidInputException> {
                Ok(())
            }
            fn get_library_ordinal(&self, _library_name: &str) -> i32 {
                -1
            }
            fn set_library_ordinal(&mut self, _library_name: &str, _ordinal: i32) -> i32 {
                -1
            }
            fn update_external_library_name(
                &mut self,
                _old_name: &str,
                _new_name: &str,
                _source: SourceType,
            ) -> Result<bool, UpdateExternalLibraryNameError> {
                Ok(false)
            }
            fn get_external_locations_for_library(
                &self,
                _library_name: &str,
            ) -> Box<dyn ExternalLocationIterator> {
                Box::new(EmptyExternalLocationIterator)
            }
            fn get_external_locations_at_address(
                &self,
                _memory_address: &Address,
            ) -> Box<dyn ExternalLocationIterator> {
                Box::new(EmptyExternalLocationIterator)
            }
            fn get_external_locations_by_label(
                &self,
                _library_name: Option<&str>,
                _label: &str,
            ) -> Vec<Arc<dyn ExternalLocation>> {
                Vec::new()
            }
            fn get_external_locations_in_namespace(
                &self,
                _namespace: Option<Arc<dyn Namespace>>,
                _label: &str,
            ) -> Vec<Arc<dyn ExternalLocation>> {
                Vec::new()
            }
            fn get_unique_external_location(
                &self,
                _library_name: Option<&str>,
                _label: &str,
            ) -> Option<Arc<dyn ExternalLocation>> {
                None
            }
            fn get_unique_external_location_in_namespace(
                &self,
                _namespace: Option<Arc<dyn Namespace>>,
                _label: &str,
            ) -> Option<Arc<dyn ExternalLocation>> {
                None
            }
            fn get_external_location(
                &self,
                _symbol: Arc<dyn Symbol>,
            ) -> Option<Arc<dyn ExternalLocation>> {
                None
            }
            fn contains(&self, _library_name: &str) -> bool {
                false
            }
            fn add_external_library_name(
                &mut self,
                _library_name: &str,
                _source: SourceType,
            ) -> Result<Arc<dyn Library>, AddExternalLibraryNameError> {
                unimplemented!("not needed for this smoke test")
            }
            fn add_ext_location_in_library(
                &mut self,
                _library_name: &str,
                _ext_label: Option<&str>,
                _ext_addr: Option<Address>,
                _source_type: SourceType,
            ) -> Result<Arc<dyn ExternalLocation>, AddExternalLocationInLibraryError> {
                unimplemented!("not needed for this smoke test")
            }
            fn add_ext_location_in_namespace_reuse(
                &mut self,
                _ext_namespace: Arc<dyn Namespace>,
                _ext_label: Option<&str>,
                _ext_addr: Option<Address>,
                _source_type: SourceType,
                reuse_existing: bool,
            ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException> {
                self.last_reuse_existing = Some(reuse_existing);
                Err(InvalidInputException::default())
            }
            fn add_ext_function_in_library(
                &mut self,
                _library_name: &str,
                _ext_label: Option<&str>,
                _ext_addr: Option<Address>,
                _source_type: SourceType,
            ) -> Result<Arc<dyn ExternalLocation>, AddExternalLocationInLibraryError> {
                unimplemented!("not needed for this smoke test")
            }
            fn add_ext_function_in_namespace_reuse(
                &mut self,
                _ext_namespace: Arc<dyn Namespace>,
                _ext_label: Option<&str>,
                _ext_addr: Option<Address>,
                _source_type: SourceType,
                reuse_existing: bool,
            ) -> Result<Arc<dyn ExternalLocation>, InvalidInputException> {
                self.last_reuse_existing = Some(reuse_existing);
                Err(InvalidInputException::default())
            }
        }

        struct MockNamespace;
        impl Namespace for MockNamespace {
            fn get_symbol(&self) -> Arc<dyn Symbol> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
                None
            }
        }

        let mut manager = RecordingExternalManager {
            last_reuse_existing: None,
        };
        let ns: Arc<dyn Namespace> = Arc::new(MockNamespace);

        let _ = manager.add_ext_location_in_namespace(
            ns.clone(),
            Some("CreateFileA"),
            None,
            SourceType::Imported,
        );
        assert_eq!(manager.last_reuse_existing, Some(false));

        let _ = manager.add_ext_function_in_namespace(
            ns,
            Some("CreateFileA"),
            None,
            SourceType::Imported,
        );
        assert_eq!(manager.last_reuse_existing, Some(false));
    }
}

//! Manages the database for external references.
//!
//! Port of `ghidra.program.database.external.ExternalManagerDB` as a trait (cycle cut-point): the
//! Java class both implements [`ExternalManager`] and is the type that constructs
//! [`ExternalLocationDb`](crate::program::database::external::ExternalLocationDb) instances (which
//! in turn hold a reference back to their owning `ExternalManagerDB`). That mutual construction is
//! what makes this class a cycle cut-point, matching how
//! [`ExternalLocationDb`](crate::program::database::external::ExternalLocationDb) itself was cut.
//!
//! Left out of this port, as intentionally out of scope for an object-safe trait:
//! - The constructor and its old-adapter upgrade path (`initializeOldAdapters`,
//!   `upgradeOldExtRefAdapter`, `programReady`), which perform one-time database migration and
//!   depend on several not-yet-ported types (`DBHandle`, `OldExtNameAdapter`, `OldExtRefAdapter`,
//!   `AddressMap`'s old-address-map view, `ReferenceManager`).
//! - `setProgram`/`invalidateCache`/`deleteAddressRange`/`moveAddressRange`/`dispose`, i.e. the
//!   `ManagerDB` half of `ExternalManagerDB implements ManagerDB, ExternalManager`. The already
//!   ported [`ManagerDB`](crate::program::database::manager_db::ManagerDB) trait captures that
//!   contract generically; it's left as a separate implementor concern rather than a supertrait
//!   bound here, mirroring the same choice made by
//!   [`FunctionManagerDb`](crate::program::database::function::FunctionManagerDb) (also a
//!   `ManagerDB`-implementing cycle cut-point).
//! - The package-private `getSymbolManager()`/`getAddressMap()`/`createFunction(ExternalLocationDB)`
//!   helpers, used only by this class's own private `ExternalLocationDBIterator` inner class and by
//!   `ExternalLocationDB`. The latter is instead modeled directly on
//!   [`ExternalLocationDb::ext_manager_create_function`](crate::program::database::external::ExternalLocationDb::ext_manager_create_function),
//!   since satisfying it means passing the location itself back to the manager -- something a
//!   concrete implementor can do trivially in its own method body.
//! - The static `getDefaultExternalName(SymbolDB)` helper: its logic already lives in
//!   [`get_default_external_name`](crate::program::model::symbol::get_default_external_name),
//!   called directly from
//!   [`CodeSymbol::do_get_name`](crate::program::database::symbol::CodeSymbol::do_get_name) and the
//!   analogous `FunctionSymbol` method, rather than routed through `ExternalManagerDB`.
//! - `ExternalLocationIterator getExternalLocations(Address)` / `(String)`: these are the
//!   `ExternalManager` interface's own `getExternalLocations(Address)` /
//!   `getExternalLocations(String)` overloads (`get_external_locations_at_address` /
//!   `get_external_locations_for_library`), already captured by the [`ExternalManager`] supertrait;
//!   `ExternalManagerDB`'s private `ExternalLocationDBIterator` inner class that backs them is an
//!   implementation detail, not additional public API.
//!
//! `ExternalManagerDB implements ExternalManager`; this trait models that relationship by extending
//! the already-ported [`ExternalManager`] interface rather than re-declaring its methods, and adds
//! this class's own extra public/package-private API needed across the cycle:
//! [`get_program`](ExternalManagerDb::get_program) (package-private `getProgram()`, needed by
//! [`ExternalLocationDb`](crate::program::database::external::ExternalLocationDb)),
//! [`get_ext_location`](ExternalManagerDb::get_ext_location) (public `getExtLocation(Address)`),
//! and [`remove_external_location`](ExternalManagerDb::remove_external_location) (public
//! `removeExternalLocation(Address)`).

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::symbol::{ExternalLocation, ExternalManager};

/// Manages the database for external references.
///
/// Port of `ghidra.program.database.external.ExternalManagerDB` (cycle cut-point; see the module
/// docs for what was intentionally left out).
pub trait ExternalManagerDb: ExternalManager {
    /// Accessor for the owning program. Stands in for the package-private
    /// `ExternalManagerDB.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Get the external location associated with the given external address, if any.
    ///
    /// Stands in for `ExternalManagerDB.getExtLocation(Address)`.
    ///
    /// # Panics
    /// Implementations should panic if `external_addr` is not in the external address space
    /// (standing in for the Java method's `IllegalArgumentException`), or if more than two
    /// symbols are found at `external_addr` (standing in for the Java method's own
    /// `AssertException`, which should never actually be observed).
    fn get_ext_location(&self, external_addr: &Address) -> Option<Arc<dyn ExternalLocation>>;

    /// Removes the external location at the given external address.
    ///
    /// Stands in for `ExternalManagerDB.removeExternalLocation(Address)`.
    ///
    /// Returns `true` if an external location was successfully removed, else `false`.
    fn remove_external_location(&mut self, external_addr: &Address) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Library;
    use crate::program::model::symbol::{
        AddExternalLibraryNameError, AddExternalLocationInLibraryError,
        EmptyExternalLocationIterator, ExternalLocationIterator, Namespace, SourceType, Symbol,
        UpdateExternalLibraryNameError,
    };
    use crate::util::exception::InvalidInputException;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockProgram;
    impl crate::framework::model::domain_object::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    fn external_space() -> Arc<AddressSpace> {
        AddressSpace::new("EXTERNAL", 32, 1, AddressSpaceType::External, 2)
    }

    fn ext_addr(offset: i64) -> Address {
        Address::new(external_space(), offset)
    }

    /// A minimal in-memory `ExternalManagerDB`, backed by a map from external address offset to a
    /// stored [`ExternalLocation`], exercising object-safety and the extra API surface (beyond
    /// [`ExternalManager`]) this trait adds.
    struct MockExternalManagerDb {
        program: Arc<dyn Program>,
        locations: Mutex<HashMap<i64, Arc<dyn ExternalLocation>>>,
    }

    struct MockExternalLocation {
        label: String,
    }

    impl ExternalLocation for MockExternalLocation {
        fn get_label(&self) -> String {
            self.label.clone()
        }
    }

    impl ExternalManager for MockExternalManagerDb {
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

    impl ExternalManagerDb for MockExternalManagerDb {
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }

        fn get_ext_location(&self, external_addr: &Address) -> Option<Arc<dyn ExternalLocation>> {
            assert!(
                external_addr.is_external_address(),
                "expected external address"
            );
            self.locations
                .lock()
                .unwrap()
                .get(&external_addr.offset())
                .cloned()
        }

        fn remove_external_location(&mut self, external_addr: &Address) -> bool {
            self.locations
                .lock()
                .unwrap()
                .remove(&external_addr.offset())
                .is_some()
        }
    }

    fn manager() -> MockExternalManagerDb {
        let mut locations = HashMap::new();
        locations.insert(
            0x100,
            Arc::new(MockExternalLocation {
                label: "CreateFileA".to_string(),
            }) as Arc<dyn ExternalLocation>,
        );
        MockExternalManagerDb {
            program: Arc::new(MockProgram),
            locations: Mutex::new(locations),
        }
    }

    #[test]
    fn get_ext_location_finds_stored_location() {
        let mgr = manager();
        let loc = ExternalManagerDb::get_ext_location(&mgr, &ext_addr(0x100));
        assert_eq!(loc.unwrap().get_label(), "CreateFileA");
        assert!(ExternalManagerDb::get_ext_location(&mgr, &ext_addr(0x200)).is_none());
    }

    #[test]
    #[should_panic(expected = "expected external address")]
    fn get_ext_location_panics_on_non_external_address() {
        let mgr = manager();
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        ExternalManagerDb::get_ext_location(&mgr, &Address::new(ram, 0x100));
    }

    #[test]
    fn remove_external_location_removes_and_reports_success() {
        let mut mgr = manager();
        assert!(ExternalManagerDb::remove_external_location(
            &mut mgr,
            &ext_addr(0x100)
        ));
        assert!(ExternalManagerDb::get_ext_location(&mgr, &ext_addr(0x100)).is_none());
        assert!(!ExternalManagerDb::remove_external_location(
            &mut mgr,
            &ext_addr(0x100)
        ));
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mgr: Box<dyn ExternalManagerDb> = Box::new(manager());
        assert!(mgr
            .get_ext_location(&ext_addr(0x100))
            .map(|l| l.get_label())
            .as_deref()
            == Some("CreateFileA"));
        assert!(!mgr.contains("advapi32.dll"));
    }
}

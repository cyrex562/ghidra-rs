//! The manager for functions.
//!
//! Port of `ghidra.program.model.listing.FunctionManager`.

use std::sync::Arc;

use crate::program::database::function::OverlappingFunctionException;
use crate::program::database::manager_db::ManagerDB;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::listing::{
    CreateFunctionError, Function, FunctionIterator, FunctionTagManager, Program, Variable,
};
use crate::program::model::symbol::{Namespace, SourceType};
use crate::program::seam_stubs::PrototypeModel;

/// The manager for functions.
///
/// Port of `ghidra.program.model.listing.FunctionManager`. Extends [`ManagerDB`], whose
/// `invalidate_cache`/`move_address_range` methods stand in for the Java interface's
/// re-declarations of those same methods (done there only to narrow the checked-exception
/// signature, which the Rust `ManagerDB` contract does not need).
pub trait FunctionManager: ManagerDB {
    /// Returns this manager's program.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Get the ordered list of defined calling convention names. The reserved names "unknown"
    /// and "default" are not included. The returned collection may not include all names
    /// referenced by various functions and function-definitions. This set is limited to those
    /// defined by the associated compiler specification.
    ///
    /// For a set of all known names (including those that are not defined by compiler spec) see
    /// `DataTypeManager::get_known_calling_convention_names`.
    fn get_calling_convention_names(&self) -> Vec<String>;

    /// Gets the default calling convention's prototype model in this program.
    fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>>;

    /// Gets the prototype model of the calling convention with the specified name in this
    /// program.
    fn get_calling_convention(&self, name: &str) -> Option<Box<dyn PrototypeModel>>;

    /// Create a function with the given body at entry point within the global namespace.
    ///
    /// # Arguments
    /// * `name` - the name of the new function, or `None` for a default name
    /// * `entry_point` - entry point of function
    /// * `body` - addresses contained in the function body
    /// * `source` - the source of this function
    ///
    /// # Errors
    /// Returns [`CreateFunctionError::InvalidInput`] if the name has invalid characters, or
    /// [`CreateFunctionError::Overlapping`] if the address set of the body overlaps an existing
    /// function.
    fn create_function(
        &mut self,
        name: Option<&str>,
        entry_point: Address,
        body: &dyn AddressSetView,
        source: SourceType,
    ) -> Result<Arc<dyn Function>, CreateFunctionError>;

    /// Create a function with the given body at entry point.
    ///
    /// # Arguments
    /// * `name` - the name of the new function, or `None` for a default name
    /// * `name_space` - the namespace in which to create the function
    /// * `entry_point` - entry point of function
    /// * `body` - addresses contained in the function body
    /// * `source` - the source of this function
    ///
    /// # Errors
    /// Returns [`CreateFunctionError::InvalidInput`] if the name has invalid characters, or
    /// [`CreateFunctionError::Overlapping`] if the address set of the body overlaps an existing
    /// function.
    fn create_function_in_namespace(
        &mut self,
        name: Option<&str>,
        name_space: Arc<dyn Namespace>,
        entry_point: Address,
        body: &dyn AddressSetView,
        source: SourceType,
    ) -> Result<Arc<dyn Function>, CreateFunctionError>;

    /// Create a thunk function with the given body at entry point.
    ///
    /// # Arguments
    /// * `name` - the name of the new function, or `None` for a default name
    /// * `name_space` - the namespace in which to create the function
    /// * `entry_point` - entry point of function
    /// * `body` - addresses contained in the function body
    /// * `thunked_function` - referenced function (required when creating a thunk function)
    /// * `source` - the source of this function
    ///
    /// # Errors
    /// Returns `Err` if the address set of the body overlaps an existing function.
    ///
    /// # Panics
    /// Implementations should panic (standing in for Java's `UnsupportedOperationException`) if
    /// invoked on an external `entry_point` address.
    fn create_thunk_function(
        &mut self,
        name: Option<&str>,
        name_space: Arc<dyn Namespace>,
        entry_point: Address,
        body: &dyn AddressSetView,
        thunked_function: Arc<dyn Function>,
        source: SourceType,
    ) -> Result<Arc<dyn Function>, OverlappingFunctionException>;

    /// Returns the total number of functions in the program including external functions.
    fn get_function_count(&self) -> usize;

    /// Remove a function defined at `entry_point`. Returns `true` if the function was removed.
    fn remove_function(&mut self, entry_point: &Address) -> bool;

    /// Get the function at `entry_point`, or `None` if there is no function there.
    fn get_function_at(&self, entry_point: &Address) -> Option<Arc<dyn Function>>;

    /// Get the function which resides at the specified address or is referenced from the
    /// specified address.
    ///
    /// # Arguments
    /// * `address` - function address or address of pointer to a function.
    fn get_referenced_function(&self, address: &Address) -> Option<Arc<dyn Function>>;

    /// Get a function containing an address, or `None` otherwise.
    fn get_function_containing(&self, addr: &Address) -> Option<Arc<dyn Function>>;

    /// Returns an iterator over all non-external functions in address (entry point) order.
    ///
    /// # Arguments
    /// * `forward` - true means to iterate in ascending address order
    fn get_functions(&self, forward: bool) -> Box<dyn FunctionIterator>;

    /// Get an iterator over non-external functions starting at an address and ordered by entry
    /// address.
    fn get_functions_from(&self, start: &Address, forward: bool) -> Box<dyn FunctionIterator>;

    /// Get an iterator over functions with entry points in the specified address set. Functions
    /// are ordered based upon entry address.
    fn get_functions_in(&self, asv: &dyn AddressSetView, forward: bool) -> Box<dyn FunctionIterator>;

    /// Returns an iterator over all REAL functions in address (entry point) order (real functions
    /// have instructions, and aren't stubs).
    fn get_functions_no_stubs(&self, forward: bool) -> Box<dyn FunctionIterator>;

    /// Get an iterator over REAL functions starting at an address and ordered by entry address
    /// (real functions have instructions, and aren't stubs).
    fn get_functions_no_stubs_from(
        &self,
        start: &Address,
        forward: bool,
    ) -> Box<dyn FunctionIterator>;

    /// Get an iterator over REAL functions with entry points in the specified address set (real
    /// functions have instructions, and aren't stubs). Functions are ordered based upon entry
    /// address.
    fn get_functions_no_stubs_in(
        &self,
        asv: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn FunctionIterator>;

    /// Get an iterator over all external functions. Functions returned have no particular order.
    fn get_external_functions(&self) -> Box<dyn FunctionIterator>;

    /// Check if this address contains a function.
    fn is_in_function(&self, addr: &Address) -> bool;

    /// Return an iterator over functions that overlap the given address set.
    fn get_functions_overlapping(&self, set: &dyn AddressSetView) -> Box<dyn FunctionIterator>;

    /// Attempts to determine which if any of the local function's variables are referenced by
    /// the specified reference. In utilizing the firstUseOffset scoping model, negative offsets
    /// (relative to the function's entry) are shifted beyond the maximum positive offset within
    /// the function. While this does not account for the actual instruction flow, it is
    /// hopefully accurate enough for most situations.
    ///
    /// # Arguments
    /// * `instr_addr` - the instruction address
    /// * `storage_addr` - the storage address
    /// * `size` - varnode size in bytes (1 is assumed if value <= 0)
    /// * `is_read` - true if the reference is a read reference
    fn get_referenced_variable(
        &self,
        instr_addr: &Address,
        storage_addr: &Address,
        size: i32,
        is_read: bool,
    ) -> Option<Box<dyn Variable>>;

    /// Get a Function object by its key, or `None` if not found.
    fn get_function(&self, key: i64) -> Option<Arc<dyn Function>>;

    /// Returns the function tag manager.
    fn get_function_tag_manager(&self) -> Arc<dyn FunctionTagManager>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct MockFunctionManager;

    impl ManagerDB for MockFunctionManager {
        fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
            Ok(())
        }
        fn delete_address_range(&mut self, _start_addr: &Address, _end_addr: &Address) -> io::Result<()> {
            Ok(())
        }
        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl FunctionManager for MockFunctionManager {
        fn get_program(&self) -> Arc<dyn Program> {
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
            Arc::new(MockProgram)
        }

        fn get_calling_convention_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn create_function(
            &mut self,
            _name: Option<&str>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }

        fn create_function_in_namespace(
            &mut self,
            _name: Option<&str>,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }

        fn create_thunk_function(
            &mut self,
            _name: Option<&str>,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _thunked_function: Arc<dyn Function>,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, OverlappingFunctionException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_function_count(&self) -> usize {
            0
        }

        fn remove_function(&mut self, _entry_point: &Address) -> bool {
            false
        }

        fn get_function_at(&self, _entry_point: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_referenced_function(&self, _address: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_functions(&self, _forward: bool) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_functions_from(&self, _start: &Address, _forward: bool) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_functions_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_functions_no_stubs(&self, _forward: bool) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_functions_no_stubs_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_functions_no_stubs_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_external_functions(&self) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }

        fn get_functions_overlapping(&self, _set: &dyn AddressSetView) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_referenced_variable(
            &self,
            _instr_addr: &Address,
            _storage_addr: &Address,
            _size: i32,
            _is_read: bool,
        ) -> Option<Box<dyn Variable>> {
            None
        }

        fn get_function(&self, _key: i64) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_function_tag_manager(&self) -> Arc<dyn FunctionTagManager> {
            struct MockTagManager;
            impl FunctionTagManager for MockTagManager {
                fn get_function_tag_by_name(
                    &self,
                    _name: &str,
                ) -> Option<&dyn crate::program::model::listing::FunctionTag> {
                    None
                }
                fn get_function_tag_by_id(
                    &self,
                    _id: i64,
                ) -> Option<&dyn crate::program::model::listing::FunctionTag> {
                    None
                }
                fn get_all_function_tags(&self) -> Vec<&dyn crate::program::model::listing::FunctionTag> {
                    Vec::new()
                }
                fn is_tag_assigned(&self, _name: &str) -> bool {
                    false
                }
                fn create_function_tag(
                    &mut self,
                    _name: &str,
                    _comment: &str,
                ) -> &dyn crate::program::model::listing::FunctionTag {
                    unimplemented!("not needed for this smoke test")
                }
                fn get_use_count(&self, _tag: &dyn crate::program::model::listing::FunctionTag) -> usize {
                    0
                }
            }
            Arc::new(MockTagManager)
        }
    }

    #[test]
    fn mock_function_manager_is_object_safe() {
        let manager: Box<dyn FunctionManager> = Box::new(MockFunctionManager);
        assert_eq!(manager.get_function_count(), 0);
        assert!(!manager.is_in_function(&test_address(0x1000)));
        assert!(manager.get_calling_convention_names().is_empty());
    }

    fn test_address(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }
}

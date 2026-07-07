use std::sync::Arc;

use thiserror::Error;

use crate::program::database::function::OverlappingFunctionException;
use crate::program::model::address::{Address, AddressIterator, AddressSetView};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::function::Function;
use crate::program::model::lang::ProcessorContextView;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::listing::program_fragment::ProgramFragment;
use crate::program::model::listing::program_module::ProgramModule;
use crate::program::model::symbol::Namespace;
use crate::program::model::util::PropertyMap;
use crate::program::seam_stubs::{
    CodeUnitComments, CodeUnitIterator, CommentHistory, CommentType, DataIterator,
    FunctionIterator, InstructionIterator, InstructionPrototype, InstructionSet, MemBuffer,
};
use crate::program::util::CodeUnitInsertionException;
use crate::util::exception::{CancelledException, DuplicateNameException, InvalidInputException};
use crate::util::task::TaskMonitor;

/// The name of the default tree in the display.
///
/// See [`Listing::remove_tree`].
pub const DEFAULT_TREE_NAME: &str = "Program Tree";

/// Combines the two checked exceptions declared on the Java methods
/// `Listing.createFunction(...)`.
#[derive(Error, Debug, PartialEq)]
pub enum CreateFunctionError {
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    #[error(transparent)]
    Overlapping(#[from] OverlappingFunctionException),
}

/// This interface provides all the methods needed to create, delete, retrieve, and modify code
/// level constructs (CodeUnits, Macros, Fragments, and Modules).
///
/// Port of `ghidra.program.model.listing.Listing`.
pub trait Listing {
    /// Get the code unit that starts at the given address, or `None` if none begins there.
    fn get_code_unit_at(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Get the code unit that contains the given address, or `None` if none contains it.
    fn get_code_unit_containing(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Get the next code unit that starts at an address that is greater than the given address.
    /// The search will include instructions, defined data, and undefined data. Returns `None` if
    /// none found.
    fn get_code_unit_after(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Get the next code unit that starts at an address that is less than the given address. The
    /// search will include instructions, defined data, and undefined data. Returns `None` if none
    /// found.
    fn get_code_unit_before(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Get an iterator that contains all code units in the program which have the specified
    /// property type defined.
    ///
    /// # Arguments
    /// * `property` - the name of the property type.
    /// * `forward` - true means get iterator in forward direction
    fn get_code_unit_iterator(&self, property: &str, forward: bool) -> Box<dyn CodeUnitIterator>;

    /// Get an iterator that contains the code units which have the specified property type
    /// defined, starting at the given address.
    ///
    /// # Arguments
    /// * `property` - the name of the property type.
    /// * `addr` - the start address
    /// * `forward` - true means get iterator in forward direction
    fn get_code_unit_iterator_from(
        &self,
        property: &str,
        addr: &Address,
        forward: bool,
    ) -> Box<dyn CodeUnitIterator>;

    /// Get an iterator that contains the code units which have the specified property type
    /// defined. Only code units starting within `addr_set` will be returned by the iterator.
    fn get_code_unit_iterator_in(
        &self,
        property: &str,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn CodeUnitIterator>;

    /// Get a forward code unit iterator over code units that have the specified comment type.
    ///
    /// # Deprecated
    /// Use [`Listing::get_comment_code_unit_iterator`] instead.
    #[deprecated(since = "11.4", note = "use get_comment_code_unit_iterator instead")]
    fn get_comment_code_unit_iterator_by_ordinal(
        &self,
        comment_type: i32,
        addr_set: &dyn AddressSetView,
    ) -> Box<dyn CodeUnitIterator> {
        self.get_comment_code_unit_iterator(
            CommentType::from_ordinal(comment_type).expect("valid comment type ordinal"),
            addr_set,
        )
    }

    /// Get a forward code unit iterator over code units that have the specified comment type.
    fn get_comment_code_unit_iterator(
        &self,
        comment_type: CommentType,
        addr_set: &dyn AddressSetView,
    ) -> Box<dyn CodeUnitIterator>;

    /// Get a forward iterator over addresses that have the specified comment type.
    ///
    /// # Deprecated
    /// Use [`Listing::get_comment_address_iterator`] instead.
    #[deprecated(since = "11.4", note = "use get_comment_address_iterator instead")]
    fn get_comment_address_iterator_by_ordinal(
        &self,
        comment_type: i32,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn AddressIterator> {
        self.get_comment_address_iterator(
            CommentType::from_ordinal(comment_type).expect("valid comment type ordinal"),
            addr_set,
            forward,
        )
    }

    /// Get a forward iterator over addresses that have the specified comment type.
    ///
    /// # Arguments
    /// * `comment_type` - the type of comment to iterate over
    /// * `addr_set` - address set to iterate code unit comments over
    /// * `forward` - true to iterate from lowest address to highest, false highest to lowest
    fn get_comment_address_iterator(
        &self,
        comment_type: CommentType,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn AddressIterator>;

    /// Get a forward iterator over addresses that have any type of comment.
    ///
    /// # Arguments
    /// * `addr_set` - address set
    /// * `forward` - true to iterate from lowest address to highest, false highest to lowest
    fn get_any_comment_address_iterator(
        &self,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn AddressIterator>;

    /// Get the comment for the given type at the specified address.
    ///
    /// # Deprecated
    /// Use [`Listing::get_comment`] instead.
    #[deprecated(since = "11.4", note = "use get_comment instead")]
    fn get_comment_by_ordinal(&self, comment_type: i32, address: &Address) -> Option<String> {
        self.get_comment(
            CommentType::from_ordinal(comment_type).expect("valid comment type ordinal"),
            address,
        )
    }

    /// Get the comment for the given type at the specified address, or `None` if no comment of
    /// that type exists for this code unit.
    fn get_comment(&self, comment_type: CommentType, address: &Address) -> Option<String>;

    /// Get all the comments at the given address.
    fn get_all_comments(&self, address: &Address) -> Box<dyn CodeUnitComments>;

    /// Set the comment for the given comment type at the specified address.
    ///
    /// # Deprecated
    /// Use [`Listing::set_comment`] instead.
    #[deprecated(since = "11.4", note = "use set_comment instead")]
    fn set_comment_by_ordinal(
        &mut self,
        address: &Address,
        comment_type: i32,
        comment: Option<String>,
    ) {
        self.set_comment(
            address,
            CommentType::from_ordinal(comment_type).expect("valid comment type ordinal"),
            comment,
        )
    }

    /// Set the comment for the given comment type at the specified address. Passing `None`
    /// clears the comment.
    fn set_comment(&mut self, address: &Address, comment_type: CommentType, comment: Option<String>);

    /// Get a CodeUnit iterator that will iterate over the entire address space.
    ///
    /// # Arguments
    /// * `forward` - true means get iterator in forward direction
    fn get_code_units(&self, forward: bool) -> Box<dyn CodeUnitIterator>;

    /// Returns an iterator of the code units in this listing (in proper sequence), starting at
    /// the specified address.
    fn get_code_units_from(&self, addr: &Address, forward: bool) -> Box<dyn CodeUnitIterator>;

    /// Get an iterator over the address range(s). Only code units whose start addresses are
    /// contained in the given address set will be returned by the iterator.
    fn get_code_units_in(
        &self,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn CodeUnitIterator>;

    /// Get the Instruction that starts at the given address, or `None` if none starts there.
    fn get_instruction_at(&self, addr: &Address) -> Option<Arc<dyn Instruction>>;

    /// Get the Instruction that contains the given address, or `None` if none contains it.
    fn get_instruction_containing(&self, addr: &Address) -> Option<Arc<dyn Instruction>>;

    /// Get the closest Instruction that starts at an address that is greater than the given
    /// address.
    fn get_instruction_after(&self, addr: &Address) -> Option<Arc<dyn Instruction>>;

    /// Get the closest Instruction that starts at an address that is less than the given
    /// address.
    fn get_instruction_before(&self, addr: &Address) -> Option<Arc<dyn Instruction>>;

    /// Get an Instruction iterator that will iterate over the entire address space.
    fn get_instructions(&self, forward: bool) -> Box<dyn InstructionIterator>;

    /// Returns an iterator of the instructions in this listing (in proper sequence), starting at
    /// the specified address.
    fn get_instructions_from(&self, addr: &Address, forward: bool) -> Box<dyn InstructionIterator>;

    /// Get an Instruction iterator over the address range(s). Only instructions whose start
    /// addresses are contained in the given address set will be returned by the iterator.
    fn get_instructions_in(
        &self,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn InstructionIterator>;

    /// Get the Data (defined or undefined) that starts at the given address, or `None` if none
    /// starts there.
    fn get_data_at(&self, addr: &Address) -> Option<Arc<dyn Data>>;

    /// Gets the data object that is at or contains the given address, or `None` if the address is
    /// not in memory or is in an instruction.
    fn get_data_containing(&self, addr: &Address) -> Option<Arc<dyn Data>>;

    /// Get the closest Data object that starts at an address that is greater than the given
    /// address.
    fn get_data_after(&self, addr: &Address) -> Option<Arc<dyn Data>>;

    /// Get the closest Data object that starts at an address that is less than the given
    /// address.
    fn get_data_before(&self, addr: &Address) -> Option<Arc<dyn Data>>;

    /// Get a Data iterator that will iterate over the entire address space; returning both
    /// defined and undefined Data objects.
    fn get_data(&self, forward: bool) -> Box<dyn DataIterator>;

    /// Returns an iterator of the data in this listing (in proper sequence), starting at the
    /// specified address.
    fn get_data_from(&self, addr: &Address, forward: bool) -> Box<dyn DataIterator>;

    /// Get an iterator over the address range(s). Only data whose start addresses are contained
    /// in the given address set will be returned by the iterator.
    fn get_data_in(&self, addr_set: &dyn AddressSetView, forward: bool) -> Box<dyn DataIterator>;

    /// Get the Data (defined) object that starts at the given address, or `None` if no Data
    /// object is defined at that address.
    fn get_defined_data_at(&self, addr: &Address) -> Option<Arc<dyn Data>>;

    /// Get the Data object that starts at the given address, or `None` if no Data objects have
    /// been defined that contain that address.
    fn get_defined_data_containing(&self, addr: &Address) -> Option<Arc<dyn Data>>;

    /// Get the defined Data object that starts at an address that is greater than the given
    /// address.
    fn get_defined_data_after(&self, addr: &Address) -> Option<Arc<dyn Data>>;

    /// Get the closest defined Data object that starts at an address that is less than the given
    /// address.
    fn get_defined_data_before(&self, addr: &Address) -> Option<Arc<dyn Data>>;

    /// Get a Data iterator that will iterate over the entire address space; returning only
    /// defined Data objects.
    fn get_defined_data(&self, forward: bool) -> Box<dyn DataIterator>;

    /// Returns an iterator of the defined data in this listing (in proper sequence), starting at
    /// the specified address.
    fn get_defined_data_from(&self, addr: &Address, forward: bool) -> Box<dyn DataIterator>;

    /// Get an iterator over the address range(s). Only defined data whose start addresses are
    /// contained in the given address set will be returned by the iterator.
    fn get_defined_data_in(
        &self,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn DataIterator>;

    /// Get the Data (undefined) object that starts at the given address, or `None` if bytes do
    /// not exist at `addr` or something has already been defined there.
    fn get_undefined_data_at(&self, addr: &Address) -> Option<Arc<dyn Data>>;

    /// Get the undefined Data object that starts at an address that is greater than the given
    /// address. This operation can be slow for large programs so a TaskMonitor is required.
    fn get_undefined_data_after(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>>;

    /// Get the undefined Data object that falls within the set. This operation can be slow for
    /// large programs so a TaskMonitor is required.
    fn get_first_undefined_data(
        &self,
        set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>>;

    /// Get the closest undefined Data object that starts at an address that is less than the
    /// given address. This operation can be slow for large programs so a TaskMonitor is
    /// required.
    fn get_undefined_data_before(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>>;

    /// Get the address set which corresponds to all undefined code units within the specified
    /// set of addresses.
    ///
    /// # Arguments
    /// * `set` - set of addresses to search
    /// * `initialized_memory_only` - if true set will be constrained to initialized memory
    ///   areas, if false set will be constrained to all defined memory blocks.
    /// * `monitor` - task monitor
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the monitor is cancelled.
    fn get_undefined_ranges(
        &self,
        set: &dyn AddressSetView,
        initialized_memory_only: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn AddressSetView>, CancelledException>;

    /// Returns the next instruction or defined data after the given address.
    fn get_defined_code_unit_after(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Returns the closest instruction or defined data that starts before the given address.
    fn get_defined_code_unit_before(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Returns all user defined property names.
    fn get_user_defined_properties(&self) -> Vec<String>;

    /// Removes the entire property from the program.
    fn remove_user_defined_property(&mut self, property_name: &str);

    /// Returns the PropertyMap associated with the given name, or `None` if there is none.
    fn get_property_map(&self, property_name: &str) -> Option<Box<dyn PropertyMap>>;

    /// Creates a new Instruction object at the given address. The specified context is only used
    /// to create the associated prototype. It is critical that the context be written
    /// immediately after creation of the instruction and must be done with a single set operation
    /// on the program context. Once a set context is done on the instruction address, any
    /// subsequent context changes will result in a `ContextChangeException`.
    ///
    /// # Arguments
    /// * `addr` - the address at which to create an instruction
    /// * `prototype` - the InstructionPrototype that describes the type of instruction to create.
    /// * `mem_buf` - buffer that provides the bytes that make up the instruction.
    /// * `context` - the processor context at this location.
    /// * `length` - instruction byte-length (must be in the range `0..=prototype.getLength()`).
    ///   If smaller than the prototype length it must have a value no greater than 7, otherwise
    ///   an error will be thrown. A value of 0 or greater-than-or-equal the prototype length will
    ///   be ignored and not impose an override length. The length value must be a multiple of the
    ///   language specified instruction alignment.
    ///
    /// # Errors
    /// Returns [`CodeUnitInsertionException`] if the new Instruction would overlap an existing
    /// [`CodeUnit`] or the specified `length` is unsupported.
    fn create_instruction(
        &mut self,
        addr: Address,
        prototype: Arc<dyn InstructionPrototype>,
        mem_buf: &dyn MemBuffer,
        context: &dyn ProcessorContextView,
        length: i32,
    ) -> Result<Arc<dyn Instruction>, CodeUnitInsertionException>;

    /// Creates a complete set of instructions. A preliminary pass will be made checking for code
    /// unit conflicts which will be marked within the instruction set causing dependent blocks to
    /// get pruned.
    ///
    /// # Arguments
    /// * `instruction_set` - the set of instructions to be added. All code unit conflicts will be
    ///   marked within the instruction set and associated blocks.
    /// * `overwrite` - if true, overwrites existing code units.
    ///
    /// # Errors
    /// Returns [`CodeUnitInsertionException`] if the instruction set is incompatible with the
    /// program memory.
    fn add_instructions(
        &mut self,
        instruction_set: &dyn InstructionSet,
        overwrite: bool,
    ) -> Result<Box<dyn AddressSetView>, CodeUnitInsertionException>;

    /// Creates a new defined Data object of a given length at the given address. This ignores the
    /// bytes that are present.
    ///
    /// # Errors
    /// Returns [`CodeUnitInsertionException`] if the new Data would overlap an existing
    /// Instruction or defined data.
    fn create_data_sized(
        &mut self,
        addr: Address,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Arc<dyn Data>, CodeUnitInsertionException>;

    /// Creates a new defined Data object at the given address. This ignores the bytes that are
    /// present.
    ///
    /// # Errors
    /// Returns [`CodeUnitInsertionException`] if the new Data would overlap an existing
    /// Instruction or defined data.
    fn create_data(
        &mut self,
        addr: Address,
        data_type: Box<dyn DataType>,
    ) -> Result<Arc<dyn Data>, CodeUnitInsertionException>;

    /// Clears any code units in the given range returning everything to "db"s, and removing any
    /// references in the affected area. Note that the module and fragment structure is
    /// unaffected. If part of a code unit is contained in the given address range then the whole
    /// code unit will be cleared.
    fn clear_code_units(&mut self, start_addr: &Address, end_addr: &Address, clear_context: bool);

    /// Clears any code units in the given range returning everything to "db"s, and removing any
    /// references in the affected area, with progress/cancellation support.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the operation was cancelled.
    fn clear_code_units_with_monitor(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
        clear_context: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Checks if the given range consists entirely of undefined data.
    fn is_undefined(&self, start: &Address, end: &Address) -> bool;

    /// Clears the comments in the given range.
    fn clear_comments(&mut self, start_addr: &Address, end_addr: &Address);

    /// Clears the properties in the given range.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the operation was cancelled.
    fn clear_properties(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Removes all CodeUnits, comments, properties, and references from the listing.
    ///
    /// # Arguments
    /// * `clear_context` - if true, also clear any instruction context that has been laid down
    ///   from previous disassembly.
    /// * `monitor` - used for tracking progress and cancelling the clear operation.
    fn clear_all(&mut self, clear_context: bool, monitor: &dyn TaskMonitor);

    /// Returns the fragment containing the given address, or `None` if the address is not in the
    /// program.
    fn get_fragment(&self, tree_name: &str, addr: &Address) -> Option<Arc<dyn ProgramFragment>>;

    /// Returns the module with the given name, or `None` if there is no module with that name.
    fn get_module(&self, tree_name: &str, name: &str) -> Option<Arc<dyn ProgramModule>>;

    /// Returns the fragment with the given name, or `None` if there is no fragment with that
    /// name.
    fn get_fragment_by_name(
        &self,
        tree_name: &str,
        name: &str,
    ) -> Option<Arc<dyn ProgramFragment>>;

    /// Create a new tree that will be identified by the given name. By default, the new root
    /// module is populated with fragments based on memory blocks. Note that the root module's
    /// name is not the same as its tree name. The root module name defaults to the name of the
    /// program.
    ///
    /// # Errors
    /// Returns [`DuplicateNameException`] if a tree with the given name already exists.
    fn create_root_module(
        &mut self,
        tree_name: &str,
    ) -> Result<Arc<dyn ProgramModule>, DuplicateNameException>;

    /// Gets the root module for a tree in this listing, or `None` if there is no tree rooted at a
    /// module with the given name.
    fn get_root_module(&self, tree_name: &str) -> Option<Arc<dyn ProgramModule>>;

    /// Returns the root module of the program tree with the given tree ID.
    fn get_root_module_by_id(&self, tree_id: i64) -> Option<Arc<dyn ProgramModule>>;

    /// Returns the root module for the default program tree. This would be the program tree that
    /// has existed the longest.
    fn get_default_root_module(&self) -> Arc<dyn ProgramModule>;

    /// Get the names of all the trees defined in this listing.
    fn get_tree_names(&self) -> Vec<String>;

    /// Remove the tree rooted at the given name. Returns false if this is the last tree for the
    /// program; the last tree cannot be deleted.
    fn remove_tree(&mut self, tree_name: &str) -> bool;

    /// Rename the tree. This method does not change the root module's name, only the identifier
    /// for the tree.
    ///
    /// # Errors
    /// Returns [`DuplicateNameException`] if `new_name` already exists for a root module.
    fn rename_tree(&mut self, old_name: &str, new_name: &str) -> Result<(), DuplicateNameException>;

    /// Gets the total number of CodeUnits (Instructions and defined Data).
    fn get_num_code_units(&self) -> i64;

    /// Gets the total number of defined Data objects in the listing.
    fn get_num_defined_data(&self) -> i64;

    /// Gets the total number of Instructions in the listing.
    fn get_num_instructions(&self) -> i64;

    /// Get the data type manager for the program.
    fn get_data_type_manager(&self) -> Box<dyn DataTypeManager>;

    /// Create a function with an entry point and a body of addresses, in the global namespace.
    ///
    /// # Errors
    /// Returns [`CreateFunctionError::InvalidInput`] if the name contains invalid characters, or
    /// [`CreateFunctionError::Overlapping`] if the given body overlaps with an existing function.
    fn create_function(
        &mut self,
        name: &str,
        entry_point: Address,
        body: &dyn AddressSetView,
        source: crate::program::model::symbol::SourceType,
    ) -> Result<Arc<dyn Function>, CreateFunctionError>;

    /// Create a function in the specified namespace with an entry point and a body of addresses.
    ///
    /// # Errors
    /// Returns [`CreateFunctionError::InvalidInput`] if the name contains invalid characters, or
    /// [`CreateFunctionError::Overlapping`] if the given body overlaps with an existing function.
    fn create_function_in_namespace(
        &mut self,
        name: &str,
        name_space: Arc<dyn Namespace>,
        entry_point: Address,
        body: &dyn AddressSetView,
        source: crate::program::model::symbol::SourceType,
    ) -> Result<Arc<dyn Function>, CreateFunctionError>;

    /// Remove a function at a given entry point.
    fn remove_function(&mut self, entry_point: &Address);

    /// Get a function with a given entry point, or `None` if there is none.
    fn get_function_at(&self, entry_point: &Address) -> Option<Arc<dyn Function>>;

    /// Returns all global functions with the given name.
    fn get_global_functions(&self, name: &str) -> Vec<Arc<dyn Function>>;

    /// Returns all functions with the given name in the given namespace.
    ///
    /// # Arguments
    /// * `namespace` - the namespace to search for functions of the given name. `None` searches
    ///   the global namespace.
    /// * `name` - the name of the functions to retrieve.
    fn get_functions_by_name(&self, namespace: Option<&str>, name: &str) -> Vec<Arc<dyn Function>>;

    /// Get a function containing an address, or `None` otherwise.
    fn get_function_containing(&self, addr: &Address) -> Option<Arc<dyn Function>>;

    /// Get an iterator over all external functions.
    fn get_external_functions(&self) -> Box<dyn FunctionIterator>;

    /// Get an iterator over all functions.
    ///
    /// # Arguments
    /// * `forward` - if true functions are returned in address order, otherwise backwards address
    ///   order
    fn get_functions(&self, forward: bool) -> Box<dyn FunctionIterator>;

    /// Get an iterator over all functions starting at the given address.
    fn get_functions_from(&self, start: &Address, forward: bool) -> Box<dyn FunctionIterator>;

    /// Get an iterator over all functions with entry points in the given address set.
    fn get_functions_in(
        &self,
        asv: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn FunctionIterator>;

    /// Check if an address is contained in a function.
    fn is_in_function(&self, addr: &Address) -> bool;

    /// Get the comment history for comments at the given address.
    ///
    /// # Deprecated
    /// Use [`Listing::get_comment_history`] instead.
    #[deprecated(since = "11.4", note = "use get_comment_history instead")]
    fn get_comment_history_by_ordinal(
        &self,
        addr: &Address,
        comment_type: i32,
    ) -> Vec<Box<dyn CommentHistory>> {
        self.get_comment_history(
            addr,
            CommentType::from_ordinal(comment_type).expect("valid comment type ordinal"),
        )
    }

    /// Get the comment history for comments at the given address.
    fn get_comment_history(
        &self,
        addr: &Address,
        comment_type: CommentType,
    ) -> Vec<Box<dyn CommentHistory>>;

    /// Returns the number of addresses where at least one comment type has been applied.
    fn get_comment_address_count(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal mock proving `Listing` is object-safe and usable as a trait object. Only a
    /// handful of representative methods are exercised; the rest simply need to type-check.
    struct MockListing;

    impl Listing for MockListing {
        fn get_code_unit_at(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_containing(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_iterator(
            &self,
            _property: &str,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_code_unit_iterator(
            &self,
            _comment_type: CommentType,
            _addr_set: &dyn AddressSetView,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_address_iterator(
            &self,
            _comment_type: CommentType,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_any_comment_address_iterator(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment(&self, _comment_type: CommentType, _address: &Address) -> Option<String> {
            None
        }
        fn get_all_comments(&self, _address: &Address) -> Box<dyn CodeUnitComments> {
            struct MockComments;
            impl CodeUnitComments for MockComments {}
            Box::new(MockComments)
        }
        fn set_comment(
            &mut self,
            _address: &Address,
            _comment_type: CommentType,
            _comment: Option<String>,
        ) {
        }
        fn get_code_units(&self, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_units_from(&self, _addr: &Address, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_units_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instruction_at(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_containing(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_after(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_before(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instructions(&self, _forward: bool) -> Box<dyn InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instructions_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instructions_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_containing(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_after(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_before(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data(&self, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_from(&self, _addr: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_containing(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_after(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_before(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data(&self, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_from(&self, _addr: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_in(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_undefined_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_after(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_first_undefined_data(
            &self,
            _set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_before(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_ranges(
            &self,
            _set: &dyn AddressSetView,
            _initialized_memory_only: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn AddressSetView>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_defined_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_user_defined_properties(&self) -> Vec<String> {
            Vec::new()
        }
        fn remove_user_defined_property(&mut self, _property_name: &str) {}
        fn get_property_map(&self, _property_name: &str) -> Option<Box<dyn PropertyMap>> {
            None
        }
        fn create_instruction(
            &mut self,
            _addr: Address,
            _prototype: Arc<dyn InstructionPrototype>,
            _mem_buf: &dyn MemBuffer,
            _context: &dyn ProcessorContextView,
            _length: i32,
        ) -> Result<Arc<dyn Instruction>, CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn add_instructions(
            &mut self,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Result<Box<dyn AddressSetView>, CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_data_sized(
            &mut self,
            _addr: Address,
            _data_type: Box<dyn DataType>,
            _length: i32,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_data(
            &mut self,
            _addr: Address,
            _data_type: Box<dyn DataType>,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn clear_code_units(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _clear_context: bool,
        ) {
        }
        fn clear_code_units_with_monitor(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _clear_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn is_undefined(&self, _start: &Address, _end: &Address) -> bool {
            true
        }
        fn clear_comments(&mut self, _start_addr: &Address, _end_addr: &Address) {}
        fn clear_properties(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn clear_all(&mut self, _clear_context: bool, _monitor: &dyn TaskMonitor) {}
        fn get_fragment(
            &self,
            _tree_name: &str,
            _addr: &Address,
        ) -> Option<Arc<dyn ProgramFragment>> {
            None
        }
        fn get_module(&self, _tree_name: &str, _name: &str) -> Option<Arc<dyn ProgramModule>> {
            None
        }
        fn get_fragment_by_name(
            &self,
            _tree_name: &str,
            _name: &str,
        ) -> Option<Arc<dyn ProgramFragment>> {
            None
        }
        fn create_root_module(
            &mut self,
            _tree_name: &str,
        ) -> Result<Arc<dyn ProgramModule>, DuplicateNameException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_root_module(&self, _tree_name: &str) -> Option<Arc<dyn ProgramModule>> {
            None
        }
        fn get_root_module_by_id(&self, _tree_id: i64) -> Option<Arc<dyn ProgramModule>> {
            None
        }
        fn get_default_root_module(&self) -> Arc<dyn ProgramModule> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_tree_names(&self) -> Vec<String> {
            vec![DEFAULT_TREE_NAME.to_string()]
        }
        fn remove_tree(&mut self, _tree_name: &str) -> bool {
            false
        }
        fn rename_tree(
            &mut self,
            _old_name: &str,
            _new_name: &str,
        ) -> Result<(), DuplicateNameException> {
            Ok(())
        }
        fn get_num_code_units(&self) -> i64 {
            0
        }
        fn get_num_defined_data(&self) -> i64 {
            0
        }
        fn get_num_instructions(&self) -> i64 {
            0
        }
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            struct MockDataTypeManager;
            impl DataTypeManager for MockDataTypeManager {}
            Box::new(MockDataTypeManager)
        }
        fn create_function(
            &mut self,
            _name: &str,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_function_in_namespace(
            &mut self,
            _name: &str,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn remove_function(&mut self, _entry_point: &Address) {}
        fn get_function_at(&self, _entry_point: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_global_functions(&self, _name: &str) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn get_functions_by_name(
            &self,
            _namespace: Option<&str>,
            _name: &str,
        ) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_external_functions(&self) -> Box<dyn FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions(&self, _forward: bool) -> Box<dyn FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_from(&self, _start: &Address, _forward: bool) -> Box<dyn FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }
        fn get_comment_history(
            &self,
            _addr: &Address,
            _comment_type: CommentType,
        ) -> Vec<Box<dyn CommentHistory>> {
            Vec::new()
        }
        fn get_comment_address_count(&self) -> i64 {
            0
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut listing: Box<dyn Listing> = Box::new(MockListing);

        assert_eq!(listing.get_tree_names(), vec![DEFAULT_TREE_NAME.to_string()]);
        assert!(listing.is_undefined(&mock_address(0x100), &mock_address(0x200)));
        assert!(!listing.remove_tree("Program Tree"));
        assert_eq!(listing.get_data_type_manager().get_universal_id().value(), 0);

        listing.set_comment(&mock_address(0x100), CommentType::Eol, Some("hi".to_string()));
        assert_eq!(listing.get_comment(CommentType::Eol, &mock_address(0x100)), None);

        #[allow(deprecated)]
        {
            assert_eq!(
                listing.get_comment_by_ordinal(0, &mock_address(0x100)),
                None
            );
        }
    }

    fn mock_address(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}

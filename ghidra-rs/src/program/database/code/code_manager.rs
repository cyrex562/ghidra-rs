//! Port of `ghidra.program.database.code.CodeManager` as a trait (cycle cut-point).
//!
//! The Java class is a concrete `ErrorHandler`/`ManagerDB` implementation that manages the
//! database tables backing instructions and data. It is constructed and held by `ProgramDB`, is
//! handed to every `InstructionDB`/`DataDB`/`CodeUnitDB` it creates (`new InstructionDB(this,
//! ...)`) for their package-private callbacks, and reaches back into `ProgramDB` (via a `program`
//! field set post-construction through `setProgram`) for memory, change notifications, and error
//! reporting. `Listing` (already ported) is largely a thin facade over this class's public API.
//! Those mutually-referential, construction-time wirings are what make `CodeManager` a
//! dependency-cycle cut-point; this port keeps only its genuinely `public` instance API (skipping
//! the constructor, `setProgram`/`programReady`/`dbError`/`dispose` -- covered abstractly by the
//! already-ported [`ManagerDB`] supertrait, exactly as [`FunctionManager`]'s port does -- and the
//! package-private accessors used only by sibling `code` classes, e.g. `getCommentAdapter()`,
//! `getInstructionAdapter()`, `getLock()`) as an object-safe trait, so a concrete DB-backed
//! implementor can be added later without reintroducing the cycle.
//!
//! Method names mirror the corresponding Java methods (`snake_case`d), splitting overloads into
//! distinctly-named methods since Rust does not support overloading on parameter type -- following
//! the same convention [`Listing`](crate::program::model::listing::Listing) already established
//! for the overloads it shares with this class. Comment/code-unit related types
//! (`CommentType`, `MemBuffer`, `CodeUnitIterator`, `InstructionIterator`, `DataIterator`,
//! `CodeUnitComments`, `CommentHistory`, `InstructionSet`) are taken from
//! [`seam_stubs`](crate::program::seam_stubs) rather than the richer same-named types under
//! `program::model::listing`, because the already-real [`CodeUnit`]/[`Data`] traits this port
//! depends on were themselves wired to the `seam_stubs` versions (see e.g.
//! `CodeUnit::get_comment`), and `Listing` made the same choice for the same reason.
//!
//! [`FunctionManager`]: crate::program::model::listing::FunctionManager

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;

use thiserror::Error;

use crate::framework::db::DBRecord;
use crate::program::database::manager_db::ManagerDB;
use crate::program::model::address::{Address, BoxedAddressIterator, AddressSetView};
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::ProcessorContextView;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::symbol::{Reference, ReferenceManager};
use crate::program::model::util::PropertyMap;
use crate::program::seam_stubs::{CodeUnitComments, CodeUnitIterator, CommentHistory, DataIterator, InstructionIterator, InstructionSet};
use crate::program::model::mem::MemBuffer;
use crate::program::model::listing::CommentType;
use crate::program::util::CodeUnitInsertionException;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Error produced by [`CodeManager::re_disassemble_all_instructions`], mirroring the Java
/// method's `throws IOException, CancelledException`.
#[derive(Debug, Error)]
pub enum ReDisassembleAllInstructionsError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Manages database tables for data and instructions.
///
/// Port of `ghidra.program.database.code.CodeManager`. See the module docs for what was
/// intentionally left out (construction/persistence details and package-private accessors).
pub trait CodeManager: ManagerDB {
    /// Enables program-context locking, if the program has a base context register. Stands in
    /// for `CodeManager.activateContextLocking()`.
    fn activate_context_locking(&mut self);

    /// Creates a complete set of instructions. A preliminary pass will be made checking for code
    /// unit conflicts which will be marked within `instruction_set` causing dependent blocks to
    /// get pruned. Stands in for `CodeManager.addInstructions(InstructionSet, boolean)`.
    ///
    /// # Returns
    /// The set of addresses over which instructions were actually added, which may differ from
    /// `instruction_set`'s address set if conflict errors occurred.
    fn add_instructions(
        &mut self,
        instruction_set: &dyn InstructionSet,
        overwrite: bool,
    ) -> Box<dyn AddressSetView>;

    /// Creates an instruction at the specified address. Stands in for
    /// `CodeManager.createCodeUnit(Address, InstructionPrototype, MemBuffer,
    /// ProcessorContextView, int)`.
    ///
    /// # Errors
    /// Returns [`CodeUnitInsertionException`] if the new instruction would overlap an existing
    /// code unit or `length` is unsupported.
    fn create_instruction(
        &mut self,
        address: Address,
        prototype: Arc<dyn InstructionPrototype>,
        mem_buf: &dyn MemBuffer,
        context: &dyn ProcessorContextView,
        length: i32,
    ) -> Result<Arc<dyn Instruction>, CodeUnitInsertionException>;

    /// Creates a data unit of the given length at the specified address. Stands in for
    /// `CodeManager.createCodeUnit(Address, DataType, int)`.
    ///
    /// # Errors
    /// Returns [`CodeUnitInsertionException`] if the new data would overlap an existing code
    /// unit.
    fn create_data(
        &mut self,
        address: Address,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Arc<dyn Data>, CodeUnitInsertionException>;

    /// Returns the code unit whose min address equals `address`, or `None` if none exists. Stands
    /// in for `CodeManager.getCodeUnitAt(Address)`.
    fn get_code_unit_at(&self, address: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Returns the next code unit whose min address is greater than `address`, or `None`. Stands
    /// in for `CodeManager.getCodeUnitAfter(Address)`.
    fn get_code_unit_after(&self, address: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Returns the next code unit whose min address is closest to and less than `address`, or
    /// `None`. Stands in for `CodeManager.getCodeUnitBefore(Address)`.
    fn get_code_unit_before(&self, address: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Returns the code unit containing `address` (`min <= address <= max`), or `None`. Stands in
    /// for `CodeManager.getCodeUnitContaining(Address)`.
    fn get_code_unit_containing(&self, address: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Returns an iterator over all user-defined property names. Stands in for
    /// `CodeManager.getUserDefinedProperties()`.
    fn get_user_defined_properties(&self) -> Vec<String>;

    /// Removes the user-defined property with the given name. Stands in for
    /// `CodeManager.removeUserDefinedProperty(String)`.
    fn remove_user_defined_property(&mut self, property_name: &str);

    /// Returns the property map associated with `property_name`, or `None`. Stands in for
    /// `CodeManager.getPropertyMap(String)`.
    fn get_property_map(&self, property_name: &str) -> Option<Box<dyn PropertyMap>>;

    /// Gets an iterator over code units with the given property defined, starting at `address`.
    /// Stands in for `CodeManager.getCodeUnitIterator(String, Address, boolean)`.
    fn get_code_unit_iterator_from(
        &self,
        property: &str,
        address: &Address,
        forward: bool,
    ) -> Box<dyn CodeUnitIterator>;

    /// Gets an iterator over code units with the given property defined, restricted to
    /// `addr_set`. Stands in for `CodeManager.getCodeUnitIterator(String, AddressSetView,
    /// boolean)`.
    fn get_code_unit_iterator_in(
        &self,
        property: &str,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn CodeUnitIterator>;

    /// Gets a forward iterator over code units that have comments of the given type. Stands in
    /// for `CodeManager.getCommentCodeUnitIterator(CommentType, AddressSetView)`.
    fn get_comment_code_unit_iterator(
        &self,
        comment_type: CommentType,
        set: &dyn AddressSetView,
    ) -> Box<dyn CodeUnitIterator>;

    /// Returns the number of addresses that have associated comments. Stands in for
    /// `CodeManager.getCommentAddressCount()`.
    fn get_comment_address_count(&self) -> i64;

    /// Gets a forward or backward iterator over addresses that have comments of the given type.
    /// Stands in for `CodeManager.getCommentAddressIterator(CommentType, AddressSetView,
    /// boolean)`.
    fn get_comment_address_iterator(
        &self,
        comment_type: CommentType,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> BoxedAddressIterator;

    /// Gets an iterator over addresses that have comments of any type. Stands in for
    /// `CodeManager.getCommentAddressIterator(AddressSetView, boolean)`.
    fn get_any_comment_address_iterator(
        &self,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> BoxedAddressIterator;

    /// Returns the instruction whose min address equals `address`, or `None`. Stands in for
    /// `CodeManager.getInstructionAt(Address)`.
    fn get_instruction_at(&self, address: &Address) -> Option<Arc<dyn Instruction>>;

    /// Returns the defined data whose min address equals `address`, or `None`. Stands in for
    /// `CodeManager.getDefinedDataAt(Address)`.
    fn get_defined_data_at(&self, address: &Address) -> Option<Arc<dyn Data>>;

    /// Returns the next instruction whose min address is closest to and less than `address`, or
    /// `None`. Stands in for `CodeManager.getInstructionBefore(Address)`.
    fn get_instruction_before(&self, address: &Address) -> Option<Arc<dyn Instruction>>;

    /// Returns the next instruction whose min address is greater than `address`, or `None`.
    /// Stands in for `CodeManager.getInstructionAfter(Address)`.
    fn get_instruction_after(&self, address: &Address) -> Option<Arc<dyn Instruction>>;

    /// Returns the instruction containing `address`, or `None`. `use_prototype_length` controls
    /// whether the prototype length or the (possibly overridden) code unit length is used to
    /// determine containment. Stands in for `CodeManager.getInstructionContaining(Address,
    /// boolean)`.
    fn get_instruction_containing(
        &self,
        address: &Address,
        use_prototype_length: bool,
    ) -> Option<Arc<dyn Instruction>>;

    /// Returns the data whose min address equals `address`, or `None`. Stands in for
    /// `CodeManager.getDataAt(Address)`.
    fn get_data_at(&self, address: &Address) -> Option<Arc<dyn Data>>;

    /// Returns the next data whose min address is closest to and less than `address`, or `None`.
    /// Stands in for `CodeManager.getDataBefore(Address)`.
    fn get_data_before(&self, address: &Address) -> Option<Arc<dyn Data>>;

    /// Returns the next data whose min address is greater than `address`, or `None`. Stands in
    /// for `CodeManager.getDataAfter(Address)`.
    fn get_data_after(&self, address: &Address) -> Option<Arc<dyn Data>>;

    /// Returns the data containing `address`, or `None`. Stands in for
    /// `CodeManager.getDataContaining(Address)`.
    fn get_data_containing(&self, address: &Address) -> Option<Arc<dyn Data>>;

    /// Returns the next defined data whose min address is greater than `address`, or `None`.
    /// Stands in for `CodeManager.getDefinedDataAfter(Address)`.
    fn get_defined_data_after(&self, address: &Address) -> Option<Arc<dyn Data>>;

    /// Returns the next defined data whose min address is closest to and less than `address`, or
    /// `None`. Stands in for `CodeManager.getDefinedDataBefore(Address)`.
    fn get_defined_data_before(&self, address: &Address) -> Option<Arc<dyn Data>>;

    /// Returns the defined data containing `address`, or `None`. Stands in for
    /// `CodeManager.getDefinedDataContaining(Address)`.
    fn get_defined_data_containing(&self, address: &Address) -> Option<Arc<dyn Data>>;

    /// Returns the address set corresponding to all undefined code units within `set`. Stands in
    /// for `CodeManager.getUndefinedRanges(AddressSetView, boolean, TaskMonitor)`.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if `monitor` is cancelled.
    fn get_undefined_ranges(
        &self,
        set: &dyn AddressSetView,
        initialized_memory_only: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn AddressSetView>, CancelledException>;

    /// Returns the undefined data whose min address equals `address`, or `None`. Stands in for
    /// `CodeManager.getUndefinedAt(Address)`.
    fn get_undefined_data_at(&self, address: &Address) -> Option<Arc<dyn Data>>;

    /// Returns the next undefined data whose min address is greater than `address`. This
    /// operation can be slow for large programs, hence the required `monitor`. Stands in for
    /// `CodeManager.getFirstUndefinedDataAfter(Address, TaskMonitor)`.
    fn get_undefined_data_after(
        &self,
        address: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>>;

    /// Returns the next undefined data whose min address falls within `set`, searching forward.
    /// Stands in for `CodeManager.getFirstUndefinedData(AddressSetView, TaskMonitor)`.
    fn get_first_undefined_data(
        &self,
        set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>>;

    /// Returns the next undefined data whose min address is closest to and less than `address`.
    /// Stands in for `CodeManager.getFirstUndefinedDataBefore(Address, TaskMonitor)`.
    fn get_undefined_data_before(
        &self,
        address: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>>;

    /// Updates the data references on `data`: existing references are removed and new ones
    /// added based on its current value. Stands in for `CodeManager.updateDataReferences(Data)`.
    fn update_data_references(&mut self, data: &dyn Data);

    /// Clears all comments in the given range (inclusive). Stands in for
    /// `CodeManager.clearComments(Address, Address)`.
    fn clear_comments(&mut self, start: &Address, end: &Address);

    /// Clears the user-defined properties in the given range (inclusive). Stands in for
    /// `CodeManager.clearProperties(Address, Address, TaskMonitor)`.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if `monitor` is cancelled.
    fn clear_properties(
        &mut self,
        start: &Address,
        end: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Removes code units, symbols, equates, and references in the given range (inclusive).
    /// Comments and comment history are retained. Stands in for
    /// `CodeManager.clearCodeUnits(Address, Address, boolean, TaskMonitor)`.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if `monitor` is cancelled.
    fn clear_code_units(
        &mut self,
        start: &Address,
        end: &Address,
        clear_context: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Clears all code units in the program. Stands in for `CodeManager.clearAll(boolean,
    /// TaskMonitor)`.
    fn clear_all(&mut self, clear_context: bool, monitor: &dyn TaskMonitor);

    /// Returns the number of instructions in the program. Stands in for
    /// `CodeManager.getNumInstructions()`.
    fn get_num_instructions(&self) -> i32;

    /// Returns the number of defined data units in the program. Stands in for
    /// `CodeManager.getNumDefinedData()`.
    fn get_num_defined_data(&self) -> i32;

    /// Returns an iterator over all code units starting at `start`. Stands in for
    /// `CodeManager.getCodeUnits(Address, boolean)`.
    fn get_code_units_from(&self, start: &Address, forward: bool) -> Box<dyn CodeUnitIterator>;

    /// Returns an iterator over all code units within `set`. Stands in for
    /// `CodeManager.getCodeUnits(AddressSetView, boolean)`.
    fn get_code_units_in(
        &self,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn CodeUnitIterator>;

    /// Returns an iterator over all instructions starting at `address`. Stands in for
    /// `CodeManager.getInstructions(Address, boolean)`.
    fn get_instructions_from(
        &self,
        address: &Address,
        forward: bool,
    ) -> Box<dyn InstructionIterator>;

    /// Returns an iterator over all defined data starting at `address`. Stands in for
    /// `CodeManager.getDefinedData(Address, boolean)`.
    fn get_defined_data_from(&self, address: &Address, forward: bool) -> Box<dyn DataIterator>;

    /// Returns an iterator over all instructions within `set`. Stands in for
    /// `CodeManager.getInstructions(AddressSetView, boolean)`.
    fn get_instructions_in(
        &self,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn InstructionIterator>;

    /// Returns an iterator over all data (defined and undefined) starting at `start`. Stands in
    /// for `CodeManager.getData(Address, boolean)`.
    fn get_data_from(&self, start: &Address, forward: bool) -> Box<dyn DataIterator>;

    /// Returns an iterator over all data (defined and undefined) within `set`. Stands in for
    /// `CodeManager.getData(AddressSetView, boolean)`.
    fn get_data_in(&self, set: &dyn AddressSetView, forward: bool) -> Box<dyn DataIterator>;

    /// Returns an iterator over all defined data within `set`. Stands in for
    /// `CodeManager.getDefinedData(AddressSetView, boolean)`.
    fn get_defined_data_in(&self, set: &dyn AddressSetView, forward: bool) -> Box<dyn DataIterator>;

    /// Checks whether any instruction intersects the given range (inclusive), for the purpose of
    /// guarding a context-register write. Stands in for `CodeManager.checkContextWrite(Address,
    /// Address)`.
    ///
    /// # Errors
    /// Returns [`ContextChangeException`] if the write would conflict with an existing
    /// instruction.
    fn check_context_write(
        &self,
        start: &Address,
        end: &Address,
    ) -> Result<(), ContextChangeException>;

    /// Checks whether all the addresses from `start` to `end` (inclusive) have undefined data.
    /// Stands in for `CodeManager.isUndefined(Address, Address)`.
    fn is_undefined(&self, start: &Address, end: &Address) -> bool;

    /// Removes any data whose data type is in `data_type_ids`. Stands in for
    /// `CodeManager.clearData(Set, TaskMonitor)`.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if `monitor` is cancelled.
    fn clear_data(
        &mut self,
        data_type_ids: &HashSet<i64>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Returns the reference manager used by this code manager. Stands in for
    /// `CodeManager.getReferenceMgr()`.
    fn get_reference_mgr(&mut self) -> &mut dyn ReferenceManager;

    /// Invalidates the code unit cache (but not the length or prototype caches). Stands in for
    /// `CodeManager.invalidateCodeUnitCache()`.
    fn invalidate_code_unit_cache(&mut self);

    /// Notification that memory has changed, so the cache for the affected code units should be
    /// cleared. Stands in for `CodeManager.memoryChanged(Address, Address)`.
    fn memory_changed(&mut self, start: &Address, end: &Address);

    /// Callback from the reference manager when a new fall-through reference is set (or removed,
    /// if `new_fall_through_ref` is `None`). Stands in for `CodeManager.fallThroughChanged(
    /// Address, Reference)`.
    ///
    /// # Panics
    /// Implementations should reject a `new_fall_through_ref` whose reference type is not
    /// `RefType::FallThrough`, mirroring Java's `IllegalArgumentException`.
    fn fall_through_changed(
        &mut self,
        from_addr: &Address,
        new_fall_through_ref: Option<Arc<dyn Reference>>,
    );

    /// Gets the comment of the given type at `address`, or `None` if no such comment exists.
    /// Stands in for `CodeManager.getComment(CommentType, Address)`.
    fn get_comment(&self, comment_type: CommentType, address: &Address) -> Option<String>;

    /// Returns all the comments at `address`. Stands in for `CodeManager.getAllComments(
    /// Address)`.
    fn get_all_comments(&self, address: &Address) -> Box<dyn CodeUnitComments>;

    /// Sets the comment of the given type at `address`. Passing `None` clears the comment. Stands
    /// in for `CodeManager.setComment(Address, CommentType, String)`.
    fn set_comment(&mut self, address: &Address, comment_type: CommentType, comment: Option<String>);

    /// Gets the comment history for the given type at `address`, oldest first. Stands in for
    /// `CodeManager.getCommentHistory(Address, CommentType)`.
    fn get_comment_history(
        &self,
        address: &Address,
        comment_type: CommentType,
    ) -> Vec<Box<dyn CommentHistory>>;

    /// Replaces data type IDs on defined data records according to `data_type_replacement_map`
    /// (old ID -> new ID). Stands in for `CodeManager.replaceDataTypes(Map)`.
    fn replace_data_types(&mut self, data_type_replacement_map: &HashMap<i64, i64>);

    /// Performs a complete language transformation of all instructions: existing prototypes are
    /// discarded and instructions are re-disassembled following flow, adjusting context as
    /// needed. Only intended for use while the context has already been re-initialized for the
    /// new language. Stands in for `CodeManager.reDisassembleAllInstructions(TaskMonitor)`.
    fn re_disassemble_all_instructions(
        &mut self,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ReDisassembleAllInstructionsError>;

    /// Returns the instruction represented by `record`, or `None`. Stands in for
    /// `CodeManager.getInstructionDB(DBRecord)`.
    fn get_instruction_from_record(&self, record: &DBRecord) -> Option<Arc<dyn Instruction>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// A minimal in-memory `CodeManager`, standing in for a real DB-backed implementation.
    /// Exercises comment storage/removal, user-defined property tracking, and cache-invalidation
    /// bookkeeping -- the parts of the contract that don't require fabricating `CodeUnit`/
    /// `Instruction`/`Data`/`ReferenceManager` trait objects.
    struct MockCodeManager {
        comments: HashMap<(i64, CommentType), String>,
        defined: HashSet<i64>,
        properties: Vec<String>,
        invalidate_all_count: u32,
        code_unit_cache_invalidations: u32,
    }

    impl MockCodeManager {
        fn new() -> Self {
            MockCodeManager {
                comments: HashMap::new(),
                defined: HashSet::new(),
                properties: Vec::new(),
                invalidate_all_count: 0,
                code_unit_cache_invalidations: 0,
            }
        }
    }

    impl ManagerDB for MockCodeManager {
        fn invalidate_cache(&mut self, all: bool) -> io::Result<()> {
            if all {
                self.invalidate_all_count += 1;
            }
            Ok(())
        }

        fn delete_address_range(&mut self, start_addr: &Address, end_addr: &Address) -> io::Result<()> {
            let (lo, hi) = (start_addr.offset(), end_addr.offset());
            self.comments.retain(|(addr, _), _| *addr < lo || *addr > hi);
            self.defined.retain(|addr| *addr < lo || *addr > hi);
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

    impl CodeManager for MockCodeManager {
        fn activate_context_locking(&mut self) {}

        fn add_instructions(
            &mut self,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_instruction(
            &mut self,
            _address: Address,
            _prototype: Arc<dyn InstructionPrototype>,
            _mem_buf: &dyn MemBuffer,
            _context: &dyn ProcessorContextView,
            _length: i32,
        ) -> Result<Arc<dyn Instruction>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_data(
            &mut self,
            address: Address,
            _data_type: Box<dyn DataType>,
            _length: i32,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            self.defined.insert(address.offset());
            Err(CodeUnitInsertionException::new(
                "MockCodeManager cannot fabricate a real Data object",
            ))
        }

        fn get_code_unit_at(&self, _address: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }

        fn get_code_unit_after(&self, _address: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }

        fn get_code_unit_before(&self, _address: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }

        fn get_code_unit_containing(&self, _address: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }

        fn get_user_defined_properties(&self) -> Vec<String> {
            self.properties.clone()
        }

        fn remove_user_defined_property(&mut self, property_name: &str) {
            self.properties.retain(|p| p != property_name);
        }

        fn get_property_map(&self, _property_name: &str) -> Option<Box<dyn PropertyMap>> {
            None
        }

        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _address: &Address,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_comment_code_unit_iterator(
            &self,
            _comment_type: CommentType,
            _set: &dyn AddressSetView,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_comment_address_count(&self) -> i64 {
            self.comments
                .keys()
                .map(|(addr, _)| addr)
                .collect::<HashSet<_>>()
                .len() as i64
        }

        fn get_comment_address_iterator(
            &self,
            _comment_type: CommentType,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> BoxedAddressIterator {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_any_comment_address_iterator(
            &self,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> BoxedAddressIterator {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_instruction_at(&self, _address: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn get_defined_data_at(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_instruction_before(&self, _address: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn get_instruction_after(&self, _address: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn get_instruction_containing(
            &self,
            _address: &Address,
            _use_prototype_length: bool,
        ) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn get_data_at(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_data_before(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_data_after(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_data_containing(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_defined_data_after(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_defined_data_before(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_defined_data_containing(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_undefined_ranges(
            &self,
            _set: &dyn AddressSetView,
            _initialized_memory_only: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn AddressSetView>, CancelledException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_undefined_data_at(&self, address: &Address) -> Option<Arc<dyn Data>> {
            if self.defined.contains(&address.offset()) {
                None
            } else {
                unimplemented!("MockCodeManager cannot fabricate a real Data object")
            }
        }

        fn get_undefined_data_after(
            &self,
            _address: &Address,
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
            _address: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }

        fn update_data_references(&mut self, _data: &dyn Data) {}

        fn clear_comments(&mut self, start: &Address, end: &Address) {
            let (lo, hi) = (start.offset(), end.offset());
            self.comments.retain(|(addr, _), _| *addr < lo || *addr > hi);
        }

        fn clear_properties(
            &mut self,
            _start: &Address,
            _end: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn clear_code_units(
            &mut self,
            start: &Address,
            end: &Address,
            _clear_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            let (lo, hi) = (start.offset(), end.offset());
            self.defined.retain(|addr| *addr < lo || *addr > hi);
            Ok(())
        }

        fn clear_all(&mut self, _clear_context: bool, _monitor: &dyn TaskMonitor) {
            self.comments.clear();
            self.defined.clear();
        }

        fn get_num_instructions(&self) -> i32 {
            0
        }

        fn get_num_defined_data(&self) -> i32 {
            self.defined.len() as i32
        }

        fn get_code_units_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_units_in(
            &self,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_instructions_from(
            &self,
            _address: &Address,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_defined_data_from(
            &self,
            _address: &Address,
            _forward: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_instructions_in(
            &self,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_data_from(&self, _start: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_data_in(&self, _set: &dyn AddressSetView, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_defined_data_in(
            &self,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn check_context_write(
            &self,
            _start: &Address,
            _end: &Address,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn is_undefined(&self, start: &Address, end: &Address) -> bool {
            let (lo, hi) = (start.offset(), end.offset());
            !(lo..=hi).any(|addr| self.defined.contains(&addr))
        }

        fn clear_data(
            &mut self,
            data_type_ids: &HashSet<i64>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            let _ = data_type_ids;
            Ok(())
        }

        fn get_reference_mgr(&mut self) -> &mut dyn ReferenceManager {
            unimplemented!("not exercised by this smoke test")
        }

        fn invalidate_code_unit_cache(&mut self) {
            self.code_unit_cache_invalidations += 1;
        }

        fn memory_changed(&mut self, _start: &Address, _end: &Address) {
            self.code_unit_cache_invalidations += 1;
        }

        fn fall_through_changed(
            &mut self,
            _from_addr: &Address,
            _new_fall_through_ref: Option<Arc<dyn Reference>>,
        ) {
        }

        fn get_comment(&self, comment_type: CommentType, address: &Address) -> Option<String> {
            self.comments.get(&(address.offset(), comment_type)).cloned()
        }

        fn get_all_comments(&self, _address: &Address) -> Box<dyn CodeUnitComments> {
            struct MockComments;
            impl CodeUnitComments for MockComments {}
            Box::new(MockComments)
        }

        fn set_comment(
            &mut self,
            address: &Address,
            comment_type: CommentType,
            comment: Option<String>,
        ) {
            let key = (address.offset(), comment_type);
            match comment {
                Some(text) => {
                    self.comments.insert(key, text);
                }
                None => {
                    self.comments.remove(&key);
                }
            }
        }

        fn get_comment_history(
            &self,
            _address: &Address,
            _comment_type: CommentType,
        ) -> Vec<Box<dyn CommentHistory>> {
            Vec::new()
        }

        fn replace_data_types(&mut self, _data_type_replacement_map: &HashMap<i64, i64>) {}

        fn re_disassemble_all_instructions(
            &mut self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), ReDisassembleAllInstructionsError> {
            Ok(())
        }

        fn get_instruction_from_record(&self, _record: &DBRecord) -> Option<Arc<dyn Instruction>> {
            None
        }
    }

    #[test]
    fn mock_manager_is_object_safe_and_tracks_comments_and_properties() {
        let mut concrete = MockCodeManager::new();
        let addr_100 = mock_address(0x100);
        let addr_200 = mock_address(0x200);

        assert_eq!(concrete.code_unit_cache_invalidations, 0);
        concrete.invalidate_code_unit_cache();
        concrete.memory_changed(&addr_100, &addr_200);
        assert_eq!(concrete.code_unit_cache_invalidations, 2);

        let mut manager: Box<dyn CodeManager> = Box::new(concrete);

        assert_eq!(manager.get_comment(CommentType::Eol, &addr_100), None);
        manager.set_comment(&addr_100, CommentType::Eol, Some("hello".to_string()));
        manager.set_comment(&addr_100, CommentType::Pre, Some("before".to_string()));
        assert_eq!(
            manager.get_comment(CommentType::Eol, &addr_100),
            Some("hello".to_string())
        );
        assert_eq!(manager.get_comment_address_count(), 1);

        manager.set_comment(&addr_100, CommentType::Eol, None);
        assert_eq!(manager.get_comment(CommentType::Eol, &addr_100), None);
        assert_eq!(
            manager.get_comment(CommentType::Pre, &addr_100),
            Some("before".to_string())
        );

        manager.clear_comments(&addr_100, &addr_100);
        assert_eq!(manager.get_comment(CommentType::Pre, &addr_100), None);

        assert!(manager.get_user_defined_properties().is_empty());

        assert!(manager.is_undefined(&addr_100, &addr_200));

        let monitor = DummyMonitor;
        assert!(manager
            .create_data(addr_100.clone(), Box::new(NoopDataType), 1)
            .is_err());
        assert!(!manager.is_undefined(&addr_100, &addr_200));
        assert_eq!(manager.get_num_defined_data(), 1);

        manager
            .clear_code_units(&addr_100, &addr_100, false, &monitor)
            .unwrap();
        assert!(manager.is_undefined(&addr_100, &addr_200));
        assert_eq!(manager.get_num_defined_data(), 0);

        manager.invalidate_code_unit_cache();
        manager.memory_changed(&addr_100, &addr_200);

        manager.invalidate_cache(true).unwrap();
        manager.delete_address_range(&addr_100, &addr_200).unwrap();
    }

    struct NoopDataType;
    impl DataType for NoopDataType {}
}

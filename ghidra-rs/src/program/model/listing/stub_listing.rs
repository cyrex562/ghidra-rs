use std::sync::Arc;

use crate::program::model::address::{Address, BoxedAddressIterator, AddressSetView, EmptyAddressIterator};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::ProcessorContextView;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::function::Function;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::listing::listing::{CreateFunctionError, Listing};
use crate::program::model::listing::program_fragment::ProgramFragment;
use crate::program::model::listing::program_module::ProgramModule;
use crate::program::model::symbol::{Namespace, SourceType};
use crate::program::model::util::PropertyMap;
use crate::program::seam_stubs::{CodeUnitComments, CodeUnitIterator, CommentHistory, DataIterator, FunctionIterator, InstructionIterator, InstructionSet};
use crate::program::model::mem::MemBuffer;
use crate::program::model::listing::CommentType;
use crate::program::util::CodeUnitInsertionException;
use crate::util::exception::{CancelledException, DuplicateNameException};
use crate::util::task::TaskMonitor;

/// Default (panicking) implementation of every [`Listing`] query/mutation, for use by tests.
///
/// Port of `ghidra.program.model.listing.StubListing`. In Java, `StubListing` is a concrete class
/// implementing `Listing` that throws `UnsupportedOperationException` from every method; test
/// code subclasses it, overriding only the handful of methods a given test actually exercises. In
/// Rust there is no subclassing, so `StubListing` is instead a trait with the same
/// panic-by-default method bodies; any type implementing `StubListing` receives a blanket
/// [`Listing`] implementation for free (see the `impl<T: StubListing> Listing for T` below) and
/// can override individual methods as needed, mirroring the Java usage pattern.
///
/// The handful of methods that don't throw in the Java original (`getCommentAddressIterator`
/// overloads returning `AddressIterator.EMPTY_ITERATOR`, `getCommentAddressCount` returning `0`,
/// and `getComment` returning `null`) keep those same non-panicking defaults here.
pub trait StubListing {
    /// Stands in for `StubListing.getCodeUnitAt(Address)`.
    fn get_code_unit_at(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        unimplemented!("StubListing::get_code_unit_at")
    }

    /// Stands in for `StubListing.getCodeUnitContaining(Address)`.
    fn get_code_unit_containing(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        unimplemented!("StubListing::get_code_unit_containing")
    }

    /// Stands in for `StubListing.getCodeUnitAfter(Address)`.
    fn get_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        unimplemented!("StubListing::get_code_unit_after")
    }

    /// Stands in for `StubListing.getCodeUnitBefore(Address)`.
    fn get_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        unimplemented!("StubListing::get_code_unit_before")
    }

    /// Stands in for `StubListing.getCodeUnitIterator(String, boolean)`.
    fn get_code_unit_iterator(&self, _property: &str, _forward: bool) -> Box<dyn CodeUnitIterator> {
        unimplemented!("StubListing::get_code_unit_iterator")
    }

    /// Stands in for `StubListing.getCodeUnitIterator(String, Address, boolean)`.
    fn get_code_unit_iterator_from(
        &self,
        _property: &str,
        _addr: &Address,
        _forward: bool,
    ) -> Box<dyn CodeUnitIterator> {
        unimplemented!("StubListing::get_code_unit_iterator_from")
    }

    /// Stands in for `StubListing.getCodeUnitIterator(String, AddressSetView, boolean)`.
    fn get_code_unit_iterator_in(
        &self,
        _property: &str,
        _addr_set: &dyn AddressSetView,
        _forward: bool,
    ) -> Box<dyn CodeUnitIterator> {
        unimplemented!("StubListing::get_code_unit_iterator_in")
    }

    /// Stands in for `StubListing.getCommentCodeUnitIterator(CommentType, AddressSetView)`.
    fn get_comment_code_unit_iterator(
        &self,
        _comment_type: CommentType,
        _addr_set: &dyn AddressSetView,
    ) -> Box<dyn CodeUnitIterator> {
        unimplemented!("StubListing::get_comment_code_unit_iterator")
    }

    /// Stands in for `StubListing.getCommentAddressIterator(CommentType, AddressSetView,
    /// boolean)`, which returns `AddressIterator.EMPTY_ITERATOR`.
    fn get_comment_address_iterator(
        &self,
        _comment_type: CommentType,
        _addr_set: &dyn AddressSetView,
        _forward: bool,
    ) -> BoxedAddressIterator {
        Box::new(EmptyAddressIterator)
    }

    /// Stands in for `StubListing.getCommentAddressIterator(AddressSetView, boolean)`, which
    /// returns `AddressIterator.EMPTY_ITERATOR`.
    fn get_any_comment_address_iterator(
        &self,
        _addr_set: &dyn AddressSetView,
        _forward: bool,
    ) -> BoxedAddressIterator {
        Box::new(EmptyAddressIterator)
    }

    /// Stands in for `StubListing.getComment(CommentType, Address)`, which returns `null`.
    fn get_comment(&self, _comment_type: CommentType, _address: &Address) -> Option<String> {
        None
    }

    /// Stands in for `StubListing.getAllComments(Address)`.
    fn get_all_comments(&self, _address: &Address) -> Box<dyn CodeUnitComments> {
        unimplemented!("StubListing::get_all_comments")
    }

    /// Stands in for `StubListing.setComment(Address, CommentType, String)`.
    fn set_comment(&mut self, _address: &Address, _comment_type: CommentType, _comment: Option<String>) {
        unimplemented!("StubListing::set_comment")
    }

    /// Stands in for `StubListing.getCodeUnits(boolean)`.
    fn get_code_units(&self, _forward: bool) -> Box<dyn CodeUnitIterator> {
        unimplemented!("StubListing::get_code_units")
    }

    /// Stands in for `StubListing.getCodeUnits(Address, boolean)`.
    fn get_code_units_from(&self, _addr: &Address, _forward: bool) -> Box<dyn CodeUnitIterator> {
        unimplemented!("StubListing::get_code_units_from")
    }

    /// Stands in for `StubListing.getCodeUnits(AddressSetView, boolean)`.
    fn get_code_units_in(
        &self,
        _addr_set: &dyn AddressSetView,
        _forward: bool,
    ) -> Box<dyn CodeUnitIterator> {
        unimplemented!("StubListing::get_code_units_in")
    }

    /// Stands in for `StubListing.getInstructionAt(Address)`.
    fn get_instruction_at(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
        unimplemented!("StubListing::get_instruction_at")
    }

    /// Stands in for `StubListing.getInstructionContaining(Address)`.
    fn get_instruction_containing(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
        unimplemented!("StubListing::get_instruction_containing")
    }

    /// Stands in for `StubListing.getInstructionAfter(Address)`.
    fn get_instruction_after(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
        unimplemented!("StubListing::get_instruction_after")
    }

    /// Stands in for `StubListing.getInstructionBefore(Address)`.
    fn get_instruction_before(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
        unimplemented!("StubListing::get_instruction_before")
    }

    /// Stands in for `StubListing.getInstructions(boolean)`.
    fn get_instructions(&self, _forward: bool) -> Box<dyn InstructionIterator> {
        unimplemented!("StubListing::get_instructions")
    }

    /// Stands in for `StubListing.getInstructions(Address, boolean)`.
    fn get_instructions_from(&self, _addr: &Address, _forward: bool) -> Box<dyn InstructionIterator> {
        unimplemented!("StubListing::get_instructions_from")
    }

    /// Stands in for `StubListing.getInstructions(AddressSetView, boolean)`.
    fn get_instructions_in(
        &self,
        _addr_set: &dyn AddressSetView,
        _forward: bool,
    ) -> Box<dyn InstructionIterator> {
        unimplemented!("StubListing::get_instructions_in")
    }

    /// Stands in for `StubListing.getDataAt(Address)`.
    fn get_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_data_at")
    }

    /// Stands in for `StubListing.getDataContaining(Address)`.
    fn get_data_containing(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_data_containing")
    }

    /// Stands in for `StubListing.getDataAfter(Address)`.
    fn get_data_after(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_data_after")
    }

    /// Stands in for `StubListing.getDataBefore(Address)`.
    fn get_data_before(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_data_before")
    }

    /// Stands in for `StubListing.getData(boolean)`.
    fn get_data(&self, _forward: bool) -> Box<dyn DataIterator> {
        unimplemented!("StubListing::get_data")
    }

    /// Stands in for `StubListing.getData(Address, boolean)`.
    fn get_data_from(&self, _addr: &Address, _forward: bool) -> Box<dyn DataIterator> {
        unimplemented!("StubListing::get_data_from")
    }

    /// Stands in for `StubListing.getData(AddressSetView, boolean)`.
    fn get_data_in(&self, _addr_set: &dyn AddressSetView, _forward: bool) -> Box<dyn DataIterator> {
        unimplemented!("StubListing::get_data_in")
    }

    /// Stands in for `StubListing.getDefinedDataAt(Address)`.
    fn get_defined_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_defined_data_at")
    }

    /// Stands in for `StubListing.getDefinedDataContaining(Address)`.
    fn get_defined_data_containing(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_defined_data_containing")
    }

    /// Stands in for `StubListing.getDefinedDataAfter(Address)`.
    fn get_defined_data_after(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_defined_data_after")
    }

    /// Stands in for `StubListing.getDefinedDataBefore(Address)`.
    fn get_defined_data_before(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_defined_data_before")
    }

    /// Stands in for `StubListing.getDefinedData(boolean)`.
    fn get_defined_data(&self, _forward: bool) -> Box<dyn DataIterator> {
        unimplemented!("StubListing::get_defined_data")
    }

    /// Stands in for `StubListing.getDefinedData(Address, boolean)`.
    fn get_defined_data_from(&self, _addr: &Address, _forward: bool) -> Box<dyn DataIterator> {
        unimplemented!("StubListing::get_defined_data_from")
    }

    /// Stands in for `StubListing.getDefinedData(AddressSetView, boolean)`.
    fn get_defined_data_in(
        &self,
        _addr_set: &dyn AddressSetView,
        _forward: bool,
    ) -> Box<dyn DataIterator> {
        unimplemented!("StubListing::get_defined_data_in")
    }

    /// Stands in for `StubListing.getUndefinedDataAt(Address)`.
    fn get_undefined_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_undefined_data_at")
    }

    /// Stands in for `StubListing.getUndefinedDataAfter(Address, TaskMonitor)`.
    fn get_undefined_data_after(
        &self,
        _addr: &Address,
        _monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_undefined_data_after")
    }

    /// Stands in for `StubListing.getFirstUndefinedData(AddressSetView, TaskMonitor)`.
    fn get_first_undefined_data(
        &self,
        _set: &dyn AddressSetView,
        _monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_first_undefined_data")
    }

    /// Stands in for `StubListing.getUndefinedDataBefore(Address, TaskMonitor)`.
    fn get_undefined_data_before(
        &self,
        _addr: &Address,
        _monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>> {
        unimplemented!("StubListing::get_undefined_data_before")
    }

    /// Stands in for `StubListing.getUndefinedRanges(AddressSetView, boolean, TaskMonitor)`.
    fn get_undefined_ranges(
        &self,
        _set: &dyn AddressSetView,
        _initialized_memory_only: bool,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn AddressSetView>, CancelledException> {
        unimplemented!("StubListing::get_undefined_ranges")
    }

    /// Stands in for `StubListing.getDefinedCodeUnitAfter(Address)`.
    fn get_defined_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        unimplemented!("StubListing::get_defined_code_unit_after")
    }

    /// Stands in for `StubListing.getDefinedCodeUnitBefore(Address)`.
    fn get_defined_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        unimplemented!("StubListing::get_defined_code_unit_before")
    }

    /// Stands in for `StubListing.getUserDefinedProperties()`.
    fn get_user_defined_properties(&self) -> Vec<String> {
        unimplemented!("StubListing::get_user_defined_properties")
    }

    /// Stands in for `StubListing.removeUserDefinedProperty(String)`.
    fn remove_user_defined_property(&mut self, _property_name: &str) {
        unimplemented!("StubListing::remove_user_defined_property")
    }

    /// Stands in for `StubListing.getPropertyMap(String)`.
    fn get_property_map(&self, _property_name: &str) -> Option<Box<dyn PropertyMap>> {
        unimplemented!("StubListing::get_property_map")
    }

    /// Stands in for `StubListing.createInstruction(Address, InstructionPrototype, MemBuffer,
    /// ProcessorContextView, int)`.
    fn create_instruction(
        &mut self,
        _addr: Address,
        _prototype: Arc<dyn InstructionPrototype>,
        _mem_buf: &dyn MemBuffer,
        _context: &dyn ProcessorContextView,
        _length: i32,
    ) -> Result<Arc<dyn Instruction>, CodeUnitInsertionException> {
        unimplemented!("StubListing::create_instruction")
    }

    /// Stands in for `StubListing.addInstructions(InstructionSet, boolean)`.
    fn add_instructions(
        &mut self,
        _instruction_set: &dyn InstructionSet,
        _overwrite: bool,
    ) -> Result<Box<dyn AddressSetView>, CodeUnitInsertionException> {
        unimplemented!("StubListing::add_instructions")
    }

    /// Stands in for `StubListing.createData(Address, DataType, int)`.
    fn create_data_sized(
        &mut self,
        _addr: Address,
        _data_type: Box<dyn DataType>,
        _length: i32,
    ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
        unimplemented!("StubListing::create_data_sized")
    }

    /// Stands in for `StubListing.createData(Address, DataType)`.
    fn create_data(
        &mut self,
        _addr: Address,
        _data_type: Box<dyn DataType>,
    ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
        unimplemented!("StubListing::create_data")
    }

    /// Stands in for `StubListing.clearCodeUnits(Address, Address, boolean)`.
    fn clear_code_units(&mut self, _start_addr: &Address, _end_addr: &Address, _clear_context: bool) {
        unimplemented!("StubListing::clear_code_units")
    }

    /// Stands in for `StubListing.clearCodeUnits(Address, Address, boolean, TaskMonitor)`.
    fn clear_code_units_with_monitor(
        &mut self,
        _start_addr: &Address,
        _end_addr: &Address,
        _clear_context: bool,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        unimplemented!("StubListing::clear_code_units_with_monitor")
    }

    /// Stands in for `StubListing.isUndefined(Address, Address)`.
    fn is_undefined(&self, _start: &Address, _end: &Address) -> bool {
        unimplemented!("StubListing::is_undefined")
    }

    /// Stands in for `StubListing.clearComments(Address, Address)`.
    fn clear_comments(&mut self, _start_addr: &Address, _end_addr: &Address) {
        unimplemented!("StubListing::clear_comments")
    }

    /// Stands in for `StubListing.clearProperties(Address, Address, TaskMonitor)`.
    fn clear_properties(
        &mut self,
        _start_addr: &Address,
        _end_addr: &Address,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        unimplemented!("StubListing::clear_properties")
    }

    /// Stands in for `StubListing.clearAll(boolean, TaskMonitor)`.
    fn clear_all(&mut self, _clear_context: bool, _monitor: &dyn TaskMonitor) {
        unimplemented!("StubListing::clear_all")
    }

    /// Stands in for `StubListing.getFragment(String, Address)`.
    fn get_fragment(&self, _tree_name: &str, _addr: &Address) -> Option<Arc<dyn ProgramFragment>> {
        unimplemented!("StubListing::get_fragment")
    }

    /// Stands in for `StubListing.getModule(String, String)`.
    fn get_module(&self, _tree_name: &str, _name: &str) -> Option<Arc<dyn ProgramModule>> {
        unimplemented!("StubListing::get_module")
    }

    /// Stands in for `StubListing.getFragment(String, String)`.
    fn get_fragment_by_name(
        &self,
        _tree_name: &str,
        _name: &str,
    ) -> Option<Arc<dyn ProgramFragment>> {
        unimplemented!("StubListing::get_fragment_by_name")
    }

    /// Stands in for `StubListing.createRootModule(String)`.
    fn create_root_module(
        &mut self,
        _tree_name: &str,
    ) -> Result<Arc<dyn ProgramModule>, DuplicateNameException> {
        unimplemented!("StubListing::create_root_module")
    }

    /// Stands in for `StubListing.getRootModule(String)`.
    fn get_root_module(&self, _tree_name: &str) -> Option<Arc<dyn ProgramModule>> {
        unimplemented!("StubListing::get_root_module")
    }

    /// Stands in for `StubListing.getRootModule(long)`.
    fn get_root_module_by_id(&self, _tree_id: i64) -> Option<Arc<dyn ProgramModule>> {
        unimplemented!("StubListing::get_root_module_by_id")
    }

    /// Stands in for `StubListing.getDefaultRootModule()`.
    fn get_default_root_module(&self) -> Arc<dyn ProgramModule> {
        unimplemented!("StubListing::get_default_root_module")
    }

    /// Stands in for `StubListing.getTreeNames()`.
    fn get_tree_names(&self) -> Vec<String> {
        unimplemented!("StubListing::get_tree_names")
    }

    /// Stands in for `StubListing.removeTree(String)`.
    fn remove_tree(&mut self, _tree_name: &str) -> bool {
        unimplemented!("StubListing::remove_tree")
    }

    /// Stands in for `StubListing.renameTree(String, String)`.
    fn rename_tree(&mut self, _old_name: &str, _new_name: &str) -> Result<(), DuplicateNameException> {
        unimplemented!("StubListing::rename_tree")
    }

    /// Stands in for `StubListing.getNumCodeUnits()`.
    fn get_num_code_units(&self) -> i64 {
        unimplemented!("StubListing::get_num_code_units")
    }

    /// Stands in for `StubListing.getNumDefinedData()`.
    fn get_num_defined_data(&self) -> i64 {
        unimplemented!("StubListing::get_num_defined_data")
    }

    /// Stands in for `StubListing.getNumInstructions()`.
    fn get_num_instructions(&self) -> i64 {
        unimplemented!("StubListing::get_num_instructions")
    }

    /// Stands in for `StubListing.getDataTypeManager()`.
    fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
        unimplemented!("StubListing::get_data_type_manager")
    }

    /// Stands in for `StubListing.createFunction(String, Address, AddressSetView, SourceType)`.
    fn create_function(
        &mut self,
        _name: &str,
        _entry_point: Address,
        _body: &dyn AddressSetView,
        _source: SourceType,
    ) -> Result<Arc<dyn Function>, CreateFunctionError> {
        unimplemented!("StubListing::create_function")
    }

    /// Stands in for `StubListing.createFunction(String, Namespace, Address, AddressSetView,
    /// SourceType)`.
    fn create_function_in_namespace(
        &mut self,
        _name: &str,
        _name_space: Arc<dyn Namespace>,
        _entry_point: Address,
        _body: &dyn AddressSetView,
        _source: SourceType,
    ) -> Result<Arc<dyn Function>, CreateFunctionError> {
        unimplemented!("StubListing::create_function_in_namespace")
    }

    /// Stands in for `StubListing.removeFunction(Address)`.
    fn remove_function(&mut self, _entry_point: &Address) {
        unimplemented!("StubListing::remove_function")
    }

    /// Stands in for `StubListing.getFunctionAt(Address)`.
    fn get_function_at(&self, _entry_point: &Address) -> Option<Arc<dyn Function>> {
        unimplemented!("StubListing::get_function_at")
    }

    /// Stands in for `StubListing.getGlobalFunctions(String)`.
    fn get_global_functions(&self, _name: &str) -> Vec<Arc<dyn Function>> {
        unimplemented!("StubListing::get_global_functions")
    }

    /// Stands in for `StubListing.getFunctions(String, String)`.
    fn get_functions_by_name(&self, _namespace: Option<&str>, _name: &str) -> Vec<Arc<dyn Function>> {
        unimplemented!("StubListing::get_functions_by_name")
    }

    /// Stands in for `StubListing.getFunctionContaining(Address)`.
    fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
        unimplemented!("StubListing::get_function_containing")
    }

    /// Stands in for `StubListing.getExternalFunctions()`.
    fn get_external_functions(&self) -> Box<dyn FunctionIterator> {
        unimplemented!("StubListing::get_external_functions")
    }

    /// Stands in for `StubListing.getFunctions(boolean)`.
    fn get_functions(&self, _forward: bool) -> Box<dyn FunctionIterator> {
        unimplemented!("StubListing::get_functions")
    }

    /// Stands in for `StubListing.getFunctions(Address, boolean)`.
    fn get_functions_from(&self, _start: &Address, _forward: bool) -> Box<dyn FunctionIterator> {
        unimplemented!("StubListing::get_functions_from")
    }

    /// Stands in for `StubListing.getFunctions(AddressSetView, boolean)`.
    fn get_functions_in(&self, _asv: &dyn AddressSetView, _forward: bool) -> Box<dyn FunctionIterator> {
        unimplemented!("StubListing::get_functions_in")
    }

    /// Stands in for `StubListing.isInFunction(Address)`.
    fn is_in_function(&self, _addr: &Address) -> bool {
        unimplemented!("StubListing::is_in_function")
    }

    /// Stands in for `StubListing.getCommentHistory(Address, CommentType)`.
    fn get_comment_history(
        &self,
        _addr: &Address,
        _comment_type: CommentType,
    ) -> Vec<Box<dyn CommentHistory>> {
        unimplemented!("StubListing::get_comment_history")
    }

    /// Stands in for `StubListing.getCommentAddressCount()`, which returns `0`.
    fn get_comment_address_count(&self) -> i64 {
        0
    }
}

impl<T: StubListing> Listing for T {
    fn get_code_unit_at(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        StubListing::get_code_unit_at(self, addr)
    }
    fn get_code_unit_containing(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        StubListing::get_code_unit_containing(self, addr)
    }
    fn get_code_unit_after(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        StubListing::get_code_unit_after(self, addr)
    }
    fn get_code_unit_before(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        StubListing::get_code_unit_before(self, addr)
    }
    fn get_code_unit_iterator(&self, property: &str, forward: bool) -> Box<dyn CodeUnitIterator> {
        StubListing::get_code_unit_iterator(self, property, forward)
    }
    fn get_code_unit_iterator_from(
        &self,
        property: &str,
        addr: &Address,
        forward: bool,
    ) -> Box<dyn CodeUnitIterator> {
        StubListing::get_code_unit_iterator_from(self, property, addr, forward)
    }
    fn get_code_unit_iterator_in(
        &self,
        property: &str,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn CodeUnitIterator> {
        StubListing::get_code_unit_iterator_in(self, property, addr_set, forward)
    }
    fn get_comment_code_unit_iterator(
        &self,
        comment_type: CommentType,
        addr_set: &dyn AddressSetView,
    ) -> Box<dyn CodeUnitIterator> {
        StubListing::get_comment_code_unit_iterator(self, comment_type, addr_set)
    }
    fn get_comment_address_iterator(
        &self,
        comment_type: CommentType,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> BoxedAddressIterator {
        StubListing::get_comment_address_iterator(self, comment_type, addr_set, forward)
    }
    fn get_any_comment_address_iterator(
        &self,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> BoxedAddressIterator {
        StubListing::get_any_comment_address_iterator(self, addr_set, forward)
    }
    fn get_comment(&self, comment_type: CommentType, address: &Address) -> Option<String> {
        StubListing::get_comment(self, comment_type, address)
    }
    fn get_all_comments(&self, address: &Address) -> Box<dyn CodeUnitComments> {
        StubListing::get_all_comments(self, address)
    }
    fn set_comment(&mut self, address: &Address, comment_type: CommentType, comment: Option<String>) {
        StubListing::set_comment(self, address, comment_type, comment)
    }
    fn get_code_units(&self, forward: bool) -> Box<dyn CodeUnitIterator> {
        StubListing::get_code_units(self, forward)
    }
    fn get_code_units_from(&self, addr: &Address, forward: bool) -> Box<dyn CodeUnitIterator> {
        StubListing::get_code_units_from(self, addr, forward)
    }
    fn get_code_units_in(
        &self,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn CodeUnitIterator> {
        StubListing::get_code_units_in(self, addr_set, forward)
    }
    fn get_instruction_at(&self, addr: &Address) -> Option<Arc<dyn Instruction>> {
        StubListing::get_instruction_at(self, addr)
    }
    fn get_instruction_containing(&self, addr: &Address) -> Option<Arc<dyn Instruction>> {
        StubListing::get_instruction_containing(self, addr)
    }
    fn get_instruction_after(&self, addr: &Address) -> Option<Arc<dyn Instruction>> {
        StubListing::get_instruction_after(self, addr)
    }
    fn get_instruction_before(&self, addr: &Address) -> Option<Arc<dyn Instruction>> {
        StubListing::get_instruction_before(self, addr)
    }
    fn get_instructions(&self, forward: bool) -> Box<dyn InstructionIterator> {
        StubListing::get_instructions(self, forward)
    }
    fn get_instructions_from(&self, addr: &Address, forward: bool) -> Box<dyn InstructionIterator> {
        StubListing::get_instructions_from(self, addr, forward)
    }
    fn get_instructions_in(
        &self,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn InstructionIterator> {
        StubListing::get_instructions_in(self, addr_set, forward)
    }
    fn get_data_at(&self, addr: &Address) -> Option<Arc<dyn Data>> {
        StubListing::get_data_at(self, addr)
    }
    fn get_data_containing(&self, addr: &Address) -> Option<Arc<dyn Data>> {
        StubListing::get_data_containing(self, addr)
    }
    fn get_data_after(&self, addr: &Address) -> Option<Arc<dyn Data>> {
        StubListing::get_data_after(self, addr)
    }
    fn get_data_before(&self, addr: &Address) -> Option<Arc<dyn Data>> {
        StubListing::get_data_before(self, addr)
    }
    fn get_data(&self, forward: bool) -> Box<dyn DataIterator> {
        StubListing::get_data(self, forward)
    }
    fn get_data_from(&self, addr: &Address, forward: bool) -> Box<dyn DataIterator> {
        StubListing::get_data_from(self, addr, forward)
    }
    fn get_data_in(&self, addr_set: &dyn AddressSetView, forward: bool) -> Box<dyn DataIterator> {
        StubListing::get_data_in(self, addr_set, forward)
    }
    fn get_defined_data_at(&self, addr: &Address) -> Option<Arc<dyn Data>> {
        StubListing::get_defined_data_at(self, addr)
    }
    fn get_defined_data_containing(&self, addr: &Address) -> Option<Arc<dyn Data>> {
        StubListing::get_defined_data_containing(self, addr)
    }
    fn get_defined_data_after(&self, addr: &Address) -> Option<Arc<dyn Data>> {
        StubListing::get_defined_data_after(self, addr)
    }
    fn get_defined_data_before(&self, addr: &Address) -> Option<Arc<dyn Data>> {
        StubListing::get_defined_data_before(self, addr)
    }
    fn get_defined_data(&self, forward: bool) -> Box<dyn DataIterator> {
        StubListing::get_defined_data(self, forward)
    }
    fn get_defined_data_from(&self, addr: &Address, forward: bool) -> Box<dyn DataIterator> {
        StubListing::get_defined_data_from(self, addr, forward)
    }
    fn get_defined_data_in(
        &self,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn DataIterator> {
        StubListing::get_defined_data_in(self, addr_set, forward)
    }
    fn get_undefined_data_at(&self, addr: &Address) -> Option<Arc<dyn Data>> {
        StubListing::get_undefined_data_at(self, addr)
    }
    fn get_undefined_data_after(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>> {
        StubListing::get_undefined_data_after(self, addr, monitor)
    }
    fn get_first_undefined_data(
        &self,
        set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>> {
        StubListing::get_first_undefined_data(self, set, monitor)
    }
    fn get_undefined_data_before(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Data>> {
        StubListing::get_undefined_data_before(self, addr, monitor)
    }
    fn get_undefined_ranges(
        &self,
        set: &dyn AddressSetView,
        initialized_memory_only: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn AddressSetView>, CancelledException> {
        StubListing::get_undefined_ranges(self, set, initialized_memory_only, monitor)
    }
    fn get_defined_code_unit_after(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        StubListing::get_defined_code_unit_after(self, addr)
    }
    fn get_defined_code_unit_before(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>> {
        StubListing::get_defined_code_unit_before(self, addr)
    }
    fn get_user_defined_properties(&self) -> Vec<String> {
        StubListing::get_user_defined_properties(self)
    }
    fn remove_user_defined_property(&mut self, property_name: &str) {
        StubListing::remove_user_defined_property(self, property_name)
    }
    fn get_property_map(&self, property_name: &str) -> Option<Box<dyn PropertyMap>> {
        StubListing::get_property_map(self, property_name)
    }
    fn create_instruction(
        &mut self,
        addr: Address,
        prototype: Arc<dyn InstructionPrototype>,
        mem_buf: &dyn MemBuffer,
        context: &dyn ProcessorContextView,
        length: i32,
    ) -> Result<Arc<dyn Instruction>, CodeUnitInsertionException> {
        StubListing::create_instruction(self, addr, prototype, mem_buf, context, length)
    }
    fn add_instructions(
        &mut self,
        instruction_set: &dyn InstructionSet,
        overwrite: bool,
    ) -> Result<Box<dyn AddressSetView>, CodeUnitInsertionException> {
        StubListing::add_instructions(self, instruction_set, overwrite)
    }
    fn create_data_sized(
        &mut self,
        addr: Address,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
        StubListing::create_data_sized(self, addr, data_type, length)
    }
    fn create_data(
        &mut self,
        addr: Address,
        data_type: Box<dyn DataType>,
    ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
        StubListing::create_data(self, addr, data_type)
    }
    fn clear_code_units(&mut self, start_addr: &Address, end_addr: &Address, clear_context: bool) {
        StubListing::clear_code_units(self, start_addr, end_addr, clear_context)
    }
    fn clear_code_units_with_monitor(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
        clear_context: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        StubListing::clear_code_units_with_monitor(self, start_addr, end_addr, clear_context, monitor)
    }
    fn is_undefined(&self, start: &Address, end: &Address) -> bool {
        StubListing::is_undefined(self, start, end)
    }
    fn clear_comments(&mut self, start_addr: &Address, end_addr: &Address) {
        StubListing::clear_comments(self, start_addr, end_addr)
    }
    fn clear_properties(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        StubListing::clear_properties(self, start_addr, end_addr, monitor)
    }
    fn clear_all(&mut self, clear_context: bool, monitor: &dyn TaskMonitor) {
        StubListing::clear_all(self, clear_context, monitor)
    }
    fn get_fragment(&self, tree_name: &str, addr: &Address) -> Option<Arc<dyn ProgramFragment>> {
        StubListing::get_fragment(self, tree_name, addr)
    }
    fn get_module(&self, tree_name: &str, name: &str) -> Option<Arc<dyn ProgramModule>> {
        StubListing::get_module(self, tree_name, name)
    }
    fn get_fragment_by_name(&self, tree_name: &str, name: &str) -> Option<Arc<dyn ProgramFragment>> {
        StubListing::get_fragment_by_name(self, tree_name, name)
    }
    fn create_root_module(
        &mut self,
        tree_name: &str,
    ) -> Result<Arc<dyn ProgramModule>, DuplicateNameException> {
        StubListing::create_root_module(self, tree_name)
    }
    fn get_root_module(&self, tree_name: &str) -> Option<Arc<dyn ProgramModule>> {
        StubListing::get_root_module(self, tree_name)
    }
    fn get_root_module_by_id(&self, tree_id: i64) -> Option<Arc<dyn ProgramModule>> {
        StubListing::get_root_module_by_id(self, tree_id)
    }
    fn get_default_root_module(&self) -> Arc<dyn ProgramModule> {
        StubListing::get_default_root_module(self)
    }
    fn get_tree_names(&self) -> Vec<String> {
        StubListing::get_tree_names(self)
    }
    fn remove_tree(&mut self, tree_name: &str) -> bool {
        StubListing::remove_tree(self, tree_name)
    }
    fn rename_tree(&mut self, old_name: &str, new_name: &str) -> Result<(), DuplicateNameException> {
        StubListing::rename_tree(self, old_name, new_name)
    }
    fn get_num_code_units(&self) -> i64 {
        StubListing::get_num_code_units(self)
    }
    fn get_num_defined_data(&self) -> i64 {
        StubListing::get_num_defined_data(self)
    }
    fn get_num_instructions(&self) -> i64 {
        StubListing::get_num_instructions(self)
    }
    fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
        StubListing::get_data_type_manager(self)
    }
    fn create_function(
        &mut self,
        name: &str,
        entry_point: Address,
        body: &dyn AddressSetView,
        source: SourceType,
    ) -> Result<Arc<dyn Function>, CreateFunctionError> {
        StubListing::create_function(self, name, entry_point, body, source)
    }
    fn create_function_in_namespace(
        &mut self,
        name: &str,
        name_space: Arc<dyn Namespace>,
        entry_point: Address,
        body: &dyn AddressSetView,
        source: SourceType,
    ) -> Result<Arc<dyn Function>, CreateFunctionError> {
        StubListing::create_function_in_namespace(self, name, name_space, entry_point, body, source)
    }
    fn remove_function(&mut self, entry_point: &Address) {
        StubListing::remove_function(self, entry_point)
    }
    fn get_function_at(&self, entry_point: &Address) -> Option<Arc<dyn Function>> {
        StubListing::get_function_at(self, entry_point)
    }
    fn get_global_functions(&self, name: &str) -> Vec<Arc<dyn Function>> {
        StubListing::get_global_functions(self, name)
    }
    fn get_functions_by_name(&self, namespace: Option<&str>, name: &str) -> Vec<Arc<dyn Function>> {
        StubListing::get_functions_by_name(self, namespace, name)
    }
    fn get_function_containing(&self, addr: &Address) -> Option<Arc<dyn Function>> {
        StubListing::get_function_containing(self, addr)
    }
    fn get_external_functions(&self) -> Box<dyn FunctionIterator> {
        StubListing::get_external_functions(self)
    }
    fn get_functions(&self, forward: bool) -> Box<dyn FunctionIterator> {
        StubListing::get_functions(self, forward)
    }
    fn get_functions_from(&self, start: &Address, forward: bool) -> Box<dyn FunctionIterator> {
        StubListing::get_functions_from(self, start, forward)
    }
    fn get_functions_in(&self, asv: &dyn AddressSetView, forward: bool) -> Box<dyn FunctionIterator> {
        StubListing::get_functions_in(self, asv, forward)
    }
    fn is_in_function(&self, addr: &Address) -> bool {
        StubListing::is_in_function(self, addr)
    }
    fn get_comment_history(
        &self,
        addr: &Address,
        comment_type: CommentType,
    ) -> Vec<Box<dyn CommentHistory>> {
        StubListing::get_comment_history(self, addr, comment_type)
    }
    fn get_comment_address_count(&self) -> i64 {
        StubListing::get_comment_address_count(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test double using only the `StubListing` defaults, proving the trait is object-safe and
    /// that its blanket `Listing` impl lets it stand in wherever a `Listing` is expected -- just
    /// like `new StubListing() {}` in Java.
    struct BareStub;
    impl StubListing for BareStub {}

    /// A test double overriding a single method, mirroring how Java tests subclass `StubListing`
    /// and override only what they need.
    struct CountingStub {
        code_unit_count: i64,
    }
    impl StubListing for CountingStub {
        fn get_num_code_units(&self) -> i64 {
            self.code_unit_count
        }
    }

    fn mock_address(offset: i64) -> Address {
        use crate::program::model::address::AddressSpaceType;
        let space = crate::program::model::address::AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    #[should_panic]
    fn bare_stub_panics_on_unoverridden_methods() {
        let stub: Box<dyn Listing> = Box::new(BareStub);
        stub.get_code_unit_at(&mock_address(0x100));
    }

    #[test]
    fn bare_stub_matches_java_non_panicking_defaults() {
        let stub: Box<dyn Listing> = Box::new(BareStub);
        assert_eq!(stub.get_comment_address_count(), 0);
        assert_eq!(
            stub.get_comment(CommentType::Eol, &mock_address(0x100)),
            None
        );
        let empty_set = crate::program::model::address::AddressSet::new();
        let mut iter = stub.get_any_comment_address_iterator(&empty_set, true);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn overriding_a_single_method_works_through_the_listing_trait_object() {
        let stub: Box<dyn Listing> = Box::new(CountingStub { code_unit_count: 42 });
        assert_eq!(stub.get_num_code_units(), 42);
    }
}

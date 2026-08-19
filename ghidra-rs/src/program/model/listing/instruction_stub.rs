use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::{ProcessorContext, ProcessorContextView};
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::instruction::{Instruction, OperandValue};
use crate::program::model::listing::program::Program;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::pcode::PcodeOp;
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::{
    ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
};
use crate::program::model::util::PropertySet;
use crate::program::seam_stubs::{FlowOverride, InstructionContext, RegisterValue};
use crate::program::model::mem::MemBuffer;
use crate::program::model::listing::CommentType;
use crate::program::util::CodeUnitInsertionException;
use crate::util::exception::NoValueException;
use crate::util::saveable::Saveable;

/// Default (panicking) implementation of every [`Instruction`] query/mutation (and the
/// [`CodeUnit`], [`MemBuffer`], [`PropertySet`], [`ProcessorContextView`], and [`ProcessorContext`]
/// supertrait methods it pulls in), for use by tests.
///
/// Port of `ghidra.program.model.listing.InstructionStub`. In Java, `InstructionStub` is a
/// concrete class implementing `Instruction` that throws `UnsupportedOperationException` from
/// every method; test code subclasses it, overriding only the handful of methods a given test
/// actually exercises. In Rust there is no subclassing, so `InstructionStub` is instead a trait
/// with the same panic-by-default method bodies; any type implementing `InstructionStub` receives
/// blanket [`MemBuffer`], [`PropertySet`], [`CodeUnit`], [`ProcessorContextView`],
/// [`ProcessorContext`], and [`Instruction`] implementations for free (see the `impl<T:
/// InstructionStub> ... for T` blocks below) and can override individual methods as needed,
/// mirroring the Java usage pattern. See [`StubListing`](crate::program::model::listing::StubListing)
/// for the same pattern applied to `Listing`.
///
/// Two methods are renamed relative to their Java/Rust trait counterparts because Rust traits
/// (unlike Java interfaces) cannot declare two methods with the same name even when their arities
/// differ:
/// * [`get_operand_address`](Self::get_operand_address) stands in for `CodeUnit.getAddress(int)`
///   (renamed from `get_address` to avoid clashing with `MemBuffer.getAddress()`, below).
/// * [`get_membuffer_address`](Self::get_membuffer_address) stands in for `MemBuffer.getAddress()`.
/// * [`get_register_by_name`](Self::get_register_by_name) stands in for
///   `ProcessorContextView.getRegister(String)` (renamed from `get_register` to avoid clashing
///   with `Instruction.getRegister(int)`, below).
///
/// The one method that doesn't throw in the Java original (`getMemory()`, which returns `null`)
/// needs no override here: [`MemBuffer::get_memory`] already defaults to `None`.
pub trait InstructionStub {
    // ---- PropertySet ----

    /// Stands in for `InstructionStub.setProperty(String, Saveable)`.
    fn set_object_property(&mut self, _name: &str, _value: Box<dyn Saveable>) {
        unimplemented!("InstructionStub::set_object_property")
    }

    /// Stands in for `InstructionStub.setProperty(String, String)`.
    fn set_string_property(&mut self, _name: &str, _value: &str) {
        unimplemented!("InstructionStub::set_string_property")
    }

    /// Stands in for `InstructionStub.setProperty(String, int)`.
    fn set_int_property(&mut self, _name: &str, _value: i32) {
        unimplemented!("InstructionStub::set_int_property")
    }

    /// Stands in for `InstructionStub.setProperty(String)`.
    fn set_void_property(&mut self, _name: &str) {
        unimplemented!("InstructionStub::set_void_property")
    }

    /// Stands in for `InstructionStub.getObjectProperty(String)`.
    fn get_object_property(&self, _name: &str) -> Option<Box<dyn Saveable>> {
        unimplemented!("InstructionStub::get_object_property")
    }

    /// Stands in for `InstructionStub.getStringProperty(String)`.
    fn get_string_property(&self, _name: &str) -> Option<String> {
        unimplemented!("InstructionStub::get_string_property")
    }

    /// Stands in for `InstructionStub.getIntProperty(String)`.
    fn get_int_property(&self, _name: &str) -> Result<i32, NoValueException> {
        unimplemented!("InstructionStub::get_int_property")
    }

    /// Stands in for `InstructionStub.hasProperty(String)`.
    fn has_property(&self, _name: &str) -> bool {
        unimplemented!("InstructionStub::has_property")
    }

    /// Stands in for `InstructionStub.getVoidProperty(String)`.
    fn get_void_property(&self, _name: &str) -> bool {
        unimplemented!("InstructionStub::get_void_property")
    }

    /// Stands in for `InstructionStub.propertyNames()`.
    fn property_names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        unimplemented!("InstructionStub::property_names")
    }

    /// Stands in for `InstructionStub.removeProperty(String)`.
    fn remove_property(&mut self, _name: &str) {
        unimplemented!("InstructionStub::remove_property")
    }

    // ---- MemBuffer ----

    /// Stands in for `InstructionStub.getAddress()`. See the trait-level docs for why this is
    /// renamed from `get_address`.
    fn get_membuffer_address(&self) -> Address {
        unimplemented!("InstructionStub::get_membuffer_address")
    }

    // ---- CodeUnit ----

    /// Stands in for `InstructionStub.getAddressString(boolean, boolean)`.
    fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
        unimplemented!("InstructionStub::get_address_string")
    }

    /// Stands in for `InstructionStub.getLabel()`.
    fn get_label(&self) -> Option<String> {
        unimplemented!("InstructionStub::get_label")
    }

    /// Stands in for `InstructionStub.getSymbols()`.
    fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
        unimplemented!("InstructionStub::get_symbols")
    }

    /// Stands in for `InstructionStub.getPrimarySymbol()`.
    fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
        unimplemented!("InstructionStub::get_primary_symbol")
    }

    /// Stands in for `InstructionStub.getMinAddress()`.
    fn get_min_address(&self) -> Address {
        unimplemented!("InstructionStub::get_min_address")
    }

    /// Stands in for `InstructionStub.getMaxAddress()`.
    fn get_max_address(&self) -> Address {
        unimplemented!("InstructionStub::get_max_address")
    }

    /// Stands in for `InstructionStub.getMnemonicString()`.
    fn get_mnemonic_string(&self) -> String {
        unimplemented!("InstructionStub::get_mnemonic_string")
    }

    /// Stands in for `InstructionStub.getComment(CommentType)`.
    fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
        unimplemented!("InstructionStub::get_comment")
    }

    /// Stands in for `InstructionStub.getCommentAsArray(CommentType)`.
    fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
        unimplemented!("InstructionStub::get_comment_as_array")
    }

    /// Stands in for `InstructionStub.setComment(CommentType, String)`.
    fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {
        unimplemented!("InstructionStub::set_comment")
    }

    /// Stands in for `InstructionStub.setCommentAsArray(CommentType, String[])`.
    fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {
        unimplemented!("InstructionStub::set_comment_as_array")
    }

    /// Stands in for `InstructionStub.getLength()`.
    fn get_length(&self) -> i32 {
        unimplemented!("InstructionStub::get_length")
    }

    /// Stands in for `InstructionStub.getBytes()`.
    fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        unimplemented!("InstructionStub::get_bytes")
    }

    /// Stands in for `InstructionStub.getBytesInCodeUnit(byte[], int)`.
    fn get_bytes_in_code_unit(
        &self,
        _buffer: &mut [u8],
        _buffer_offset: i32,
    ) -> Result<(), MemoryAccessException> {
        unimplemented!("InstructionStub::get_bytes_in_code_unit")
    }

    /// Stands in for `InstructionStub.contains(Address)`.
    fn contains(&self, _test_addr: &Address) -> bool {
        unimplemented!("InstructionStub::contains")
    }

    /// Stands in for `InstructionStub.compareTo(Address)`.
    fn compare_to(&self, _addr: &Address) -> i32 {
        unimplemented!("InstructionStub::compare_to")
    }

    /// Stands in for `InstructionStub.addMnemonicReference(Address, RefType, SourceType)`.
    fn add_mnemonic_reference(
        &mut self,
        _ref_addr: Address,
        _ref_type: RefType,
        _source_type: SourceType,
    ) {
        unimplemented!("InstructionStub::add_mnemonic_reference")
    }

    /// Stands in for `InstructionStub.removeMnemonicReference(Address)`.
    fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {
        unimplemented!("InstructionStub::remove_mnemonic_reference")
    }

    /// Stands in for `InstructionStub.getMnemonicReferences()`.
    fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
        unimplemented!("InstructionStub::get_mnemonic_references")
    }

    /// Stands in for `InstructionStub.getOperandReferences(int)`.
    fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
        unimplemented!("InstructionStub::get_operand_references")
    }

    /// Stands in for `InstructionStub.getPrimaryReference(int)`.
    fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
        unimplemented!("InstructionStub::get_primary_reference")
    }

    /// Stands in for `InstructionStub.addOperandReference(int, Address, RefType, SourceType)`.
    fn add_operand_reference(
        &mut self,
        _index: i32,
        _ref_addr: Address,
        _ref_type: RefType,
        _source_type: SourceType,
    ) {
        unimplemented!("InstructionStub::add_operand_reference")
    }

    /// Stands in for `InstructionStub.removeOperandReference(int, Address)`.
    fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {
        unimplemented!("InstructionStub::remove_operand_reference")
    }

    /// Stands in for `InstructionStub.getReferencesFrom()`.
    fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
        unimplemented!("InstructionStub::get_references_from")
    }

    /// Stands in for `InstructionStub.getReferenceIteratorTo()`.
    fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
        unimplemented!("InstructionStub::get_reference_iterator_to")
    }

    /// Stands in for `InstructionStub.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program> {
        unimplemented!("InstructionStub::get_program")
    }

    /// Stands in for `InstructionStub.getExternalReference(int)`.
    fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
        unimplemented!("InstructionStub::get_external_reference")
    }

    /// Stands in for `InstructionStub.removeExternalReference(int)`.
    fn remove_external_reference(&mut self, _op_index: i32) {
        unimplemented!("InstructionStub::remove_external_reference")
    }

    /// Stands in for `InstructionStub.setPrimaryMemoryReference(Reference)`.
    fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {
        unimplemented!("InstructionStub::set_primary_memory_reference")
    }

    /// Stands in for `InstructionStub.setStackReference(int, int, SourceType, RefType)`.
    fn set_stack_reference(
        &mut self,
        _op_index: i32,
        _offset: i32,
        _source_type: SourceType,
        _ref_type: RefType,
    ) {
        unimplemented!("InstructionStub::set_stack_reference")
    }

    /// Stands in for `InstructionStub.setRegisterReference(int, Register, SourceType, RefType)`.
    fn set_register_reference(
        &mut self,
        _op_index: i32,
        _reg: &Register,
        _source_type: SourceType,
        _ref_type: RefType,
    ) {
        unimplemented!("InstructionStub::set_register_reference")
    }

    /// Stands in for `InstructionStub.getNumOperands()`.
    fn get_num_operands(&self) -> i32 {
        unimplemented!("InstructionStub::get_num_operands")
    }

    /// Stands in for `InstructionStub.getAddress(int)`. See the trait-level docs for why this is
    /// renamed from `get_address`.
    fn get_operand_address(&self, _op_index: i32) -> Option<Address> {
        unimplemented!("InstructionStub::get_operand_address")
    }

    /// Stands in for `InstructionStub.getScalar(int)`.
    fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
        unimplemented!("InstructionStub::get_scalar")
    }

    // ---- ProcessorContextView ----

    /// Stands in for `InstructionStub.getBaseContextRegister()`.
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        unimplemented!("InstructionStub::get_base_context_register")
    }

    /// Stands in for `InstructionStub.getRegisters()`.
    fn get_registers(&self) -> Vec<RegisterRef> {
        unimplemented!("InstructionStub::get_registers")
    }

    /// Stands in for `InstructionStub.getRegister(String)`. See the trait-level docs for why this
    /// is renamed from `get_register`.
    fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
        unimplemented!("InstructionStub::get_register_by_name")
    }

    /// Stands in for `InstructionStub.getValue(Register, boolean)`.
    fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
        unimplemented!("InstructionStub::get_value")
    }

    /// Stands in for `InstructionStub.getRegisterValue(Register)`.
    fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
        unimplemented!("InstructionStub::get_register_value")
    }

    /// Stands in for `InstructionStub.hasValue(Register)`.
    fn has_value(&self, _register: &Register) -> bool {
        unimplemented!("InstructionStub::has_value")
    }

    // ---- ProcessorContext ----

    /// Stands in for `InstructionStub.setValue(Register, BigInteger)`.
    fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> {
        unimplemented!("InstructionStub::set_value")
    }

    /// Stands in for `InstructionStub.setRegisterValue(RegisterValue)`.
    fn set_register_value(
        &mut self,
        _value: Box<dyn RegisterValue>,
    ) -> Result<(), ContextChangeException> {
        unimplemented!("InstructionStub::set_register_value")
    }

    /// Stands in for `InstructionStub.clearRegister(Register)`.
    fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
        unimplemented!("InstructionStub::clear_register")
    }

    // ---- Instruction ----

    /// Stands in for `InstructionStub.getPrototype()`.
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        unimplemented!("InstructionStub::get_prototype")
    }

    /// Stands in for `InstructionStub.getRegister(int)`.
    fn get_register(&self, _operand_index: i32) -> Option<RegisterRef> {
        unimplemented!("InstructionStub::get_register")
    }

    /// Stands in for `InstructionStub.getOpObjects(int)`.
    fn get_op_objects(&self, _operand_index: i32) -> Vec<OperandValue> {
        unimplemented!("InstructionStub::get_op_objects")
    }

    /// Stands in for `InstructionStub.getInputObjects()`.
    fn get_input_objects(&self) -> Vec<OperandValue> {
        unimplemented!("InstructionStub::get_input_objects")
    }

    /// Stands in for `InstructionStub.getResultObjects()`.
    fn get_result_objects(&self) -> Vec<OperandValue> {
        unimplemented!("InstructionStub::get_result_objects")
    }

    /// Stands in for `InstructionStub.getDefaultOperandRepresentation(int)`.
    fn get_default_operand_representation(&self, _operand_index: i32) -> String {
        unimplemented!("InstructionStub::get_default_operand_representation")
    }

    /// Stands in for `InstructionStub.getDefaultOperandRepresentationList(int)`.
    fn get_default_operand_representation_list(
        &self,
        _operand_index: i32,
    ) -> Option<Vec<OperandValue>> {
        unimplemented!("InstructionStub::get_default_operand_representation_list")
    }

    /// Stands in for `InstructionStub.getSeparator(int)`.
    fn get_separator(&self, _operand_index: i32) -> Option<String> {
        unimplemented!("InstructionStub::get_separator")
    }

    /// Stands in for `InstructionStub.getOperandType(int)`.
    fn get_operand_type(&self, _operand_index: i32) -> i32 {
        unimplemented!("InstructionStub::get_operand_type")
    }

    /// Stands in for `InstructionStub.getOperandRefType(int)`.
    fn get_operand_ref_type(&self, _index: i32) -> RefType {
        unimplemented!("InstructionStub::get_operand_ref_type")
    }

    /// Stands in for `InstructionStub.getDefaultFallThroughOffset()`.
    fn get_default_fall_through_offset(&self) -> i32 {
        unimplemented!("InstructionStub::get_default_fall_through_offset")
    }

    /// Stands in for `InstructionStub.getDefaultFallThrough()`.
    fn get_default_fall_through(&self) -> Option<Address> {
        unimplemented!("InstructionStub::get_default_fall_through")
    }

    /// Stands in for `InstructionStub.getFallThrough()`.
    fn get_fall_through(&self) -> Option<Address> {
        unimplemented!("InstructionStub::get_fall_through")
    }

    /// Stands in for `InstructionStub.getFallFrom()`.
    fn get_fall_from(&self) -> Option<Address> {
        unimplemented!("InstructionStub::get_fall_from")
    }

    /// Stands in for `InstructionStub.getFlows()`.
    fn get_flows(&self) -> Option<Vec<Address>> {
        unimplemented!("InstructionStub::get_flows")
    }

    /// Stands in for `InstructionStub.getDefaultFlows()`.
    fn get_default_flows(&self) -> Option<Vec<Address>> {
        unimplemented!("InstructionStub::get_default_flows")
    }

    /// Stands in for `InstructionStub.getFlowType()`.
    fn get_flow_type(&self) -> RefType {
        unimplemented!("InstructionStub::get_flow_type")
    }

    /// Stands in for `InstructionStub.isFallthrough()`.
    fn is_fallthrough(&self) -> bool {
        unimplemented!("InstructionStub::is_fallthrough")
    }

    /// Stands in for `InstructionStub.hasFallthrough()`.
    fn has_fallthrough(&self) -> bool {
        unimplemented!("InstructionStub::has_fallthrough")
    }

    /// Stands in for `InstructionStub.getFlowOverride()`.
    fn get_flow_override(&self) -> FlowOverride {
        unimplemented!("InstructionStub::get_flow_override")
    }

    /// Stands in for `InstructionStub.setFlowOverride(FlowOverride)`.
    fn set_flow_override(&mut self, _flow_override: FlowOverride) {
        unimplemented!("InstructionStub::set_flow_override")
    }

    /// Stands in for `InstructionStub.setLengthOverride(int)`.
    fn set_length_override(&mut self, _length: i32) -> Result<(), CodeUnitInsertionException> {
        unimplemented!("InstructionStub::set_length_override")
    }

    /// Stands in for `InstructionStub.isLengthOverridden()`.
    fn is_length_overridden(&self) -> bool {
        unimplemented!("InstructionStub::is_length_overridden")
    }

    /// Stands in for `InstructionStub.getParsedLength()`.
    fn get_parsed_length(&self) -> i32 {
        unimplemented!("InstructionStub::get_parsed_length")
    }

    /// Stands in for `InstructionStub.getParsedBytes()`.
    fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        unimplemented!("InstructionStub::get_parsed_bytes")
    }

    /// Stands in for `InstructionStub.getPcode()`.
    fn get_pcode(&self) -> Vec<PcodeOp> {
        unimplemented!("InstructionStub::get_pcode")
    }

    /// Stands in for `InstructionStub.getPcode(boolean)`.
    fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<PcodeOp> {
        unimplemented!("InstructionStub::get_pcode_with_overrides")
    }

    /// Stands in for `InstructionStub.getPcode(int)`.
    fn get_pcode_for_operand(&self, _operand_index: i32) -> Vec<PcodeOp> {
        unimplemented!("InstructionStub::get_pcode_for_operand")
    }

    /// Stands in for `InstructionStub.getDelaySlotDepth()`.
    fn get_delay_slot_depth(&self) -> i32 {
        unimplemented!("InstructionStub::get_delay_slot_depth")
    }

    /// Stands in for `InstructionStub.isInDelaySlot()`.
    fn is_in_delay_slot(&self) -> bool {
        unimplemented!("InstructionStub::is_in_delay_slot")
    }

    /// Stands in for `InstructionStub.getNext()`.
    fn get_next(&self) -> Option<Arc<dyn Instruction>> {
        unimplemented!("InstructionStub::get_next")
    }

    /// Stands in for `InstructionStub.getPrevious()`.
    fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
        unimplemented!("InstructionStub::get_previous")
    }

    /// Stands in for `InstructionStub.setFallThrough(Address)`.
    fn set_fall_through(&mut self, _addr: Option<Address>) {
        unimplemented!("InstructionStub::set_fall_through")
    }

    /// Stands in for `InstructionStub.clearFallThroughOverride()`.
    fn clear_fall_through_override(&mut self) {
        unimplemented!("InstructionStub::clear_fall_through_override")
    }

    /// Stands in for `InstructionStub.isFallThroughOverridden()`.
    fn is_fall_through_overridden(&self) -> bool {
        unimplemented!("InstructionStub::is_fall_through_overridden")
    }

    /// Stands in for `InstructionStub.getInstructionContext()`.
    fn get_instruction_context(&self) -> Arc<dyn InstructionContext> {
        unimplemented!("InstructionStub::get_instruction_context")
    }
}

impl<T: InstructionStub + Send + Sync> PropertySet for T {
    fn set_object_property(&mut self, name: &str, value: Box<dyn Saveable>) {
        InstructionStub::set_object_property(self, name, value)
    }
    fn set_string_property(&mut self, name: &str, value: &str) {
        InstructionStub::set_string_property(self, name, value)
    }
    fn set_int_property(&mut self, name: &str, value: i32) {
        InstructionStub::set_int_property(self, name, value)
    }
    fn set_void_property(&mut self, name: &str) {
        InstructionStub::set_void_property(self, name)
    }
    fn get_object_property(&self, name: &str) -> Option<Box<dyn Saveable>> {
        InstructionStub::get_object_property(self, name)
    }
    fn get_string_property(&self, name: &str) -> Option<String> {
        InstructionStub::get_string_property(self, name)
    }
    fn get_int_property(&self, name: &str) -> Result<i32, NoValueException> {
        InstructionStub::get_int_property(self, name)
    }
    fn has_property(&self, name: &str) -> bool {
        InstructionStub::has_property(self, name)
    }
    fn get_void_property(&self, name: &str) -> bool {
        InstructionStub::get_void_property(self, name)
    }
    fn property_names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        InstructionStub::property_names(self)
    }
    fn remove_property(&mut self, name: &str) {
        InstructionStub::remove_property(self, name)
    }
}

impl<T: InstructionStub + Send + Sync> MemBuffer for T {
    fn get_address(&self) -> Address {
        InstructionStub::get_membuffer_address(self)
    }

    // Java's InstructionStub throws UnsupportedOperationException for each of these; the stub
    // exists to be subclassed, and a subclass that needs byte access overrides them. Panicking
    // is the faithful rendering -- a silent default would let a caller read zeros and believe
    // them.
    fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
        unimplemented!("InstructionStub::get_byte -- override in the concrete instruction")
    }

    fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
        unimplemented!("InstructionStub::get_bytes -- override in the concrete instruction")
    }

    fn is_big_endian(&self) -> bool {
        unimplemented!("InstructionStub::is_big_endian -- override in the concrete instruction")
    }
}

impl<T: InstructionStub + Send + Sync> CodeUnit for T {
    fn get_address_string(&self, show_block_name: bool, pad: bool) -> String {
        InstructionStub::get_address_string(self, show_block_name, pad)
    }
    fn get_label(&self) -> Option<String> {
        InstructionStub::get_label(self)
    }
    fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
        InstructionStub::get_symbols(self)
    }
    fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
        InstructionStub::get_primary_symbol(self)
    }
    fn get_min_address(&self) -> Address {
        InstructionStub::get_min_address(self)
    }
    fn get_max_address(&self) -> Address {
        InstructionStub::get_max_address(self)
    }
    fn get_mnemonic_string(&self) -> String {
        InstructionStub::get_mnemonic_string(self)
    }
    fn get_comment(&self, comment_type: CommentType) -> Option<String> {
        InstructionStub::get_comment(self, comment_type)
    }
    fn get_comment_as_array(&self, comment_type: CommentType) -> Vec<String> {
        InstructionStub::get_comment_as_array(self, comment_type)
    }
    fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>) {
        InstructionStub::set_comment(self, comment_type, comment)
    }
    fn set_comment_as_array(&mut self, comment_type: CommentType, comment: &[String]) {
        InstructionStub::set_comment_as_array(self, comment_type, comment)
    }
    fn get_length(&self) -> i32 {
        InstructionStub::get_length(self)
    }
    fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        InstructionStub::get_bytes(self)
    }
    fn get_bytes_in_code_unit(
        &self,
        buffer: &mut [u8],
        buffer_offset: i32,
    ) -> Result<(), MemoryAccessException> {
        InstructionStub::get_bytes_in_code_unit(self, buffer, buffer_offset)
    }
    fn contains(&self, test_addr: &Address) -> bool {
        InstructionStub::contains(self, test_addr)
    }
    fn compare_to(&self, addr: &Address) -> i32 {
        InstructionStub::compare_to(self, addr)
    }
    fn add_mnemonic_reference(&mut self, ref_addr: Address, ref_type: RefType, source_type: SourceType) {
        InstructionStub::add_mnemonic_reference(self, ref_addr, ref_type, source_type)
    }
    fn remove_mnemonic_reference(&mut self, ref_addr: &Address) {
        InstructionStub::remove_mnemonic_reference(self, ref_addr)
    }
    fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
        InstructionStub::get_mnemonic_references(self)
    }
    fn get_operand_references(&self, index: i32) -> Vec<Arc<dyn Reference>> {
        InstructionStub::get_operand_references(self, index)
    }
    fn get_primary_reference(&self, index: i32) -> Option<Arc<dyn Reference>> {
        InstructionStub::get_primary_reference(self, index)
    }
    fn add_operand_reference(
        &mut self,
        index: i32,
        ref_addr: Address,
        ref_type: RefType,
        source_type: SourceType,
    ) {
        InstructionStub::add_operand_reference(self, index, ref_addr, ref_type, source_type)
    }
    fn remove_operand_reference(&mut self, index: i32, ref_addr: &Address) {
        InstructionStub::remove_operand_reference(self, index, ref_addr)
    }
    fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
        InstructionStub::get_references_from(self)
    }
    fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
        InstructionStub::get_reference_iterator_to(self)
    }
    fn get_program(&self) -> Arc<dyn Program> {
        InstructionStub::get_program(self)
    }
    fn get_external_reference(&self, op_index: i32) -> Option<Arc<dyn ExternalReference>> {
        InstructionStub::get_external_reference(self, op_index)
    }
    fn remove_external_reference(&mut self, op_index: i32) {
        InstructionStub::remove_external_reference(self, op_index)
    }
    fn set_primary_memory_reference(&mut self, reference: Arc<dyn Reference>) {
        InstructionStub::set_primary_memory_reference(self, reference)
    }
    fn set_stack_reference(
        &mut self,
        op_index: i32,
        offset: i32,
        source_type: SourceType,
        ref_type: RefType,
    ) {
        InstructionStub::set_stack_reference(self, op_index, offset, source_type, ref_type)
    }
    fn set_register_reference(
        &mut self,
        op_index: i32,
        reg: &Register,
        source_type: SourceType,
        ref_type: RefType,
    ) {
        InstructionStub::set_register_reference(self, op_index, reg, source_type, ref_type)
    }
    fn get_num_operands(&self) -> i32 {
        InstructionStub::get_num_operands(self)
    }
    fn get_address(&self, op_index: i32) -> Option<Address> {
        InstructionStub::get_operand_address(self, op_index)
    }
    fn get_scalar(&self, op_index: i32) -> Option<Scalar> {
        InstructionStub::get_scalar(self, op_index)
    }
}

impl<T: InstructionStub + Send + Sync> ProcessorContextView for T {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        InstructionStub::get_base_context_register(self)
    }
    fn get_registers(&self) -> Vec<RegisterRef> {
        InstructionStub::get_registers(self)
    }
    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        InstructionStub::get_register_by_name(self, name)
    }
    fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        InstructionStub::get_value(self, register, signed)
    }
    fn get_register_value(&self, register: &Register) -> Option<Box<dyn RegisterValue>> {
        InstructionStub::get_register_value(self, register)
    }
    fn has_value(&self, register: &Register) -> bool {
        InstructionStub::has_value(self, register)
    }
}

impl<T: InstructionStub + Send + Sync> ProcessorContext for T {
    fn set_value(&mut self, register: &Register, value: i128) -> Result<(), ContextChangeException> {
        InstructionStub::set_value(self, register, value)
    }
    fn set_register_value(
        &mut self,
        value: Box<dyn RegisterValue>,
    ) -> Result<(), ContextChangeException> {
        InstructionStub::set_register_value(self, value)
    }
    fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException> {
        InstructionStub::clear_register(self, register)
    }
}

impl<T: InstructionStub + Send + Sync> Instruction for T {
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        InstructionStub::get_prototype(self)
    }
    fn get_register(&self, operand_index: i32) -> Option<RegisterRef> {
        InstructionStub::get_register(self, operand_index)
    }
    fn get_op_objects(&self, operand_index: i32) -> Vec<OperandValue> {
        InstructionStub::get_op_objects(self, operand_index)
    }
    fn get_input_objects(&self) -> Vec<OperandValue> {
        InstructionStub::get_input_objects(self)
    }
    fn get_result_objects(&self) -> Vec<OperandValue> {
        InstructionStub::get_result_objects(self)
    }
    fn get_default_operand_representation(&self, operand_index: i32) -> String {
        InstructionStub::get_default_operand_representation(self, operand_index)
    }
    fn get_default_operand_representation_list(
        &self,
        operand_index: i32,
    ) -> Option<Vec<OperandValue>> {
        InstructionStub::get_default_operand_representation_list(self, operand_index)
    }
    fn get_separator(&self, operand_index: i32) -> Option<String> {
        InstructionStub::get_separator(self, operand_index)
    }
    fn get_operand_type(&self, operand_index: i32) -> i32 {
        InstructionStub::get_operand_type(self, operand_index)
    }
    fn get_operand_ref_type(&self, index: i32) -> RefType {
        InstructionStub::get_operand_ref_type(self, index)
    }
    fn get_default_fall_through_offset(&self) -> i32 {
        InstructionStub::get_default_fall_through_offset(self)
    }
    fn get_default_fall_through(&self) -> Option<Address> {
        InstructionStub::get_default_fall_through(self)
    }
    fn get_fall_through(&self) -> Option<Address> {
        InstructionStub::get_fall_through(self)
    }
    fn get_fall_from(&self) -> Option<Address> {
        InstructionStub::get_fall_from(self)
    }
    fn get_flows(&self) -> Option<Vec<Address>> {
        InstructionStub::get_flows(self)
    }
    fn get_default_flows(&self) -> Option<Vec<Address>> {
        InstructionStub::get_default_flows(self)
    }
    fn get_flow_type(&self) -> RefType {
        InstructionStub::get_flow_type(self)
    }
    fn is_fallthrough(&self) -> bool {
        InstructionStub::is_fallthrough(self)
    }
    fn has_fallthrough(&self) -> bool {
        InstructionStub::has_fallthrough(self)
    }
    fn get_flow_override(&self) -> FlowOverride {
        InstructionStub::get_flow_override(self)
    }
    fn set_flow_override(&mut self, flow_override: FlowOverride) {
        InstructionStub::set_flow_override(self, flow_override)
    }
    fn set_length_override(&mut self, length: i32) -> Result<(), CodeUnitInsertionException> {
        InstructionStub::set_length_override(self, length)
    }
    fn is_length_overridden(&self) -> bool {
        InstructionStub::is_length_overridden(self)
    }
    fn get_parsed_length(&self) -> i32 {
        InstructionStub::get_parsed_length(self)
    }
    fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        InstructionStub::get_parsed_bytes(self)
    }
    fn get_pcode(&self) -> Vec<PcodeOp> {
        InstructionStub::get_pcode(self)
    }
    fn get_pcode_with_overrides(&self, include_overrides: bool) -> Vec<PcodeOp> {
        InstructionStub::get_pcode_with_overrides(self, include_overrides)
    }
    fn get_pcode_for_operand(&self, operand_index: i32) -> Vec<PcodeOp> {
        InstructionStub::get_pcode_for_operand(self, operand_index)
    }
    fn get_delay_slot_depth(&self) -> i32 {
        InstructionStub::get_delay_slot_depth(self)
    }
    fn is_in_delay_slot(&self) -> bool {
        InstructionStub::is_in_delay_slot(self)
    }
    fn get_next(&self) -> Option<Arc<dyn Instruction>> {
        InstructionStub::get_next(self)
    }
    fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
        InstructionStub::get_previous(self)
    }
    fn set_fall_through(&mut self, addr: Option<Address>) {
        InstructionStub::set_fall_through(self, addr)
    }
    fn clear_fall_through_override(&mut self) {
        InstructionStub::clear_fall_through_override(self)
    }
    fn is_fall_through_overridden(&self) -> bool {
        InstructionStub::is_fall_through_overridden(self)
    }
    fn get_instruction_context(&self) -> Arc<dyn InstructionContext> {
        InstructionStub::get_instruction_context(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test double using only the `InstructionStub` defaults, proving the trait is object-safe
    /// and that its blanket `Instruction` impl lets it stand in wherever an `Instruction` is
    /// expected -- just like `new InstructionStub() {}` in Java.
    struct BareStub;
    impl InstructionStub for BareStub {}

    /// A test double overriding a couple of methods, mirroring how Java tests subclass
    /// `InstructionStub` and override only what they need.
    struct CountingStub {
        length: i32,
    }
    impl InstructionStub for CountingStub {
        fn get_length(&self) -> i32 {
            self.length
        }

        fn is_fallthrough(&self) -> bool {
            true
        }
    }

    #[test]
    #[should_panic]
    fn bare_stub_panics_on_unoverridden_methods() {
        let stub: Box<dyn Instruction> = Box::new(BareStub);
        stub.get_length();
    }

    #[test]
    fn overriding_methods_works_through_the_instruction_trait_object() {
        let stub: Box<dyn Instruction> = Box::new(CountingStub { length: 4 });
        assert_eq!(stub.get_length(), 4);
        assert!(stub.is_fallthrough());
    }

    #[test]
    #[should_panic]
    fn unoverridden_processor_context_method_panics_through_trait_object() {
        let stub: Box<dyn Instruction> = Box::new(CountingStub { length: 4 });
        let register = make_register();
        stub.has_value(&register.borrow());
    }

    fn make_register() -> RegisterRef {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Register::new("r0", "General register", Address::new(space, 0), 4, false, 0)
    }
}

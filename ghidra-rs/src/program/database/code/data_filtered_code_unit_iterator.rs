//! Port of `ghidra.program.database.code.DataFilteredCodeUnitIterator`.
//!
//! Converts a [`CodeUnitIterator`] into a [`DataIterator`] by skipping every code unit that is
//! not [`Data`].
//!
//! # The `Arc<dyn CodeUnit>` -> `Box<dyn Data>` seam
//!
//! [`CodeUnitIterator`]'s item type is a *shared* `Arc<dyn CodeUnit>` (arbitrary source -- it
//! could come from `CodeUnitRecordIterator`, `CodeUnitKeyIterator`, or any future implementation),
//! while [`DataIterator`]'s item type is an *owned* `Box<dyn Data>`. `CodeUnit::as_data` can prove
//! at runtime that a given `Arc<dyn CodeUnit>` is also `Data`, but it only ever hands back a
//! *borrowed* `&dyn Data` tied to that `Arc`'s lifetime -- there is no generic way to turn an
//! arbitrary `Arc<dyn CodeUnit>` into an owned `Box<dyn Data>` (unlike
//! [`DataRecordIterator`](super::data_record_iterator::DataRecordIterator)/
//! [`DataKeyIterator`](super::data_key_iterator::DataKeyIterator), which start from a concrete
//! `DataDB` and can call its crate-internal `DataDb::to_boxed_data`; a plain `CodeUnitIterator`
//! makes no such guarantee about what is behind its `Arc<dyn CodeUnit>`).
//!
//! [`DataView`] is the honest way through: rather than trying to *extract* an owned `Data` from
//! the shared code unit, it *wraps* the `Arc<dyn CodeUnit>` in a new, uniquely-owned struct that
//! implements `Data` (and its `CodeUnit`/`Settings`/`MemBuffer`/`PropertySet` supertraits) by
//! forwarding every read to `self.0.as_data().expect(..)` at call time. Boxing *that* wrapper
//! satisfies `Box<dyn Data>` without needing to move or clone the underlying code unit at all.
//!
//! The one real limitation this introduces: `CodeUnit`/`Data`'s mutating methods (`set_comment`,
//! `add_mnemonic_reference`, `add_value_reference`, ...) take `&mut self`, which would require
//! `&mut dyn CodeUnit` to forward to -- and a shared `Arc<dyn CodeUnit>` can never yield one
//! (`Arc::get_mut` only succeeds at reference count 1, which a cached, iterator-shared code unit
//! essentially never is). This is not a limitation `DataFilteredCodeUnitIterator` introduces on
//! its own: nothing downstream of a plain `CodeUnitIterator`'s `Arc<dyn CodeUnit>` output could
//! mutate through it either, for the identical reason. Each such method is marked `TODO(port)`
//! at its site rather than silently doing nothing important -- the class's actual job (per its
//! Java doc, "Converts a code unit iterator into a data iterator") is read-only filtering, and
//! every read-only method is a real, working forward.

use std::any::{Any, TypeId};
use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::lang::register::Register;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::code_unit_iterator::CodeUnitIterator;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::data_iterator::DataIterator;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::CommentType;
use crate::program::model::mem::{MemBuffer, Memory, MemoryAccessException};
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::{
    ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
    SourceType, Symbol,
};
use crate::program::model::util::PropertySet;
use crate::program::seam_stubs::{RefType, Reference};
use crate::util::exception::NoValueException;
use crate::util::saveable::Saveable;

/// A read-only `Data` view over an `Arc<dyn CodeUnit>` already confirmed (via
/// [`CodeUnit::as_data`]) to also implement [`Data`]. See the module docs.
struct DataView(Arc<dyn CodeUnit>);

impl DataView {
    /// # Panics
    /// Panics if this `DataView` was constructed over a code unit that is not `Data` -- which
    /// [`DataFilteredCodeUnitIterator::next`] never does; see its body.
    fn data(&self) -> &dyn Data {
        self.0
            .as_data()
            .expect("DataView only ever wraps a code unit already confirmed to be Data")
    }
}

impl MemBuffer for DataView {
    fn get_address(&self) -> Address {
        MemBuffer::get_address(self.data())
    }
    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        MemBuffer::get_byte(self.data(), offset)
    }
    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        MemBuffer::get_bytes(self.data(), buf, offset)
    }
    fn is_big_endian(&self) -> bool {
        MemBuffer::is_big_endian(self.data())
    }
    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        MemBuffer::get_memory(self.data())
    }
}

impl PropertySet for DataView {
    fn get_object_property(&self, name: &str) -> Option<Box<dyn Saveable>> {
        PropertySet::get_object_property(self.data(), name)
    }
    fn get_string_property(&self, name: &str) -> Option<String> {
        PropertySet::get_string_property(self.data(), name)
    }
    fn get_int_property(&self, name: &str) -> Result<i32, NoValueException> {
        PropertySet::get_int_property(self.data(), name)
    }
    fn has_property(&self, name: &str) -> bool {
        PropertySet::has_property(self.data(), name)
    }
    fn get_void_property(&self, name: &str) -> bool {
        PropertySet::get_void_property(self.data(), name)
    }
    fn property_names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        PropertySet::property_names(self.data())
    }
    // set_object_property/set_string_property/set_int_property/set_void_property/remove_property
    // keep their no-op defaults -- see the module docs on why mutation cannot be forwarded.
}

impl Settings for DataView {
    fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
        Settings::get_default_settings(self.data())
    }
    fn get_long(&self, name: &str) -> Option<i64> {
        Settings::get_long(self.data(), name)
    }
    fn get_string(&self, name: &str) -> Option<String> {
        Settings::get_string(self.data(), name)
    }
    fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
        Settings::get_value(self.data(), name)
    }
    fn get_names(&self) -> Vec<String> {
        Settings::get_names(self.data())
    }
    fn is_empty(&self) -> bool {
        Settings::is_empty(self.data())
    }
    fn is_change_allowed(&self, settings_definition: &dyn SettingsDefinition) -> bool {
        Settings::is_change_allowed(self.data(), settings_definition)
    }
    // set_long/set_string/set_value/clear_setting/clear_all_settings keep their no-op defaults --
    // see the module docs.
}

impl CodeUnit for DataView {
    fn get_address_string(&self, show_block_name: bool, pad: bool) -> String {
        CodeUnit::get_address_string(self.data(), show_block_name, pad)
    }
    fn get_label(&self) -> Option<String> {
        CodeUnit::get_label(self.data())
    }
    fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
        CodeUnit::get_symbols(self.data())
    }
    fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
        CodeUnit::get_primary_symbol(self.data())
    }
    fn get_min_address(&self) -> Address {
        CodeUnit::get_min_address(self.data())
    }
    fn get_max_address(&self) -> Address {
        CodeUnit::get_max_address(self.data())
    }
    fn get_mnemonic_string(&self) -> String {
        CodeUnit::get_mnemonic_string(self.data())
    }
    fn get_comment(&self, comment_type: CommentType) -> Option<String> {
        CodeUnit::get_comment(self.data(), comment_type)
    }
    fn get_comment_as_array(&self, comment_type: CommentType) -> Vec<String> {
        CodeUnit::get_comment_as_array(self.data(), comment_type)
    }
    fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn get_length(&self) -> i32 {
        CodeUnit::get_length(self.data())
    }
    fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        CodeUnit::get_bytes(self.data())
    }
    fn get_bytes_in_code_unit(
        &self,
        buffer: &mut [u8],
        buffer_offset: i32,
    ) -> Result<(), MemoryAccessException> {
        CodeUnit::get_bytes_in_code_unit(self.data(), buffer, buffer_offset)
    }
    fn contains(&self, test_addr: &Address) -> bool {
        CodeUnit::contains(self.data(), test_addr)
    }
    fn compare_to(&self, addr: &Address) -> i32 {
        CodeUnit::compare_to(self.data(), addr)
    }
    fn add_mnemonic_reference(
        &mut self,
        _ref_addr: Address,
        _ref_type: SymRefType,
        _source_type: SourceType,
    ) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
        CodeUnit::get_mnemonic_references(self.data())
    }
    fn get_operand_references(&self, index: i32) -> Vec<Arc<dyn SymReference>> {
        CodeUnit::get_operand_references(self.data(), index)
    }
    fn get_primary_reference(&self, index: i32) -> Option<Arc<dyn SymReference>> {
        CodeUnit::get_primary_reference(self.data(), index)
    }
    fn add_operand_reference(
        &mut self,
        _index: i32,
        _ref_addr: Address,
        _ref_type: SymRefType,
        _source_type: SourceType,
    ) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
        CodeUnit::get_references_from(self.data())
    }
    fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
        CodeUnit::get_reference_iterator_to(self.data())
    }
    fn get_program(&self) -> Arc<dyn Program> {
        CodeUnit::get_program(self.data())
    }
    fn get_external_reference(&self, op_index: i32) -> Option<Arc<dyn ExternalReference>> {
        CodeUnit::get_external_reference(self.data(), op_index)
    }
    fn remove_external_reference(&mut self, _op_index: i32) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn set_primary_memory_reference(&mut self, _reference: Arc<dyn SymReference>) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn set_stack_reference(
        &mut self,
        _op_index: i32,
        _offset: i32,
        _source_type: SourceType,
        _ref_type: SymRefType,
    ) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn set_register_reference(
        &mut self,
        _op_index: i32,
        _reg: &Register,
        _source_type: SourceType,
        _ref_type: SymRefType,
    ) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn get_num_operands(&self) -> i32 {
        CodeUnit::get_num_operands(self.data())
    }
    fn get_address(&self, op_index: i32) -> Option<Address> {
        CodeUnit::get_address(self.data(), op_index)
    }
    fn get_scalar(&self, op_index: i32) -> Option<Scalar> {
        CodeUnit::get_scalar(self.data(), op_index)
    }
    fn as_data(&self) -> Option<&dyn Data> {
        Some(self.data())
    }
}

impl Data for DataView {
    fn get_value(&self) -> Option<Box<dyn Any>> {
        Data::get_value(self.data())
    }
    fn get_value_class(&self) -> Option<TypeId> {
        Data::get_value_class(self.data())
    }
    fn has_string_value(&self) -> bool {
        Data::has_string_value(self.data())
    }
    fn is_constant(&self) -> bool {
        Data::is_constant(self.data())
    }
    fn is_writable(&self) -> bool {
        Data::is_writable(self.data())
    }
    fn is_volatile(&self) -> bool {
        Data::is_volatile(self.data())
    }
    fn is_defined(&self) -> bool {
        Data::is_defined(self.data())
    }
    fn get_data_type(&self) -> Box<dyn DataType> {
        Data::get_data_type(self.data())
    }
    fn get_base_data_type(&self) -> Box<dyn DataType> {
        Data::get_base_data_type(self.data())
    }
    fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
        Data::get_value_references(self.data())
    }
    fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn remove_value_reference(&mut self, _ref_addr: Address) {
        // TODO(port): cannot forward -- see the module docs.
    }
    fn get_field_name(&self) -> Option<String> {
        Data::get_field_name(self.data())
    }
    fn get_path_name(&self) -> String {
        Data::get_path_name(self.data())
    }
    fn get_component_path_name(&self) -> String {
        Data::get_component_path_name(self.data())
    }
    fn is_pointer(&self) -> bool {
        Data::is_pointer(self.data())
    }
    fn is_union(&self) -> bool {
        Data::is_union(self.data())
    }
    fn is_structure(&self) -> bool {
        Data::is_structure(self.data())
    }
    fn is_array(&self) -> bool {
        Data::is_array(self.data())
    }
    fn is_dynamic(&self) -> bool {
        Data::is_dynamic(self.data())
    }
    fn get_parent(&self) -> Option<Box<dyn Data>> {
        Data::get_parent(self.data())
    }
    fn get_root(&self) -> Box<dyn Data> {
        Data::get_root(self.data())
    }
    fn get_root_offset(&self) -> i32 {
        Data::get_root_offset(self.data())
    }
    fn get_parent_offset(&self) -> i32 {
        Data::get_parent_offset(self.data())
    }
    fn get_component(&self, index: i32) -> Option<Box<dyn Data>> {
        Data::get_component(self.data(), index)
    }
    fn get_component_by_path(&self, component_path: &[i32]) -> Option<Box<dyn Data>> {
        Data::get_component_by_path(self.data(), component_path)
    }
    fn get_component_path(&self) -> Vec<i32> {
        Data::get_component_path(self.data())
    }
    fn get_num_components(&self) -> i32 {
        Data::get_num_components(self.data())
    }
    #[allow(deprecated)]
    fn get_component_at(&self, offset: i32) -> Option<Box<dyn Data>> {
        Data::get_component_at(self.data(), offset)
    }
    fn get_component_containing(&self, offset: i32) -> Option<Box<dyn Data>> {
        Data::get_component_containing(self.data(), offset)
    }
    fn get_components_containing(&self, offset: i32) -> Option<Vec<Box<dyn Data>>> {
        Data::get_components_containing(self.data(), offset)
    }
    fn get_primitive_at(&self, offset: i32) -> Option<Box<dyn Data>> {
        Data::get_primitive_at(self.data(), offset)
    }
    fn get_component_index(&self) -> i32 {
        Data::get_component_index(self.data())
    }
    fn get_component_level(&self) -> i32 {
        Data::get_component_level(self.data())
    }
    fn get_default_value_representation(&self) -> String {
        Data::get_default_value_representation(self.data())
    }
    fn get_default_label_prefix(&self, options: &dyn DataTypeDisplayOptions) -> Option<String> {
        Data::get_default_label_prefix(self.data(), options)
    }
}

/// Converts a code unit iterator into a data iterator.
///
/// Port of `ghidra.program.database.code.DataFilteredCodeUnitIterator`. See the module docs for
/// the `Arc<dyn CodeUnit>` -> `Box<dyn Data>` seam this class has to cross.
pub struct DataFilteredCodeUnitIterator {
    it: Box<dyn CodeUnitIterator>,
}

impl DataFilteredCodeUnitIterator {
    /// Constructs a new `DataFilteredCodeUnitIterator`.
    ///
    /// # Arguments
    /// * `it` - the code unit iterator to filter on
    pub fn new(it: Box<dyn CodeUnitIterator>) -> Self {
        DataFilteredCodeUnitIterator { it }
    }
}

impl Iterator for DataFilteredCodeUnitIterator {
    type Item = Box<dyn Data>;

    /// Port of the private `DataFilteredCodeUnitIterator.findNext()`.
    fn next(&mut self) -> Option<Self::Item> {
        for cu in self.it.by_ref() {
            if cu.as_data().is_some() {
                return Some(Box::new(DataView(cu)));
            }
        }
        None
    }
}

impl DataIterator for DataFilteredCodeUnitIterator {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::program::Program;
    use crate::program::model::scalar::Scalar;
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    /// A `CodeUnit` that is *not* `Data` (leaves `as_data` at its `None` default) -- an
    /// instruction stand-in for the filter to skip.
    struct PlainCodeUnit {
        address: Address,
    }

    impl MemBuffer for PlainCodeUnit {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
    }
    impl PropertySet for PlainCodeUnit {}
    impl CodeUnit for PlainCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            String::new()
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            "NOP".to_string()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            *test_addr == self.address
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn SymReference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by these tests")
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn SymReference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            0
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    /// Reuses `PlainCodeUnit`'s field/behavior via composition, adding just enough `Data` surface
    /// to be a meaningful, distinguishable fixture (a fixed mnemonic + length + defined-ness the
    /// tests can assert on to prove the *real* object is reachable through `DataView`, not merely
    /// that dispatch happened).
    struct TestDataUnit {
        inner: PlainCodeUnit,
    }

    impl MemBuffer for TestDataUnit {
        fn get_address(&self) -> Address {
            MemBuffer::get_address(&self.inner)
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            MemBuffer::get_byte(&self.inner, offset)
        }
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            MemBuffer::get_bytes(&self.inner, buf, offset)
        }
        fn is_big_endian(&self) -> bool {
            MemBuffer::is_big_endian(&self.inner)
        }
    }
    impl PropertySet for TestDataUnit {}
    impl CodeUnit for TestDataUnit {
        fn get_address_string(&self, show_block_name: bool, pad: bool) -> String {
            self.inner.get_address_string(show_block_name, pad)
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.inner.get_min_address()
        }
        fn get_max_address(&self) -> Address {
            self.inner.get_max_address()
        }
        fn get_mnemonic_string(&self) -> String {
            "db".to_string()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x42])
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            self.inner.contains(test_addr)
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            self.inner.compare_to(addr)
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn SymReference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by these tests")
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn SymReference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
        fn as_data(&self) -> Option<&dyn Data> {
            Some(self)
        }
    }

    impl Settings for TestDataUnit {}
    impl Data for TestDataUnit {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            None
        }
        fn get_value_class(&self) -> Option<TypeId> {
            None
        }
        fn has_string_value(&self) -> bool {
            false
        }
        fn is_constant(&self) -> bool {
            false
        }
        fn is_writable(&self) -> bool {
            true
        }
        fn is_volatile(&self) -> bool {
            false
        }
        fn is_defined(&self) -> bool {
            true
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            struct D;
            impl DataType for D {}
            Box::new(D)
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            struct D;
            impl DataType for D {}
            Box::new(D)
        }
        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            String::new()
        }
        fn get_component_path_name(&self) -> String {
            String::new()
        }
        fn is_pointer(&self) -> bool {
            false
        }
        fn is_union(&self) -> bool {
            false
        }
        fn is_structure(&self) -> bool {
            false
        }
        fn is_array(&self) -> bool {
            false
        }
        fn is_dynamic(&self) -> bool {
            false
        }
        fn get_parent(&self) -> Option<Box<dyn Data>> {
            None
        }
        fn get_root(&self) -> Box<dyn Data> {
            unimplemented!("not exercised by these tests")
        }
        fn get_root_offset(&self) -> i32 {
            0
        }
        fn get_parent_offset(&self) -> i32 {
            0
        }
        fn get_component(&self, _index: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_path(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_num_components(&self) -> i32 {
            0
        }
        #[allow(deprecated)]
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> {
            None
        }
        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_index(&self) -> i32 {
            -1
        }
        fn get_component_level(&self) -> i32 {
            0
        }
        fn get_default_value_representation(&self) -> String {
            String::new()
        }
        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> {
            None
        }
    }

    fn addr(offset: i64) -> Address {
        space().address(offset)
    }

    struct VecCodeUnitIterator {
        items: std::vec::IntoIter<Arc<dyn CodeUnit>>,
    }

    impl Iterator for VecCodeUnitIterator {
        type Item = Arc<dyn CodeUnit>;
        fn next(&mut self) -> Option<Self::Item> {
            self.items.next()
        }
    }
    impl CodeUnitIterator for VecCodeUnitIterator {}

    #[test]
    fn skips_non_data_code_units_and_yields_only_data() {
        let items: Vec<Arc<dyn CodeUnit>> = vec![
            Arc::new(PlainCodeUnit { address: addr(0x1000) }),
            Arc::new(TestDataUnit {
                inner: PlainCodeUnit { address: addr(0x1002) },
            }),
            Arc::new(PlainCodeUnit { address: addr(0x1003) }),
            Arc::new(TestDataUnit {
                inner: PlainCodeUnit { address: addr(0x1004) },
            }),
        ];
        let source = VecCodeUnitIterator {
            items: items.into_iter(),
        };

        let mut iter = DataFilteredCodeUnitIterator::new(Box::new(source));

        let first = iter.next().expect("first data item");
        assert_eq!(first.get_min_address(), addr(0x1002));
        assert_eq!(first.get_mnemonic_string(), "db");

        let second = iter.next().expect("second data item");
        assert_eq!(second.get_min_address(), addr(0x1004));

        assert!(iter.next().is_none());
    }

    #[test]
    fn empty_source_yields_nothing() {
        let source = VecCodeUnitIterator {
            items: Vec::new().into_iter(),
        };
        let mut iter = DataFilteredCodeUnitIterator::new(Box::new(source));
        assert!(iter.next().is_none());
    }

    #[test]
    fn all_non_data_yields_nothing() {
        let items: Vec<Arc<dyn CodeUnit>> = vec![
            Arc::new(PlainCodeUnit { address: addr(0x1000) }),
            Arc::new(PlainCodeUnit { address: addr(0x1001) }),
        ];
        let source = VecCodeUnitIterator {
            items: items.into_iter(),
        };
        let mut iter = DataFilteredCodeUnitIterator::new(Box::new(source));
        assert!(iter.next().is_none());
    }

    #[test]
    fn data_view_forwards_real_data_behavior_not_just_identity() {
        let items: Vec<Arc<dyn CodeUnit>> = vec![Arc::new(TestDataUnit {
            inner: PlainCodeUnit { address: addr(0x2000) },
        })];
        let source = VecCodeUnitIterator {
            items: items.into_iter(),
        };
        let mut iter = DataFilteredCodeUnitIterator::new(Box::new(source));
        let data = iter.next().expect("data item");

        // Exercise both `CodeUnit` and `Data` methods through the box to prove `DataView` really
        // forwards into the wrapped object rather than answering from stubbed defaults.
        assert!(Data::is_defined(data.as_ref()));
        assert!(Data::is_writable(data.as_ref()));
        assert_eq!(CodeUnit::get_bytes(data.as_ref()).unwrap(), vec![0x42]);
        assert_eq!(data.get_num_operands(), 1);
    }
}

//! Port of `ghidra.program.model.pcode.MappedEntry`.
//!
//! A normal mapping of a `HighSymbol` to a particular `Address`, consuming a set number of bytes.
//!
//! The Java class `extends SymbolEntry` (now a real trait, see
//! [`symbol_entry`](crate::program::model::pcode::symbol_entry)); `MappedEntry` implements it
//! directly as a real, concrete struct carrying the `storage` field the base class declares.
//!
//! [`decode`](SymbolEntry::decode)/[`encode`](SymbolEntry::encode) are faithful ports of
//! `MappedEntry.decode(Decoder)`/`encode(Encoder)`, modulo `decode`'s extra `pcode_factory`
//! parameter (see the [`symbol_entry`](crate::program::model::pcode::symbol_entry) module docs for
//! why). [`get_mutability_of_address`](MappedEntry::get_mutability_of_address) ports the public
//! static `MappedEntry.getMutabilityOfAddress(Address, Program)`; see its own docs for how it
//! degrades when it cannot obtain mutable `Program` access to check reference write-ness (the same
//! `Arc::get_mut` pattern already used by
//! [`DataUtilities::get_data_at_location`](crate::program::model::data::data_utilities) and
//! documented on `code_unit_format::with_program_mut`).
//!
//! [`get_storage`](SymbolEntry::get_storage)/[`get_size`](SymbolEntry::get_size)/
//! [`get_mutability`](SymbolEntry::get_mutability) dereference the `storage` field the way the
//! Java methods do; see the [`symbol_entry`](crate::program::model::pcode::symbol_entry) module
//! docs for why `get_storage` alone stays null-safe (returns `None`) while `get_size`/
//! `get_mutability` panic (mirroring Java's `NullPointerException`) if called before `storage` is
//! set -- tested below.

use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::mutability_settings_definition::{CONSTANT, NORMAL, VOLATILE};
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::listing::Program;
use crate::program::model::pcode::address_xml;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::high_symbol::HighSymbol;
use crate::program::model::pcode::ids::ELEM_ADDR;
use crate::program::model::pcode::pcode_factory::PcodeFactory;
use crate::program::model::pcode::symbol_entry::SymbolEntry;
use crate::program::seam_stubs::share_variable_storage;

/// A normal mapping of a `HighSymbol` to a particular `Address`, consuming a set number of bytes.
/// Port of `ghidra.program.model.pcode.MappedEntry`.
pub struct MappedEntry {
    symbol: Arc<dyn HighSymbol>,
    pc_address: Option<Address>,
    storage: Option<Arc<dyn VariableStorage>>,
}

impl MappedEntry {
    /// For use with [`SymbolEntry::decode`]. Port of the `MappedEntry(HighSymbol sym)`
    /// constructor.
    pub fn new(symbol: Arc<dyn HighSymbol>) -> Self {
        MappedEntry { symbol, pc_address: None, storage: None }
    }

    /// Construct given a symbol, storage, and first-use `Address`. Port of
    /// `MappedEntry(HighSymbol sym, VariableStorage store, Address addr)`.
    pub fn with_storage(
        symbol: Arc<dyn HighSymbol>,
        storage: Arc<dyn VariableStorage>,
        addr: Option<Address>,
    ) -> Self {
        MappedEntry { symbol, pc_address: addr, storage: Some(storage) }
    }

    /// Port of the public static `MappedEntry.getMutabilityOfAddress(Address, Program)`: the
    /// underlying mutability setting of an Address based on the Program configuration and the
    /// `MemoryBlock`. Ignores any overrides of Data at the address.
    ///
    /// Java calls `program.getReferenceManager()` unconditionally to scan for write references to
    /// a read-only block; this crate's [`Program::get_reference_manager`] requires `&mut self`,
    /// unreachable generically through the shared `Arc<dyn Program>` handed back by
    /// `HighSymbol::get_program()` unless `program` happens to be the only live handle to that
    /// `Program` (checked via `Arc::get_mut`, the same degrade already used elsewhere in this
    /// crate -- see the module docs). When it is not, this treats the address as if the reference
    /// scan found no write reference (the same outcome as an empty `getReferencesTo` iterator),
    /// which is the closest honest fallback available without mutable `Program` access.
    pub fn get_mutability_of_address(addr: Option<&Address>, mut program: Arc<dyn Program>) -> i32 {
        let Some(addr) = addr else {
            return NORMAL;
        };
        if let Some(language) = program.get_language() {
            if language.is_volatile(addr) {
                return VOLATILE;
            }
        }
        let Some(memory) = program.get_memory() else {
            return NORMAL;
        };
        let Some(block) = memory.get_block(addr) else {
            return NORMAL;
        };
        if block.is_volatile() {
            return VOLATILE;
        }
        if !block.is_write() {
            let found_write_reference = Arc::get_mut(&mut program)
                .and_then(|p| p.get_reference_manager())
                .map(|rm| {
                    rm.get_references_to(addr.clone())
                        .take(100)
                        .any(|r| r.reference_type().is_write())
                })
                .unwrap_or(false);
            return if found_write_reference { NORMAL } else { CONSTANT };
        }
        NORMAL
    }

    /// Port of accessing the (possibly still-unset) `storage` field, panicking with a message
    /// mirroring Java's `NullPointerException` if it has not been set yet by
    /// [`SymbolEntry::decode`] or [`MappedEntry::with_storage`].
    fn require_storage(&self) -> &Arc<dyn VariableStorage> {
        self.storage.as_ref().expect(
            "MappedEntry: `storage` was dereferenced before decode()/with_storage() set it \
             (mirrors Java's NullPointerException on the null `storage` field)",
        )
    }
}

impl SymbolEntry for MappedEntry {
    fn get_high_symbol(&self) -> Arc<dyn HighSymbol> {
        self.symbol.clone()
    }

    fn get_pc_address(&self) -> Option<Address> {
        self.pc_address.clone()
    }

    fn set_pc_address(&mut self, addr: Option<Address>) {
        self.pc_address = addr;
    }

    fn decode(
        &mut self,
        decoder: &dyn Decoder,
        pcode_factory: &dyn PcodeFactory,
    ) -> Result<(), DecoderException> {
        let data_type = self.symbol.get_data_type();
        let sz = data_type.get_length();
        if sz == 0 {
            return Err(DecoderException::new(&format!(
                "Invalid symbol 0-sized data-type: {}",
                data_type.get_name()
            )));
        }
        let addrel = decoder.open_element_with_id(ELEM_ADDR).map_err(decode_err)?;
        let storage = address_xml::decode_storage_from_attributes(sz, decoder, pcode_factory)?;
        self.storage = Some(Arc::from(storage));
        decoder.close_element(addrel).map_err(decode_err)?;

        self.decode_range_list(decoder)?;
        Ok(())
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        let storage = self.require_storage();
        let mut logical_size: i64 = 0; // Assume datatype size and storage size are the same
        let data_type = self.symbol.get_data_type();
        let type_length = data_type.get_length();
        if type_length != storage.size() && data_type.is_floating_point() {
            logical_size = type_length as i64; // Force a logicalsize
        }
        let varnodes = storage.get_varnodes();
        address_xml::encode_varnodes(encoder, Some(&varnodes), logical_size)?;
        self.encode_rangelist(encoder)
    }

    fn get_storage(&self) -> Option<Box<dyn VariableStorage>> {
        self.storage.as_ref().map(share_variable_storage)
    }

    fn get_size(&self) -> i32 {
        self.require_storage().size()
    }

    fn get_mutability(&self) -> i32 {
        let addr = self.require_storage().get_min_address();
        MappedEntry::get_mutability_of_address(addr.as_ref(), self.symbol.get_program())
    }
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode MappedEntry", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::{Language, ParseError};
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::{
        Memory, MemoryAccessException, MemoryBlock,
    };
    use crate::program::model::pcode::ids::{AttributeId, ATTRIB_FIRST, ATTRIB_OFFSET, ATTRIB_SPACE, ElementId};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{
        AddExternalReferenceError, ExternalLocation, Namespace, RefType, Reference,
        ReferenceIterator, ReferenceManager, SourceType, Symbol,
    };
    use crate::program::seam_stubs::VarnodeListStorage;
    use crate::util::task::TaskMonitor;
    use std::any::Any;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 3)
    }

    struct MockDataType {
        length: i32,
        floating_point: bool,
    }
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_floating_point(&self) -> bool {
            self.floating_point
        }
    }

    struct MockHighSymbol {
        length: i32,
        floating_point: bool,
        program: Arc<dyn Program>,
    }
    impl HighSymbol for MockHighSymbol {
        fn get_id(&self) -> i64 {
            1
        }
        fn get_high_function(&self) -> Arc<dyn crate::program::model::pcode::high_function::HighFunction> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: self.length, floating_point: self.floating_point })
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            unimplemented!("not needed for this smoke test")
        }
    }

    fn mock_symbol(length: i32, program: Arc<dyn Program>) -> Arc<dyn HighSymbol> {
        Arc::new(MockHighSymbol { length, floating_point: false, program })
    }

    // --- minimal Program/Language/Memory/MemoryBlock/ReferenceManager mocks for
    // get_mutability_of_address ---

    // `Language` is not `Send + Sync` bounded anywhere in this crate (see `MockLanguage`'s own
    // ~40-method boilerplate below), so `Program` (which *is* `Send + Sync` bounded) cannot store
    // an `Arc<dyn Language>` field directly without breaking auto-trait derivation. `MockProgram`
    // instead stores just the one bit `get_language`'s caller cares about and builds a fresh
    // `MockLanguage` on demand inside `get_language()`, where the `Arc<dyn Language>` only needs
    // to be a *return value*, not a stored field.
    struct MockProgram {
        language_volatile: Option<bool>,
        memory: Option<Arc<dyn Memory>>,
        reference_manager: Option<MockReferenceManager>,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_language(&self) -> Option<Arc<dyn Language>> {
            self.language_volatile.map(|volatile| Arc::new(MockLanguage { volatile }) as Arc<dyn Language>)
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            self.memory.clone()
        }
        fn get_reference_manager(&mut self) -> Option<&mut dyn ReferenceManager> {
            self.reference_manager.as_mut().map(|rm| rm as &mut dyn ReferenceManager)
        }
    }

    fn program_with(
        language_volatile: Option<bool>,
        memory: Option<Arc<dyn Memory>>,
        reference_manager: Option<MockReferenceManager>,
    ) -> Arc<dyn Program> {
        Arc::new(MockProgram { language_volatile, memory, reference_manager })
    }

    struct MockLanguage {
        volatile: bool,
    }
    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            crate::program::model::lang::language_id::LanguageID::new("x86:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by this test")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by this test")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this test")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            self.volatile
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            unimplemented!("not exercised by this test")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this test")
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            unimplemented!("not exercised by this test")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this test")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct MockMemory {
        block: Option<Arc<dyn MemoryBlock>>,
    }
    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by this test")
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not exercised by this test")
        }
        fn get_block(&self, _addr: &Address) -> Option<Arc<dyn MemoryBlock>> {
            self.block.clone()
        }
    }

    struct MockMemoryBlock {
        write: bool,
        volatile: bool,
    }
    impl MemoryBlock for MockMemoryBlock {
        fn get_name(&self) -> &str {
            "mockblock"
        }
        fn get_start(&self) -> Address {
            ram_space().address(0)
        }
        fn get_end(&self) -> Address {
            ram_space().address(0xffff)
        }
        fn get_size(&self) -> u64 {
            0x1_0000
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by this test")
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not exercised by this test")
        }
        fn is_write(&self) -> bool {
            self.write
        }
        fn is_volatile(&self) -> bool {
            self.volatile
        }
    }

    struct MockReference {
        ref_type: RefType,
    }
    impl Reference for MockReference {
        fn from_address(&self) -> Address {
            ram_space().address(0)
        }
        fn to_address(&self) -> Address {
            ram_space().address(0x10)
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn symbol_id(&self) -> i64 {
            -1
        }
        fn reference_type(&self) -> RefType {
            self.ref_type
        }
        fn operand_index(&self) -> i32 {
            0
        }
        fn is_mnemonic_reference(&self) -> bool {
            false
        }
        fn is_operand_reference(&self) -> bool {
            true
        }
        fn is_stack_reference(&self) -> bool {
            false
        }
        fn is_external_reference(&self) -> bool {
            false
        }
        fn is_entry_point_reference(&self) -> bool {
            false
        }
        fn is_memory_reference(&self) -> bool {
            true
        }
        fn is_register_reference(&self) -> bool {
            false
        }
        fn is_offset_reference(&self) -> bool {
            false
        }
        fn is_shifted_reference(&self) -> bool {
            false
        }
        fn source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct MockReferenceIterator(std::vec::IntoIter<Arc<dyn Reference>>);
    impl Iterator for MockReferenceIterator {
        type Item = Arc<dyn Reference>;
        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }
    impl ReferenceIterator for MockReferenceIterator {}

    struct MockReferenceManager {
        references_to: Vec<Arc<dyn Reference>>,
    }
    impl ReferenceManager for MockReferenceManager {
        fn add_reference(&mut self, reference: Arc<dyn Reference>) -> Arc<dyn Reference> {
            reference
        }
        fn add_stack_reference(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _stack_offset: i32,
            _ref_type: RefType,
            _source: SourceType,
        ) -> Arc<dyn Reference> {
            unimplemented!("not exercised by this test")
        }
        fn add_register_reference(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _register: &crate::program::model::lang::Register,
            _ref_type: RefType,
            _source: SourceType,
        ) -> Arc<dyn Reference> {
            unimplemented!("not exercised by this test")
        }
        fn add_memory_reference(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _ref_type: RefType,
            _source: SourceType,
            _op_index: i32,
        ) -> Arc<dyn Reference> {
            unimplemented!("not exercised by this test")
        }
        fn add_offset_mem_reference(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _to_addr_is_base: bool,
            _offset: i64,
            _ref_type: RefType,
            _source: SourceType,
            _op_index: i32,
        ) -> Arc<dyn Reference> {
            unimplemented!("not exercised by this test")
        }
        fn add_shifted_mem_reference(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _shift_value: i32,
            _ref_type: RefType,
            _source: SourceType,
            _op_index: i32,
        ) -> Arc<dyn Reference> {
            unimplemented!("not exercised by this test")
        }
        fn add_external_reference(
            &mut self,
            _from_addr: Address,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source: SourceType,
            _op_index: i32,
            _ref_type: RefType,
        ) -> Result<Arc<dyn Reference>, AddExternalReferenceError> {
            unimplemented!("not exercised by this test")
        }
        fn add_external_reference_in_namespace(
            &mut self,
            _from_addr: Address,
            _ext_namespace: Arc<dyn Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source: SourceType,
            _op_index: i32,
            _ref_type: RefType,
        ) -> Result<Arc<dyn Reference>, AddExternalReferenceError> {
            unimplemented!("not exercised by this test")
        }
        fn add_external_reference_for_location(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _location: Arc<dyn ExternalLocation>,
            _source: SourceType,
            _ref_type: RefType,
        ) -> Result<Arc<dyn Reference>, crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by this test")
        }
        fn remove_all_references_from_range(&mut self, _begin_addr: Address, _end_addr: Address) {
            unimplemented!("not exercised by this test")
        }
        fn remove_all_references_from(&mut self, _from_addr: Address) {
            unimplemented!("not exercised by this test")
        }
        fn remove_all_references_to(&mut self, _to_addr: Address) {
            unimplemented!("not exercised by this test")
        }
        fn get_references_to_variable(
            &self,
            _var: &dyn crate::program::model::listing::Variable,
        ) -> Vec<Arc<dyn Reference>> {
            unimplemented!("not exercised by this test")
        }
        fn get_referenced_variable(
            &self,
            _reference: &dyn Reference,
        ) -> Option<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!("not exercised by this test")
        }
        fn set_primary(&mut self, _reference: Arc<dyn Reference>, _is_primary: bool) {
            unimplemented!("not exercised by this test")
        }
        fn has_flow_references_from(&self, _addr: Address) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn get_flow_references_from(&self, _addr: Address) -> Vec<Arc<dyn Reference>> {
            unimplemented!("not exercised by this test")
        }
        fn get_external_references(&self) -> Box<dyn ReferenceIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_references_to(&self, _addr: Address) -> Box<dyn ReferenceIterator> {
            Box::new(MockReferenceIterator(self.references_to.clone().into_iter()))
        }
        fn get_reference_iterator(&self, _start_addr: Address) -> Box<dyn ReferenceIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_reference(
            &self,
            _from_addr: Address,
            _to_addr: Address,
            _op_index: i32,
        ) -> Option<Arc<dyn Reference>> {
            unimplemented!("not exercised by this test")
        }
        fn get_references_from(&self, _addr: Address) -> Vec<Arc<dyn Reference>> {
            unimplemented!("not exercised by this test")
        }
        fn get_references_from_operand(&self, _from_addr: Address, _op_index: i32) -> Vec<Arc<dyn Reference>> {
            unimplemented!("not exercised by this test")
        }
        fn has_references_from_operand(&self, _from_addr: Address, _op_index: i32) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn has_references_from(&self, _from_addr: Address) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn get_primary_reference_from(&self, _addr: Address, _op_index: i32) -> Option<Arc<dyn Reference>> {
            unimplemented!("not exercised by this test")
        }
        fn get_reference_source_iterator(
            &self,
            _start_addr: Address,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not exercised by this test")
        }
        fn get_reference_source_iterator_in_set(
            &self,
            _addr_set: Option<&dyn crate::program::model::address::AddressSetView>,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not exercised by this test")
        }
        fn get_reference_destination_iterator(
            &self,
            _start_addr: Address,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not exercised by this test")
        }
        fn get_reference_destination_iterator_in_set(
            &self,
            _addr_set: Option<&dyn crate::program::model::address::AddressSetView>,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not exercised by this test")
        }
        fn get_reference_count_to(&self, _to_addr: Address) -> i32 {
            unimplemented!("not exercised by this test")
        }
        fn get_reference_count_from(&self, _from_addr: Address) -> i32 {
            unimplemented!("not exercised by this test")
        }
        fn get_reference_destination_count(&self) -> i32 {
            unimplemented!("not exercised by this test")
        }
        fn get_reference_source_count(&self) -> i32 {
            unimplemented!("not exercised by this test")
        }
        fn has_references_to(&self, _to_addr: Address) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn update_ref_type(&mut self, _reference: Arc<dyn Reference>, _ref_type: RefType) -> Arc<dyn Reference> {
            unimplemented!("not exercised by this test")
        }
        fn set_association(&mut self, _symbol: Arc<dyn Symbol>, _reference: Arc<dyn Reference>) {
            unimplemented!("not exercised by this test")
        }
        fn remove_association(&mut self, _reference: Arc<dyn Reference>) {
            unimplemented!("not exercised by this test")
        }
        fn delete(&mut self, _reference: Arc<dyn Reference>) {
            unimplemented!("not exercised by this test")
        }
        fn get_reference_level(&self, _to_addr: Address) -> i8 {
            unimplemented!("not exercised by this test")
        }
    }

    // --- Decoder/Encoder/PcodeFactory mocks for decode()/encode() ---

    struct MockPcodeFactory;
    impl PcodeFactory for MockPcodeFactory {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn get_data_type_manager(
            &self,
        ) -> Arc<dyn crate::program::model::pcode::pcode_data_type_manager::PcodeDataTypeManager> {
            unimplemented!("not exercised by these tests")
        }
        fn new_varnode_with_ref(&self, _sz: i32, _addr: Address, _ref_id: i32) -> Varnode {
            unimplemented!("not exercised by these tests")
        }
        fn get_join_address(&self, _storage: &dyn VariableStorage) -> Option<Address> {
            unimplemented!("not exercised by these tests")
        }
        fn build_storage(
            &self,
            _vn: &Varnode,
        ) -> Result<Box<dyn VariableStorage>, crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_ref(&self, _refid: i32) -> Option<Varnode> {
            unimplemented!("not exercised by these tests")
        }
        fn get_op_ref(&self, _refid: i32) -> Option<crate::program::model::pcode::PcodeOp> {
            unimplemented!("not exercised by these tests")
        }
        fn get_symbol(&self, _symbol_id: i64) -> Option<Arc<dyn crate::program::seam_stubs::HighSymbol>> {
            unimplemented!("not exercised by these tests")
        }
        fn new_op(
            &self,
            _sq: crate::program::model::pcode::SequenceNumber,
            _opc: crate::program::model::pcode::OpCode,
            _inputs: Vec<Varnode>,
            _output: Option<Varnode>,
        ) -> crate::program::model::pcode::PcodeOp {
            unimplemented!("not exercised by these tests")
        }
    }

    /// Decoder that plays back a single `<addr>` element (space/offset attributes) followed by an
    /// optional `<rangelist><range .../></rangelist>`, mirroring the stream
    /// [`SymbolEntry::encode`] produces for [`MappedEntry`].
    struct MockDecoder {
        space: Arc<AddressSpace>,
        offset: u64,
        attr_pos: AtomicUsize,
        has_range: bool,
        range_offset: u64,
    }

    impl Decoder for MockDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(if self.has_range { 1 } else { 0 })
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(1)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            self.open_element()
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            let idx = self.attr_pos.fetch_add(1, Ordering::SeqCst);
            Ok(match idx {
                0 => ATTRIB_SPACE.id,
                1 => ATTRIB_OFFSET.id,
                _ => 0,
            })
        }
        fn rewind_attributes(&self) {
            self.attr_pos.store(0, Ordering::SeqCst);
        }
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(&self, _attrib_id: AttributeId) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            Ok(self.offset)
        }
        fn read_unsigned_integer_with_id(&self, attrib_id: AttributeId) -> Result<u64, DecoderError> {
            if attrib_id.id == ATTRIB_FIRST.id {
                Ok(self.range_offset)
            } else {
                Err(DecoderError::MissingAttribute(attrib_id.name.to_string()))
            }
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            Ok(self.space.clone())
        }
        fn read_space_with_id(&self, _attrib_id: AttributeId) -> Result<Arc<AddressSpace>, DecoderError> {
            Ok(self.space.clone())
        }
    }

    #[derive(Default)]
    struct RecordingEncoder {
        events: Vec<String>,
    }
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.events.push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.events.push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string_indexed(&mut self, attrib_id: AttributeId, index: i32, val: &str) -> io::Result<()> {
            self.events.push(format!("attr:{}[{}]={}", attrib_id.name, index, val));
            Ok(())
        }
        fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, spc.name()));
            Ok(())
        }
        fn write_space_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _name: &str) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    fn no_program() -> Arc<dyn Program> {
        program_with(None, None, None)
    }

    // --- decode/encode ---

    #[test]
    fn decode_reads_storage_and_pc_address() {
        let space = ram_space();
        let mut entry = MappedEntry::new(mock_symbol(4, no_program()));
        let decoder = MockDecoder {
            space: space.clone(),
            offset: 0x100,
            attr_pos: AtomicUsize::new(0),
            has_range: true,
            range_offset: 0x200,
        };

        entry.decode(&decoder, &MockPcodeFactory).expect("decode should succeed");

        assert_eq!(entry.get_size(), 4);
        assert_eq!(entry.get_pc_address(), Some(space.address(0x200)));
        let storage = entry.get_storage().expect("storage should be set after decode");
        assert_eq!(storage.get_min_address(), Some(space.address(0x100)));
    }

    #[test]
    fn decode_rejects_zero_sized_datatype() {
        let mut entry = MappedEntry::new(mock_symbol(0, no_program()));
        let decoder = MockDecoder {
            space: ram_space(),
            offset: 0,
            attr_pos: AtomicUsize::new(0),
            has_range: false,
            range_offset: 0,
        };

        let err = entry.decode(&decoder, &MockPcodeFactory).unwrap_err();
        assert!(err.to_string().contains("Invalid symbol 0-sized data-type"));
    }

    #[test]
    fn encode_writes_varnode_and_rangelist() {
        let space = ram_space();
        let storage: Arc<dyn VariableStorage> =
            Arc::new(VarnodeListStorage(vec![Varnode::new(space.address(0x40), 4)]));
        let entry =
            MappedEntry::with_storage(mock_symbol(4, no_program()), storage, Some(space.address(0x50)));

        let mut encoder = RecordingEncoder::default();
        entry.encode(&mut encoder).expect("encode should succeed");

        assert_eq!(
            encoder.events,
            vec![
                "open:addr".to_string(),
                "attr:space=ram".to_string(),
                "attr:offset=64".to_string(),
                "attr:size=4".to_string(),
                "close:addr".to_string(),
                "open:rangelist".to_string(),
                "open:range".to_string(),
                "attr:space=ram".to_string(),
                "attr:first=80".to_string(),
                "attr:last=80".to_string(),
                "close:range".to_string(),
                "close:rangelist".to_string(),
            ]
        );
    }

    #[test]
    fn encode_forces_logical_size_for_mismatched_floating_point_storage() {
        let space = ram_space();
        // 10-byte extended-precision float symbol backed by 8 bytes of storage: Java forces a
        // `logicalsize` attribute in exactly this case (size mismatch + floating point type).
        let storage: Arc<dyn VariableStorage> =
            Arc::new(VarnodeListStorage(vec![Varnode::new(space.address(0x40), 8)]));
        let symbol = Arc::new(MockHighSymbol { length: 10, floating_point: true, program: no_program() });
        let entry = MappedEntry::with_storage(symbol, storage, None);

        let mut encoder = RecordingEncoder::default();
        entry.encode(&mut encoder).expect("encode should succeed");

        assert!(encoder.events.iter().any(|e| e == "attr:logicalsize=10"));
    }

    #[test]
    fn get_storage_before_decode_is_none() {
        // Faithful to Java: `MappedEntry.getStorage()` just returns the (possibly still null)
        // `storage` field with no dereference, so it never NPEs by itself.
        let entry = MappedEntry::new(mock_symbol(4, no_program()));
        assert!(entry.get_storage().is_none());
    }

    #[test]
    #[should_panic(expected = "storage")]
    fn get_size_before_decode_panics() {
        // Faithful to Java: `MappedEntry.getSize()` calls `storage.size()`, which NPEs on an
        // unset `storage` field.
        let entry = MappedEntry::new(mock_symbol(4, no_program()));
        entry.get_size();
    }

    // --- get_mutability_of_address ---

    #[test]
    fn mutability_of_address_defaults_to_normal_for_no_address() {
        assert_eq!(MappedEntry::get_mutability_of_address(None, no_program()), NORMAL);
    }

    #[test]
    fn mutability_of_address_is_volatile_when_language_says_so() {
        let addr = ram_space().address(0x10);
        let program = program_with(Some(true), None, None);
        assert_eq!(MappedEntry::get_mutability_of_address(Some(&addr), program), VOLATILE);
    }

    #[test]
    fn mutability_of_address_defaults_to_normal_when_no_block_found() {
        let addr = ram_space().address(0x10);
        let memory: Arc<dyn Memory> = Arc::new(MockMemory { block: None });
        let program = program_with(None, Some(memory), None);
        assert_eq!(MappedEntry::get_mutability_of_address(Some(&addr), program), NORMAL);
    }

    #[test]
    fn mutability_of_address_is_volatile_when_block_says_so() {
        let addr = ram_space().address(0x10);
        let block: Arc<dyn MemoryBlock> = Arc::new(MockMemoryBlock { write: false, volatile: true });
        let memory: Arc<dyn Memory> = Arc::new(MockMemory { block: Some(block) });
        let program = program_with(None, Some(memory), None);
        assert_eq!(MappedEntry::get_mutability_of_address(Some(&addr), program), VOLATILE);
    }

    #[test]
    fn mutability_of_address_is_normal_for_writable_block() {
        let addr = ram_space().address(0x10);
        let block: Arc<dyn MemoryBlock> = Arc::new(MockMemoryBlock { write: true, volatile: false });
        let memory: Arc<dyn Memory> = Arc::new(MockMemory { block: Some(block) });
        let program = program_with(None, Some(memory), None);
        assert_eq!(MappedEntry::get_mutability_of_address(Some(&addr), program), NORMAL);
    }

    #[test]
    fn mutability_of_address_is_constant_for_read_only_block_with_no_write_reference() {
        let addr = ram_space().address(0x10);
        let block: Arc<dyn MemoryBlock> = Arc::new(MockMemoryBlock { write: false, volatile: false });
        let memory: Arc<dyn Memory> = Arc::new(MockMemory { block: Some(block) });
        let reference_manager = MockReferenceManager {
            references_to: vec![Arc::new(MockReference { ref_type: RefType::Read })],
        };
        // A fresh Arc has refcount 1, so `Arc::get_mut` succeeds here: this exercises the "real"
        // reference-scanning path (not the degrade path) and matches Java exactly.
        let program = program_with(None, Some(memory), Some(reference_manager));
        assert_eq!(MappedEntry::get_mutability_of_address(Some(&addr), program), CONSTANT);
    }

    #[test]
    fn mutability_of_address_is_normal_for_read_only_block_with_write_reference() {
        let addr = ram_space().address(0x10);
        let block: Arc<dyn MemoryBlock> = Arc::new(MockMemoryBlock { write: false, volatile: false });
        let memory: Arc<dyn Memory> = Arc::new(MockMemory { block: Some(block) });
        let reference_manager = MockReferenceManager {
            references_to: vec![Arc::new(MockReference { ref_type: RefType::Write })],
        };
        let program = program_with(None, Some(memory), Some(reference_manager));
        assert_eq!(MappedEntry::get_mutability_of_address(Some(&addr), program), NORMAL);
    }

    #[test]
    fn mutability_of_address_degrades_to_constant_when_program_arc_is_shared() {
        let addr = ram_space().address(0x10);
        let block: Arc<dyn MemoryBlock> = Arc::new(MockMemoryBlock { write: false, volatile: false });
        let memory: Arc<dyn Memory> = Arc::new(MockMemory { block: Some(block) });
        let reference_manager = MockReferenceManager {
            references_to: vec![Arc::new(MockReference { ref_type: RefType::Write })],
        };
        let program = program_with(None, Some(memory), Some(reference_manager));
        // A second live clone means `Arc::get_mut` fails inside `get_mutability_of_address`, even
        // though a write reference genuinely exists -- the documented degrade path.
        let _extra_handle = program.clone();
        assert_eq!(MappedEntry::get_mutability_of_address(Some(&addr), program), CONSTANT);
    }

    #[test]
    fn get_mutability_delegates_to_storage_min_address() {
        let space = ram_space();
        let storage: Arc<dyn VariableStorage> =
            Arc::new(VarnodeListStorage(vec![Varnode::new(space.address(0x10), 4)]));
        let program = program_with(None, None, None);
        let entry = MappedEntry::with_storage(mock_symbol(4, program), storage, None);
        assert_eq!(entry.get_mutability(), NORMAL);
    }
}

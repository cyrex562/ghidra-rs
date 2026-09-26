//! Port of `ghidra.program.model.pcode.HighLabelSymbol`.
//!
//! A symbol with no underlying data-type: a label within code, used to model named jump targets
//! within a function to the decompiler.
//!
//! In Java this `extends HighSymbol`. Following the "`extends X`" convention established
//! throughout this crate for its `HighVariable`/`HighSymbol` hierarchies (composition, not
//! inheritance -- see [`high_local`](crate::program::model::pcode::high_local)'s module docs for
//! the `HighVariable` side; this file is the first of the `HighSymbol` side), [`HighLabelSymbol`]
//! is a concrete struct implementing the already-ported
//! [`high_symbol::HighSymbol`](crate::program::model::pcode::high_symbol::HighSymbol) trait
//! directly, holding the fields Java inherits from the private/protected `HighSymbol` state
//! (`id`/`name`/`typelock`/`namelock`) that this constructor path sets, plus its own resolved
//! [`VariableStorage`].
//!
//! # Deliberate deviation: `PcodeDataTypeManager` replaced by `Program`/`ProgramArchitecture`
//! Java's constructor takes a `PcodeDataTypeManager` (`dtmanage`), used only to reach
//! `getProgram()` (`dtmanage.getProgram()`) so the real `new VariableStorage(getProgram(), addr,
//! 1)` call can validate the storage. `PcodeDataTypeManager` is not ported in this crate. Since
//! this crate's ported [`Program`](crate::program::model::listing::Program) trait does not itself
//! implement [`ProgramArchitecture`] (unlike real Ghidra, where `Program` does), this port's
//! [`HighLabelSymbol::new`] takes the `Program` (to satisfy
//! [`HighSymbol::get_program`](crate::program::model::pcode::high_symbol::HighSymbol::get_program))
//! and a separate `ProgramArchitecture` (needed only to validate/construct the
//! [`VariableStorage`]) directly as constructor parameters, in place of `dtmanage`.
//!
//! # Known gap: `getHighFunction()`
//! Java's 6-argument protected `HighSymbol` constructor this class uses sets `function = null`.
//! [`HighSymbol::get_high_function`] has no `Option` in its signature (a pre-existing,
//! already-ported trait method), so any real caller of Java's `getHighFunction()` here would get
//! `null` and NPE on first use; this port's closest faithful analogue is a private
//! [`AbsentHighFunction`] stand-in whose every method panics with a message documenting the gap,
//! rather than silently fabricating function data or changing the trait's signature.

use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::mutability_settings_definition::{CONSTANT, VOLATILE};
use crate::program::model::lang::ProgramArchitecture;
use crate::program::model::listing::{Program, UnassignedStorage, VariableStorage, VariableStorageImpl};
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::high_symbol::{HighSymbol, ID_BASE};
use crate::program::model::pcode::ids::{
    ATTRIB_CAT, ATTRIB_HIDDENRETPARM, ATTRIB_ID, ATTRIB_MERGE, ATTRIB_NAME, ATTRIB_NAMELOCK,
    ATTRIB_READONLY, ATTRIB_THISPTR, ATTRIB_TYPELOCK, ATTRIB_VOLATILE, ELEM_LABELSYM,
};
use crate::program::model::pcode::{Encoder, Varnode};
use crate::program::seam_stubs::PlaceholderDataType;

/// Stand-in for a `null` `HighSymbol.function` field (see the module docs): every method panics,
/// documenting that this `HighSymbol` is not backed by any `HighFunction`, matching how Java would
/// NPE on first real use of `getHighFunction()` here.
struct AbsentHighFunction;

macro_rules! absent {
    () => {
        panic!(
            "this HighSymbol was constructed with no associated HighFunction (function == null \
             in Java); see high_label_symbol.rs module docs"
        )
    };
}

impl HighFunction for AbsentHighFunction {
    fn get_function(&self) -> Box<dyn crate::program::model::listing::Function> {
        absent!()
    }
    fn get_id(&self) -> i64 {
        absent!()
    }
    fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
        absent!()
    }
    fn get_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
        absent!()
    }
    fn get_local_symbol_map(&self) -> Box<dyn crate::program::seam_stubs::LocalSymbolMap> {
        absent!()
    }
    fn get_global_symbol_map(&self) -> Arc<dyn crate::program::model::pcode::global_symbol_map::GlobalSymbolMap> {
        absent!()
    }
    fn grab_from_function(&mut self, _override_extrapop: i32, _include_default_names: bool, _do_override: bool) {
        absent!()
    }
    fn decode(
        &mut self,
        _decoder: &dyn crate::program::model::pcode::decoder::Decoder,
    ) -> Result<(), crate::program::model::pcode::decoder_exception::DecoderException> {
        absent!()
    }
    fn split_out_merge_group(
        &mut self,
        _high: Box<dyn crate::program::model::pcode::high_variable::HighVariable>,
        _vn: &crate::program::model::pcode::Varnode,
    ) -> Result<
        Box<dyn crate::program::model::pcode::high_variable::HighVariable>,
        crate::program::model::pcode::pcode_exception::PcodeException,
    > {
        absent!()
    }
    fn encode(
        &self,
        _encoder: &mut dyn Encoder,
        _id: i64,
        _namespace: &dyn crate::program::model::symbol::Namespace,
        _entry_point: Option<Address>,
        _size: i32,
    ) -> io::Result<()> {
        absent!()
    }
    fn set_volatile(&mut self, _vn: &crate::program::model::pcode::Varnode, _val: bool) {
        absent!()
    }
}

/// A resolved `VariableStorage` result, held as a small `Send + Sync` value rather than
/// `Arc<dyn VariableStorage>` directly: the [`VariableStorage`] trait itself has no `Send + Sync`
/// bound, so a `HighSymbol` implementor (which must be `Send + Sync`) cannot hold a trait object
/// of it as a field. [`ResolvedStorage::to_variable_storage`] reconstructs a fresh
/// `Box<dyn VariableStorage>` on demand for [`HighSymbol::get_storage`].
#[derive(Clone)]
pub(crate) enum ResolvedStorage {
    Assigned(Varnode),
    Unassigned,
}

impl ResolvedStorage {
    /// Attempts `VariableStorage(ProgramArchitecture, Address, int)`, falling back to
    /// `VariableStorage.UNASSIGNED_STORAGE` on failure. Port of the shared
    /// `try { store = new VariableStorage(getProgram(), addr, size); } catch
    /// (InvalidInputException e) { store = VariableStorage.UNASSIGNED_STORAGE; }` pattern common
    /// to all four `HighSymbol`-subclass constructors in this file family.
    pub(crate) fn resolve(program_arch: Arc<dyn ProgramArchitecture>, addr: Address, size: i32) -> Self {
        match VariableStorageImpl::from_address(program_arch, addr.clone(), size) {
            Ok(_) => ResolvedStorage::Assigned(Varnode::new(addr, size)),
            Err(_) => ResolvedStorage::Unassigned,
        }
    }

    pub(crate) fn to_variable_storage(&self) -> Box<dyn VariableStorage> {
        match self {
            ResolvedStorage::Assigned(vn) => Box::new(SingleVarnodeStorage(vn.clone())),
            ResolvedStorage::Unassigned => Box::new(UnassignedStorage),
        }
    }

    pub(crate) fn size(&self) -> i32 {
        match self {
            ResolvedStorage::Assigned(vn) => vn.get_size(),
            ResolvedStorage::Unassigned => 0,
        }
    }

    /// Port of `getStorage().getMinAddress()`, used by
    /// [`HighFunctionShellSymbol::encode`](crate::program::model::pcode::high_function_shell_symbol::HighFunctionShellSymbol::encode)/
    /// [`HighFunctionSymbol::encode`](crate::program::model::pcode::high_function_symbol::HighFunctionSymbol::encode).
    pub(crate) fn min_address(&self) -> Option<Address> {
        match self {
            ResolvedStorage::Assigned(vn) => Some(vn.get_address().clone()),
            ResolvedStorage::Unassigned => None,
        }
    }
}

/// Minimal [`VariableStorage`] backing [`ResolvedStorage::to_variable_storage`]'s `Assigned`
/// case: a single storage varnode. Not a port of any specific Java class.
struct SingleVarnodeStorage(Varnode);

impl VariableStorage for SingleVarnodeStorage {
    fn get_first_varnode(&self) -> Option<Varnode> {
        Some(self.0.clone())
    }
}

/// A symbol with no underlying data-type: a label within code. Port of
/// `ghidra.program.model.pcode.HighLabelSymbol`.
pub struct HighLabelSymbol {
    name: String,
    typelock: bool,
    namelock: bool,
    program: Arc<dyn Program>,
    storage: ResolvedStorage,
}

impl HighLabelSymbol {
    /// Construct the label given a name and address. See the module docs for why this takes
    /// `program`/`program_arch` in place of Java's `dtmanage: PcodeDataTypeManager`.
    ///
    /// Port of `HighLabelSymbol(String, Address, PcodeDataTypeManager)`.
    pub fn new(
        nm: impl Into<String>,
        addr: Address,
        program: Arc<dyn Program>,
        program_arch: Arc<dyn ProgramArchitecture>,
    ) -> Self {
        let storage = ResolvedStorage::resolve(program_arch, addr, 1);
        HighLabelSymbol { name: nm.into(), typelock: true, namelock: true, program, storage }
    }

    /// Test-only shortcut bypassing the `Address`/`ProgramArchitecture` -> `VariableStorage`
    /// resolution ([`ResolvedStorage::resolve`] is exercised directly and in isolation instead;
    /// see `resolve_storage_falls_back_to_unassigned_storage_on_failure` below), so the rest of
    /// this class's tests don't each need a full [`ProgramArchitecture`]/[`Language`] mock.
    #[cfg(test)]
    fn new_with_storage(nm: impl Into<String>, program: Arc<dyn Program>, storage: ResolvedStorage) -> Self {
        HighLabelSymbol { name: nm.into(), typelock: true, namelock: true, program, storage }
    }
}

impl HighSymbol for HighLabelSymbol {
    fn get_id(&self) -> i64 {
        0
    }

    fn get_high_function(&self) -> Arc<dyn HighFunction> {
        Arc::new(AbsentHighFunction)
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        Box::new(PlaceholderDataType)
    }

    fn get_storage(&self) -> Box<dyn VariableStorage> {
        self.storage.to_variable_storage()
    }

    fn get_size(&self) -> i32 {
        self.storage.size()
    }

    fn is_type_locked(&self) -> bool {
        self.typelock
    }

    fn is_name_locked(&self) -> bool {
        self.namelock
    }

    fn set_type_lock(&mut self, typelock: bool) {
        self.typelock = typelock;
    }

    fn set_name_lock(&mut self, namelock: bool) {
        self.namelock = namelock;
    }

    /// Port of `HighLabelSymbol.encode(Encoder)`, inlining Java's protected
    /// `HighSymbol.encodeHeader(Encoder)` (not modeled as shared trait API -- see
    /// [`high_symbol`](crate::program::model::pcode::high_symbol)'s module docs) specialized to
    /// this class's fixed state (`category = -1`, never "this"/hidden-return).
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_LABELSYM)?;

        let id = self.get_id();
        if (id >> 56) != (ID_BASE >> 56) {
            encoder.write_unsigned_integer(ATTRIB_ID, id as u64)?;
        }
        encoder.write_string(ATTRIB_NAME, &self.name)?;
        encoder.write_bool(ATTRIB_TYPELOCK, self.typelock)?;
        encoder.write_bool(ATTRIB_NAMELOCK, self.namelock)?;
        let mutability = self.get_mutability();
        if mutability == CONSTANT {
            encoder.write_bool(ATTRIB_READONLY, true)?;
        } else if mutability == VOLATILE {
            encoder.write_bool(ATTRIB_VOLATILE, true)?;
        }
        if self.is_isolated() {
            encoder.write_bool(ATTRIB_MERGE, false)?;
        }
        // `isThis`/`isHidden` are never set for a HighLabelSymbol (its storage is never
        // auto-storage), so the ATTRIB_THISPTR/ATTRIB_HIDDENRETPARM branches never fire; the
        // constants are still imported/referenced here for documentation fidelity with Java's
        // encodeHeader.
        let _ = (ATTRIB_THISPTR, ATTRIB_HIDDENRETPARM);
        encoder.write_signed_integer(ATTRIB_CAT, -1)?;
        // categoryIndex is always -1 for this class -> ATTRIB_INDEX is never written.

        encoder.close_element(ELEM_LABELSYM)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared, deliberately-minimal mocks for exercising [`super::resolve_storage`] (and, by
    //! extension, every `HighSymbol`-subclass constructor in this module family that calls it):
    //! a [`Language`] whose only *reachable* method (per `check_varnodes`'s call graph -- see
    //! `variable_storage.rs`) is [`Language::is_big_endian`], and a [`ProgramArchitecture`] whose
    //! [`ProgramArchitecture::get_address_factory`] is deliberately empty so storage resolution
    //! always fails fast (before `get_register_at`/any other `Language` method would ever be
    //! reached), always falling back to `UnassignedStorage`. Every other trait method is required
    //! by the trait definition but is provably unreachable from that call path, so it panics if
    //! ever invoked.
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSetView, AddressSpace, DefaultAddressFactory};
    use crate::program::model::lang::{
        compiler_spec_description::CompilerSpecDescription,
        compiler_spec_id::CompilerSpecID,
        compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        instruction_prototype::InstructionPrototype,
        language_description::LanguageDescription,
        language_id::LanguageID,
        parallel_instruction_language_helper::ParallelInstructionLanguageHelper,
        processor_context::ProcessorContext,
        register::RegisterRef,
        CompilerSpec, Language, ParseError,
    };
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::util::task::TaskMonitor;
    use std::collections::HashSet;

    fn unreachable_in_this_mock() -> ! {
        panic!(
            "this Language/ProgramArchitecture mock only supports the immediate-failure path \
             through check_varnodes (empty address factory); this method should be provably \
             unreachable -- see test_support module docs"
        )
    }

    pub(crate) struct MockLanguage;
    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            unreachable_in_this_mock()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unreachable_in_this_mock()
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            unreachable_in_this_mock()
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unreachable_in_this_mock()
        }
        fn get_version(&self) -> i32 {
            unreachable_in_this_mock()
        }
        fn get_minor_version(&self) -> i32 {
            unreachable_in_this_mock()
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unreachable_in_this_mock()
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unreachable_in_this_mock()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unreachable_in_this_mock()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            unreachable_in_this_mock()
        }
        fn supports_pcode(&self) -> bool {
            unreachable_in_this_mock()
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            unreachable_in_this_mock()
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            unreachable_in_this_mock()
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            unreachable_in_this_mock()
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            unreachable_in_this_mock()
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            unreachable_in_this_mock()
        }
        fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> {
            unreachable_in_this_mock()
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            unreachable_in_this_mock()
        }
        fn get_register_names(&self) -> Vec<String> {
            unreachable_in_this_mock()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            unreachable_in_this_mock()
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            unreachable_in_this_mock()
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            unreachable_in_this_mock()
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            unreachable_in_this_mock()
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            unreachable_in_this_mock()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            unreachable_in_this_mock()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            unreachable_in_this_mock()
        }
        fn get_segmented_space(&self) -> String {
            unreachable_in_this_mock()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            unreachable_in_this_mock()
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {
            unreachable_in_this_mock()
        }
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> io::Result<()> {
            unreachable_in_this_mock()
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            unreachable_in_this_mock()
        }
        fn get_compiler_spec_by_id(&self, _id: &CompilerSpecID) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            unreachable_in_this_mock()
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unreachable_in_this_mock()
        }
        fn has_property(&self, _key: &str) -> bool {
            unreachable_in_this_mock()
        }
        fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
            unreachable_in_this_mock()
        }
        fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
            unreachable_in_this_mock()
        }
        fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
            unreachable_in_this_mock()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            unreachable_in_this_mock()
        }
        fn get_property_keys(&self) -> HashSet<String> {
            unreachable_in_this_mock()
        }
        fn has_manual(&self) -> bool {
            unreachable_in_this_mock()
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            unreachable_in_this_mock()
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            unreachable_in_this_mock()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            unreachable_in_this_mock()
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            unreachable_in_this_mock()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            unreachable_in_this_mock()
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            unreachable_in_this_mock()
        }
    }

    pub(crate) struct AlwaysEmptyProgramArchitecture;
    impl ProgramArchitecture for AlwaysEmptyProgramArchitecture {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            // Deliberately empty: `check_varnodes`'s address-space lookup always misses, so
            // storage resolution always fails fast (see module docs).
            Box::new(DefaultAddressFactory::new(Vec::new()))
        }
        fn get_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unreachable_in_this_mock()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::AlwaysEmptyProgramArchitecture;
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::UnassignedStorage;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use std::sync::Arc;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<ElementId>,
        closed: Vec<ElementId>,
        bools: Vec<(AttributeId, bool)>,
        strings: Vec<(AttributeId, String)>,
        signed: Vec<(AttributeId, i64)>,
        unsigned: Vec<(AttributeId, u64)>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.opened.push(elem_id);
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.closed.push(elem_id);
            Ok(())
        }
        fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()> {
            self.bools.push((attrib_id, val));
            Ok(())
        }
        fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
            self.signed.push((attrib_id, val));
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.unsigned.push((attrib_id, val));
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.strings.push((attrib_id, val.to_string()));
            Ok(())
        }
        fn write_string_indexed(&mut self, attrib_id: AttributeId, index: i32, val: &str) -> io::Result<()> {
            self.strings.push((attrib_id, format!("[{index}]{val}")));
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _name: &str) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    /// Construction matches Java's constructor: name/typelock/namelock come from the fixed
    /// `super(0, nm, DataType.DEFAULT, true, true, dtmanage)` call.
    #[test]
    fn new_is_always_type_and_name_locked_with_id_zero() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let sym = HighLabelSymbol::new_with_storage("LAB_0x1000", program, ResolvedStorage::Unassigned);

        assert_eq!(sym.get_id(), 0);
        assert_eq!(sym.get_name(), "LAB_0x1000");
        assert!(sym.is_type_locked());
        assert!(sym.is_name_locked());
        assert!(sym.is_isolated());
    }

    /// [`resolve_storage`] (used by every `HighSymbol`-subclass constructor in this module
    /// family) falls back to `VariableStorage.UNASSIGNED_STORAGE` when construction fails,
    /// matching Java's `try { ... } catch (InvalidInputException e) { store =
    /// VariableStorage.UNASSIGNED_STORAGE; }`. Exercised once here via a real (if deliberately
    /// always-failing) `ProgramArchitecture`/`Language` pair; see `test_support`'s module docs.
    #[test]
    fn resolve_storage_falls_back_to_unassigned_storage_on_failure() {
        let space = ram_space();
        let addr = Address::new(space, 0x1000);
        let storage = ResolvedStorage::resolve(Arc::new(AlwaysEmptyProgramArchitecture), addr, 1);
        assert!(matches!(storage, ResolvedStorage::Unassigned));
    }

    /// [`HighLabelSymbol::new`] wires `resolve_storage`'s result into the constructed symbol's
    /// storage end-to-end (not just `resolve_storage` in isolation).
    #[test]
    fn new_wires_resolve_storage_result_into_symbol() {
        let space = ram_space();
        let addr = Address::new(space, 0x1000);
        let program: Arc<dyn Program> = Arc::new(MockProgram);

        let sym = HighLabelSymbol::new("LAB_end_to_end", addr, program, Arc::new(AlwaysEmptyProgramArchitecture));

        assert!(sym.get_storage().is_unassigned_storage());
        assert_eq!(sym.get_name(), "LAB_end_to_end");
    }

    /// A `HighLabelSymbol` constructed with no associated `HighFunction` panics (rather than
    /// silently fabricating one) if `get_high_function` is actually invoked -- see the module docs
    /// for why Java's `null` field has no direct Rust analogue here.
    #[test]
    #[should_panic(expected = "no associated HighFunction")]
    fn get_high_function_panics_documenting_the_null_function_gap() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let sym = HighLabelSymbol::new_with_storage("LAB_0x2000", program, ResolvedStorage::Unassigned);
        let _ = sym.get_high_function().get_id();
    }

    /// `encode` writes the fixed `<labelsym>` header: id (since `0 >> 56 != ID_BASE >> 56`),
    /// name, both locks, and `cat = -1`; `ATTRIB_MERGE=false` appears because this symbol is
    /// always isolated (typelock=true).
    #[test]
    fn encode_writes_labelsym_header() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let sym = HighLabelSymbol::new_with_storage("mylabel", program, ResolvedStorage::Unassigned);

        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened, vec![ELEM_LABELSYM]);
        assert_eq!(encoder.closed, vec![ELEM_LABELSYM]);
        assert!(encoder.unsigned.contains(&(ATTRIB_ID, 0)));
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "mylabel".to_string())));
        assert!(encoder.bools.contains(&(ATTRIB_TYPELOCK, true)));
        assert!(encoder.bools.contains(&(ATTRIB_NAMELOCK, true)));
        assert!(encoder.bools.contains(&(ATTRIB_MERGE, false)));
        assert!(encoder.signed.contains(&(ATTRIB_CAT, -1)));
        assert!(!encoder.bools.iter().any(|(id, _)| *id == ATTRIB_READONLY));
        assert!(!encoder.bools.iter().any(|(id, _)| *id == ATTRIB_VOLATILE));
    }

    /// `set_type_lock`/`set_name_lock` are real mutators, not hardcoded `true`s -- matching Java's
    /// `setTypeLock`/`setNameLock` remaining callable after construction.
    #[test]
    fn locks_are_mutable_after_construction() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let mut sym = HighLabelSymbol::new_with_storage("mut_lock", program, ResolvedStorage::Unassigned);

        sym.set_type_lock(false);
        sym.set_name_lock(false);
        assert!(!sym.is_type_locked());
        assert!(!sym.is_name_locked());
        assert!(!sym.is_isolated());
    }
}

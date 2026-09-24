//! Port of `ghidra.pcode.memstate.DefaultMemoryState`.
//!
//! All storage/state for a p-code emulator machine. Every piece of information in a p-code
//! emulator machine is representable as a triple `(AddressSpace, offset, size)`. This type allows
//! getting and setting of all state information of this form.
//!
//! # Shape
//!
//! Java's `DefaultMemoryState extends AbstractMemoryState` (itself `implements MemoryState`).
//! Rust has no inheritance, so this struct stores the `language` field the superclass constructor
//! captures (`super(language)`) directly -- the same treatment
//! [`AdaptedMemoryState`](crate::app::emulator::AdaptedMemoryState) gives its own identical
//! `language` field -- and implements both [`AbstractMemoryState`] (for the `set_chunk`/
//! `get_chunk` primitives, which in turn supply [`AbstractMemoryState`]'s default
//! convenience-method bodies) and [`MemoryState`] (so this type is directly usable wherever `dyn
//! MemoryState` is expected, matching how Java's `DefaultMemoryState` transitively `implements
//! MemoryState`). The two traits declare identically-named convenience methods (e.g. both have
//! `set_value_varnode`), so [`MemoryState`]'s implementations below call through to
//! [`AbstractMemoryState`]'s default bodies using fully-qualified syntax to disambiguate.
//!
//! Java's `memspace` field is a `VectorSTL<MemoryBank>` indexed by `AddressSpace.getUnique()`,
//! auto-growing (`push_back(null)`) to accommodate whatever unique index is registered; this is
//! mirrored here with a `Vec<Option<Box<dyn MemoryBankImpl>>>` grown the same way, indexed by
//! [`AddressSpace::unique`].
//!
//! # Deprecation
//!
//! Deprecated since Ghidra 12.1 and scheduled for removal, matching [`AbstractMemoryState`].

use std::sync::Arc;

use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::memstate::abstract_memory_state::AbstractMemoryState;
use crate::pcode::memstate::memory_bank::MemoryBankImpl;
use crate::pcode::memstate::memory_state::MemoryState;
use crate::pcode::utils::long_to_bytes;
use crate::program::model::address::{AddressSpace, AddressSpaceType};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::pcode::Varnode;

#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub struct DefaultMemoryState {
    memspace: Vec<Option<Box<dyn MemoryBankImpl>>>,
    language: Box<dyn Language>,
}

#[allow(deprecated)]
impl DefaultMemoryState {
    /// `MemoryState` constructor for a specified processor language.
    ///
    /// Port of `DefaultMemoryState(Language language)`.
    pub fn new(language: Box<dyn Language>) -> Self {
        Self { memspace: Vec::new(), language }
    }

    fn bank(&self, spc: &Arc<AddressSpace>) -> Option<&dyn MemoryBankImpl> {
        let index = spc.unique() as usize;
        self.memspace.get(index).and_then(|slot| slot.as_deref())
    }

    fn bank_mut<'s>(
        &'s mut self,
        spc: &Arc<AddressSpace>,
    ) -> Option<&'s mut (dyn MemoryBankImpl + 'static)> {
        let index = spc.unique() as usize;
        match self.memspace.get_mut(index) {
            Some(slot) => slot.as_deref_mut(),
            None => None,
        }
    }
}

#[allow(deprecated)]
impl AbstractMemoryState for DefaultMemoryState {
    fn is_big_endian(&self) -> bool {
        self.language.is_big_endian()
    }

    fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
        self.language.get_register_by_name(name)
    }

    /// This is the main interface for setting values for a range of bytes in the `MemoryState`.
    /// The `MemoryBank` associated with the desired address space is looked up and the write is
    /// forwarded to the `set_chunk` method on the `MemoryBank`. If there is no registered
    /// `MemoryBank` or some other error, an error is returned. All `set_value` methods utilize
    /// this method to write the bytes to the appropriate memory bank.
    ///
    /// Port of `setChunk(byte[], AddressSpace, long, int)`.
    fn set_chunk(
        &mut self,
        val: &[u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
    ) -> Result<(), LowlevelError> {
        let name = spc.name().to_string();
        let bank = self.bank_mut(spc).ok_or_else(|| {
            LowlevelError::with_message(format!("Setting chunk of unmapped memory space: {name}"))
        })?;
        bank.set_chunk(off, size, val);
        Ok(())
    }

    /// This is the main interface for reading a range of bytes from the `MemoryState`. The
    /// `MemoryBank` associated with the address space of the query is looked up and the request
    /// is forwarded to the `get_chunk` method on the `MemoryBank`. If there is no registered
    /// `MemoryBank` or some other error, an error is returned. All `get_value` methods utilize
    /// this method to read the bytes from the appropriate memory bank.
    ///
    /// `stop_on_uninitialized`: if `true` a partial read is permitted and returned size may be
    /// smaller than size requested.
    ///
    /// Port of `getChunk(byte[], AddressSpace, long, int, boolean)`.
    fn get_chunk(
        &mut self,
        res: &mut [u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        stop_on_uninitialized: bool,
    ) -> Result<i32, LowlevelError> {
        if spc.space_type() == AddressSpaceType::Constant {
            let bytes = long_to_bytes(off, size as usize, self.language.is_big_endian());
            res[..size as usize].copy_from_slice(&bytes);
            return Ok(size);
        }
        let name = spc.name().to_string();
        let bank = self.bank_mut(spc).ok_or_else(|| {
            LowlevelError::with_message(format!("Getting chunk from unmapped memory space: {name}"))
        })?;
        Ok(bank.get_chunk(off, size, res, stop_on_uninitialized))
    }
}

#[allow(deprecated)]
impl MemoryState for DefaultMemoryState {
    /// `MemoryBank`s associated with specific address spaces must be registered with this
    /// `MemoryState` via this method. Each address space that will be used during emulation must
    /// be registered separately. The `MemoryState` object does not assume responsibility for
    /// freeing the `MemoryBank`.
    ///
    /// Port of the `final void setMemoryBank(MemoryBank bank)`.
    fn set_memory_bank(&mut self, bank: Box<dyn MemoryBankImpl>) {
        let index = bank.state().space().unique() as usize;
        while index >= self.memspace.len() {
            self.memspace.push(None);
        }
        self.memspace[index] = Some(bank);
    }

    /// Any `MemoryBank` that has been registered with this `MemoryState` can be retrieved via
    /// this method if the `MemoryBank`'s associated address space is known.
    ///
    /// Port of the `final MemoryBank getMemoryBank(AddressSpace spc)`. Returns `None` if no bank
    /// is associated with `spc`.
    fn get_memory_bank(&self, spc: &Arc<AddressSpace>) -> Option<&dyn MemoryBankImpl> {
        self.bank(spc)
    }

    fn set_value_varnode(&mut self, vn: &Varnode, cval: i64) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_value_varnode(self, vn, cval)
    }

    fn set_value_register(&mut self, reg: &Register, cval: i64) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_value_register(self, reg, cval)
    }

    fn set_value_by_name(&mut self, nm: &str, cval: i64) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_value_by_name(self, nm, cval)
    }

    fn set_value(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        cval: i64,
    ) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_value(self, spc, off, size, cval)
    }

    fn get_value_varnode(&mut self, vn: &Varnode) -> Result<i64, LowlevelError> {
        AbstractMemoryState::get_value_varnode(self, vn)
    }

    fn get_value_register(&mut self, reg: &Register) -> Result<i64, LowlevelError> {
        AbstractMemoryState::get_value_register(self, reg)
    }

    fn get_value_by_name(&mut self, nm: &str) -> Result<i64, LowlevelError> {
        AbstractMemoryState::get_value_by_name(self, nm)
    }

    fn get_value(&mut self, spc: &Arc<AddressSpace>, off: i64, size: i32) -> Result<i64, LowlevelError> {
        AbstractMemoryState::get_value(self, spc, off, size)
    }

    fn set_big_value_varnode(&mut self, vn: &Varnode, cval: i128) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_big_value_varnode(self, vn, cval)
    }

    fn set_big_value_register(&mut self, reg: &Register, cval: i128) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_big_value_register(self, reg, cval)
    }

    fn set_big_value_by_name(&mut self, nm: &str, cval: i128) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_big_value_by_name(self, nm, cval)
    }

    fn set_big_value(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        cval: i128,
    ) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_big_value(self, spc, off, size, cval)
    }

    fn get_big_integer_varnode(&mut self, vn: &Varnode, signed: bool) -> Result<i128, LowlevelError> {
        AbstractMemoryState::get_big_integer_varnode(self, vn, signed)
    }

    fn get_big_integer_register(&mut self, reg: &Register) -> Result<i128, LowlevelError> {
        AbstractMemoryState::get_big_integer_register(self, reg)
    }

    fn get_big_integer_by_name(&mut self, nm: &str) -> Result<i128, LowlevelError> {
        AbstractMemoryState::get_big_integer_by_name(self, nm)
    }

    fn get_big_integer(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        signed: bool,
    ) -> Result<i128, LowlevelError> {
        AbstractMemoryState::get_big_integer(self, spc, off, size, signed)
    }

    fn get_chunk(
        &mut self,
        res: &mut [u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        stop_on_uninitialized: bool,
    ) -> Result<i32, LowlevelError> {
        AbstractMemoryState::get_chunk(self, res, spc, off, size, stop_on_uninitialized)
    }

    fn set_chunk(
        &mut self,
        val: &[u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
    ) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_chunk(self, val, spc, off, size)
    }

    /// This method allows ranges of bytes to be marked as initialized or not. There is no
    /// restriction on the offset to write to or the number of bytes to be written, except that
    /// the range must be contained in the address space.
    ///
    /// Port of `setInitialized(boolean, AddressSpace, long, int)`.
    ///
    /// # Preserved quirk
    /// Java's error message reads `"Setting intialization status of unmapped memory space: "`
    /// (missing the first `i` in "initialization") -- reproduced verbatim here rather than
    /// corrected.
    fn set_initialized(
        &mut self,
        initialized: bool,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
    ) -> Result<(), LowlevelError> {
        let name = spc.name().to_string();
        let bank = self.bank_mut(spc).ok_or_else(|| {
            LowlevelError::with_message(format!(
                "Setting intialization status of unmapped memory space: {name}"
            ))
        })?;
        bank.set_initialized(off, size, initialized);
        Ok(())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    // Deliberately *not* `use super::*` -- that would bring both `AbstractMemoryState` and
    // `MemoryState` into scope, and since `DefaultMemoryState` implements both (with identically
    // named convenience methods), plain dot-call syntax below would become ambiguous. Only
    // `MemoryState` is imported, so these tests exercise it unambiguously via `state.method(...)`.
    use super::{DefaultMemoryState, Language};
    use crate::pcode::error::lowlevel_error::LowlevelError;
    use crate::pcode::memstate::memory_bank::MemoryBankImpl;
    use crate::pcode::memstate::memory_bank::MemoryBankState;
    use crate::pcode::memstate::memory_state::MemoryState;
    use crate::program::model::pcode::Varnode;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::pcode::memstate::memory_page::MemoryPage;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::sync::Arc;
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::program::model::address::{AddressFactory, AddressSet, AddressSetView};
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::util::task::TaskMonitor;
    use std::collections::{HashMap, HashSet};

    /// A minimal [`Language`] double: only [`is_big_endian`](Language::is_big_endian) and
    /// [`get_register_by_name`](Language::get_register_by_name) are exercised by
    /// `DefaultMemoryState`'s convenience methods (mirroring the superclass's cached `language`
    /// field); every other member is unreachable from these tests. Mirrors the identical
    /// `TestLanguage` double in `app::emulator::adapted_memory_state`'s own tests.
    struct TestLanguage {
        is_big_endian: bool,
        registers: HashMap<String, RegisterRef>,
    }

    impl Language for TestLanguage {
        fn get_language_id(&self) -> LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            self.is_big_endian
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(UnknownInstructionException::new()))
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
            self.registers.values().cloned().collect()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers.keys().cloned().collect()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers.get(name).cloned()
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
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
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
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by these tests")
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
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    fn language(is_big_endian: bool) -> Box<dyn Language> {
        Box::new(TestLanguage { is_big_endian, registers: HashMap::new() })
    }

    fn language_with_register(is_big_endian: bool, reg: RegisterRef) -> Box<dyn Language> {
        let name = reg.name().to_string();
        let mut registers = HashMap::new();
        registers.insert(name, reg);
        Box::new(TestLanguage { is_big_endian, registers })
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn other_ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM2", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn constant_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 2)
    }

    struct SinglePageBank {
        state: MemoryBankState,
        page: MemoryPage,
    }

    impl SinglePageBank {
        fn new(space: Arc<AddressSpace>, is_big_endian: bool, pagesize: i32) -> Self {
            Self {
                state: MemoryBankState::new(space, is_big_endian, pagesize, None),
                page: MemoryPage::new(pagesize as usize),
            }
        }
    }

    impl MemoryBankImpl for SinglePageBank {
        fn state(&self) -> &MemoryBankState {
            &self.state
        }
        fn get_page(&mut self, _addr: i64) -> &mut MemoryPage {
            &mut self.page
        }
        fn set_page(&mut self, _addr: i64, val: &[u8], skip: i32, size: i32, buf_offset: i32) {
            let skip = skip as usize;
            let size = size as usize;
            let buf_offset = buf_offset as usize;
            self.page.data[skip..skip + size].copy_from_slice(&val[buf_offset..buf_offset + size]);
        }
        fn set_page_initialized(
            &mut self,
            _addr: i64,
            initialized: bool,
            skip: i32,
            size: i32,
            _buf_offset: i32,
        ) {
            if initialized {
                self.page.mark_initialized(skip as usize, size as usize);
            } else {
                self.page.mark_uninitialized(skip as usize, size as usize);
            }
        }
    }

    fn state_with_ram(is_big_endian: bool) -> (DefaultMemoryState, Arc<AddressSpace>) {
        let space = ram_space();
        let mut state = DefaultMemoryState::new(language(is_big_endian));
        state.set_memory_bank(Box::new(SinglePageBank::new(space.clone(), is_big_endian, 64)));
        (state, space)
    }

    #[test]
    fn set_value_then_get_value_round_trips() {
        let (mut state, space) = state_with_ram(false);
        state.set_value(&space, 0x10, 4, 0x01020304).unwrap();
        assert_eq!(state.get_value(&space, 0x10, 4).unwrap(), 0x01020304);
    }

    #[test]
    fn set_value_encodes_big_endian_bytes() {
        let (mut state, space) = state_with_ram(true);
        state.set_value(&space, 0, 4, 0x01020304).unwrap();
        let mut raw = [0u8; 4];
        state.get_chunk(&mut raw, &space, 0, 4, false).unwrap();
        assert_eq!(raw, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn get_value_constant_space_returns_offset_directly() {
        let (mut state, _space) = state_with_ram(false);
        let space = constant_space();
        // No bank is ever registered for the constant space; getValue must not touch getChunk's
        // memory-bank lookup at all.
        assert_eq!(state.get_value(&space, 42, 4).unwrap(), 42);
    }

    #[test]
    fn get_chunk_constant_space_encodes_offset_directly() {
        let (mut state, _space) = state_with_ram(false);
        let space = constant_space();
        let mut res = [0u8; 4];
        let n = state.get_chunk(&mut res, &space, 0x01020304, 4, false).unwrap();
        assert_eq!(n, 4);
        assert_eq!(res, [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn set_value_by_name_then_get_value_by_name_round_trips() {
        let space = ram_space();
        let reg = Register::new("pc", "program counter", Address::new(space.clone(), 0x30), 4, false, 0);
        let mut state = DefaultMemoryState::new(language_with_register(false, reg));
        state.set_memory_bank(Box::new(SinglePageBank::new(space, false, 64)));

        state.set_value_by_name("pc", 0xdeadbeefu32 as i64).unwrap();
        assert_eq!(state.get_value_by_name("pc").unwrap(), 0xdeadbeefu32 as i64);
    }

    #[test]
    fn value_by_name_for_unknown_register_is_an_error_not_a_panic() {
        let (mut state, _space) = state_with_ram(false);
        assert!(state.set_value_by_name("nope", 1).is_err());
        assert!(state.get_value_by_name("nope").is_err());
    }

    #[test]
    fn set_value_varnode_then_get_value_varnode_round_trips() {
        let (mut state, space) = state_with_ram(false);
        let vn = Varnode::new(Address::new(space, 0x40), 2);
        state.set_value_varnode(&vn, 0x1234).unwrap();
        assert_eq!(state.get_value_varnode(&vn).unwrap(), 0x1234);
    }

    #[test]
    fn set_big_value_then_get_big_integer_round_trips() {
        let (mut state, space) = state_with_ram(false);
        state.set_big_value(&space, 0x50, 8, 0x1122334455667788).unwrap();
        assert_eq!(state.get_big_integer(&space, 0x50, 8, false).unwrap(), 0x1122334455667788);
    }

    #[test]
    fn set_chunk_on_unmapped_space_is_an_error() {
        let (mut state, _space) = state_with_ram(false);
        let unmapped = other_ram_space();
        let result = state.set_chunk(&[1, 2, 3, 4], &unmapped, 0, 4);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Setting chunk of unmapped memory space"));
    }

    #[test]
    fn get_chunk_on_unmapped_space_is_an_error() {
        let (mut state, _space) = state_with_ram(false);
        let unmapped = other_ram_space();
        let mut res = [0u8; 4];
        let result = state.get_chunk(&mut res, &unmapped, 0, 4, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Getting chunk from unmapped memory space"));
    }

    /// Preserved Java quirk (see `set_initialized`'s own docs): the error message has a real typo,
    /// "intialization" rather than "initialization".
    #[test]
    fn set_initialized_on_unmapped_space_reports_the_javas_typo_verbatim() {
        let (mut state, _space) = state_with_ram(false);
        let unmapped = other_ram_space();
        let result = state.set_initialized(true, &unmapped, 0, 4);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Setting intialization status of unmapped memory space"));
    }

    #[test]
    fn set_initialized_false_makes_get_chunk_stop_early() {
        let (mut state, space) = state_with_ram(false);
        state.set_value(&space, 0, 4, 0x01020304).unwrap();
        state.set_initialized(false, &space, 1, 2).unwrap();

        let mut res = [0u8; 4];
        let n = state.get_chunk(&mut res, &space, 0, 4, true).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn get_memory_bank_returns_registered_bank() {
        let (state, space) = state_with_ram(false);
        assert!(state.get_memory_bank(&space).is_some());
    }

    #[test]
    fn get_memory_bank_none_for_unregistered_space() {
        let (state, _space) = state_with_ram(false);
        assert!(state.get_memory_bank(&other_ram_space()).is_none());
    }

    #[test]
    fn set_memory_bank_grows_memspace_to_accommodate_unique_index() {
        // A space registered with a large `unique()` index should not disturb one registered at a
        // smaller index earlier (mirrors Java's auto-growing VectorSTL, padding with nulls).
        let mut state = DefaultMemoryState::new(language(false));
        let low = AddressSpace::new("low", 32, 1, AddressSpaceType::Ram, 0);
        let high = AddressSpace::new("high", 32, 1, AddressSpaceType::Ram, 5);
        state.set_memory_bank(Box::new(SinglePageBank::new(low.clone(), false, 16)));
        state.set_memory_bank(Box::new(SinglePageBank::new(high.clone(), false, 16)));

        assert!(state.get_memory_bank(&low).is_some());
        assert!(state.get_memory_bank(&high).is_some());
    }

    #[test]
    fn usable_as_a_memory_state_trait_object() {
        let (state, _space) = state_with_ram(false);
        let boxed: Box<dyn MemoryState> = Box::new(state);
        assert!(boxed.get_memory_bank(&ram_space()).is_some());
    }
}

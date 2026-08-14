//! Port of `ghidra.app.util.bin.format.elf.relocation.PowerPC_ElfRelocationContext`.
//!
//! Provides PowerPC-specific relocation context with support for establishing the small data
//! area base registers (`_SDA_BASE_`/r13 and `_SDA2_BASE_`/r2) used by `-msdata` relocations.
//!
//! # Shape
//!
//! Java's `PowerPC_ElfRelocationContext` is a concrete leaf: it extends
//! `ElfRelocationContext<PowerPC_ElfRelocationHandler>` with cached `sdaBase`/`sda2Base` fields
//! and package-private accessors used by the PowerPC relocation handler. Per the port's shape
//! rules a concrete leaf class becomes a `struct` + `impl`, never a trait.
//!
//! # Departures from the Java class
//!
//! * `Symbol.isPinned()` has no port on this crate's [`Symbol`](crate::program::model::symbol::Symbol)
//!   trait, so [`get_base_offset`](PowerPcElfRelocationContext::get_base_offset) always logs the
//!   non-absolute form of the "Using ..." message rather than Java's `"Using absolute ..."`
//!   variant.
//! * Java mutates the shared `Program` directly (`program.getProgramContext().setValue(...)`,
//!   `program.getSymbolTable().createLabel(...)`). This port's `Program` is held behind
//!   `Arc<dyn Program>`, whose mutable accessors require unique ownership; mirroring the
//!   `Arc::get_mut` best-effort idiom already used elsewhere in this crate (e.g.
//!   [`DataUtilities`](crate::program::model::data::data_utilities::DataUtilities),
//!   [`SymbolUtilities::create_preferred_label_or_function_symbol`](crate::program::model::symbol::symbol_utilities::SymbolUtilities::create_preferred_label_or_function_symbol)),
//!   both operations silently no-op when the `Program` handle is not uniquely owned rather than
//!   Java's unconditional mutation.

use std::collections::HashMap;
use std::sync::Arc;

use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::elf::relocation::elf_relocation_context::{
    ElfRelocationContext, ElfRelocationContextBase,
};
use crate::format::seam_stubs::ElfRelocationHandler;
use crate::program::model::address::address_set::AddressSet;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::symbol::source_type::SourceType;
use crate::program::model::symbol::symbol_utilities::{DefaultSymbolUtilities, SymbolUtilities};

/// Provides PowerPC-specific relocation context with small data area (SDA) base handling.
///
/// PowerPC `-msdata` relocations are computed relative to `_SDA_BASE_` (held in r13) and
/// `_SDA2_BASE_` (held in r2). These bases are established lazily, on first use, either from an
/// existing symbol or by defining one over the `.sdata`/`.sbss` (respectively `.sdata2`/`.sbss2`)
/// memory block range.
pub struct PowerPcElfRelocationContext {
    base: ElfRelocationContextBase,
    /// Cached `_SDA_BASE_` offset. `None` means not yet computed; `Some(-1)` means computation
    /// was attempted and failed.
    sda_base: Option<i32>,
    /// Cached `_SDA2_BASE_` offset. `None` means not yet computed; `Some(-1)` means computation
    /// was attempted and failed.
    sda2_base: Option<i32>,
}

impl PowerPcElfRelocationContext {
    /// Creates a new PowerPC relocation context.
    ///
    /// # Arguments
    /// * `handler` - PowerPC relocation handler, or `None` if not available
    /// * `load_helper` - the ELF load helper
    /// * `symbol_map` - ELF symbol placement map
    pub fn new(
        handler: Option<Arc<dyn ElfRelocationHandler>>,
        load_helper: Arc<dyn ElfLoadHelper>,
        symbol_map: Arc<HashMap<ElfSymbol, Address>>,
    ) -> Self {
        PowerPcElfRelocationContext {
            base: ElfRelocationContextBase::new(handler, load_helper, symbol_map),
            sda_base: None,
            sda2_base: None,
        }
    }

    /// Get or establish the `_SDA_BASE_` value and apply it as the r13 context value to all
    /// memory blocks with execute permission.
    ///
    /// Returns the `_SDA_BASE_` offset, or `None` if unable to determine or establish it.
    pub fn get_sda_base(&mut self) -> Option<i32> {
        if let Some(sda_base) = self.sda_base {
            return (sda_base != -1).then_some(sda_base);
        }
        let sda_base = self.get_base_offset("_SDA_BASE_", &[".sdata", ".sbss"]);
        self.sda_base = Some(sda_base);
        if sda_base == -1 {
            self.base.get_log().append_msg("ERROR: failed to establish _SDA_BASE_");
            return None;
        }
        self.set_register_context("r13", sda_base as i64);
        Some(sda_base)
    }

    /// Get or establish the `_SDA2_BASE_` value and apply it as the r2 context value to all
    /// memory blocks with execute permission.
    ///
    /// Returns the `_SDA2_BASE_` offset, or `None` if unable to determine or establish it.
    pub fn get_sda2_base(&mut self) -> Option<i32> {
        if let Some(sda2_base) = self.sda2_base {
            return (sda2_base != -1).then_some(sda2_base);
        }
        let sda2_base = self.get_base_offset("_SDA2_BASE_", &[".sdata2", ".sbss2"]);
        self.sda2_base = Some(sda2_base);
        if sda2_base == -1 {
            self.base.get_log().append_msg("ERROR: failed to establish _SDA2_BASE_");
            return None;
        }
        self.set_register_context("r2", sda2_base as i64);
        Some(sda2_base)
    }

    /// Apply register context to all memory blocks which have execute permission.
    ///
    /// See the module documentation for why this is best-effort: it silently does nothing if the
    /// underlying `Program` handle is not uniquely owned.
    fn set_register_context(&self, reg_name: &str, value: i64) {
        let program = self.base.get_program();
        let Some(reg) = program.get_register(reg_name) else {
            return;
        };
        let Some(memory) = program.get_memory() else {
            return;
        };

        let mut program = program.clone();
        let Some(program) = Arc::get_mut(&mut program) else {
            return;
        };
        let Some(context) = program.get_program_context() else {
            return;
        };

        let reg = reg.borrow();
        for block in memory.get_blocks() {
            if block.is_execute() {
                // No instructions should exist yet, so a `ContextChangeException` here would be
                // Java's `AssertException`-worthy programming error; this port simply drops the
                // (never expected) failure rather than panicking.
                let _ = context.set_value(&reg, &block.get_start(), &block.get_end(), Some(value as i128));
            }
        }
    }

    /// Establish a base offset from a symbol, or from the range of the specified memory blocks.
    ///
    /// Returns the base offset, or `-1` on failure.
    fn get_base_offset(&self, symbol_name: &str, block_names: &[&str]) -> i32 {
        let log = self.base.get_log();
        let program = self.base.get_program();

        let mut program_clone = program.clone();
        let base_symbol = Arc::get_mut(&mut program_clone).and_then(|program| {
            let log = log.clone();
            DefaultSymbolUtilities.get_label_or_function_symbol(program, symbol_name, &mut |msg| {
                log.append_msg(&msg);
            })
        });

        if let Some(base_symbol) = base_symbol {
            let base_offset = base_symbol.get_address().offset() as i32;
            // Java also prefixes "absolute " here when `baseSymbol.isPinned()`; this port's
            // `Symbol` trait has no pinned accessor (see module docs).
            log.append_msg(&format!("Using {symbol_name} of 0x{base_offset:x}"));
            return base_offset;
        }

        let Some(memory) = program.get_memory() else {
            return -1;
        };
        let Some(default_space) = program
            .get_address_factory()
            .and_then(|factory| factory.get_default_address_space())
        else {
            return -1;
        };

        let mut block_set = AddressSet::new();
        for block_name in block_names {
            let Some(block) = memory.get_block_by_name(block_name) else {
                continue;
            };
            if block.get_start().space() != &default_space {
                log.append_msg(&format!("ERROR: {block_name} not in default space"));
                return -1;
            }
            block_set.add_range(&block.get_start(), &block.get_end());
        }
        if block_set.is_empty() {
            return -1;
        }

        let min_addr = block_set.min_address().expect("non-empty set has a min address");
        let max_addr = block_set.max_address().expect("non-empty set has a max address");
        let range = max_addr.subtract(&min_addr) + 1;
        let mut base_addr = min_addr;
        if range > i16::MAX as i64 {
            // Use the aligned midpoint of the range.
            base_addr = base_addr.add_wrap((range / 2) & !0x0f_i64);
        }

        let mut program_clone = program.clone();
        if let Some(program) = Arc::get_mut(&mut program_clone) {
            if let Some(symbol_table) = program.get_symbol_table() {
                let _ = symbol_table.create_label(&base_addr, symbol_name, SourceType::Analysis);
            }
        }

        let base_offset = base_addr.offset() as i32;
        log.append_msg(&format!("Defined {symbol_name} of 0x{base_offset:x}"));
        base_offset
    }
}

impl ElfRelocationContext for PowerPcElfRelocationContext {
    fn base(&self) -> &ElfRelocationContextBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ElfRelocationContextBase {
        &mut self.base
    }

    fn as_relocation_context(&self) -> &dyn ElfRelocationContext {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::{ElfHeader, MessageLog, Throwable};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::memory::Memory;
    use crate::program::model::mem::memory_block::MemoryBlock;
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::Mutex;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.elf".to_string()
        }
        fn get_language_id(&self) -> String {
            "PowerPC:BE:32:default".to_string()
        }
    }

    #[derive(Default)]
    struct RecordingLog {
        messages: Mutex<Vec<String>>,
    }

    impl MessageLog for RecordingLog {
        fn copy_from(&self, _log: &dyn MessageLog) {}
        fn append_msg(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn append_exception(&self, _t: &dyn Throwable) {}
        fn error(&self, _originator: &str, _message: &str) {}
        fn has_messages(&self) -> bool {
            !self.messages.lock().unwrap().is_empty()
        }
        fn clear(&self) {
            self.messages.lock().unwrap().clear();
        }
        fn set_status(&self, _status: &str) {}
        fn clear_status(&self) {}
        fn get_status(&self) -> String {
            String::new()
        }
        fn to_string(&self) -> String {
            self.messages.lock().unwrap().join("\n")
        }
        fn write(&self, _owner: &dyn crate::format::seam_stubs::Class, _message_header: &str) {}
    }

    struct MockElfHeader;
    impl ElfHeader for MockElfHeader {
        fn is32_bit(&self) -> bool {
            true
        }
        fn is_relocatable(&self) -> bool {
            true
        }
        fn get_sections(&self) -> Vec<Box<dyn crate::format::seam_stubs::ElfSectionHeader>> {
            Vec::new()
        }
    }

    struct MockLoadHelper {
        log: Arc<RecordingLog>,
    }

    impl ElfLoadHelper for MockLoadHelper {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_option_bool(&self, _option_name: &str, default_value: bool) -> bool {
            default_value
        }
        fn get_option_string(
            &self,
            _option_name: &str,
            default_value: Option<String>,
        ) -> Option<String> {
            default_value
        }
        fn get_option_i32(&self, _option_name: &str, default_value: i32) -> i32 {
            default_value
        }
        fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
            Arc::new(MockElfHeader)
        }
        fn get_log(&self) -> Arc<dyn MessageLog> {
            self.log.clone()
        }
        fn log(&self, _msg: &str) {}
        fn log_exception(&self, _t: &dyn std::error::Error) {}
        fn mark_as_code(&self, _address: Address) {}
        fn create_one_byte_function(
            &self,
            _name: Option<&str>,
            _address: Address,
            _is_entry: bool,
        ) -> Arc<dyn crate::program::model::listing::function::Function> {
            unimplemented!("not exercised by these tests")
        }
        fn create_external_function_linkage(
            &self,
            _name: &str,
            _function_addr: Address,
            _indirect_pointer_addr: Option<Address>,
        ) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_undefined_data(
            &self,
            _address: Address,
            _length: i32,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_data(
            &self,
            _address: Address,
            _dt: Box<dyn crate::program::model::data::data_type::DataType>,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_elf_symbol_address(&self, _elf_symbol: &ElfSymbol, _address: Option<Address>) {}
        fn get_elf_symbol_address(&self, _elf_symbol: &ElfSymbol) -> Option<Address> {
            None
        }
        fn create_symbol(
            &self,
            _addr: Address,
            _name: &str,
            _is_primary: bool,
            _pin_absolute: bool,
            _namespace: Option<Arc<dyn crate::program::model::symbol::namespace::Namespace>>,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::Symbol>,
            crate::util::exception::InvalidInputException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn find_load_address(
            &self,
            _section: &dyn crate::format::memory_loadable::MemoryLoadable,
            _byte_offset_within_section: i64,
        ) -> Option<Address> {
            None
        }
        fn get_default_address(&self, _addressable_word_offset: i64) -> Address {
            unimplemented!("not exercised by these tests")
        }
        fn get_image_base_word_adjustment_offset(&self) -> i64 {
            0
        }
        fn get_got_value(&self) -> Option<i64> {
            None
        }
        fn allocate_linkage_block(
            &self,
            _alignment: i32,
            _size: i32,
            _purpose: &str,
        ) -> Option<crate::program::model::address::range::AddressRange> {
            None
        }
        fn get_original_value(
            &self,
            _addr: Address,
            _sign_extend: bool,
        ) -> Result<i64, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn add_artificial_reloc_table_entry(&self, _address: Address, _length: i32) -> bool {
            false
        }
    }

    fn create_context() -> PowerPcElfRelocationContext {
        let load_helper = Arc::new(MockLoadHelper {
            log: Arc::new(RecordingLog::default()),
        });
        PowerPcElfRelocationContext::new(None, load_helper, Arc::new(HashMap::new()))
    }

    #[test]
    fn new_wires_the_base_context() {
        struct MockHandler;
        impl ElfRelocationHandler for MockHandler {
            fn relocate(
                &self,
                _context: &dyn ElfRelocationContext,
                _relocation: &dyn crate::format::seam_stubs::ElfRelocation,
                _relocation_address: &Address,
            ) -> Result<
                crate::program::model::reloc::RelocationResult,
                crate::format::elf::relocation::elf_relocation_context::RelocationProcessingError,
            > {
                unimplemented!("not exercised by this test")
            }
            fn mark_as_error(
                &self,
                _program: &dyn Program,
                _relocation_address: &Address,
                _type_id: i32,
                _symbol_name: Option<&str>,
                _symbol_index: i32,
                _msg: &str,
                _log: &dyn MessageLog,
            ) {
            }
            fn mark_as_warning(
                &self,
                _program: &dyn Program,
                _relocation_address: &Address,
                _type_id: i32,
                _symbol_name: Option<&str>,
                _symbol_index: i32,
                _msg: &str,
                _log: &dyn MessageLog,
            ) {
            }
        }

        let load_helper = Arc::new(MockLoadHelper {
            log: Arc::new(RecordingLog::default()),
        });
        let context = PowerPcElfRelocationContext::new(
            Some(Arc::new(MockHandler)),
            load_helper,
            Arc::new(HashMap::new()),
        );
        assert!(context.base().has_relocation_handler());
    }

    #[test]
    fn get_sda_base_fails_without_symbol_or_blocks() {
        let mut context = create_context();
        // `MockProgram` has no memory/address factory, so the base cannot be established.
        assert_eq!(context.get_sda_base(), None);
        // The failure is cached: a second call returns None without recomputation.
        assert_eq!(context.get_sda_base(), None);
    }

    #[test]
    fn get_sda2_base_fails_without_symbol_or_blocks() {
        let mut context = create_context();
        assert_eq!(context.get_sda2_base(), None);
    }

    struct FakeMemoryBlock {
        name: String,
        start: Address,
        end: Address,
    }

    impl MemoryBlock for FakeMemoryBlock {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_start(&self) -> Address {
            self.start.clone()
        }
        fn get_end(&self) -> Address {
            self.end.clone()
        }
        fn get_size(&self) -> u64 {
            (self.end.offset() - self.start.offset() + 1) as u64
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
    }

    struct FakeMemory {
        blocks: Vec<Arc<dyn MemoryBlock>>,
    }

    impl Memory for FakeMemory {
        fn is_big_endian(&self) -> bool {
            true
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn get_block_by_name(&self, name: &str) -> Option<Arc<dyn MemoryBlock>> {
            self.blocks.iter().find(|b| b.get_name() == name).cloned()
        }
        fn get_blocks(&self) -> Vec<Arc<dyn MemoryBlock>> {
            self.blocks.clone()
        }
    }

    struct MockProgramWithMemory {
        memory: Arc<FakeMemory>,
        address_factory: Arc<dyn crate::program::model::address::factory::AddressFactory>,
    }

    impl crate::framework::model::DomainObject for MockProgramWithMemory {}
    impl Program for MockProgramWithMemory {
        fn get_name(&self) -> String {
            "mock.elf".to_string()
        }
        fn get_language_id(&self) -> String {
            "PowerPC:BE:32:default".to_string()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
        fn get_address_factory(
            &self,
        ) -> Option<Arc<dyn crate::program::model::address::factory::AddressFactory>> {
            Some(self.address_factory.clone())
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    /// Mirrors Java's `getBaseOffset`/`getSDABase` behavior when no `_SDA_BASE_` symbol exists
    /// but the `.sdata`/`.sbss` blocks do: the base is defined as the minimum address of the
    /// combined block range (17 bytes here, well under the `Short.MAX_VALUE` threshold that
    /// would otherwise trigger midpoint alignment).
    #[test]
    fn get_sda_base_uses_minimum_block_address_when_range_is_small() {
        use crate::program::model::address::factory::DefaultAddressFactory;

        let space = ram_space();
        let sdata = FakeMemoryBlock {
            name: ".sdata".to_string(),
            start: space.address(0x1000),
            end: space.address(0x1010),
        };
        let memory = Arc::new(FakeMemory {
            blocks: vec![Arc::new(sdata)],
        });
        let address_factory = Arc::new(DefaultAddressFactory::new(vec![space.clone()]));
        let program = Arc::new(MockProgramWithMemory {
            memory,
            address_factory,
        });

        let log = Arc::new(RecordingLog::default());
        // Route the load helper's program through the same mock instance so the test can assert
        // on its log messages.
        struct ProgramLoadHelper {
            program: Arc<dyn Program>,
            log: Arc<RecordingLog>,
        }
        impl ElfLoadHelper for ProgramLoadHelper {
            fn get_program(&self) -> Arc<dyn Program> {
                self.program.clone()
            }
            fn get_option_bool(&self, _option_name: &str, default_value: bool) -> bool {
                default_value
            }
            fn get_option_string(
                &self,
                _option_name: &str,
                default_value: Option<String>,
            ) -> Option<String> {
                default_value
            }
            fn get_option_i32(&self, _option_name: &str, default_value: i32) -> i32 {
                default_value
            }
            fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
                Arc::new(MockElfHeader)
            }
            fn get_log(&self) -> Arc<dyn MessageLog> {
                self.log.clone()
            }
            fn log(&self, _msg: &str) {}
            fn log_exception(&self, _t: &dyn std::error::Error) {}
            fn mark_as_code(&self, _address: Address) {}
            fn create_one_byte_function(
                &self,
                _name: Option<&str>,
                _address: Address,
                _is_entry: bool,
            ) -> Arc<dyn crate::program::model::listing::function::Function> {
                unimplemented!("not exercised by these tests")
            }
            fn create_external_function_linkage(
                &self,
                _name: &str,
                _function_addr: Address,
                _indirect_pointer_addr: Option<Address>,
            ) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
                unimplemented!("not exercised by these tests")
            }
            fn create_undefined_data(
                &self,
                _address: Address,
                _length: i32,
            ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
                unimplemented!("not exercised by these tests")
            }
            fn create_data(
                &self,
                _address: Address,
                _dt: Box<dyn crate::program::model::data::data_type::DataType>,
            ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
                unimplemented!("not exercised by these tests")
            }
            fn set_elf_symbol_address(&self, _elf_symbol: &ElfSymbol, _address: Option<Address>) {}
            fn get_elf_symbol_address(&self, _elf_symbol: &ElfSymbol) -> Option<Address> {
                None
            }
            fn create_symbol(
                &self,
                _addr: Address,
                _name: &str,
                _is_primary: bool,
                _pin_absolute: bool,
                _namespace: Option<Arc<dyn crate::program::model::symbol::namespace::Namespace>>,
            ) -> Result<
                Arc<dyn crate::program::model::symbol::Symbol>,
                crate::util::exception::InvalidInputException,
            > {
                unimplemented!("not exercised by these tests")
            }
            fn find_load_address(
                &self,
                _section: &dyn crate::format::memory_loadable::MemoryLoadable,
                _byte_offset_within_section: i64,
            ) -> Option<Address> {
                None
            }
            fn get_default_address(&self, _addressable_word_offset: i64) -> Address {
                unimplemented!("not exercised by these tests")
            }
            fn get_image_base_word_adjustment_offset(&self) -> i64 {
                0
            }
            fn get_got_value(&self) -> Option<i64> {
                None
            }
            fn allocate_linkage_block(
                &self,
                _alignment: i32,
                _size: i32,
                _purpose: &str,
            ) -> Option<crate::program::model::address::range::AddressRange> {
                None
            }
            fn get_original_value(
                &self,
                _addr: Address,
                _sign_extend: bool,
            ) -> Result<i64, MemoryAccessException> {
                unimplemented!("not exercised by these tests")
            }
            fn add_artificial_reloc_table_entry(&self, _address: Address, _length: i32) -> bool {
                false
            }
        }

        let load_helper = Arc::new(ProgramLoadHelper { program, log: log.clone() });
        let mut context =
            PowerPcElfRelocationContext::new(None, load_helper, Arc::new(HashMap::new()));

        assert_eq!(context.get_sda_base(), Some(0x1000));
        // Cached on the second call.
        assert_eq!(context.get_sda_base(), Some(0x1000));

        let messages = log.messages.lock().unwrap();
        assert!(
            messages.iter().any(|m| m == "Defined _SDA_BASE_ of 0x1000"),
            "unexpected log messages: {messages:?}"
        );
    }
}

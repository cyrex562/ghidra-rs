//! Port of `ghidra.app.util.bin.format.elf.relocation.RISCV_ElfRelocationContext`.
//!
//! Provides RISC-V-specific relocation context with a lookup that pairs a `%pcrel_lo`/`%tls_lo`
//! relocation with the `PCREL_HI20`/`GOT_HI20` relocation its addend is relative to.
//!
//! # Shape
//!
//! Java's `RISCV_ElfRelocationContext` is a concrete leaf: it extends
//! `ElfRelocationContext<RISCV_ElfRelocationHandler>` with a single package-private lookup method
//! (`getHi20Relocation`) and a private nested `OffsetComparator`. Per the port's shape rules a
//! concrete leaf class becomes a `struct` + `impl`, never a trait.
//!
//! # Departures from the Java class
//!
//! * Java's `getHi20Relocation` runs `Arrays.binarySearch` with an `OffsetComparator` over the
//!   table's relocation array (relying on it being sorted by offset, as `ElfRelocationTable`
//!   loads it). This port uses [`slice::binary_search_by`] with an unsigned-offset comparator,
//!   which is the direct Rust equivalent -- both require the input sorted by offset and answer
//!   any matching index.
//! * The matched relocation is taken out of the vector [`ElfRelocationTable::get_relocations`]
//!   returns (an owned `Vec`, unlike Java's live table-owned array) and returned by value.

use std::collections::HashMap;
use std::sync::Arc;

use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::elf::relocation::elf_relocation_context::{
    ElfRelocationContext, ElfRelocationContextBase,
};
use crate::format::elf::relocation::riscv_elf_relocation_type::RiscvElfRelocationType;
use crate::format::seam_stubs::{ElfRelocation, ElfRelocationHandler};
use crate::program::model::address::Address;

/// Provides RISC-V-specific relocation context with HI20/LO12 relocation pairing.
///
/// RISC-V splits many address computations across two relocations: a `PCREL_HI20`/`GOT_HI20`
/// relocation that establishes the high 20 bits, and a `PCREL_LO12_I`/`PCREL_LO12_S` relocation
/// whose addend references the *offset* of that HI20 relocation (rather than the symbol
/// directly). [`get_hi20_relocation`](Self::get_hi20_relocation) resolves that reference.
pub struct RiscvElfRelocationContext {
    base: ElfRelocationContextBase,
}

impl RiscvElfRelocationContext {
    /// Creates a new RISC-V relocation context.
    ///
    /// # Arguments
    /// * `handler` - RISC-V relocation handler, or `None` if not available
    /// * `load_helper` - the ELF load helper
    /// * `symbol_map` - ELF symbol placement map
    pub fn new(
        handler: Option<Arc<dyn ElfRelocationHandler>>,
        load_helper: Arc<dyn ElfLoadHelper>,
        symbol_map: Arc<HashMap<ElfSymbol, Address>>,
    ) -> Self {
        RiscvElfRelocationContext {
            base: ElfRelocationContextBase::new(handler, load_helper, symbol_map),
        }
    }

    /// Find the HI20 relocation whose offset matches the value of the specified symbol.
    ///
    /// Returns `None` if there is no relocation table currently being processed, or no matching
    /// `R_RISCV_PCREL_HI20`/`R_RISCV_GOT_HI20` relocation is found.
    pub fn get_hi20_relocation(&self, hi20_symbol: &ElfSymbol) -> Option<Box<dyn ElfRelocation>> {
        let sym_value = hi20_symbol.get_value();

        let table = self.base.relocation_table()?;
        let mut relocations = table.get_relocations();

        // Search for first relocation within the table whose offset matches the specified
        // hi20Symbol value.
        let mut rel_index = match relocations
            .binary_search_by(|rel| (rel.get_offset() as u64).cmp(&sym_value))
        {
            Ok(index) => index,
            Err(_) => return None, // relocation not found
        };

        // Back up in the event there is more than one matching relocation offset.
        while rel_index > 0 && (relocations[rel_index - 1].get_offset() as u64) == sym_value {
            rel_index -= 1;
        }

        // Look for hi20 relocation.
        while rel_index < relocations.len()
            && (relocations[rel_index].get_offset() as u64) == sym_value
        {
            let type_id = relocations[rel_index].get_type();
            if type_id == RiscvElfRelocationType::R_RISCV_PCREL_HI20.type_id_value()
                || type_id == RiscvElfRelocationType::R_RISCV_GOT_HI20.type_id_value()
            {
                return Some(relocations.remove(rel_index));
            }
            rel_index += 1;
        }
        None
    }
}

impl ElfRelocationContext for RiscvElfRelocationContext {
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
    use crate::format::seam_stubs::{ElfHeader, ElfRelocationTable, ElfSymbolTable, MessageLog};
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::Mutex;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.elf".to_string()
        }
        fn get_language_id(&self) -> String {
            "RISCV:LE:64:default".to_string()
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
        fn append_exception(&self, _t: &dyn crate::format::seam_stubs::Throwable) {}
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
            false
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

    struct MockRelocation {
        offset: i64,
        type_id: i32,
    }

    impl ElfRelocation for MockRelocation {
        fn get_symbol_index(&self) -> i32 {
            0
        }
        fn get_type(&self) -> i32 {
            self.type_id
        }
        fn get_offset(&self) -> i64 {
            self.offset
        }
    }

    struct MockRelocationTable {
        relocations: Vec<MockRelocationSpec>,
    }

    #[derive(Clone, Copy)]
    struct MockRelocationSpec {
        offset: i64,
        type_id: i32,
    }

    impl ElfRelocationTable for MockRelocationTable {
        fn has_addend_relocations(&self) -> bool {
            true
        }
        fn get_associated_symbol_table(&self) -> Option<Arc<dyn ElfSymbolTable>> {
            None
        }
        fn get_relocations(&self) -> Vec<Box<dyn ElfRelocation>> {
            self.relocations
                .iter()
                .map(|spec| {
                    Box::new(MockRelocation { offset: spec.offset, type_id: spec.type_id })
                        as Box<dyn ElfRelocation>
                })
                .collect()
        }
    }

    fn create_context() -> RiscvElfRelocationContext {
        let load_helper = Arc::new(MockLoadHelper { log: Arc::new(RecordingLog::default()) });
        RiscvElfRelocationContext::new(None, load_helper, Arc::new(HashMap::new()))
    }

    fn symbol_with_value(value: u64) -> ElfSymbol {
        // st_name, st_value, st_size, st_info, st_other, st_shndx (little endian Elf64_Sym-ish).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // st_name
        bytes.push(0); // st_info
        bytes.push(0); // st_other
        bytes.extend_from_slice(&0u16.to_le_bytes()); // st_shndx
        bytes.extend_from_slice(&value.to_le_bytes()); // st_value
        bytes.extend_from_slice(&0u64.to_le_bytes()); // st_size

        let mut reader = VecReader::new(bytes);
        ElfSymbol::parse(&mut reader, 1, &MockElfHeader).expect("symbol entry parses")
    }

    struct VecProvider(Vec<u8>);
    impl crate::filesystem::ghidra::g_binary_reader::ByteProvider for VecProvider {
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            let start = index as usize;
            self.0
                .get(start..start + length)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
            unimplemented!()
        }
    }

    struct VecReader {
        provider: std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>>,
        current_index: u64,
    }

    impl VecReader {
        fn new(data: Vec<u8>) -> Self {
            VecReader {
                provider: std::rc::Rc::new(std::cell::RefCell::new(VecProvider(data))),
                current_index: 0,
            }
        }
    }

    impl crate::app::util::bin::binary_reader::BinaryReader for VecReader {
        fn length(&self) -> std::io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            std::mem::replace(&mut self.current_index, index)
        }
        fn is_little_endian(&self) -> bool {
            true
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> std::io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> std::io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(
            &self,
        ) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>>
        {
            std::rc::Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader> {
            Box::new(VecReader { provider: std::rc::Rc::clone(&self.provider), current_index: new_index })
        }
    }

    #[test]
    fn finds_pcrel_hi20_relocation_matching_symbol_offset() {
        let mut context = create_context();
        let table: Arc<dyn ElfRelocationTable> = Arc::new(MockRelocationTable {
            relocations: vec![
                MockRelocationSpec { offset: 0x1000, type_id: 2 },
                MockRelocationSpec {
                    offset: 0x2000,
                    type_id: RiscvElfRelocationType::R_RISCV_PCREL_HI20.type_id_value(),
                },
                MockRelocationSpec { offset: 0x3000, type_id: 2 },
            ],
        });
        context.base_mut().start_relocation_table_processing(table);

        let symbol = symbol_with_value(0x2000);
        let found = context.get_hi20_relocation(&symbol).expect("relocation found");
        assert_eq!(found.get_offset(), 0x2000);
        assert_eq!(found.get_type(), RiscvElfRelocationType::R_RISCV_PCREL_HI20.type_id_value());
    }

    #[test]
    fn finds_got_hi20_relocation_when_multiple_relocations_share_an_offset() {
        let mut context = create_context();
        let table: Arc<dyn ElfRelocationTable> = Arc::new(MockRelocationTable {
            relocations: vec![
                MockRelocationSpec { offset: 0x2000, type_id: 99 },
                MockRelocationSpec {
                    offset: 0x2000,
                    type_id: RiscvElfRelocationType::R_RISCV_GOT_HI20.type_id_value(),
                },
                MockRelocationSpec { offset: 0x2000, type_id: 100 },
            ],
        });
        context.base_mut().start_relocation_table_processing(table);

        let symbol = symbol_with_value(0x2000);
        let found = context.get_hi20_relocation(&symbol).expect("relocation found");
        assert_eq!(found.get_type(), RiscvElfRelocationType::R_RISCV_GOT_HI20.type_id_value());
    }

    #[test]
    fn returns_none_when_no_relocation_matches_the_offset() {
        let mut context = create_context();
        let table: Arc<dyn ElfRelocationTable> = Arc::new(MockRelocationTable {
            relocations: vec![MockRelocationSpec { offset: 0x1000, type_id: 2 }],
        });
        context.base_mut().start_relocation_table_processing(table);

        let symbol = symbol_with_value(0x9999);
        assert!(context.get_hi20_relocation(&symbol).is_none());
    }

    #[test]
    fn returns_none_when_offset_matches_but_no_hi20_relocation_present() {
        let mut context = create_context();
        let table: Arc<dyn ElfRelocationTable> = Arc::new(MockRelocationTable {
            relocations: vec![MockRelocationSpec { offset: 0x2000, type_id: 2 }],
        });
        context.base_mut().start_relocation_table_processing(table);

        let symbol = symbol_with_value(0x2000);
        assert!(context.get_hi20_relocation(&symbol).is_none());
    }

    #[test]
    fn returns_none_without_an_active_relocation_table() {
        let context = create_context();
        let symbol = symbol_with_value(0x2000);
        assert!(context.get_hi20_relocation(&symbol).is_none());
    }
}

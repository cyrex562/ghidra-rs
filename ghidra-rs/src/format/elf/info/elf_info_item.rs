//! Trait ported from the interface `ghidra.app.util.bin.format.elf.info.ElfInfoItem`.
//!
//! Interface and helper functions to read and markup things that have been read from an Elf
//! program.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::format::seam_stubs::MemoryByteProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::MemoryBlock;
use crate::util::msg::Msg;

/// Markup a program's info and memory with this item.
///
/// Port of `ElfInfoItem`.
pub trait ElfInfoItem {
    /// Markup a program's info and memory with this item.
    fn markup_program(&self, program: &mut dyn Program, address: &Address);
}

/// Port of the Java record `ElfInfoItem.ItemWithAddress<T>`.
#[derive(Debug, Clone)]
pub struct ItemWithAddress<T> {
    pub item: T,
    pub address: Address,
}

/// A concrete [`BinaryReader`] backed by a [`ByteProvider`].
///
/// The crate does not yet have a canonical production implementer of the [`BinaryReader`] trait
/// (only test mocks exist so far), so [`read_item_from_block`] constructs this minimal one --
/// mirroring the `ByteProvider`-backed constructor of the original `BinaryReader.java` class --
/// to actually read an item out of a memory section.
struct ProviderBinaryReader {
    provider: Rc<RefCell<dyn ByteProvider>>,
    is_little_endian: bool,
    current_index: u64,
}

impl ProviderBinaryReader {
    fn new(provider: Rc<RefCell<dyn ByteProvider>>, is_little_endian: bool) -> Self {
        ProviderBinaryReader { provider, is_little_endian, current_index: 0 }
    }
}

impl BinaryReader for ProviderBinaryReader {
    fn length(&self) -> io::Result<u64> {
        self.provider.borrow_mut().length()
    }

    fn is_valid_index(&self, index: u64) -> bool {
        self.provider.borrow_mut().is_valid_index(index)
    }

    fn get_pointer_index(&self) -> u64 {
        self.current_index
    }

    fn set_pointer_index(&mut self, index: u64) -> u64 {
        let previous = self.current_index;
        self.current_index = index;
        previous
    }

    fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    fn set_little_endian(&mut self, is_little_endian: bool) {
        self.is_little_endian = is_little_endian;
    }

    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.provider.borrow_mut().read_byte(index)
    }

    fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
        self.provider.borrow_mut().read_bytes(index, n_elements)
    }

    fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
        Rc::clone(&self.provider)
    }

    fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
        Box::new(ProviderBinaryReader {
            provider: Rc::clone(&self.provider),
            is_little_endian: self.is_little_endian,
            current_index: new_index,
        })
    }
}

/// Helper method to markup a program if it contains the specified item in the specified memory
/// section.
///
/// Port of `ElfInfoItem.markupElfInfoItemSection(Program, String, ReaderFunc)`.
pub fn markup_elf_info_item_section<T: ElfInfoItem>(
    program: &mut dyn Program,
    section_name: &str,
    read_func: impl FnOnce(&mut dyn BinaryReader, &dyn Program) -> io::Result<T>,
) {
    if let Some(wrapped) = read_item_from_section(&*program, section_name, read_func) {
        wrapped.item.markup_program(program, &wrapped.address);
    }
}

/// Helper method to read an item from a program's memory section, looked up by section name.
///
/// Port of `ElfInfoItem.readItemFromSection(Program, String, ReaderFunc)`.
pub fn read_item_from_section<T: ElfInfoItem>(
    program: &dyn Program,
    section_name: &str,
    read_func: impl FnOnce(&mut dyn BinaryReader, &dyn Program) -> io::Result<T>,
) -> Option<ItemWithAddress<T>> {
    let block = program.get_memory()?.get_block_by_name(section_name)?;
    read_item_from_block(program, block.as_ref(), read_func)
}

/// Helper method to read an item from the given memory block.
///
/// Port of `ElfInfoItem.readItemFromSection(Program, MemoryBlock, ReaderFunc)`.
pub fn read_item_from_block<T: ElfInfoItem>(
    program: &dyn Program,
    mem_block: &dyn MemoryBlock,
    read_func: impl FnOnce(&mut dyn BinaryReader, &dyn Program) -> io::Result<T>,
) -> Option<ItemWithAddress<T>> {
    let memory = program.get_memory()?;
    let is_little_endian = !memory.is_big_endian();
    let provider = MemoryByteProvider::create_memory_block_byte_provider(memory, mem_block);
    let mut reader = ProviderBinaryReader::new(Rc::new(RefCell::new(provider)), is_little_endian);

    match read_func(&mut reader, program) {
        Ok(item) => Some(ItemWithAddress { item, address: mem_block.get_start() }),
        Err(e) => {
            Msg::warn_with_error(
                "ElfInfoItem",
                &format!("Unable to read Elf item in section: {}", mem_block.get_name()),
                &e,
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::{Memory, MemoryAccessException};

    struct FakeMemoryBlock {
        name: String,
        start: Address,
        data: Vec<u8>,
    }

    impl MemoryBlock for FakeMemoryBlock {
        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_start(&self) -> Address {
            self.start.clone()
        }

        fn get_end(&self) -> Address {
            self.start.add((self.data.len() as i64 - 1).max(0)).unwrap()
        }

        fn get_size(&self) -> u64 {
            self.data.len() as u64
        }

        fn is_initialized(&self) -> bool {
            true
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let offset = addr.subtract(&self.start) as usize;
            self.data.get(offset).copied().ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let offset = addr.subtract(&self.start) as usize;
            let available = self.data.len().saturating_sub(offset);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&self.data[offset..offset + n]);
            n
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not needed by these tests")
        }
    }

    struct FakeMemory {
        block: Arc<dyn MemoryBlock>,
        big_endian: bool,
    }

    impl Memory for FakeMemory {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.block.get_byte(addr)
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            self.block.get_bytes(addr, dest)
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not needed by these tests")
        }

        fn get_block_by_name(&self, name: &str) -> Option<Arc<dyn MemoryBlock>> {
            if self.block.get_name() == name { Some(self.block.clone()) } else { None }
        }
    }

    struct FakeProgram {
        memory: Arc<dyn Memory>,
    }

    impl crate::framework::model::DomainObject for FakeProgram {}

    impl Program for FakeProgram {
        fn get_name(&self) -> String {
            "elf_info_item_test".to_string()
        }

        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }

        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
    }

    const SECTION_NAME: &str = ".test_section";

    fn program_with_section(data: &[u8]) -> FakeProgram {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let start = Address::new(space, 0x1000);
        let block: Arc<dyn MemoryBlock> =
            Arc::new(FakeMemoryBlock { name: SECTION_NAME.to_string(), start, data: data.to_vec() });
        FakeProgram { memory: Arc::new(FakeMemory { block, big_endian: false }) }
    }

    struct TestItem {
        value: u8,
        markup_calls: Rc<RefCell<Vec<i64>>>,
    }

    impl ElfInfoItem for TestItem {
        fn markup_program(&self, _program: &mut dyn Program, address: &Address) {
            self.markup_calls.borrow_mut().push(address.offset());
        }
    }

    #[test]
    fn read_item_from_section_reads_item_at_block_start() {
        let program = program_with_section(&[0xAB, 0xCD]);
        let wrapped = read_item_from_section(&program, SECTION_NAME, |br, _program| {
            let value = br.read_next_byte()?;
            Ok(TestItem { value, markup_calls: Rc::new(RefCell::new(Vec::new())) })
        })
        .expect("section should be found and item read");

        assert_eq!(wrapped.item.value, 0xAB);
        assert_eq!(wrapped.address.offset(), 0x1000);
    }

    #[test]
    fn read_item_from_section_returns_none_when_section_missing() {
        let program = program_with_section(&[0xAB]);
        let wrapped = read_item_from_section(&program, ".does_not_exist", |br, _program| {
            let value = br.read_next_byte()?;
            Ok(TestItem { value, markup_calls: Rc::new(RefCell::new(Vec::new())) })
        });

        assert!(wrapped.is_none());
    }

    #[test]
    fn read_item_from_section_returns_none_on_read_error() {
        let program = program_with_section(&[]);
        let wrapped = read_item_from_section(&program, SECTION_NAME, |br, _program| {
            let value = br.read_next_byte()?;
            Ok(TestItem { value, markup_calls: Rc::new(RefCell::new(Vec::new())) })
        });

        assert!(wrapped.is_none());
    }

    #[test]
    fn markup_elf_info_item_section_invokes_markup_program_with_block_address() {
        let mut program = program_with_section(&[0x42]);
        let calls = Rc::new(RefCell::new(Vec::new()));
        let calls_for_closure = calls.clone();

        markup_elf_info_item_section(&mut program, SECTION_NAME, move |br, _program| {
            let value = br.read_next_byte()?;
            Ok(TestItem { value, markup_calls: calls_for_closure })
        });

        assert_eq!(*calls.borrow(), vec![0x1000]);
    }
}

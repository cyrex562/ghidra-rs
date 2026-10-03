//! Port of `ghidra.app.util.bin.MemoryByteProvider`.
//!
//! A [`ByteProvider`] over a program's [`Memory`], starting at a base address: index `i` is the
//! byte at `base + i`. The valid range ends at a maximum address (by default the highest
//! address mapped in the base address's space, or the end of the base address's block).
//!
//! Java's `getAddressRanges()` walk in `findAddressSpaceMax` is done over the memory's blocks
//! (whose ranges are the memory's address ranges).
//!
//! The legacy [`GByteStore`] interface is also implemented, as a read-only bridge for callers
//! not yet migrated off it (e.g. the DWARF section provider).

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::ghidra::g_binary_reader::GByteStore;
use crate::program::model::address::address_set::AddressSet;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::listing::program::Program;
use crate::program::model::mem::{Memory, MemoryBlock};

/// Port of `ghidra.app.util.bin.MemoryByteProvider`.
pub struct MemoryByteProvider {
    memory: Arc<dyn Memory>,
    base_address: Address,
    /// Max valid offset, inclusive.
    max_offset: u64,
    /// Tracked separately because `max_offset == 0` does not mean empty.
    is_empty: bool,
}

impl MemoryByteProvider {
    /// Java `createMemoryBlockByteProvider(Memory, MemoryBlock)`: the bytes of one block.
    pub fn create_memory_block_byte_provider(memory: Arc<dyn Memory>, block: &dyn MemoryBlock) -> Self {
        Self::with_max_address(memory, block.get_start(), Some(block.get_end()))
    }

    /// Java `createProgramHeaderByteProvider(Program, boolean)`: from the program's minimum
    /// address. `None` if the program has no memory or minimum address.
    pub fn create_program_header_byte_provider(program: &dyn Program, first_block_only: bool) -> Option<Self> {
        Some(Self::with_first_block_only(program.get_memory()?, program.get_min_address()?, first_block_only))
    }

    /// Java `createDefaultAddressSpaceByteProvider(Program, boolean)`: from the start of the
    /// program's default address space. `None` if the program has no memory or address factory.
    pub fn create_default_address_space_byte_provider(program: &dyn Program, first_block_only: bool) -> Option<Self> {
        let space = program.get_address_factory()?.get_default_address_space()?;
        Some(Self::with_first_block_only(program.get_memory()?, space.min_address(), first_block_only))
    }

    /// Java `MemoryByteProvider(Memory, AddressSpace)`: from the start of `space`.
    pub fn new(memory: Arc<dyn Memory>, space: &Arc<AddressSpace>) -> Self {
        Self::from_address(memory, space.min_address())
    }

    /// Java `MemoryByteProvider(Memory, Address)`: from `base_address` to the highest mapped
    /// address in its space.
    pub fn from_address(memory: Arc<dyn Memory>, base_address: Address) -> Self {
        Self::with_first_block_only(memory, base_address, false)
    }

    /// Java `MemoryByteProvider(Memory, Address, boolean)`: from `base_address` to the end of its
    /// block (`first_block_only`) or to the highest mapped address in its space.
    pub fn with_first_block_only(memory: Arc<dyn Memory>, base_address: Address, first_block_only: bool) -> Self {
        let max = if first_block_only {
            find_end_of_block(memory.as_ref(), &base_address)
        } else {
            find_address_space_max(memory.as_ref(), &base_address)
        };
        Self::with_max_address(memory, base_address, max)
    }

    /// Java `MemoryByteProvider(Memory, Address, Address)`: from `base_address` to `max_address`
    /// inclusive; empty when `max_address` is `None` (Java `null`).
    pub fn with_max_address(memory: Arc<dyn Memory>, base_address: Address, max_address: Option<Address>) -> Self {
        let max_offset = max_address.as_ref().map_or(0, |m| m.subtract(&base_address) as u64);
        MemoryByteProvider { memory, base_address, max_offset, is_empty: max_address.is_none() }
    }

    /// Java `getMemory()`.
    pub fn get_memory(&self) -> &Arc<dyn Memory> {
        &self.memory
    }

    /// Java `getStartAddress()`.
    pub fn get_start_address(&self) -> &Address {
        &self.base_address
    }

    /// Java `getEndAddress()`.
    pub fn get_end_address(&self) -> Address {
        self.base_address
            .space()
            .address(self.base_address.offset().wrapping_add(self.max_offset as i64))
    }

    /// Java `getAddressSet()`.
    pub fn get_address_set(&self) -> AddressSet {
        let mut set = AddressSet::new();
        set.add_range(&self.base_address, &self.get_end_address());
        set
    }

    /// Java's private `getAddress(long)`.
    fn get_address(&self, index: u64) -> io::Result<Address> {
        if index == 0 {
            return Ok(self.base_address.clone());
        }
        let base = self.base_address.offset() as u64;
        let new_address = base.wrapping_add(index);
        if base > new_address {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid index: {index}")));
        }
        Ok(self.base_address.space().address(new_address as i64))
    }

    /// Java's private `ensureBounds(long, long)`.
    fn ensure_bounds(&self, index: u64, length: u64) -> io::Result<()> {
        if length > i32::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unable to read more than Integer.MAX_VALUE bytes in one operation: {length}"),
            ));
        }
        if index == 0 && length == 0 {
            return Ok(()); // success for read of 0 bytes at offset 0
        }
        if self.is_empty || index > self.max_offset {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("Invalid index: {index}")));
        }
        // `remaining + 1` could overflow, so compare against `length - 1` instead.
        let remaining = self.max_offset - index;
        if length != 0 && length - 1 > remaining {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Unable to read past EOF: {index}, {length}"),
            ));
        }
        Ok(())
    }
}

/// Java's private `findEndOfBlock(Memory, Address)`: the end of the block containing `min_addr`,
/// else of the first block in the same space ending at or after it.
fn find_end_of_block(memory: &dyn Memory, min_addr: &Address) -> Option<Address> {
    if let Some(block) = memory.get_block(min_addr) {
        return Some(block.get_end());
    }
    memory
        .get_blocks()
        .into_iter()
        .map(|b| b.get_end())
        .find(|end| end.same_address_space(min_addr) && end >= min_addr)
}

/// Java's private `findAddressSpaceMax(Memory, Address)`: the highest mapped address in
/// `min_addr`'s space at or after it.
fn find_address_space_max(memory: &dyn Memory, min_addr: &Address) -> Option<Address> {
    let mut max_addr: Option<Address> = None;
    for block in memory.get_blocks() {
        let range_end = block.get_end();
        if !range_end.same_address_space(min_addr) {
            continue;
        }
        if range_end >= *min_addr && max_addr.as_ref().is_none_or(|m| range_end >= *m) {
            max_addr = Some(range_end);
        }
    }
    max_addr
}

impl ByteProvider for MemoryByteProvider {
    /// Java `getFile()`: the program's executable path.
    fn get_file(&self) -> Option<PathBuf> {
        self.memory.get_program().map(|p| PathBuf::from(p.get_executable_path()))
    }

    /// Java `getName()`: the program's name.
    fn get_name(&self) -> Option<String> {
        self.memory.get_program().map(|p| Program::get_name(p.as_ref()))
    }

    /// Java `getAbsolutePath()`: the program's executable path.
    fn get_absolute_path(&self) -> Option<String> {
        self.memory.get_program().map(|p| p.get_executable_path())
    }

    /// Java `length()`, clamped to `Long.MAX_VALUE`.
    fn length(&self) -> u64 {
        if self.is_empty {
            return 0;
        }
        if self.max_offset >= i64::MAX as u64 - 1 {
            i64::MAX as u64
        } else {
            self.max_offset + 1
        }
    }

    /// Java `isValidIndex(long)`: within range and mapped.
    fn is_valid_index(&self, index: u64) -> bool {
        if self.is_empty || index > self.max_offset {
            return false;
        }
        self.get_address(index).is_ok_and(|a| self.memory.contains(&a))
    }

    /// Java `close()`: nothing to do.
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Java `readByte(long)`.
    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.ensure_bounds(index, 1)?;
        self.memory.get_byte(&self.get_address(index)?).map_err(|e| io::Error::other(e.to_string()))
    }

    /// Java `readBytes(long, long)`.
    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
        self.ensure_bounds(index, length)?;
        let mut bytes = vec![0u8; length as usize];
        let n_read = self.memory.get_bytes(&self.get_address(index)?, &mut bytes);
        if n_read as u64 != length {
            return Err(io::Error::other(format!("Unable to read {length} bytes at index {index}")));
        }
        Ok(bytes)
    }

    /// Java `isEmpty()`.
    fn is_empty(&self) -> bool {
        self.is_empty
    }
}

/// Read-only bridge onto the legacy [`GByteStore`] interface.
impl GByteStore for MemoryByteProvider {
    fn length(&mut self) -> io::Result<u64> {
        Ok(ByteProvider::length(self))
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        ByteProvider::is_valid_index(self, index)
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        ByteProvider::read_byte(self, index)
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        ByteProvider::read_bytes(self, index, length as u64)
    }

    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "MemoryByteProvider does not support writes"))
    }

    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "MemoryByteProvider does not support writes"))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A multi-block [`Memory`] for tests.

    use std::sync::{Arc, RwLock};

    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::mem::memory_access_exception::MemoryAccessException;
    use crate::program::model::mem::{Memory, MemoryBlock};

    pub(crate) struct Block {
        name: String,
        start: Address,
        bytes: Vec<u8>,
    }

    impl MemoryBlock for Block {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_start(&self) -> Address {
            self.start.clone()
        }
        fn get_end(&self) -> Address {
            self.start.add_wrap(self.bytes.len() as i64 - 1)
        }
        fn get_size(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(addr.subtract(&self.start) as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of block"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let off = addr.subtract(&self.start) as usize;
            let n = dest.len().min(self.bytes.len().saturating_sub(off));
            dest[..n].copy_from_slice(&self.bytes[off..off + n]);
            n
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("read-only"))
        }
    }

    /// Blocks `(name, start, bytes)` in a 64-bit `ram` space.
    pub(crate) struct BlockMemory {
        pub(crate) space: Arc<AddressSpace>,
        blocks: RwLock<Vec<Arc<Block>>>,
        big_endian: bool,
    }

    impl BlockMemory {
        pub(crate) fn new(blocks: &[(&str, i64, Vec<u8>)], big_endian: bool) -> Self {
            let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
            let blocks = blocks
                .iter()
                .map(|(n, s, b)| Arc::new(Block { name: n.to_string(), start: space.address(*s), bytes: b.clone() }))
                .collect();
            BlockMemory { space, blocks: RwLock::new(blocks), big_endian }
        }

        fn find(&self, addr: &Address) -> Option<Arc<Block>> {
            self.blocks
                .read()
                .unwrap()
                .iter()
                .find(|b| b.start.same_address_space(addr) && *addr >= b.start && *addr <= b.get_end())
                .cloned()
        }
    }

    impl Memory for BlockMemory {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.find(addr).ok_or_else(|| MemoryAccessException::new("unmapped"))?.get_byte(addr)
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            self.find(addr).map_or(0, |b| b.get_bytes(addr, dest))
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("read-only"))
        }
        fn get_block(&self, addr: &Address) -> Option<Arc<dyn MemoryBlock>> {
            self.find(addr).map(|b| b as Arc<dyn MemoryBlock>)
        }
        fn contains(&self, addr: &Address) -> bool {
            self.find(addr).is_some()
        }
        fn get_blocks(&self) -> Vec<Arc<dyn MemoryBlock>> {
            self.blocks.read().unwrap().iter().map(|b| Arc::clone(b) as Arc<dyn MemoryBlock>).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::BlockMemory;
    use super::*;

    fn memory() -> Arc<BlockMemory> {
        Arc::new(BlockMemory::new(
            &[("a", 0x1000, (0u8..0x10).collect()), ("b", 0x2000, vec![0xbb; 8])],
            false,
        ))
    }

    #[test]
    fn space_provider_spans_to_highest_mapped_address() {
        let m = memory();
        let p = MemoryByteProvider::new(m.clone(), &m.space);
        assert_eq!(p.get_start_address().offset(), 0);
        assert_eq!(p.get_end_address().offset(), 0x2007);
        assert_eq!(ByteProvider::length(&p), 0x2008);
        assert!(!ByteProvider::is_valid_index(&p, 0x10));
        assert!(ByteProvider::is_valid_index(&p, 0x1001));
        assert_eq!(ByteProvider::read_bytes(&p, 0x1004, 4).unwrap(), [4, 5, 6, 7]);
        assert_eq!(ByteProvider::read_byte(&p, 0x2007).unwrap(), 0xbb);
        assert!(ByteProvider::read_byte(&p, 0x2008).is_err());
        // Crossing from block a into the unmapped gap is a short read.
        assert!(ByteProvider::read_bytes(&p, 0x100e, 4).is_err());
    }

    #[test]
    fn block_and_first_block_only_providers() {
        let m = memory();
        let blocks = m.get_blocks();
        let p = MemoryByteProvider::create_memory_block_byte_provider(m.clone(), blocks[1].as_ref());
        assert_eq!(ByteProvider::length(&p), 8);
        assert_eq!(ByteProvider::read_bytes(&p, 0, 8).unwrap(), vec![0xbb; 8]);
        assert!(ByteProvider::read_bytes(&p, 4, 5).is_err());

        let p = MemoryByteProvider::with_first_block_only(m.clone(), m.space.address(0x1008), true);
        assert_eq!(ByteProvider::length(&p), 8);
        assert_eq!(ByteProvider::read_byte(&p, 0).unwrap(), 8);

        // Outside every block: the first block in the space ending at or after the address.
        let p = MemoryByteProvider::with_first_block_only(m.clone(), m.space.address(0x1800), true);
        assert_eq!(p.get_end_address().offset(), 0x2007);
    }

    #[test]
    fn empty_provider_and_bounds_checks() {
        let m = memory();
        let p = MemoryByteProvider::from_address(m.clone(), m.space.address(0x3000));
        assert!(ByteProvider::is_empty(&p));
        assert_eq!(ByteProvider::length(&p), 0);
        assert!(ByteProvider::read_bytes(&p, 0, 0).unwrap().is_empty());
        assert!(ByteProvider::read_byte(&p, 0).is_err());

        let p = MemoryByteProvider::from_address(m.clone(), m.space.address(0x1000));
        assert!(ByteProvider::read_bytes(&p, 0, 1 << 31).is_err());
        assert!(!ByteProvider::is_empty(&p));
    }

    #[test]
    fn reads_through_binary_reader_and_gbytestore() {
        use crate::app::util::bin::binary_reader::BinaryReader;
        let m = memory();
        let p = MemoryByteProvider::from_address(m.clone(), m.space.address(0x1000));
        let mut r = BinaryReader::new(std::rc::Rc::new(p), true);
        assert_eq!(r.read_next_int().unwrap(), 0x0302_0100);

        let mut p = MemoryByteProvider::from_address(m.clone(), m.space.address(0x1000));
        assert_eq!(GByteStore::read_bytes(&mut p, 2, 2).unwrap(), [2, 3]);
        assert!(GByteStore::write_byte(&mut p, 0, 0).is_err());
    }
}

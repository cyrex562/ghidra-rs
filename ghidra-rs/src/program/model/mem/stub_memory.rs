//! Trait ported from the class `ghidra.program.model.mem.StubMemory`.
//!
//! In Java, `StubMemory` is a test helper: it extends `AddressSet` and implements the (large)
//! `Memory` interface, throwing `UnsupportedOperationException` from every override so tests can
//! extend it and provide real behavior for just the handful of methods they need. It was selected
//! as a dependency-cycle cut point, so it is ported here as a trait rather than a concrete struct:
//! `StubMemory` requires the already-ported [`AddressSetView`] and [`Memory`] traits (whose
//! members have no defaults, matching that Java also throws unconditionally from those overrides
//! too) and supplies every other Java `Memory`-interface method `StubMemory` overrides as a
//! default trait method that panics, mirroring `UnsupportedOperationException`. A concrete test
//! type implements this trait plus its two supertraits and overrides only the methods it actually
//! needs, exactly like extending the Java class.

use std::io::Read;
use std::sync::Arc;

use crate::framework::store::LockException;
use crate::program::database::mem::{AddressSourceInfo, FileBytes};
use crate::program::model::address::{Address, AddressOverflowException, AddressSetView};
use crate::program::model::listing::Program;
use crate::program::model::mem::{
    Memory, MemoryAccessException, MemoryBlock, MemoryBlockException, MemoryConflictException,
};
use crate::program::seam_stubs::ByteMappingScheme;
use crate::util::task::TaskMonitor;

/// Aggregates the checked exceptions Java's `Memory`-interface block-management methods declare
/// across their various `throws` clauses (`LockException`, `MemoryConflictException`,
/// `AddressOverflowException`, `MemoryBlockException`), plus `IllegalArgumentException` from
/// `createByteMappedBlock`. Not a port of any specific Java class -- see
/// [`FileBytesError`](crate::program::database::mem::file_bytes::FileBytesError) for the same
/// aggregation pattern used elsewhere in this crate.
#[derive(Debug)]
pub enum StubMemoryError {
    Lock(LockException),
    Conflict(MemoryConflictException),
    Overflow(AddressOverflowException),
    Block(MemoryBlockException),
    InvalidArgument(String),
}

impl std::fmt::Display for StubMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lock(e) => write!(f, "{e}"),
            Self::Conflict(e) => write!(f, "{e}"),
            Self::Overflow(e) => write!(f, "{e}"),
            Self::Block(e) => write!(f, "{e}"),
            Self::InvalidArgument(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for StubMemoryError {}

impl From<LockException> for StubMemoryError {
    fn from(e: LockException) -> Self {
        Self::Lock(e)
    }
}

impl From<MemoryConflictException> for StubMemoryError {
    fn from(e: MemoryConflictException) -> Self {
        Self::Conflict(e)
    }
}

impl From<AddressOverflowException> for StubMemoryError {
    fn from(e: AddressOverflowException) -> Self {
        Self::Overflow(e)
    }
}

impl From<MemoryBlockException> for StubMemoryError {
    fn from(e: MemoryBlockException) -> Self {
        Self::Block(e)
    }
}

/// Test stub covering the full `Memory` interface plus the `AddressSet` behavior Java's
/// `StubMemory` inherits.
///
/// Mirrors Ghidra's `StubMemory`: every method below defaults to panicking (standing in for
/// `UnsupportedOperationException`); a test type implementing this trait (plus its
/// [`AddressSetView`]/[`Memory`] supertraits) overrides only what it actually needs.
pub trait StubMemory: AddressSetView + Memory {
    /// Stands in for `Memory.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program> {
        unsupported()
    }

    /// Stands in for `Memory.getLoadedAndInitializedAddressSet()`.
    fn get_loaded_and_initialized_address_set(&self) -> Box<dyn AddressSetView> {
        unsupported()
    }

    /// Stands in for `Memory.getAllInitializedAddressSet()`.
    fn get_all_initialized_address_set(&self) -> Box<dyn AddressSetView> {
        unsupported()
    }

    /// Stands in for `Memory.getInitializedAddressSet()`.
    fn get_initialized_address_set(&self) -> Box<dyn AddressSetView> {
        unsupported()
    }

    /// Stands in for `Memory.getExecuteSet()`.
    fn get_execute_set(&self) -> Box<dyn AddressSetView> {
        unsupported()
    }

    /// Stands in for `Memory.createInitializedBlock(String, Address, InputStream, long,
    /// TaskMonitor, boolean)`.
    fn create_initialized_block_from_stream(
        &mut self,
        name: &str,
        start: &Address,
        is: &mut dyn Read,
        length: u64,
        monitor: &dyn TaskMonitor,
        overlay: bool,
    ) -> Box<dyn MemoryBlock> {
        let _ = (name, start, is, length, monitor, overlay);
        unsupported()
    }

    /// Stands in for `Memory.createInitializedBlock(String, Address, long, byte, TaskMonitor,
    /// boolean)`.
    fn create_initialized_block(
        &mut self,
        name: &str,
        start: &Address,
        size: u64,
        initial_value: u8,
        monitor: &dyn TaskMonitor,
        overlay: bool,
    ) -> Box<dyn MemoryBlock> {
        let _ = (name, start, size, initial_value, monitor, overlay);
        unsupported()
    }

    /// Stands in for `Memory.createUninitializedBlock(String, Address, long, boolean)`.
    fn create_uninitialized_block(
        &mut self,
        name: &str,
        start: &Address,
        size: u64,
        overlay: bool,
    ) -> Box<dyn MemoryBlock> {
        let _ = (name, start, size, overlay);
        unsupported()
    }

    /// Stands in for `Memory.createBitMappedBlock(String, Address, Address, long, boolean)`.
    fn create_bit_mapped_block(
        &mut self,
        name: &str,
        start: &Address,
        mapped_address: &Address,
        length: u64,
        overlay: bool,
    ) -> Result<Box<dyn MemoryBlock>, StubMemoryError> {
        let _ = (name, start, mapped_address, length, overlay);
        unsupported()
    }

    /// Stands in for `Memory.createByteMappedBlock(String, Address, Address, long,
    /// ByteMappingScheme, boolean)`.
    fn create_byte_mapped_block(
        &mut self,
        name: &str,
        start: &Address,
        mapped_address: &Address,
        length: u64,
        byte_mapping_scheme: Option<Arc<dyn ByteMappingScheme>>,
        overlay: bool,
    ) -> Result<Box<dyn MemoryBlock>, StubMemoryError> {
        let _ = (name, start, mapped_address, length, byte_mapping_scheme, overlay);
        unsupported()
    }

    /// Stands in for `Memory.createBlock(MemoryBlock, String, Address, long)`.
    fn create_block(
        &mut self,
        block: &dyn MemoryBlock,
        name: &str,
        start: &Address,
        length: u64,
    ) -> Result<Box<dyn MemoryBlock>, StubMemoryError> {
        let _ = (block, name, start, length);
        unsupported()
    }

    /// Stands in for `Memory.removeBlock(MemoryBlock, TaskMonitor)`.
    fn remove_block(&mut self, block: &dyn MemoryBlock, monitor: &dyn TaskMonitor) -> Result<(), LockException> {
        let _ = (block, monitor);
        unsupported()
    }

    /// Stands in for `Memory.getSize()`.
    fn get_size(&self) -> u64 {
        unsupported()
    }

    /// Stands in for `Memory.getBlock(Address)`.
    fn get_block(&self, addr: &Address) -> Option<Box<dyn MemoryBlock>> {
        let _ = addr;
        unsupported()
    }

    /// Stands in for `Memory.getBlock(String)`.
    fn get_block_by_name(&self, block_name: &str) -> Option<Box<dyn MemoryBlock>> {
        let _ = block_name;
        unsupported()
    }

    /// Stands in for `Memory.getBlocks()`.
    fn get_blocks(&self) -> Vec<Box<dyn MemoryBlock>> {
        unsupported()
    }

    /// Stands in for `Memory.moveBlock(MemoryBlock, Address, TaskMonitor)`.
    fn move_block(
        &mut self,
        block: &dyn MemoryBlock,
        new_start_addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), StubMemoryError> {
        let _ = (block, new_start_addr, monitor);
        unsupported()
    }

    /// Stands in for `Memory.split(MemoryBlock, Address)`.
    fn split(&mut self, block: &dyn MemoryBlock, addr: &Address) -> Result<(), StubMemoryError> {
        let _ = (block, addr);
        unsupported()
    }

    /// Stands in for `Memory.join(MemoryBlock, MemoryBlock)`.
    fn join(
        &mut self,
        block_one: &dyn MemoryBlock,
        block_two: &dyn MemoryBlock,
    ) -> Result<Box<dyn MemoryBlock>, StubMemoryError> {
        let _ = (block_one, block_two);
        unsupported()
    }

    /// Stands in for `Memory.convertToInitialized(MemoryBlock, byte)`.
    fn convert_to_initialized(
        &mut self,
        uninitialized_block: &dyn MemoryBlock,
        initial_value: u8,
    ) -> Result<Box<dyn MemoryBlock>, StubMemoryError> {
        let _ = (uninitialized_block, initial_value);
        unsupported()
    }

    /// Stands in for `Memory.convertToUninitialized(MemoryBlock)`.
    fn convert_to_uninitialized(
        &mut self,
        initialized_block: &dyn MemoryBlock,
    ) -> Result<Box<dyn MemoryBlock>, StubMemoryError> {
        let _ = initialized_block;
        unsupported()
    }

    /// Stands in for `Memory.findBytes(Address, byte[], byte[], boolean, TaskMonitor)`.
    fn find_bytes(
        &self,
        addr: &Address,
        bytes: &[u8],
        masks: Option<&[u8]>,
        forward: bool,
        monitor: &dyn TaskMonitor,
    ) -> Option<Address> {
        let _ = (addr, bytes, masks, forward, monitor);
        unsupported()
    }

    /// Stands in for `Memory.findBytes(Address, Address, byte[], byte[], boolean, TaskMonitor)`.
    fn find_bytes_in_range(
        &self,
        start_addr: &Address,
        end_addr: &Address,
        bytes: &[u8],
        masks: Option<&[u8]>,
        forward: bool,
        monitor: &dyn TaskMonitor,
    ) -> Option<Address> {
        let _ = (start_addr, end_addr, bytes, masks, forward, monitor);
        unsupported()
    }

    /// Stands in for `Memory.getBytes(Address, byte[], int, int)`. The zero-index, whole-buffer
    /// overload is already covered by [`Memory::get_bytes`].
    fn get_bytes_range(
        &self,
        addr: &Address,
        dest: &mut [u8],
        d_index: usize,
        size: usize,
    ) -> Result<usize, MemoryAccessException> {
        let _ = (addr, dest, d_index, size);
        unsupported()
    }

    /// Stands in for `Memory.getShort(Address)`.
    fn get_short(&self, addr: &Address) -> Result<i16, MemoryAccessException> {
        let _ = addr;
        unsupported()
    }

    /// Stands in for `Memory.getShort(Address, boolean)`.
    fn get_short_endian(&self, addr: &Address, big_endian: bool) -> Result<i16, MemoryAccessException> {
        let _ = (addr, big_endian);
        unsupported()
    }

    /// Stands in for `Memory.getShorts(Address, short[])`.
    fn get_shorts(&self, addr: &Address, dest: &mut [i16]) -> Result<usize, MemoryAccessException> {
        let _ = (addr, dest);
        unsupported()
    }

    /// Stands in for `Memory.getShorts(Address, short[], int, int)`.
    fn get_shorts_range(
        &self,
        addr: &Address,
        dest: &mut [i16],
        d_index: usize,
        n_elem: usize,
    ) -> Result<usize, MemoryAccessException> {
        let _ = (addr, dest, d_index, n_elem);
        unsupported()
    }

    /// Stands in for `Memory.getShorts(Address, short[], int, int, boolean)`.
    fn get_shorts_range_endian(
        &self,
        addr: &Address,
        dest: &mut [i16],
        d_index: usize,
        n_elem: usize,
        is_big_endian: bool,
    ) -> Result<usize, MemoryAccessException> {
        let _ = (addr, dest, d_index, n_elem, is_big_endian);
        unsupported()
    }

    /// Stands in for `Memory.getInt(Address)`.
    fn get_int(&self, addr: &Address) -> Result<i32, MemoryAccessException> {
        let _ = addr;
        unsupported()
    }

    /// Stands in for `Memory.getInt(Address, boolean)`.
    fn get_int_endian(&self, addr: &Address, big_endian: bool) -> Result<i32, MemoryAccessException> {
        let _ = (addr, big_endian);
        unsupported()
    }

    /// Stands in for `Memory.getInts(Address, int[])`.
    fn get_ints(&self, addr: &Address, dest: &mut [i32]) -> Result<usize, MemoryAccessException> {
        let _ = (addr, dest);
        unsupported()
    }

    /// Stands in for `Memory.getInts(Address, int[], int, int)`.
    fn get_ints_range(
        &self,
        addr: &Address,
        dest: &mut [i32],
        d_index: usize,
        n_elem: usize,
    ) -> Result<usize, MemoryAccessException> {
        let _ = (addr, dest, d_index, n_elem);
        unsupported()
    }

    /// Stands in for `Memory.getInts(Address, int[], int, int, boolean)`.
    fn get_ints_range_endian(
        &self,
        addr: &Address,
        dest: &mut [i32],
        d_index: usize,
        n_elem: usize,
        is_big_endian: bool,
    ) -> Result<usize, MemoryAccessException> {
        let _ = (addr, dest, d_index, n_elem, is_big_endian);
        unsupported()
    }

    /// Stands in for `Memory.getLong(Address)`.
    fn get_long(&self, addr: &Address) -> Result<i64, MemoryAccessException> {
        let _ = addr;
        unsupported()
    }

    /// Stands in for `Memory.getLong(Address, boolean)`.
    fn get_long_endian(&self, addr: &Address, big_endian: bool) -> Result<i64, MemoryAccessException> {
        let _ = (addr, big_endian);
        unsupported()
    }

    /// Stands in for `Memory.getLongs(Address, long[])`.
    fn get_longs(&self, addr: &Address, dest: &mut [i64]) -> Result<usize, MemoryAccessException> {
        let _ = (addr, dest);
        unsupported()
    }

    /// Stands in for `Memory.getLongs(Address, long[], int, int)`.
    fn get_longs_range(
        &self,
        addr: &Address,
        dest: &mut [i64],
        d_index: usize,
        n_elem: usize,
    ) -> Result<usize, MemoryAccessException> {
        let _ = (addr, dest, d_index, n_elem);
        unsupported()
    }

    /// Stands in for `Memory.getLongs(Address, long[], int, int, boolean)`.
    fn get_longs_range_endian(
        &self,
        addr: &Address,
        dest: &mut [i64],
        d_index: usize,
        n_elem: usize,
        is_big_endian: bool,
    ) -> Result<usize, MemoryAccessException> {
        let _ = (addr, dest, d_index, n_elem, is_big_endian);
        unsupported()
    }

    /// Stands in for `Memory.setByte(Address, byte)`.
    fn set_byte(&mut self, addr: &Address, value: u8) -> Result<(), MemoryAccessException> {
        let _ = (addr, value);
        unsupported()
    }

    /// Stands in for `Memory.setBytes(Address, byte[], int, int)`. The zero-index, whole-buffer
    /// overload is already covered by [`Memory::set_bytes`].
    fn set_bytes_range(
        &mut self,
        addr: &Address,
        source: &[u8],
        s_index: usize,
        size: usize,
    ) -> Result<(), MemoryAccessException> {
        let _ = (addr, source, s_index, size);
        unsupported()
    }

    /// Stands in for `Memory.setShort(Address, short)`.
    fn set_short(&mut self, addr: &Address, value: i16) -> Result<(), MemoryAccessException> {
        let _ = (addr, value);
        unsupported()
    }

    /// Stands in for `Memory.setShort(Address, short, boolean)`.
    fn set_short_endian(
        &mut self,
        addr: &Address,
        value: i16,
        big_endian: bool,
    ) -> Result<(), MemoryAccessException> {
        let _ = (addr, value, big_endian);
        unsupported()
    }

    /// Stands in for `Memory.setInt(Address, int)`.
    fn set_int(&mut self, addr: &Address, value: i32) -> Result<(), MemoryAccessException> {
        let _ = (addr, value);
        unsupported()
    }

    /// Stands in for `Memory.setInt(Address, int, boolean)`.
    fn set_int_endian(
        &mut self,
        addr: &Address,
        value: i32,
        big_endian: bool,
    ) -> Result<(), MemoryAccessException> {
        let _ = (addr, value, big_endian);
        unsupported()
    }

    /// Stands in for `Memory.setLong(Address, long)`.
    fn set_long(&mut self, addr: &Address, value: i64) -> Result<(), MemoryAccessException> {
        let _ = (addr, value);
        unsupported()
    }

    /// Stands in for `Memory.setLong(Address, long, boolean)`.
    fn set_long_endian(
        &mut self,
        addr: &Address,
        value: i64,
        big_endian: bool,
    ) -> Result<(), MemoryAccessException> {
        let _ = (addr, value, big_endian);
        unsupported()
    }

    /// Stands in for `Memory.createFileBytes(String, long, long, InputStream, TaskMonitor)`.
    fn create_file_bytes(
        &mut self,
        filename: &str,
        offset: i64,
        size: i64,
        is: &mut dyn Read,
        monitor: &dyn TaskMonitor,
    ) -> std::io::Result<Arc<dyn FileBytes>> {
        let _ = (filename, offset, size, is, monitor);
        unsupported()
    }

    /// Stands in for `Memory.getAllFileBytes()`.
    fn get_all_file_bytes(&self) -> Vec<Arc<dyn FileBytes>> {
        unsupported()
    }

    /// Stands in for `Memory.deleteFileBytes(FileBytes)`.
    fn delete_file_bytes(&mut self, descriptor: &dyn FileBytes) -> bool {
        let _ = descriptor;
        unsupported()
    }

    /// Stands in for `Memory.createInitializedBlock(String, Address, FileBytes, long, long,
    /// boolean)`.
    fn create_initialized_block_from_file_bytes(
        &mut self,
        name: &str,
        start: &Address,
        file_bytes: Arc<dyn FileBytes>,
        offset: i64,
        size: i64,
        overlay: bool,
    ) -> Box<dyn MemoryBlock> {
        let _ = (name, start, file_bytes, offset, size, overlay);
        unsupported()
    }

    /// Stands in for `Memory.getAddressSourceInfo(Address)`.
    fn get_address_source_info(&self, address: &Address) -> Option<Arc<dyn AddressSourceInfo>> {
        let _ = address;
        unsupported()
    }
}

fn unsupported<T>() -> T {
    panic!("unsupported StubMemory operation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressRange, AddressRangeIterator, AddressSet, AddressSpace, AddressSpaceType};

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("Mem", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    /// Mirrors `new StubMemory(byte[])`: wraps an `AddressSet` covering exactly the supplied
    /// bytes and answers real byte reads from them, while every other method stays at the
    /// panicking default -- proving the trait is object-safe and that a minimal implementor only
    /// needs to override what it actually uses.
    struct BytesStubMemory {
        set: AddressSet,
        bytes: Vec<u8>,
    }

    impl BytesStubMemory {
        fn new(bytes: Vec<u8>) -> Self {
            let start = test_address(0);
            let end = test_address(bytes.len() as i64 - 1);
            Self {
                set: AddressSet::from_start_end(start, end),
                bytes,
            }
        }
    }

    impl AddressSetView for BytesStubMemory {
        fn contains(&self, address: &Address) -> bool {
            self.set.contains(address)
        }
        fn contains_range(&self, start: &Address, end: &Address) -> bool {
            self.set.contains_range(start, end)
        }
        fn contains_set(&self, set: &dyn AddressSetView) -> bool {
            self.set.contains_set(set)
        }
        fn is_empty(&self) -> bool {
            self.set.is_empty()
        }
        fn min_address(&self) -> Option<Address> {
            self.set.min_address()
        }
        fn max_address(&self) -> Option<Address> {
            self.set.max_address()
        }
        fn num_address_ranges(&self) -> usize {
            self.set.num_address_ranges()
        }
        fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
            self.set.address_ranges()
        }
        fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
            self.set.address_ranges_ordered(forward)
        }
        fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
            self.set.address_ranges_from(start, forward)
        }
        fn num_addresses(&self) -> u64 {
            self.set.num_addresses()
        }
        fn addresses(&self, forward: bool) -> Box<dyn crate::program::model::address::AddressIterator> {
            self.set.addresses(forward)
        }
        fn addresses_from(
            &self,
            start: &Address,
            forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            self.set.addresses_from(start, forward)
        }
        fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
            self.set.intersects_set(set)
        }
        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.set.intersects_range(start, end)
        }
        fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
            self.set.intersect(set)
        }
        fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
            self.set.intersect_range(start, end)
        }
        fn union(&self, set: &dyn AddressSetView) -> AddressSet {
            self.set.union(set)
        }
        fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
            self.set.subtract(set)
        }
        fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
            self.set.xor(set)
        }
        fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
            self.set.has_same_addresses(set)
        }
        fn first_range(&self) -> Option<AddressRange> {
            self.set.first_range()
        }
        fn last_range(&self) -> Option<AddressRange> {
            self.set.last_range()
        }
        fn range_containing(&self, address: &Address) -> Option<AddressRange> {
            self.set.range_containing(address)
        }
        fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
            self.set.find_first_address_in_common(set)
        }
    }

    impl Memory for BytesStubMemory {
        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(addr.offset() as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("offset out of range"))
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let start = addr.offset() as usize;
            let available = self.bytes.len().saturating_sub(start);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&self.bytes[start..start + n]);
            n
        }

        fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
            let start = addr.offset() as usize;
            if start + source.len() > self.bytes.len() {
                return Err(MemoryAccessException::new("write out of range"));
            }
            self.bytes[start..start + source.len()].copy_from_slice(source);
            Ok(())
        }
    }

    impl StubMemory for BytesStubMemory {}

    #[test]
    fn default_constructor_bytes_are_readable_and_writable() {
        let mut mem = BytesStubMemory::new(vec![0, 0, 0, 0, 0, 0, 0, 0]);

        assert_eq!(mem.get_byte(&test_address(0)).unwrap(), 0);
        assert!(mem.contains_range(&test_address(0), &test_address(7)));
        assert_eq!(mem.num_addresses(), 8);

        mem.set_bytes(&test_address(2), &[0xAA, 0xBB]).unwrap();
        assert_eq!(mem.get_byte(&test_address(2)).unwrap(), 0xAA);
        assert_eq!(mem.get_byte(&test_address(3)).unwrap(), 0xBB);

        let mut dest = [0u8; 3];
        let n = mem.get_bytes(&test_address(1), &mut dest);
        assert_eq!(n, 3);
        assert_eq!(dest, [0, 0xAA, 0xBB]);
    }

    #[test]
    fn out_of_range_access_is_an_error_not_a_panic() {
        let mem = BytesStubMemory::new(vec![1, 2, 3]);
        assert!(mem.get_byte(&test_address(10)).is_err());
    }

    #[test]
    #[should_panic(expected = "unsupported StubMemory operation")]
    fn unoverridden_methods_panic_like_unsupportedoperationexception() {
        let mem = BytesStubMemory::new(vec![0; 8]);
        let _ = mem.get_size();
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mem: Box<dyn StubMemory> = Box::new(BytesStubMemory::new(vec![9, 9]));
        assert_eq!(mem.get_byte(&test_address(0)).unwrap(), 9);
        assert!(!mem.is_big_endian());
    }
}

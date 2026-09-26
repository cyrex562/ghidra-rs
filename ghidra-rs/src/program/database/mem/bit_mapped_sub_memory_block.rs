//! Port of the class `ghidra.program.database.mem.BitMappedSubMemoryBlock`.
//!
//! Implementation of `SubMemoryBlock` for bit-mapped memory sub blocks: each byte visible in this
//! sub block is a single bit (0 or 1) read from/written into the corresponding bit of a byte in
//! another memory range (`mapped_address` onward), used e.g. for flag-bit overlay memory blocks.
//!
//! Java's constructor resolves `mappedAddress` via `memMap.getAddressMap().decodeAddress(...)` --
//! `AddressMapDB` is not reachable from this crate's `MemoryMapDBAdapter::get_memory_map` (which
//! deliberately returns the generic `Memory` trait rather than `MemoryMapDB`, to cut the back
//! reference cycle described in that trait's module docs). Per this crate's "explicit parameters
//! instead of virtual calls" convention, [`new`](BitMappedSubMemoryBlock::new) takes the
//! already-decoded `mapped_address` directly from its caller instead.
//!
//! Java's `ioPending` reentrancy guard is mutated from `getByte`/`getBytes` (`&self` in this
//! port's trait) as well as `putByte`/`putBytes` (`&mut self`), so it needs interior mutability
//! here; an `AtomicBool` satisfies `SubMemoryBlock: Send + Sync` without a `Mutex`.
//!
//! This port faithfully replicates several apparent bugs/inconsistencies present in the real
//! Ghidra source rather than silently "fixing" them (see the `NOTE:` comments below at each site):
//! `getBytes`/`putByte`/`putBytes` each construct (but never `throw`) a
//! `new MemoryAccessException(...)` under their `ioPending`/overflow guards, so those exceptions
//! are never actually raised on those paths, unlike `getByte`, which does `throw`. `getBytes` also
//! passes the un-adjusted `offsetInMemBlock` (not `offsetInMemBlock - subBlockOffset`) into
//! `getBitOverlayByte`, unlike `getByte`, which subtracts `subBlockOffset` first.
//!
//! `get_source_info` delegates to
//! [`MemoryBlockSourceInfoDB::new`](crate::program::database::mem::memory_block_source_info_db::MemoryBlockSourceInfoDB::new),
//! mirroring Java's `SubMemoryBlock.getSourceInfo` constructing a `MemoryBlockSourceInfoDB`.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::framework::db::record::DBRecord;
use crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter;
use crate::program::database::mem::sub_block_header::SubBlockHeader;
use crate::program::database::mem::sub_memory_block::{SubMemoryBlock, SubMemoryBlockError};
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock, MemoryBlockSourceInfo, MemoryBlockType};

/// Implementation of `SubMemoryBlock` for bit-mapped memory sub blocks. Mirrors
/// `ghidra.program.database.mem.BitMappedSubMemoryBlock`.
pub struct BitMappedSubMemoryBlock {
    header: SubBlockHeader,
    mem_map: Arc<RwLock<dyn Memory>>,
    mapped_address: Address,
    io_pending: AtomicBool,
}

impl BitMappedSubMemoryBlock {
    /// Mirrors `BitMappedSubMemoryBlock(MemoryMapDBAdapter, DBRecord)`. See this module's docs
    /// for why `mapped_address` is supplied directly rather than decoded from `record` here.
    pub fn new(adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>, record: DBRecord, mapped_address: Address) -> Self {
        let mem_map = adapter.read().unwrap().get_memory_map();
        Self::from_parts(adapter, record, mem_map, mapped_address)
    }

    /// Constructs a `BitMappedSubMemoryBlock` from an already-resolved `mem_map`, skipping the
    /// `adapter.get_memory_map()` lookup [`new`](Self::new) performs. Used by adapter
    /// implementations (e.g. `MemoryMapDBAdapterV3`) that already hold their own `mem_map` field
    /// and need to construct this sub block from within a method that already has `self` (and
    /// thus the adapter's lock) borrowed -- calling [`new`](Self::new) there would re-lock the
    /// same `Arc<RwLock<dyn MemoryMapDBAdapter>>` the caller is already holding and deadlock.
    pub(crate) fn from_parts(
        adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>,
        record: DBRecord,
        mem_map: Arc<RwLock<dyn Memory>>,
        mapped_address: Address,
    ) -> Self {
        Self {
            header: SubBlockHeader::new(adapter, record),
            mem_map,
            mapped_address,
            io_pending: AtomicBool::new(false),
        }
    }

    /// Mirrors the package-private `getMappedRange()`.
    pub fn get_mapped_range(&self) -> Option<AddressRange> {
        let end_mapped_address = self.mapped_address.add((self.header.get_length() - 1) / 8).ok()?;
        Some(AddressRange::new(self.mapped_address.clone(), end_mapped_address))
    }

    /// Mirrors the private `getBitOverlayByte(long)`.
    fn get_bit_overlay_byte(&self, block_offset: i64) -> Result<u8, SubMemoryBlockError> {
        let other_addr = self
            .mapped_address
            .add_no_wrap(block_offset / 8)
            .map_err(|_| MemoryAccessException::new("No memory at address"))?;
        let b = self.mem_map.read().unwrap().get_byte(&other_addr)?;
        Ok((b as u8 >> (block_offset % 8)) & 0x01)
    }

    /// Mirrors the private `doPutByte(Address, int, byte)`.
    fn do_put_byte(&self, addr: &Address, bit_index: i32, b: u8) -> Result<(), MemoryAccessException> {
        // Mirrors Java's redundant `ioPending = true;` re-assignment inside `doPutByte` itself
        // (the callers already set it before calling in).
        self.io_pending.store(true, Ordering::SeqCst);
        let value = self.mem_map.read().unwrap().get_byte(addr)?;
        let mask: u8 = 1 << (bit_index.rem_euclid(8));
        let new_value = if b == 0 { value & !mask } else { value | mask };
        self.mem_map.write().unwrap().set_bytes(addr, &[new_value])?;
        Ok(())
    }
}

impl SubMemoryBlock for BitMappedSubMemoryBlock {
    fn is_initialized(&self) -> bool {
        false
    }

    fn get_parent_block_id(&self) -> i64 {
        self.header.get_parent_block_id()
    }

    fn get_starting_offset(&self) -> i64 {
        self.header.get_starting_offset()
    }

    fn get_length(&self) -> i64 {
        self.header.get_length()
    }

    fn get_byte(&self, offset_in_mem_block: i64) -> Result<u8, SubMemoryBlockError> {
        let offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        if self.io_pending.load(Ordering::SeqCst) {
            return Err(MemoryAccessException::new("Cyclic Access").into());
        }
        self.io_pending.store(true, Ordering::SeqCst);
        let result = self.get_bit_overlay_byte(offset_in_sub_block);
        self.io_pending.store(false, Ordering::SeqCst);
        result
    }

    fn get_bytes(
        &self,
        offset_in_mem_block: i64,
        b: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<usize, SubMemoryBlockError> {
        let offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        let available = self.header.get_length() - offset_in_sub_block;
        let len = (len as i64).min(available.max(0)) as usize;
        // NOTE: Java's `ioPending` guard here constructs but never `throw`s the "Cyclic Access"
        // exception, so a reentrant call proceeds anyway. Replicated verbatim.
        self.io_pending.store(true, Ordering::SeqCst);
        // NOTE: Java passes the un-adjusted `offsetInMemBlock` (not `offsetInSubBlock`) into
        // `getBitOverlayByte` here, unlike `getByte` above. Replicated verbatim; only differs
        // from `getByte`'s behavior when this sub block's starting offset is non-zero.
        let mut cur = offset_in_mem_block;
        let result = (|| -> Result<usize, SubMemoryBlockError> {
            for i in 0..len {
                b[i + off] = self.get_bit_overlay_byte(cur)?;
                cur += 1;
            }
            Ok(len)
        })();
        self.io_pending.store(false, Ordering::SeqCst);
        result
    }

    fn put_byte(&mut self, offset_in_mem_block: i64, b: u8) -> Result<(), SubMemoryBlockError> {
        let offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        // NOTE: same "constructed but never thrown" ioPending guard as `get_bytes`.
        self.io_pending.store(true, Ordering::SeqCst);
        let result = match self.mapped_address.add_no_wrap(offset_in_sub_block / 8) {
            Ok(addr) => self
                .do_put_byte(&addr, (offset_in_sub_block % 8) as i32, b)
                .map_err(SubMemoryBlockError::from),
            // NOTE: Java's `catch (AddressOverflowException e)` here also constructs but never
            // `throw`s `new MemoryAccessException("No memory at address")`, so the method
            // silently succeeds instead of propagating the error. Replicated verbatim (unlike
            // `put_bytes` below, whose equivalent catch block does `throw`).
            Err(_) => Ok(()),
        };
        self.io_pending.store(false, Ordering::SeqCst);
        result
    }

    fn put_bytes(
        &mut self,
        offset_in_mem_block: i64,
        b: &[u8],
        off: usize,
        len: usize,
    ) -> Result<usize, SubMemoryBlockError> {
        let mut offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        let available = self.header.get_length() - offset_in_sub_block;
        let len = (len as i64).min(available.max(0)) as usize;
        // NOTE: same "constructed but never thrown" ioPending guard as `get_bytes`/`put_byte`.
        self.io_pending.store(true, Ordering::SeqCst);
        let result = (|| -> Result<usize, SubMemoryBlockError> {
            for i in 0..len {
                let addr = self
                    .mapped_address
                    .add_no_wrap(offset_in_sub_block / 8)
                    .map_err(|_| MemoryAccessException::new("No memory at address"))?;
                self.do_put_byte(&addr, (offset_in_sub_block % 8) as i32, b[off + i])?;
                offset_in_sub_block += 1;
            }
            Ok(len)
        })();
        self.io_pending.store(false, Ordering::SeqCst);
        result
    }

    fn delete(&mut self) -> io::Result<()> {
        self.header.delete()
    }

    fn set_length(&mut self, length: i64) -> io::Result<()> {
        self.header.set_length(length)
    }

    fn join(&mut self, _sub2: &mut dyn SubMemoryBlock) -> io::Result<bool> {
        Ok(false)
    }

    fn is_mapped(&self) -> bool {
        true
    }

    fn get_type(&self) -> MemoryBlockType {
        MemoryBlockType::BitMapped
    }

    fn get_source_info(&self, block: Arc<dyn MemoryBlock>) -> Arc<dyn MemoryBlockSourceInfo> {
        Arc::new(crate::program::database::mem::memory_block_source_info_db::MemoryBlockSourceInfoDB::new(
            block, self,
        ))
    }

    fn split(&mut self, _mem_block_offset: i64) -> Result<Box<dyn SubMemoryBlock>, SubMemoryBlockError> {
        // Mirrors Java's `throw new UnsupportedOperationException()`.
        Err(SubMemoryBlockError::IllegalArgument(
            "split is not supported for bit-mapped blocks".to_string(),
        ))
    }

    fn set_parent_id_and_starting_offset(&mut self, key: i64, starting_offset: i64) -> io::Result<()> {
        self.header.set_parent_id_and_starting_offset(key, starting_offset)
    }

    fn get_description(&self) -> String {
        format!(
            "bitmap[{:#x}, {:#x}, {}]",
            self.header.get_starting_offset(),
            self.header.get_length(),
            self.mapped_address
        )
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::mem::sub_block_header::test_support::{make_record, test_addr, MockAdapter, MockMemory};
    use std::sync::{Arc, RwLock};

    fn adapter_over(memory: MockMemory) -> Arc<RwLock<MockAdapter>> {
        let mem: Arc<RwLock<dyn Memory>> = Arc::new(RwLock::new(memory));
        Arc::new(RwLock::new(MockAdapter::with_memory(mem)))
    }

    fn block(adapter: &Arc<RwLock<MockAdapter>>, key: i64, starting_offset: i64, length: i64, mapped: Address) -> BitMappedSubMemoryBlock {
        let record = make_record(key, 1, starting_offset, length, 0, 0);
        BitMappedSubMemoryBlock::new(adapter.clone() as Arc<RwLock<dyn MemoryMapDBAdapter>>, record, mapped)
    }

    #[test]
    fn is_never_initialized_but_is_mapped() {
        let adapter = adapter_over(MockMemory::new(0, vec![0; 4]));
        let b = block(&adapter, 1, 0, 32, test_addr(0));
        assert!(!b.is_initialized());
        assert!(b.is_mapped());
        assert_eq!(b.get_type(), MemoryBlockType::BitMapped);
    }

    #[test]
    fn get_byte_reads_a_single_bit_from_the_mapped_source() {
        // source byte 0 = 0b0000_0101 -> bit 0 = 1, bit 1 = 0, bit 2 = 1, bit 3 = 0
        let adapter = adapter_over(MockMemory::new(0, vec![0b0000_0101]));
        let b = block(&adapter, 1, 0, 8, test_addr(0));

        assert_eq!(b.get_byte(0).unwrap(), 1);
        assert_eq!(b.get_byte(1).unwrap(), 0);
        assert_eq!(b.get_byte(2).unwrap(), 1);
        assert_eq!(b.get_byte(3).unwrap(), 0);
    }

    #[test]
    fn get_byte_crosses_source_byte_boundaries_every_eight_bits() {
        // source byte 0 = 0xFF (all bits set), source byte 1 = 0x00 (all clear)
        let adapter = adapter_over(MockMemory::new(0, vec![0xFF, 0x00]));
        let b = block(&adapter, 1, 0, 16, test_addr(0));

        for offset in 0..8 {
            assert_eq!(b.get_byte(offset).unwrap(), 1, "bit {offset} of source byte 0 should be set");
        }
        for offset in 8..16 {
            assert_eq!(b.get_byte(offset).unwrap(), 0, "bit {offset} of source byte 1 should be clear");
        }
    }

    #[test]
    fn put_byte_sets_and_clears_individual_bits() {
        let adapter = adapter_over(MockMemory::new(0, vec![0x00]));
        let mut b = block(&adapter, 1, 0, 8, test_addr(0));

        b.put_byte(3, 1).unwrap();
        assert_eq!(b.get_byte(3).unwrap(), 1);
        assert_eq!(b.get_byte(0).unwrap(), 0);

        b.put_byte(3, 0).unwrap();
        assert_eq!(b.get_byte(3).unwrap(), 0);
    }

    #[test]
    fn put_bytes_writes_each_mapped_bit_independently() {
        let adapter = adapter_over(MockMemory::new(0, vec![0x00, 0x00]));
        let mut b = block(&adapter, 1, 0, 16, test_addr(0));

        // Write bit pattern 1,0,1,0,1,0,1,0 into the first 8 mapped bits.
        let pattern = [1u8, 0, 1, 0, 1, 0, 1, 0];
        b.put_bytes(0, &pattern, 0, 8).unwrap();

        let mut out = [0u8; 8];
        b.get_bytes(0, &mut out, 0, 8).unwrap();
        assert_eq!(out, pattern);
    }

    #[test]
    fn get_bytes_clamps_to_available_length() {
        let adapter = adapter_over(MockMemory::new(0, vec![0xFF]));
        let b = block(&adapter, 1, 0, 4, test_addr(0));
        let mut out = [0u8; 10];
        let n = b.get_bytes(0, &mut out, 0, 10).unwrap();
        assert_eq!(n, 4);
    }

    #[test]
    fn get_byte_out_of_range_source_reports_memory_access_error() {
        let adapter = adapter_over(MockMemory::new(0, vec![0xFF]));
        // mapped_address is far beyond the tiny 1-byte backing memory.
        let b = block(&adapter, 1, 0, 800, test_addr(0));
        let err = b.get_byte(100).unwrap_err(); // bit 100 -> source byte 12, out of range
        assert!(matches!(err, SubMemoryBlockError::MemoryAccess(_)));
    }

    #[test]
    fn join_always_reports_unsupported() {
        let adapter = adapter_over(MockMemory::new(0, vec![0xFF]));
        let mut a = block(&adapter, 1, 0, 8, test_addr(0));
        let mut b = block(&adapter, 2, 8, 8, test_addr(1));
        assert!(!a.join(&mut b).unwrap());
    }

    #[test]
    fn split_is_unsupported() {
        let adapter = adapter_over(MockMemory::new(0, vec![0xFF]));
        let mut a = block(&adapter, 1, 0, 8, test_addr(0));
        assert!(a.split(4).is_err());
    }

    #[test]
    fn get_mapped_range_spans_one_byte_per_eight_bits() {
        let adapter = adapter_over(MockMemory::new(0, vec![0; 4]));
        let b = block(&adapter, 1, 0, 32, test_addr(0x100));
        let range = b.get_mapped_range().unwrap();
        assert_eq!(range.min_address().offset(), 0x100);
        assert_eq!(range.max_address().offset(), 0x103); // (32-1)/8 = 3
    }

    #[test]
    fn description_includes_offset_length_and_mapped_address() {
        let adapter = adapter_over(MockMemory::new(0, vec![0; 4]));
        let b = block(&adapter, 1, 0x10, 0x20, test_addr(0x100));
        assert!(b.get_description().starts_with("bitmap[0x10, 0x20, "));
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let adapter = adapter_over(MockMemory::new(0, vec![0xFF]));
        let boxed: Box<dyn SubMemoryBlock> = Box::new(block(&adapter, 1, 0, 8, test_addr(0)));
        assert!(!boxed.is_initialized());
        assert!(boxed.is_mapped());
    }
}

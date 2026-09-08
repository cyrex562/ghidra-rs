//! Port of the class `ghidra.program.database.mem.ByteMappedSubMemoryBlock`.
//!
//! Implementation of `SubMemoryBlock` for byte-mapped memory sub blocks: bytes visible in this
//! sub block are read from/written to another memory range (`mapped_address` onward) via a
//! [`ByteMappingScheme`] (an arbitrary N:M byte ratio, e.g. for modeling bank-switched or
//! interleaved memory; 1:1 is the common case).
//!
//! Java's constructor resolves `mappedAddress` via `memMap.getAddressMap().decodeAddress(...)` --
//! not reachable from this crate's `MemoryMapDBAdapter::get_memory_map` (see
//! `bit_mapped_sub_memory_block`'s module docs for the same gap and why). Per this crate's
//! "explicit parameters instead of virtual calls" convention, [`new`](ByteMappedSubMemoryBlock::new)
//! takes the already-decoded `mapped_address` directly; the mapping scheme, however, *is* decoded
//! from `record`'s own `SUB_INT_DATA1_COL`, since [`ByteMappingScheme::from_encoded`] needs no
//! address-map plumbing.
//!
//! Java's `ioPending` reentrancy guard is mutated from `getByte`/`getBytes` (`&self` in this
//! port's trait) as well as `putByte`/`putBytes` (`&mut self`), so it needs interior mutability
//! here; an `AtomicBool` satisfies `SubMemoryBlock: Send + Sync` without a `Mutex`.
//!
//! This port faithfully replicates an apparent bug present in all four of the real Ghidra source's
//! byte-access methods rather than silently "fixing" it: each constructs (but never `throw`s) a
//! `new MemoryAccessException("Cyclic Access")` under its `ioPending` guard, so that check never
//! actually raises anything (unlike `BitMappedSubMemoryBlock.getByte`, which does `throw`). Each
//! method's own overflow-catch block, unlike the guard, *does* correctly `throw` a fresh
//! `MemoryAccessException("No memory at address")`, and that part is replicated faithfully too.
//!
//! `get_source_info` delegates to
//! [`MemoryBlockSourceInfoDB::new`](crate::program::database::mem::memory_block_source_info_db::MemoryBlockSourceInfoDB::new),
//! mirroring Java's `SubMemoryBlock.getSourceInfo` constructing a `MemoryBlockSourceInfoDB`.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::framework::db::record::DBRecord;
use crate::program::database::mem::byte_mapping_scheme::{ByteMappingScheme, ByteMappingSchemeError};
use crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter;
use crate::program::database::mem::sub_block_header::{SubBlockHeader, SUB_INT_DATA1_COL, SUB_TYPE_BYTE_MAPPED};
use crate::program::database::mem::sub_memory_block::{SubMemoryBlock, SubMemoryBlockError};
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock, MemoryBlockSourceInfo, MemoryBlockType};

/// Converts a [`ByteMappingSchemeError`] the way each byte-access method's
/// `catch (AddressOverflowException e)` block does: overflow becomes a fresh
/// `MemoryAccessException("No memory at address")`, while everything else (an `IllegalArgument`
/// from a malformed/negative offset, or a `MemoryAccess` error that already came from `Memory`)
/// passes through unchanged, matching what an uncaught/unwrapped Java exception of that same kind
/// would do.
fn map_byte_mapping_error(err: ByteMappingSchemeError) -> SubMemoryBlockError {
    match err {
        ByteMappingSchemeError::AddressOverflow(_) => MemoryAccessException::new("No memory at address").into(),
        ByteMappingSchemeError::IllegalArgument(msg) => SubMemoryBlockError::IllegalArgument(msg),
        ByteMappingSchemeError::MemoryAccess(err) => SubMemoryBlockError::MemoryAccess(err),
    }
}

/// Implementation of `SubMemoryBlock` for byte-mapped memory sub blocks. Mirrors
/// `ghidra.program.database.mem.ByteMappedSubMemoryBlock`.
pub struct ByteMappedSubMemoryBlock {
    header: SubBlockHeader,
    mem_map: Arc<RwLock<dyn Memory>>,
    mapped_address: Address,
    byte_mapping_scheme: ByteMappingScheme,
    io_pending: AtomicBool,
}

impl ByteMappedSubMemoryBlock {
    /// Mirrors `ByteMappedSubMemoryBlock(MemoryMapDBAdapter, DBRecord)`. See this module's docs
    /// for why `mapped_address` is supplied directly rather than decoded from `record` here.
    pub fn new(
        adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>,
        record: DBRecord,
        mapped_address: Address,
    ) -> Result<Self, ByteMappingSchemeError> {
        let mem_map = adapter.read().unwrap().get_memory_map();
        let encoded_mapping_scheme = record.get_int(SUB_INT_DATA1_COL).unwrap_or(0);
        let byte_mapping_scheme = ByteMappingScheme::from_encoded(encoded_mapping_scheme)?;
        Ok(Self {
            header: SubBlockHeader::new(adapter, record),
            mem_map,
            mapped_address,
            byte_mapping_scheme,
            io_pending: AtomicBool::new(false),
        })
    }

    /// Mirrors the package-private `getByteMappingScheme()`.
    pub fn get_byte_mapping_scheme(&self) -> ByteMappingScheme {
        self.byte_mapping_scheme
    }

    /// Mirrors the package-private `getMappedRange()`.
    pub fn get_mapped_range(&self) -> AddressRange {
        let length = self.header.get_length();
        match self.byte_mapping_scheme.get_mapped_source_address(&self.mapped_address, length - 1) {
            Ok(end_mapped_address) => AddressRange::new(self.mapped_address.clone(), end_mapped_address),
            Err(ByteMappingSchemeError::AddressOverflow(_)) => {
                // "keep things happy", per Java's comment on the equivalent catch block.
                let max = self.mapped_address.space().max_address();
                AddressRange::new(self.mapped_address.clone(), max)
            }
            // Java's catch clause here only catches `AddressOverflowException`; any other error
            // (e.g. `IllegalArgumentException` from a malformed/zero-length block) would
            // propagate out of `getMappedRange()` uncaught, same as this does.
            Err(other) => panic!("{other}"),
        }
    }
}

impl SubMemoryBlock for ByteMappedSubMemoryBlock {
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
        // NOTE: Java's `ioPending` guard here constructs but never `throw`s the "Cyclic Access"
        // exception; replicated verbatim (see module docs).
        self.io_pending.store(true, Ordering::SeqCst);
        let result = (|| -> Result<u8, SubMemoryBlockError> {
            let source_addr = self
                .byte_mapping_scheme
                .get_mapped_source_address(&self.mapped_address, offset_in_sub_block)
                .map_err(map_byte_mapping_error)?;
            Ok(self.mem_map.read().unwrap().get_byte(&source_addr)?)
        })();
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
        // NOTE: same "constructed but never thrown" ioPending guard bug as `get_byte`.
        self.io_pending.store(true, Ordering::SeqCst);
        let result = self
            .byte_mapping_scheme
            .get_bytes(&*self.mem_map.read().unwrap(), &self.mapped_address, offset_in_sub_block, b, off, len)
            .map_err(map_byte_mapping_error);
        self.io_pending.store(false, Ordering::SeqCst);
        result
    }

    fn put_byte(&mut self, offset_in_mem_block: i64, b: u8) -> Result<(), SubMemoryBlockError> {
        let offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        // NOTE: same "constructed but never thrown" ioPending guard bug as `get_byte`.
        self.io_pending.store(true, Ordering::SeqCst);
        let result = (|| -> Result<(), SubMemoryBlockError> {
            let source_addr = self
                .byte_mapping_scheme
                .get_mapped_source_address(&self.mapped_address, offset_in_sub_block)
                .map_err(map_byte_mapping_error)?;
            self.mem_map.write().unwrap().set_bytes(&source_addr, &[b])?;
            Ok(())
        })();
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
        let offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        let available = self.header.get_length() - offset_in_sub_block;
        let len = (len as i64).min(available.max(0)) as usize;
        // NOTE: same "constructed but never thrown" ioPending guard bug as `get_byte`.
        self.io_pending.store(true, Ordering::SeqCst);
        let result = (|| -> Result<usize, SubMemoryBlockError> {
            let mut guard = self.mem_map.write().unwrap();
            self.byte_mapping_scheme
                .set_bytes(&mut *guard, &self.mapped_address, offset_in_sub_block, b, off, len)
                .map_err(map_byte_mapping_error)?;
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
        MemoryBlockType::ByteMapped
    }

    fn get_source_info(&self, block: Arc<dyn MemoryBlock>) -> Arc<dyn MemoryBlockSourceInfo> {
        Arc::new(crate::program::database::mem::memory_block_source_info_db::MemoryBlockSourceInfoDB::new(
            block, self,
        ))
    }

    fn split(&mut self, mem_block_offset: i64) -> Result<Box<dyn SubMemoryBlock>, SubMemoryBlockError> {
        // NOTE - GUI does not support any split of any byte-mapped blocks although API does.
        //        Not sure we really need to support it for byte-mapped block. (Java's comment,
        //        preserved verbatim.)
        if !self.byte_mapping_scheme.is_one_to_one_mapping() {
            // Mirrors Java's `throw new UnsupportedOperationException(...)`.
            return Err(SubMemoryBlockError::IllegalArgument(format!(
                "split not supported for byte-mapped block with {}",
                self.byte_mapping_scheme
            )));
        }

        let offset = mem_block_offset - self.header.get_starting_offset();
        let new_length = self.header.get_length() - offset;
        self.header.set_length(offset)?;

        let new_addr = self
            .mapped_address
            .add(offset)
            .map_err(|e| SubMemoryBlockError::IllegalArgument(e.to_string()))?;

        // Java encodes `newAddr` into the new record's `SUB_LONG_DATA2_COL` via
        // `adapter.getMemoryMap().getAddressMap().getKey(newAddr, true)` so the *next* load can
        // decode it back out of the record. This crate's constructor takes `mapped_address`
        // directly instead (see module docs), so `new_addr` is threaded straight through here
        // and the record's data2 column is left unused (0) rather than encoded.
        let new_record = self.header.adapter().write().unwrap().create_sub_block_record(
            0,
            0,
            new_length,
            SUB_TYPE_BYTE_MAPPED,
            0, // data1 = 0 -> 1:1 encoded mapping scheme, matching the one-to-one check above
            0,
        )?;

        let new_block = ByteMappedSubMemoryBlock::new(self.header.adapter().clone(), new_record, new_addr)
            .map_err(map_byte_mapping_error)?;
        Ok(Box::new(new_block))
    }

    fn set_parent_id_and_starting_offset(&mut self, key: i64, starting_offset: i64) -> io::Result<()> {
        self.header.set_parent_id_and_starting_offset(key, starting_offset)
    }

    fn get_description(&self) -> String {
        format!(
            "bytemap[{:#x}, {:#x}, {}]",
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

    fn block(
        adapter: &Arc<RwLock<MockAdapter>>,
        key: i64,
        starting_offset: i64,
        length: i64,
        mapped: Address,
        encoded_mapping_scheme: i32,
    ) -> ByteMappedSubMemoryBlock {
        let record = make_record(key, 1, starting_offset, length, encoded_mapping_scheme, 0);
        ByteMappedSubMemoryBlock::new(adapter.clone() as Arc<RwLock<dyn MemoryMapDBAdapter>>, record, mapped).unwrap()
    }

    #[test]
    fn is_never_initialized_but_is_mapped() {
        let adapter = adapter_over(MockMemory::new(0, vec![0; 4]));
        let b = block(&adapter, 1, 0, 4, test_addr(0), 0);
        assert!(!b.is_initialized());
        assert!(b.is_mapped());
        assert_eq!(b.get_type(), MemoryBlockType::ByteMapped);
    }

    #[test]
    fn one_to_one_mapping_reads_and_writes_pass_through() {
        let adapter = adapter_over(MockMemory::new(0, vec![0; 8]));
        let mut b = block(&adapter, 1, 100, 8, test_addr(0), 0);

        b.put_byte(100, 0xAA).unwrap();
        b.put_byte(107, 0xBB).unwrap();
        assert_eq!(b.get_byte(100).unwrap(), 0xAA);
        assert_eq!(b.get_byte(107).unwrap(), 0xBB);
    }

    #[test]
    fn ratio_mapping_reads_and_writes_apply_decimation_arithmetic() {
        // 1:2 mapping: mapped byte i lands at source offset 2*i.
        let encoded = ByteMappingScheme::new(1, 2).unwrap().get_encoded_mapping_scheme();
        let mem: Arc<RwLock<dyn Memory>> = Arc::new(RwLock::new(MockMemory::new(0, vec![0xFF; 8])));
        let adapter = Arc::new(RwLock::new(MockAdapter::with_memory(mem.clone())));
        let mut b = block(&adapter, 1, 0, 4, test_addr(0), encoded);

        b.put_bytes(0, &[1, 2, 3, 4], 0, 4).unwrap();
        let mut out = [0u8; 4];
        let n = b.get_bytes(0, &mut out, 0, 4).unwrap();
        assert_eq!(n, 4);
        assert_eq!(out, [1, 2, 3, 4]);

        // Verify the underlying source really is decimated: mapped bytes land at even source
        // offsets, leaving the skipped odd offsets at their original sentinel (0xFF) value.
        let mut raw = [0u8; 8];
        mem.read().unwrap().get_bytes(&test_addr(0), &mut raw);
        assert_eq!(raw, [1, 0xFF, 2, 0xFF, 3, 0xFF, 4, 0xFF]);
    }

    #[test]
    fn get_bytes_clamps_to_available_length() {
        let adapter = adapter_over(MockMemory::new(0, vec![1, 2, 3, 4]));
        let b = block(&adapter, 1, 0, 4, test_addr(0), 0);
        let mut out = [0u8; 10];
        let n = b.get_bytes(2, &mut out, 0, 10).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&out[..2], &[3, 4]);
    }

    #[test]
    fn get_byte_out_of_range_source_reports_memory_access_error() {
        let adapter = adapter_over(MockMemory::new(0, vec![1]));
        let b = block(&adapter, 1, 0, 100, test_addr(50), 0);
        let err = b.get_byte(0).unwrap_err();
        assert!(matches!(err, SubMemoryBlockError::MemoryAccess(_)));
    }

    #[test]
    fn join_always_returns_false() {
        let adapter = adapter_over(MockMemory::new(0, vec![0; 8]));
        let mut a = block(&adapter, 1, 0, 4, test_addr(0), 0);
        let mut b = block(&adapter, 2, 4, 4, test_addr(4), 0);
        assert!(!a.join(&mut b).unwrap());
    }

    #[test]
    fn split_one_to_one_mapping_produces_an_advanced_mapped_address() {
        let adapter = adapter_over(MockMemory::new(0, vec![10, 20, 30, 40]));
        let mut a = block(&adapter, 1, 100, 4, test_addr(0), 0);

        let mut back = a.split(102).unwrap();
        assert_eq!(a.get_length(), 2);
        assert_eq!(back.get_length(), 2);

        let mut tail = [0u8; 2];
        back.get_bytes(0, &mut tail, 0, 2).unwrap();
        assert_eq!(tail, [30, 40]);
    }

    #[test]
    fn split_rejects_non_one_to_one_mapping() {
        let encoded = ByteMappingScheme::new(1, 2).unwrap().get_encoded_mapping_scheme();
        let adapter = adapter_over(MockMemory::new(0, vec![0; 8]));
        let mut a = block(&adapter, 1, 0, 4, test_addr(0), encoded);
        assert!(a.split(2).is_err());
    }

    #[test]
    fn get_mapped_range_reflects_the_mapping_scheme() {
        let adapter = adapter_over(MockMemory::new(0, vec![0; 4]));
        let b = block(&adapter, 1, 0, 4, test_addr(0x100), 0);
        let range = b.get_mapped_range();
        assert_eq!(range.min_address().offset(), 0x100);
        assert_eq!(range.max_address().offset(), 0x103); // 1:1 mapping over 4 bytes
    }

    #[test]
    fn description_includes_offset_length_and_mapped_address() {
        let adapter = adapter_over(MockMemory::new(0, vec![0; 4]));
        let b = block(&adapter, 1, 0x10, 0x20, test_addr(0x100), 0);
        assert!(b.get_description().starts_with("bytemap[0x10, 0x20, "));
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let adapter = adapter_over(MockMemory::new(0, vec![1, 2, 3]));
        let boxed: Box<dyn SubMemoryBlock> = Box::new(block(&adapter, 1, 0, 3, test_addr(0), 0));
        assert!(!boxed.is_initialized());
        assert!(boxed.is_mapped());
    }
}

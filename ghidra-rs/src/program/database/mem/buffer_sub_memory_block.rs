//! Port of the class `ghidra.program.database.mem.BufferSubMemoryBlock`.
//!
//! Implementation of `SubMemoryBlock` for blocks that store bytes in their own private database
//! buffer (a [`DBBuffer`]).
//!
//! Per this crate's "extends X is composition, not inheritance" convention, this struct holds a
//! [`SubBlockHeader`] (the Rust stand-in for `SubMemoryBlock`'s protected fields/methods) plus its
//! own `buf: Box<dyn DBBuffer>`, instead of subclassing an abstract base. See that module's docs
//! for the record column-index convention used here.
//!
//! `get_source_info` delegates to
//! [`MemoryBlockSourceInfoDB::new`](crate::program::database::mem::memory_block_source_info_db::MemoryBlockSourceInfoDB::new),
//! mirroring Java's `SubMemoryBlock.getSourceInfo` constructing a `MemoryBlockSourceInfoDB`.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::record::DBRecord;
use crate::framework::db::DBBuffer;
use crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter;
use crate::program::database::mem::sub_block_header::{SubBlockHeader, SUB_INT_DATA1_COL, SUB_TYPE_BUFFER};
use crate::program::database::mem::sub_memory_block::{SubMemoryBlock, SubMemoryBlockError};
use crate::program::model::mem::{MemoryBlock, MemoryBlockSourceInfo};

/// Maximum combined length two `BufferSubMemoryBlock`s may have after a `join`. Mirrors
/// `ghidra.program.model.mem.Memory.GBYTE` (`1L << 30`), which has not been ported onto this
/// crate's `Memory` trait as an associated constant.
const GBYTE: i64 = 1 << 30;

/// Implementation of `SubMemoryBlock` for blocks that store bytes in their own private database
/// buffer. Mirrors `ghidra.program.database.mem.BufferSubMemoryBlock`.
pub struct BufferSubMemoryBlock {
    header: SubBlockHeader,
    buf: Box<dyn DBBuffer>,
}

impl BufferSubMemoryBlock {
    /// Mirrors `BufferSubMemoryBlock(MemoryMapDBAdapter, DBRecord)`, which reads the backing
    /// buffer's id out of `record` and resolves it via `adapter.getBuffer(int)`.
    pub fn new(adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>, record: DBRecord) -> io::Result<Self> {
        let buffer_id = record.get_int(SUB_INT_DATA1_COL).unwrap_or(0);
        let buf = adapter.read().unwrap().get_buffer(buffer_id)?;
        Ok(Self {
            header: SubBlockHeader::new(adapter, record),
            buf,
        })
    }

    /// Constructs a `BufferSubMemoryBlock` directly from an already-resolved buffer, skipping the
    /// `adapter.getBuffer` lookup Java's constructor performs. Used by
    /// [`split`](SubMemoryBlock::split) to wrap the tail buffer `DBBuffer::split` already
    /// produced, instead of asking the adapter to re-resolve the same buffer id by its (now
    /// newly-assigned) id -- an equivalent, but more direct, route to the same state.
    ///
    /// Also used by adapter implementations (e.g. `MemoryMapDBAdapterV3`) constructing a freshly
    /// created buffer sub block from within a method that already has the adapter's own lock
    /// borrowed: calling [`new`](Self::new) there would re-lock the same
    /// `Arc<RwLock<dyn MemoryMapDBAdapter>>` the caller is already holding (to resolve the buffer
    /// via `adapter.get_buffer`) and deadlock, whereas this constructor takes an already-resolved
    /// buffer and never locks `adapter` itself.
    pub(crate) fn from_parts(adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>, record: DBRecord, buf: Box<dyn DBBuffer>) -> Self {
        Self {
            header: SubBlockHeader::new(adapter, record),
            buf,
        }
    }

    /// Mirrors the package-private `getKey()`.
    pub fn get_key(&self) -> i64 {
        self.header.key()
    }
}

impl SubMemoryBlock for BufferSubMemoryBlock {
    fn is_initialized(&self) -> bool {
        true
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
        Ok(self.buf.get_byte(offset_in_sub_block as usize)?)
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
        self.buf.get(offset_in_sub_block as usize, b, off, len)?;
        Ok(len)
    }

    fn put_byte(&mut self, offset_in_mem_block: i64, b: u8) -> Result<(), SubMemoryBlockError> {
        let offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        self.buf.put_byte(offset_in_sub_block as usize, b)?;
        Ok(())
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
        self.buf.put(offset_in_sub_block as usize, b, off, len)?;
        Ok(len)
    }

    fn delete(&mut self) -> io::Result<()> {
        self.buf.delete()?;
        self.header.delete()
    }

    fn set_length(&mut self, length: i64) -> io::Result<()> {
        self.header.set_length(length)
    }

    fn join(&mut self, other: &mut dyn SubMemoryBlock) -> io::Result<bool> {
        let Some(other_ref) = other.as_any().downcast_ref::<BufferSubMemoryBlock>() else {
            return Ok(false);
        };
        let other_len = other_ref.get_length();
        if other_len + self.header.get_length() > GBYTE {
            return Ok(false);
        }
        let other_key = other_ref.header.key();

        // Mirrors `buf.append(other.buf)` (Java concatenates `other`'s bytes onto the end of
        // this buffer, invalidating `other.buf` in the process): `DBBuffer::append` needs to
        // *own* the other `DBBuffer`, but `other` here is only a `&mut dyn SubMemoryBlock` --
        // there is no way to move a private field out from behind a trait-object reference
        // (Rust has no `instanceof`-then-move idiom for that). So instead of moving the
        // underlying `DBBuffer`, this reads `other`'s bytes through the public
        // `SubMemoryBlock::get_bytes` API and copies them into a grown `self.buf`, which
        // produces the identical observable result (the concatenated bytes) via this crate's
        // already-available public surface.
        let old_length = self.header.get_length();
        let other_len_usize = other_len as usize;
        let mut tail = vec![0u8; other_len_usize];
        let other_start = other.get_starting_offset();
        let n = other
            .get_bytes(other_start, &mut tail, 0, other_len_usize)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        self.buf.set_size((old_length + other_len) as usize, true)?;
        self.buf.put(old_length as usize, &tail, 0, n)?;

        self.header.set_length(old_length + other_len)?;
        self.header.adapter().write().unwrap().delete_sub_block(other_key)?;
        Ok(true)
    }

    fn get_source_info(&self, block: Arc<dyn MemoryBlock>) -> Arc<dyn MemoryBlockSourceInfo> {
        Arc::new(crate::program::database::mem::memory_block_source_info_db::MemoryBlockSourceInfoDB::new(
            block, self,
        ))
    }

    fn split(&mut self, mem_block_offset: i64) -> Result<Box<dyn SubMemoryBlock>, SubMemoryBlockError> {
        let offset = (mem_block_offset - self.header.get_starting_offset()) as usize;
        let new_length = self.header.get_length() - offset as i64;
        self.header.set_length(offset as i64)?;

        let split_buf = self.buf.split(offset)?;
        let split_id = split_buf.get_id();

        let new_record = self.header.adapter().write().unwrap().create_sub_block_record(
            0,
            0,
            new_length,
            SUB_TYPE_BUFFER,
            split_id,
            0,
        )?;

        Ok(Box::new(BufferSubMemoryBlock::from_parts(
            self.header.adapter().clone(),
            new_record,
            split_buf,
        )))
    }

    fn set_parent_id_and_starting_offset(&mut self, key: i64, starting_offset: i64) -> io::Result<()> {
        self.header.set_parent_id_and_starting_offset(key, starting_offset)
    }

    fn get_description(&self) -> String {
        format!("init[{:#x}]", self.header.get_length())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::mem::sub_block_header::test_support::{make_record, MockAdapter};
    use crate::program::database::mem::sub_memory_block::SubMemoryBlockError;
    use crate::program::database::mem::uninitialized_sub_memory_block::UninitializedSubMemoryBlock;
    use std::sync::{Arc, RwLock};

    fn adapter_with_buffer(data: Vec<u8>) -> (Arc<RwLock<MockAdapter>>, i32) {
        let mut adapter = MockAdapter::new();
        let id = adapter.register_buffer(data);
        (Arc::new(RwLock::new(adapter)), id)
    }

    fn block(
        adapter: &Arc<RwLock<MockAdapter>>,
        key: i64,
        starting_offset: i64,
        length: i64,
        buffer_id: i32,
    ) -> BufferSubMemoryBlock {
        let record = make_record(key, 1, starting_offset, length, buffer_id, 0);
        BufferSubMemoryBlock::new(adapter.clone() as Arc<RwLock<dyn MemoryMapDBAdapter>>, record).unwrap()
    }

    #[test]
    fn is_always_initialized() {
        let (adapter, id) = adapter_with_buffer(vec![0; 4]);
        let b = block(&adapter, 1, 0, 4, id);
        assert!(b.is_initialized());
    }

    #[test]
    fn put_and_get_byte_round_trip_at_various_offsets() {
        let (adapter, id) = adapter_with_buffer(vec![0; 8]);
        let mut b = block(&adapter, 1, 100, 8, id);

        b.put_byte(100, 0xAA).unwrap();
        b.put_byte(107, 0xBB).unwrap();
        assert_eq!(b.get_byte(100).unwrap(), 0xAA);
        assert_eq!(b.get_byte(107).unwrap(), 0xBB);
        assert_eq!(b.get_byte(103).unwrap(), 0);
    }

    #[test]
    fn get_bytes_clamps_to_available_length() {
        let (adapter, id) = adapter_with_buffer(vec![1, 2, 3, 4]);
        let b = block(&adapter, 1, 0, 4, id);

        let mut dest = [0u8; 10];
        let n = b.get_bytes(2, &mut dest, 0, 10).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&dest[..2], &[3, 4]);
    }

    #[test]
    fn put_bytes_clamps_to_available_length() {
        let (adapter, id) = adapter_with_buffer(vec![0; 4]);
        let mut b = block(&adapter, 1, 0, 4, id);

        let n = b.put_bytes(2, &[9, 9, 9, 9], 0, 4).unwrap();
        assert_eq!(n, 2);
        let mut dest = [0u8; 4];
        b.get_bytes(0, &mut dest, 0, 4).unwrap();
        assert_eq!(dest, [0, 0, 9, 9]);
    }

    #[test]
    fn get_byte_out_of_range_reports_io_error() {
        let (adapter, id) = adapter_with_buffer(vec![1, 2, 3, 4]);
        let b = block(&adapter, 1, 0, 4, id);
        let err = b.get_byte(100).unwrap_err();
        assert!(matches!(err, SubMemoryBlockError::Io(_)));
    }

    #[test]
    fn split_moves_back_half_into_a_new_buffer_block() {
        let (adapter, id) = adapter_with_buffer(vec![10, 20, 30, 40]);
        let mut a = block(&adapter, 1, 100, 4, id);

        let mut back = a.split(102).unwrap();
        assert_eq!(a.get_length(), 2);
        assert_eq!(back.get_length(), 2);
        assert_eq!(back.get_starting_offset(), 0); // record-local; header offset unset by split

        let mut head = [0u8; 2];
        a.get_bytes(100, &mut head, 0, 2).unwrap();
        assert_eq!(head, [10, 20]);

        let mut tail = [0u8; 2];
        back.get_bytes(0, &mut tail, 0, 2).unwrap();
        assert_eq!(tail, [30, 40]);
    }

    #[test]
    fn join_merges_adjacent_buffer_blocks_and_deletes_the_other() {
        let (adapter, id_a) = adapter_with_buffer(vec![1, 2]);
        let id_b = adapter.write().unwrap().register_buffer(vec![3, 4]);

        let mut a = block(&adapter, 1, 0, 2, id_a);
        let mut other = block(&adapter, 2, 2, 2, id_b);

        assert!(a.join(&mut other).unwrap());
        assert_eq!(a.get_length(), 4);

        let mut out = [0u8; 4];
        a.get_bytes(0, &mut out, 0, 4).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(adapter.read().unwrap().deleted_sub_blocks, vec![2]);
    }

    #[test]
    fn join_rejects_non_buffer_sibling() {
        let (adapter, id) = adapter_with_buffer(vec![1, 2]);
        let mut a = block(&adapter, 1, 0, 2, id);
        let record = make_record(9, 1, 2, 2, 0, 0);
        let mut other =
            UninitializedSubMemoryBlock::new(adapter.clone() as Arc<RwLock<dyn MemoryMapDBAdapter>>, record);
        assert!(!a.join(&mut other).unwrap());
        assert_eq!(a.get_length(), 2);
    }

    #[test]
    fn join_rejects_when_combined_length_exceeds_one_gbyte() {
        let (adapter, id_a) = adapter_with_buffer(vec![1, 2]);
        let id_b = adapter.write().unwrap().register_buffer(vec![3, 4]);

        // Record lengths don't have to match the (tiny) backing buffer sizes for this check --
        // the GBYTE guard runs before any bytes are touched, exactly like Java's early-return.
        let mut a = block(&adapter, 1, 0, GBYTE, id_a);
        let mut other = block(&adapter, 2, GBYTE, 2, id_b);

        assert!(!a.join(&mut other).unwrap());
        assert_eq!(a.get_length(), GBYTE);
        assert!(adapter.read().unwrap().deleted_sub_blocks.is_empty());
    }

    #[test]
    fn delete_deletes_both_buffer_and_record() {
        let (adapter, id) = adapter_with_buffer(vec![1, 2]);
        let mut b = block(&adapter, 5, 0, 2, id);
        b.delete().unwrap();
        assert_eq!(adapter.read().unwrap().deleted_sub_blocks, vec![5]);
    }

    #[test]
    fn description_reports_length_in_hex() {
        let (adapter, id) = adapter_with_buffer(vec![0; 0x10]);
        let b = block(&adapter, 1, 0, 0x10, id);
        assert_eq!(b.get_description(), "init[0x10]");
    }

    #[test]
    fn get_key_matches_record_key() {
        let (adapter, id) = adapter_with_buffer(vec![0; 2]);
        let b = block(&adapter, 42, 0, 2, id);
        assert_eq!(b.get_key(), 42);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let (adapter, id) = adapter_with_buffer(vec![1, 2, 3]);
        let boxed: Box<dyn SubMemoryBlock> = Box::new(block(&adapter, 1, 0, 3, id));
        assert!(boxed.is_initialized());
        assert_eq!(boxed.get_description(), "init[0x3]");
    }
}

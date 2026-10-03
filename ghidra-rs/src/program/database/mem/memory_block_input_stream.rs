//! Adapts a [`MemoryBlockDB`] into a [`Read`] stream over its bytes.
//!
//! Java source: `ghidra.program.database.mem.MemoryBlockInputStream`, a package-private `class
//! MemoryBlockInputStream extends InputStream`.
//!
//! # Shape
//!
//! Java's `getByte(long offset)`/`getBytes(long offset, byte[], int, int)` that this class calls
//! on `MemoryBlockDB` are package-private, offset-based fast paths distinct from the public,
//! `Address`-based [`MemoryBlock::get_byte`]/[`MemoryBlock::get_bytes`] -- and `MemoryBlockDB` has
//! not (yet) grown a Rust equivalent of those offset-based overloads. This port instead converts
//! the block-relative offset into an `Address` (`block.get_start().add(offset)`) and calls
//! through the already-ported, public [`MemoryBlock`] trait, which both existing
//! [`MemoryBlockDB`] byte-access methods already delegate to the same sub-block machinery Java's
//! offset-based overloads use. The two paths agree on every offset actually inside the block (the
//! only ones this stream ever produces), so this is a faithful, if indirect, translation -- not a
//! behavior change.
//!
//! Following [`MemBufferInputStream`](crate::program::model::mem::mem_buffer_input_stream::MemBufferInputStream),
//! the sibling `InputStream` adapter already ported in this crate, [`Read::read`] is implemented
//! for the single-byte case (mirroring Java's `read()`), a bulk `read_range` inherent method
//! mirrors Java's `read(byte[], int, int)`, and `mark`/`reset`/`skip`/`available` (which have no
//! [`Read`] trait equivalent) become additional inherent methods. Unlike `MemBufferInputStream`,
//! Java's `MemoryBlockInputStream` also overrides `markSupported()` (returning `true`) and
//! `mark`/`reset`, so those are ported too.
use std::io;

use crate::program::database::mem::memory_block_db::MemoryBlockDB;
use crate::program::model::mem::MemoryBlock;

/// Maps a [`MemoryBlockDB`] into an input stream over its bytes.
///
/// Port of `ghidra.program.database.mem.MemoryBlockInputStream`.
pub struct MemoryBlockInputStream<'a> {
    index: i64,
    reset_index: i64,
    num_bytes: i64,
    block: &'a MemoryBlockDB,
}

impl<'a> MemoryBlockInputStream<'a> {
    /// Constructs a new stream for reading the bytes of a memory block.
    ///
    /// Port of `MemoryBlockInputStream(MemoryBlockDB)`.
    pub fn new(block: &'a MemoryBlockDB) -> Self {
        let num_bytes = if block.is_initialized() { block.get_size() as i64 } else { 0 };
        Self { index: 0, reset_index: 0, num_bytes, block }
    }

    /// The number of bytes that can be read before reaching the end of the stream.
    ///
    /// Port of `available()`. Java clamps to `Integer.MAX_VALUE`; this port's `num_bytes`/`index`
    /// are already `i64`, so the same clamp is applied on the way out to `i32`.
    pub fn available(&self) -> i32 {
        let remaining = self.num_bytes - self.index;
        remaining.min(i32::MAX as i64) as i32
    }

    /// Marks the current position for a later [`Self::reset`].
    ///
    /// Port of `mark(int)`. Java's `readlimit` parameter is unused by this override (the mark
    /// never expires), so it is not represented here.
    pub fn mark(&mut self) {
        self.reset_index = self.index;
    }

    /// Whether this stream supports [`Self::mark`]/[`Self::reset`].
    ///
    /// Port of `markSupported()`.
    pub fn mark_supported(&self) -> bool {
        true
    }

    /// Resets the stream's position back to the last [`Self::mark`] (or the start, if never
    /// marked).
    ///
    /// Port of `reset()`.
    pub fn reset(&mut self) {
        self.index = self.reset_index;
    }

    /// Skips up to `n` bytes, returning the number actually skipped.
    ///
    /// Port of `skip(long)`.
    pub fn skip(&mut self, n: i64) -> i64 {
        let num_skipped = n.min(self.num_bytes - self.index);
        self.index += num_skipped;
        num_skipped
    }

    /// Reads up to `buf.len()` bytes into `buf`, starting at `off`, returning the number of bytes
    /// read, or `0` at end of stream.
    ///
    /// Port of `read(byte[], int, int)`. Java signals end-of-stream with `-1`; this returns `0`
    /// instead (matching [`Read::read`]'s own end-of-stream convention, which this method feeds).
    pub fn read_range(&mut self, buf: &mut [u8], off: usize) -> io::Result<usize> {
        if self.index >= self.num_bytes {
            return Ok(0);
        }
        let remaining = self.num_bytes - self.index;
        let mut len = buf.len() - off;
        if remaining < len as i64 {
            len = remaining as usize;
        }
        let address = self
            .block
            .get_start()
            .add(self.index)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let actually_read = self.block.get_bytes(&address, &mut buf[off..off + len]);
        self.index += actually_read as i64;
        Ok(actually_read)
    }
}

impl<'a> io::Read for MemoryBlockInputStream<'a> {
    /// Port of `read()`, generalized to a buffer per [`Read::read`]'s contract: fills as much of
    /// `buf` as available, one byte read at a time (mirroring Java's single-byte `read()`, which
    /// is all Java's `InputStream` guarantees without the bulk override).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.read_range(buf, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBRecord, Field, FieldType, Schema};
    use crate::program::database::map::AddressMapDB;
    use crate::program::database::mem::buffer_sub_memory_block::BufferSubMemoryBlock;
    use crate::program::database::mem::sub_block_header::test_support::{make_record, MockAdapter};
    use crate::program::database::mem::sub_memory_block::SubMemoryBlock;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use std::io::Read;
    use std::sync::{Arc, RwLock};

    fn test_addr_map() -> Arc<RwLock<AddressMapDB>> {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let factory = DefaultAddressFactory::new(vec![space]);
        let handle = Arc::new(RwLock::new(crate::framework::db::DBHandle::new().unwrap()));
        let map = AddressMapDB::new(handle, Arc::new(factory)).unwrap();
        Arc::new(RwLock::new(map))
    }

    /// Mirrors `MemoryBlockDB`'s own test module's `block_record` helper.
    fn block_record(addr_map: &Arc<RwLock<AddressMapDB>>, start: i64, size: i64) -> DBRecord {
        let schema = Arc::new(Schema::new(
            3,
            FieldType::Long,
            "Key".to_string(),
            vec![
                FieldType::String,
                FieldType::String,
                FieldType::String,
                FieldType::Byte,
                FieldType::Long,
                FieldType::Long,
                FieldType::Int,
            ],
            vec![
                "Name".to_string(),
                "Comments".to_string(),
                "Source Name".to_string(),
                "Flags".to_string(),
                "Start Address".to_string(),
                "Length".to_string(),
                "Segment".to_string(),
            ],
            vec![],
        ));
        let mut record = DBRecord::new(schema, Field::Long(Some(1)));
        record.set_string(0, Some("block1".to_string()));
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let start_addr = Address::new(space, start);
        let key = addr_map.read().unwrap().get_key(&start_addr, true);
        record.set_long(4, key);
        record.set_long(5, size);
        record
    }

    /// Builds a real, initialized `MemoryBlockDB` of `data.len()` bytes starting at `start`,
    /// backed by a single in-memory `BufferSubMemoryBlock` holding `data`.
    fn test_block(start: i64, data: Vec<u8>) -> MemoryBlockDB {
        let addr_map = test_addr_map();
        let record = block_record(&addr_map, start, data.len() as i64);

        let mut mock_adapter = MockAdapter::new();
        let buffer_id = mock_adapter.register_buffer(data.clone());
        let adapter: Arc<RwLock<dyn crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter>> =
            Arc::new(RwLock::new(mock_adapter));
        let sub_record = make_record(100, 1, 0, data.len() as i64, buffer_id, 0);
        let sub_block: Box<dyn SubMemoryBlock> =
            Box::new(BufferSubMemoryBlock::new(adapter, sub_record).unwrap());

        MemoryBlockDB::with_sub_blocks(record, addr_map, vec![sub_block])
    }

    #[test]
    fn reads_bytes_sequentially() {
        let block = test_block(0x1000, vec![0x41, 0x42, 0x43]);
        let mut stream = MemoryBlockInputStream::new(&block);
        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0x41);
        assert_eq!(stream.read(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0x42);
        assert_eq!(stream.read(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0x43);
        // End of stream.
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn available_reflects_the_records_declared_size_even_without_sub_blocks() {
        // `MemoryBlockDB`'s legacy two-arg constructor has no sub blocks, but `get_size()` reads
        // straight from the DB record regardless (see `MemoryBlockDB`'s own module docs), and
        // `is_initialized()` defaults to `true` when there are no sub blocks to consult -- so the
        // constructor still adopts the record's declared size, even though (per `MemoryBlockDB`'s
        // stub behavior) nothing is actually backing those bytes for real reads.
        let addr_map = test_addr_map();
        let record = block_record(&addr_map, 0x1000, 4);
        let block = MemoryBlockDB::new(record, addr_map);
        let stream = MemoryBlockInputStream::new(&block);
        assert_eq!(stream.available(), 4);
    }

    #[test]
    fn available_is_zero_when_the_record_declares_no_size() {
        let addr_map = test_addr_map();
        let record = block_record(&addr_map, 0x1000, 0);
        let block = MemoryBlockDB::new(record, addr_map);
        let stream = MemoryBlockInputStream::new(&block);
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn read_range_fills_the_requested_slice_and_advances() {
        let block = test_block(0x1000, vec![0x10, 0x20, 0x30, 0x40, 0x50]);
        let mut stream = MemoryBlockInputStream::new(&block);

        let mut buf = [0u8; 3];
        let n = stream.read_range(&mut buf, 0).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [0x10, 0x20, 0x30]);
        assert_eq!(stream.index, 3);
    }

    #[test]
    fn read_range_stops_at_num_bytes_even_if_buffer_is_larger() {
        let block = test_block(0x1000, vec![0x10, 0x20]);
        let mut stream = MemoryBlockInputStream::new(&block);

        let mut buf = [0u8; 10];
        let n = stream.read_range(&mut buf, 0).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0x10, 0x20]);

        // Now exhausted.
        let n2 = stream.read_range(&mut buf, 0).unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn mark_and_reset_restore_the_position() {
        let block = test_block(0x1000, vec![0x01, 0x02, 0x03, 0x04]);
        let mut stream = MemoryBlockInputStream::new(&block);

        let mut buf = [0u8; 1];
        stream.read_range(&mut buf, 0).unwrap();
        stream.mark();
        stream.read_range(&mut buf, 0).unwrap();
        stream.read_range(&mut buf, 0).unwrap();
        assert_eq!(stream.index, 3);

        stream.reset();
        assert_eq!(stream.index, 1);
    }

    #[test]
    fn mark_supported_is_always_true() {
        let block = test_block(0x1000, vec![0x01]);
        let stream = MemoryBlockInputStream::new(&block);
        assert!(stream.mark_supported());
    }

    #[test]
    fn skip_clamps_to_remaining_bytes() {
        let block = test_block(0x1000, vec![0x01, 0x02, 0x03]);
        let mut stream = MemoryBlockInputStream::new(&block);

        assert_eq!(stream.skip(2), 2);
        assert_eq!(stream.index, 2);
        // Only 1 byte left, even though 10 were requested.
        assert_eq!(stream.skip(10), 1);
        assert_eq!(stream.index, 3);
        assert_eq!(stream.skip(1), 0);
    }

    #[test]
    fn available_reflects_remaining_bytes_after_reads() {
        let block = test_block(0x1000, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        let mut stream = MemoryBlockInputStream::new(&block);

        assert_eq!(stream.available(), 5);
        stream.skip(2);
        assert_eq!(stream.available(), 3);
    }

    #[test]
    fn empty_read_buffer_returns_zero_without_advancing() {
        let block = test_block(0x1000, vec![0x01, 0x02]);
        let mut stream = MemoryBlockInputStream::new(&block);

        assert_eq!(stream.read(&mut []).unwrap(), 0);
        assert_eq!(stream.index, 0);
    }

    /// Sanity check that address translation actually reaches real block data at a non-zero
    /// start address, confirming `read_range` lands on the right bytes via
    /// `get_start().add(offset)`.
    #[test]
    fn read_reaches_real_bytes_through_address_translation() {
        let block = test_block(0x2000, vec![0xAA, 0xBB, 0xCC]);
        let mut stream = MemoryBlockInputStream::new(&block);

        let mut buf = [0u8; 3];
        let n = stream.read_range(&mut buf, 0).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [0xAA, 0xBB, 0xCC]);
    }
}

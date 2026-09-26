//! Port of `db.buffers.BufferFileBlock`.
//!
//! A plain data holder used to carry `BufferFile` blocks during block-streaming operations
//! (`InputBlockStream`/`OutputBlockStream`). The Java class is a concrete, final-shaped leaf
//! (no `extends`, no subclasses) holding just `blockIndex` and `buffer`, so this is ported
//! directly as a struct rather than a trait -- there is no inheritance to decouple via
//! composition here.
//!
//! Block indexes are absolute, where 0 corresponds to the head block in the `BufferFile`. This
//! is off by 1 from `DataBuffer` numbering and the index values used by
//! `BufferFile::get_index_count`/`get`/`put`; it is each implementation's responsibility to
//! normalize to absolute block indexes (see the original class doc comment).
//!
//! # Relationship to the pre-existing `BufferFileBlock` seam stub
//!
//! `crate::framework::seam_stubs::BufferFileBlock` is a placeholder *trait* introduced earlier
//! so that already-ported callers (`InputBlockStream`, `OutputBlockStream`,
//! `BufferFileHandle`, and a handful of other `framework::db::buffers` types) could reference
//! "a `BufferFileBlock`" before this class existed. This module adds the real, concrete type at
//! its natural path (`framework::db::buffers::BufferFileBlock`); rewiring the seam-stub call
//! sites over to it is a separate follow-up (it touches `framework::seam_stubs`, outside this
//! change's scope) and is intentionally not done here.

use crate::util::big_endian_data_converter::INSTANCE;
use crate::util::data_converter::DataConverter;

/// Holds a single `BufferFile` block for use during block-streaming operations. Mirrors
/// `db.buffers.BufferFileBlock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferFileBlock {
    block_index: i32,
    buffer: Vec<u8>,
}

impl BufferFileBlock {
    /// Constructs a block from an explicit index and block buffer (whose size must match the
    /// block size for the associated buffer file). Mirrors `BufferFileBlock(int, byte[])`.
    pub fn new(block_index: i32, buffer: Vec<u8>) -> Self {
        Self { block_index, buffer }
    }

    /// Reconstructs a block from data received over a block stream: the first 4 bytes give the
    /// (big-endian) block index, and the remainder is the block buffer. Mirrors
    /// `BufferFileBlock(byte[])`.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is shorter than 4 bytes -- mirroring Java, where `new byte[bytes.length
    /// - 4]` throws an (unchecked) `NegativeArraySizeException` in the same situation; neither
    /// version validates the input length before subtracting.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let block_index = INSTANCE.get_int_at(bytes, 0);
        let buffer = bytes[4..].to_vec();
        Self { block_index, buffer }
    }

    /// Returns the block size. Mirrors `size()`.
    pub fn size(&self) -> usize {
        self.buffer.len()
    }

    /// Returns the absolute block index, where 0 corresponds to the first physical block within
    /// the buffer file. Mirrors `getIndex()`.
    pub fn get_index(&self) -> i32 {
        self.block_index
    }

    /// Returns the block's data buffer. Mirrors `getData()`.
    pub fn get_data(&self) -> &[u8] {
        &self.buffer
    }

    /// Returns this block encoded as bytes suitable for use in a block stream and later
    /// reconstruction via [`from_bytes`](Self::from_bytes): the 4-byte big-endian index followed
    /// by the raw block buffer. Mirrors `toBytes()`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; self.buffer.len() + 4];
        bytes[4..].copy_from_slice(&self.buffer);
        INSTANCE.put_int_at(&mut bytes, 0, self.block_index);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_index_and_buffer_verbatim() {
        let block = BufferFileBlock::new(3, vec![1, 2, 3, 4]);
        assert_eq!(block.get_index(), 3);
        assert_eq!(block.get_data(), &[1, 2, 3, 4]);
        assert_eq!(block.size(), 4);
    }

    #[test]
    fn to_bytes_prefixes_big_endian_index_before_data() {
        let block = BufferFileBlock::new(0x0102_0304, vec![0xAA, 0xBB]);
        let bytes = block.to_bytes();
        assert_eq!(bytes, vec![0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB]);
    }

    #[test]
    fn from_bytes_reads_big_endian_index_and_remaining_data() {
        let bytes = vec![0x00, 0x00, 0x00, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF];
        let block = BufferFileBlock::from_bytes(&bytes);
        assert_eq!(block.get_index(), 42);
        assert_eq!(block.get_data(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn to_bytes_and_from_bytes_round_trip() {
        let original = BufferFileBlock::new(-7, vec![9, 8, 7, 6, 5]);
        let reconstructed = BufferFileBlock::from_bytes(&original.to_bytes());
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn from_bytes_with_empty_block_data_yields_zero_size() {
        let bytes = vec![0x00, 0x00, 0x00, 0x01];
        let block = BufferFileBlock::from_bytes(&bytes);
        assert_eq!(block.get_index(), 1);
        assert_eq!(block.size(), 0);
        assert_eq!(block.get_data(), &[] as &[u8]);
    }

    #[test]
    fn negative_block_index_round_trips_through_bytes() {
        // Java's `blockIndex` is a plain `int` with no non-negative validation anywhere in the
        // class; a negative index round-trips through toBytes()/the constructor exactly like any
        // other int, and this port preserves that.
        let block = BufferFileBlock::new(-1, vec![0x11]);
        let bytes = block.to_bytes();
        assert_eq!(bytes[..4], [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(BufferFileBlock::from_bytes(&bytes).get_index(), -1);
    }

    #[test]
    fn from_bytes_with_fewer_than_four_bytes_panics() {
        // Mirrors Java's `new byte[bytes.length - 4]` throwing NegativeArraySizeException for
        // input shorter than the 4-byte index prefix: this port's equivalent (subtracting from a
        // usize length) panics the same way, faithfully reproducing the missing validation.
        let result = std::panic::catch_unwind(|| BufferFileBlock::from_bytes(&[0x00, 0x01]));
        assert!(result.is_err(), "expected from_bytes to panic on undersized input");
    }
}

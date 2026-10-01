//! Test-only reader constructor shared by the Swift type-metadata structure tests.

use crate::app::util::bin::binary_reader::BinaryReader;

/// A little-endian reader over `bytes`, positioned at `index`.
pub(crate) fn le_reader_at(bytes: Vec<u8>, index: u64) -> BinaryReader {
    BinaryReader::from_bytes(bytes, true).clone_at(index)
}

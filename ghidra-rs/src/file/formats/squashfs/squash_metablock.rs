use std::io;

use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;

use super::squash_constants::METABLOCK_UNCOMPRESSED_MASK;

/// Represents metadata preceding a data block within a SquashFS archive.
///
/// The metablock header contains two fields:
/// - `is_compressed`: If bit 15 is cleared, the metablock is compressed
/// - `block_size`: The size of the metablock in bytes (lower 15 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SquashMetablock {
    header: i16,
}

impl SquashMetablock {
    /// Reads a SquashFS metablock header from the given binary reader.
    ///
    /// # Arguments
    /// * `reader` - A mutable binary reader positioned at the start of the metablock header
    ///
    /// # Errors
    /// Returns `io::Error` if the read operation fails.
    pub fn read(reader: &mut GBinaryReader) -> io::Result<Self> {
        let header = reader.read_next_short()?;
        Ok(SquashMetablock { header })
    }

    /// Returns `true` if the metablock is compressed (bit 15 is cleared).
    pub fn is_compressed(&self) -> bool {
        (self.header as u32 & METABLOCK_UNCOMPRESSED_MASK) == 0
    }

    /// Returns the size of the metablock in bytes (lower 15 bits).
    ///
    /// Logs a warning if the block size exceeds the maximum allowed size per the SquashFS standard.
    pub fn get_block_size(&self) -> i16 {
        let block_size = self.header & !(METABLOCK_UNCOMPRESSED_MASK as i16);

        if (block_size as u32) > METABLOCK_UNCOMPRESSED_MASK {
            tracing::warn!("Unit block size is too large!");
        }

        block_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct TestProvider(Vec<u8>);

    impl crate::filesystem::ghidra::g_binary_reader::ByteProvider for TestProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past end"));
            }
            Ok(self.0[start..end].to_vec())
        }

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            let idx = index as usize;
            if idx >= self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            self.0[idx] = value;
            Ok(())
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            let end = start + values.len();
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "write past end"));
            }
            self.0[start..end].copy_from_slice(values);
            Ok(())
        }
    }

    fn test_reader(data: Vec<u8>, little_endian: bool) -> GBinaryReader {
        GBinaryReader::new(Rc::new(RefCell::new(TestProvider(data))), little_endian)
    }

    #[test]
    fn reads_header() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234i16.to_le_bytes());
        let mut reader = test_reader(data, true);
        let metablock = SquashMetablock::read(&mut reader).unwrap();
        assert_eq!(metablock.header, 0x1234);
    }

    #[test]
    fn is_compressed_when_bit15_cleared() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000i16.to_le_bytes()); // bit 15 = 0, so compressed
        let mut reader = test_reader(data, true);
        let metablock = SquashMetablock::read(&mut reader).unwrap();
        assert!(metablock.is_compressed());
    }

    #[test]
    fn is_not_compressed_when_bit15_set() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i16).to_le_bytes()); // all bits set, including bit 15
        let mut reader = test_reader(data, true);
        let metablock = SquashMetablock::read(&mut reader).unwrap();
        assert!(!metablock.is_compressed());
    }

    #[test]
    fn gets_block_size_lower_15_bits() {
        let mut data = Vec::new();
        let header = 0x7FFFi16; // bit 15 = 0, lower 15 bits all set
        data.extend_from_slice(&header.to_le_bytes());
        let mut reader = test_reader(data, true);
        let metablock = SquashMetablock::read(&mut reader).unwrap();
        assert_eq!(metablock.get_block_size(), 0x7FFF);
    }

    #[test]
    fn block_size_masks_out_bit15() {
        let mut data = Vec::new();
        let header = (-1i16); // all bits set including bit 15
        data.extend_from_slice(&header.to_le_bytes());
        let mut reader = test_reader(data, true);
        let metablock = SquashMetablock::read(&mut reader).unwrap();
        let block_size = metablock.get_block_size();
        // The lower 15 bits should be preserved, bit 15 should be cleared
        assert_eq!(block_size as u16 & 0x7FFF, 0x7FFF);
    }

    #[test]
    fn small_block_size() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0100i16.to_le_bytes()); // bit 15 = 0, size = 256
        let mut reader = test_reader(data, true);
        let metablock = SquashMetablock::read(&mut reader).unwrap();
        assert!(metablock.is_compressed());
        assert_eq!(metablock.get_block_size(), 0x0100);
    }

    #[test]
    fn big_endian() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234i16.to_be_bytes());
        let mut reader = test_reader(data, false);
        let metablock = SquashMetablock::read(&mut reader).unwrap();
        assert_eq!(metablock.header, 0x1234);
    }

    #[test]
    fn struct_is_copy() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234i16.to_le_bytes());
        let mut reader = test_reader(data, true);
        let metablock1 = SquashMetablock::read(&mut reader).unwrap();
        let metablock2 = metablock1;
        assert_eq!(metablock1, metablock2);
    }

    #[test]
    fn compressed_vs_uncompressed_distinction() {
        let mut data = Vec::new();
        // Compressed: bit 15 = 0, size = 0x0500
        data.extend_from_slice(&0x0500i16.to_le_bytes());
        let mut reader = test_reader(data, true);
        let compressed = SquashMetablock::read(&mut reader).unwrap();
        assert!(compressed.is_compressed());
        assert_eq!(compressed.get_block_size(), 0x0500);

        // Uncompressed: bit 15 = 1, size = 0x0500
        let mut data = Vec::new();
        data.extend_from_slice(&(-32513i16).to_le_bytes()); // 0x8003 with bit 15 set
        let mut reader = test_reader(data, true);
        let uncompressed = SquashMetablock::read(&mut reader).unwrap();
        assert!(!uncompressed.is_compressed());
    }
}

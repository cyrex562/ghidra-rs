use std::io;

use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;

use super::squash_constants::{FRAGMENT_COMPRESSED_MASK};

/// Represents a SquashFS fragment.
///
/// A fragment entry contains:
/// - `fragment_offset`: Offset within the archive where the fragment starts
/// - `header`: Contains compression status and size info:
///   - Bit 24 (FRAGMENT_COMPRESSED_MASK): If cleared (0), the fragment is compressed
///   - Lower 24 bits: Size of the fragment in bytes
/// - `unused_field`: Unused as of SquashFS 4.0; warns if non-zero
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SquashFragment {
    fragment_offset: u64,
    header: u32,
    unused_field: u32,
}

impl SquashFragment {
    /// Reads a SquashFS fragment from the given binary reader.
    ///
    /// # Arguments
    /// * `reader` - A mutable binary reader positioned at the start of the fragment data
    ///
    /// # Errors
    /// Returns `io::Error` if any read operation fails.
    pub fn read(reader: &mut GBinaryReader) -> io::Result<Self> {
        let fragment_offset = reader.read_next_long()? as u64;
        let header = reader.read_next_int()? as u32;
        let unused_field = reader.read_next_int()? as u32;

        Ok(SquashFragment {
            fragment_offset,
            header,
            unused_field,
        })
    }

    /// Returns the offset within the archive where the fragment starts.
    pub fn get_fragment_offset(&self) -> u64 {
        self.fragment_offset
    }

    /// Returns `true` if the fragment is compressed (bit 24 is cleared).
    pub fn is_compressed(&self) -> bool {
        (self.header & FRAGMENT_COMPRESSED_MASK) == 0
    }

    /// Returns the size of the fragment in bytes (lower 24 bits of the header).
    pub fn get_fragment_size(&self) -> u64 {
        (self.header & !FRAGMENT_COMPRESSED_MASK) as u64
    }

    /// Returns the unused field value.
    ///
    /// Logs a warning if the value is non-zero (as this field has been unused since SquashFS 4.0).
    pub fn get_unused_field(&self) -> u32 {
        if self.unused_field != 0 {
            tracing::warn!("Fragment has non-zero \"unused\" field: {}", self.unused_field);
        }
        self.unused_field
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
    fn reads_all_fields() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // fragment_offset
        data.extend_from_slice(&0x00123400u32.to_le_bytes()); // header (bit 24 clear = compressed, size = 0x123400)
        data.extend_from_slice(&0x00000000u32.to_le_bytes()); // unused_field = 0
        let mut reader = test_reader(data, true);
        let frag = SquashFragment::read(&mut reader).unwrap();
        assert_eq!(frag.get_fragment_offset(), 0x1000);
        assert!(frag.is_compressed());
        assert_eq!(frag.get_fragment_size(), 0x123400);
        assert_eq!(frag.get_unused_field(), 0);
    }

    #[test]
    fn is_compressed_when_bit24_cleared() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0x00000000u32.to_le_bytes()); // bit 24 = 0, so compressed
        data.extend_from_slice(&0u32.to_le_bytes());
        let mut reader = test_reader(data, true);
        let frag = SquashFragment::read(&mut reader).unwrap();
        assert!(frag.is_compressed());
    }

    #[test]
    fn is_not_compressed_when_bit24_set() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&(1u32 << 24).to_le_bytes()); // bit 24 = 1, so not compressed
        data.extend_from_slice(&0u32.to_le_bytes());
        let mut reader = test_reader(data, true);
        let frag = SquashFragment::read(&mut reader).unwrap();
        assert!(!frag.is_compressed());
    }

    #[test]
    fn extracts_lower_24_bits_as_size() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u64.to_le_bytes());
        // Set header to have lower 24 bits = 0xABCDEF and bit 24 = 1
        let header = (1u32 << 24) | 0x00ABCDEF;
        data.extend_from_slice(&header.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let mut reader = test_reader(data, true);
        let frag = SquashFragment::read(&mut reader).unwrap();
        assert_eq!(frag.get_fragment_size(), 0x00ABCDEF);
    }

    #[test]
    fn unused_field_returns_value() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x12345678u32.to_le_bytes());
        let mut reader = test_reader(data, true);
        let frag = SquashFragment::read(&mut reader).unwrap();
        assert_eq!(frag.get_unused_field(), 0x12345678);
    }

    #[test]
    fn big_endian_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000000012345678u64.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let mut reader = test_reader(data, false);
        let frag = SquashFragment::read(&mut reader).unwrap();
        assert_eq!(frag.get_fragment_offset(), 0x0000000012345678);
    }

    #[test]
    fn struct_is_copy() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x00100000u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let mut reader = test_reader(data, true);
        let frag1 = SquashFragment::read(&mut reader).unwrap();
        let frag2 = frag1;
        assert_eq!(frag1, frag2);
    }

    #[test]
    fn max_offset_value() {
        let mut data = Vec::new();
        data.extend_from_slice(&u64::MAX.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let mut reader = test_reader(data, true);
        let frag = SquashFragment::read(&mut reader).unwrap();
        assert_eq!(frag.get_fragment_offset(), u64::MAX);
    }

    #[test]
    fn max_fragment_size() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0x00FFFFFFu32.to_le_bytes()); // max 24-bit value
        data.extend_from_slice(&0u32.to_le_bytes());
        let mut reader = test_reader(data, true);
        let frag = SquashFragment::read(&mut reader).unwrap();
        assert_eq!(frag.get_fragment_size(), 0xFFFFFF);
    }
}

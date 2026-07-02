use std::io;

use super::super::ghidra::{g_binary_reader::GBinaryReader, g_string_utilities};

/// Header structure for the `decmpfs` extended attribute.
///
/// Reads compression metadata and attribute bytes from a binary reader,
/// mirroring the original Java `DecmpfsHeader` class.
pub struct DecmpfsHeader {
    compression_magic: i32,
    compression_type: i32,
    uncompressed_size: i64,
    attr_bytes: Vec<u8>,
}

impl DecmpfsHeader {
    /// Creates a new `DecmpfsHeader` by reading from a binary reader.
    ///
    /// # Arguments
    /// * `reader` - A mutable binary reader positioned at the start of the header.
    /// * `size` - The total size of the header in bytes (excluding some alignment overhead).
    ///
    /// # Errors
    /// Returns `io::Error` if reading from the underlying data source fails.
    ///
    /// # Algorithm
    /// 1. Reads a 4-byte `compression_magic` in the reader's current endianness (big-endian by default).
    /// 2. Saves the reader's endianness, switches to little-endian, and reads `compression_type` (4 bytes) and `uncompressed_size` (8 bytes).
    /// 3. Restores the original endianness.
    /// 4. Calculates the byte count for remaining attribute bytes, accounting for alignment.
    /// 5. Reads the remaining bytes into `attr_bytes`.
    pub fn new(reader: &mut GBinaryReader, size: usize) -> io::Result<Self> {
        let index = reader.get_pointer_index();

        let compression_magic = reader.read_next_int()?;

        let original_endian = reader.is_little_endian();
        reader.set_little_endian(true);

        let compression_type = reader.read_next_int()?;
        let uncompressed_size = reader.read_next_long()?;

        reader.set_little_endian(original_endian);

        let mut end_index = index + (size as u64) + 1;

        if (end_index % 2) != 0 {
            end_index -= 1;
        }

        let mut n_elements = end_index.saturating_sub(reader.get_pointer_index());

        if (n_elements % 2) != 0 {
            n_elements += 1;
        }

        let attr_bytes = reader.read_next_byte_array(n_elements as usize)?;

        Ok(DecmpfsHeader {
            compression_magic,
            compression_type,
            uncompressed_size,
            attr_bytes,
        })
    }

    /// Returns the compression magic as a four-character string.
    ///
    /// Interprets the 4-byte compression magic as big-endian ASCII characters.
    pub fn get_compression_magic(&self) -> String {
        g_string_utilities::int_to_string(self.compression_magic)
    }

    /// Returns the compression type.
    pub fn get_compression_type(&self) -> i32 {
        self.compression_type
    }

    /// Returns the uncompressed size.
    pub fn get_uncompressed_size(&self) -> i64 {
        self.uncompressed_size
    }

    /// Returns a reference to the attribute bytes.
    pub fn get_attr_bytes(&self) -> &[u8] {
        &self.attr_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct TestProvider(Vec<u8>);

    impl super::super::ghidra::g_binary_reader::ByteProvider for TestProvider {
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
    fn compression_magic_big_endian() {
        // 'fpmc' = 0x6670 6d63
        let data = vec![0x66_u8, 0x70, 0x6d, 0x63, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = test_reader(data, false);
        let header = DecmpfsHeader::new(&mut reader, 16).unwrap();
        assert_eq!(header.get_compression_magic(), "fpmc");
    }

    #[test]
    fn compression_type_little_endian() {
        // Magic: 0x6670 6d63, Type: 0x03 (little-endian)
        let data = vec![0x66_u8, 0x70, 0x6d, 0x63, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = test_reader(data, false);
        let header = DecmpfsHeader::new(&mut reader, 16).unwrap();
        assert_eq!(header.get_compression_type(), 3);
    }

    #[test]
    fn uncompressed_size_little_endian() {
        // Magic: 0x6670 6d63, Type: 0x01, Size: 0x1234 (little-endian)
        let data = vec![
            0x66_u8, 0x70, 0x6d, 0x63, 0x01, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut reader = test_reader(data, false);
        let header = DecmpfsHeader::new(&mut reader, 16).unwrap();
        assert_eq!(header.get_uncompressed_size(), 0x1234);
    }

    #[test]
    fn attr_bytes_reads_remainder() {
        // Construct: 4-byte magic + 4-byte type + 8-byte size + 2 extra bytes
        // With size=17: endIndex = 0 + 17 + 1 = 18 (even, no alignment change)
        // nElements = 18 - 16 = 2 (even, no alignment change), so read 2 bytes
        let data = vec![
            0x66_u8, 0x70, 0x6d, 0x63, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xAB, 0xCD,
        ];
        let mut reader = test_reader(data, false);
        let header = DecmpfsHeader::new(&mut reader, 17).unwrap();
        assert_eq!(header.get_attr_bytes(), &[0xAB, 0xCD]);
    }

    #[test]
    fn empty_attr_bytes() {
        // With size=16: endIndex = 0 + 16 + 1 = 17 (odd, aligned down to 16)
        // nElements = 16 - 16 = 0 (even, no change), so read 0 bytes
        let data = vec![0x66_u8, 0x70, 0x6d, 0x63, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = test_reader(data, false);
        let header = DecmpfsHeader::new(&mut reader, 16).unwrap();
        assert!(header.get_attr_bytes().is_empty());
    }

    #[test]
    fn endianness_is_restored() {
        let data = vec![0x66_u8, 0x70, 0x6d, 0x63, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = test_reader(data, true);
        assert!(reader.is_little_endian());
        let _ = DecmpfsHeader::new(&mut reader, 16).unwrap();
        assert!(reader.is_little_endian());
    }

    #[test]
    fn endianness_restored_from_big_endian() {
        let data = vec![0x66_u8, 0x70, 0x6d, 0x63, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = test_reader(data, false);
        assert!(!reader.is_little_endian());
        let _ = DecmpfsHeader::new(&mut reader, 16).unwrap();
        assert!(!reader.is_little_endian());
    }

    #[test]
    fn large_uncompressed_size() {
        let data = vec![
            0x66_u8, 0x70, 0x6d, 0x63, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut reader = test_reader(data, false);
        let header = DecmpfsHeader::new(&mut reader, 16).unwrap();
        assert_eq!(header.get_uncompressed_size(), 0x01000000);
    }

    #[test]
    fn all_compression_types_read() {
        for ct in &[1u8, 3, 4, 10] {
            let data = vec![
                0x66_u8, 0x70, 0x6d, 0x63, *ct, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            let mut reader = test_reader(data, false);
            let header = DecmpfsHeader::new(&mut reader, 16).unwrap();
            assert_eq!(header.get_compression_type(), *ct as i32);
        }
    }
}

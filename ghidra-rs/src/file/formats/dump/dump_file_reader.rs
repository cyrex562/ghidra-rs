use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Reads pointer values (32-bit or 64-bit) from a binary data source.
///
/// Extends the capabilities of `BinaryReader` to handle architecture-dependent pointer sizes.
/// Mirrors `ghidra.file.formats.dump.DumpFileReader` from the original Ghidra source.
pub struct DumpFileReader {
    reader: BinaryReader,
    size: u32,
}

impl DumpFileReader {
    /// Creates a new `DumpFileReader` wrapping the given `BinaryReader`.
    ///
    /// # Arguments
    /// * `reader` - The underlying binary reader
    /// * `size` - Pointer size in bits (32 or 64)
    pub fn new(reader: BinaryReader, size: u32) -> Self {
        Self { reader, size }
    }

    /// Reads the next pointer value from the current position, advancing the reader's pointer.
    ///
    /// Returns a 32-bit value if size is 32, or a 64-bit value if size is 64.
    pub fn read_next_pointer(&mut self) -> io::Result<i64> {
        if self.size == 32 {
            Ok(self.reader.read_next_int()? as i64)
        } else {
            self.reader.read_next_long()
        }
    }

    /// Reads a pointer value at the specified offset.
    ///
    /// Returns a 32-bit value if size is 32, or a 64-bit value if size is 64.
    pub fn read_pointer(&self, offset: u64) -> io::Result<i64> {
        if self.size == 32 {
            Ok(self.read_int(offset)? as i64)
        } else {
            self.read_long(offset)
        }
    }

    /// Returns the pointer size in bytes.
    pub fn get_pointer_size(&self) -> u32 {
        self.size / 8
    }

    /// Sets the pointer size in bits.
    pub fn set_pointer_size(&mut self, size: u32) {
        self.size = size;
    }

    /// Returns the underlying reader's current position.
    pub fn get_pointer_index(&self) -> u64 {
        self.reader.get_pointer_index()
    }

    /// Sets the underlying reader's current position.
    pub fn set_pointer_index(&mut self, index: u64) -> u64 {
        self.reader.set_pointer_index(index)
    }

    /// Returns true if the reader extracts values in little-endian order.
    pub fn is_little_endian(&self) -> bool {
        self.reader.is_little_endian()
    }

    /// Sets the endianness used to extract values.
    pub fn set_little_endian(&mut self, is_little_endian: bool) {
        self.reader.set_little_endian(is_little_endian);
    }

    /// Returns the length of the underlying byte provider.
    pub fn length(&self) -> io::Result<u64> {
        self.reader.length()
    }

    /// Returns the signed int at the specified offset.
    fn read_int(&self, index: u64) -> io::Result<i32> {
        self.reader.read_int(index)
    }

    /// Returns the signed long at the specified offset.
    fn read_long(&self, index: u64) -> io::Result<i64> {
        self.reader.read_long(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_reader_and_size() {
        let reader = BinaryReader::from_bytes(vec![0; 16], true);
        let dump_reader = DumpFileReader::new(reader, 32);
        assert_eq!(dump_reader.size, 32);
    }

    #[test]
    fn get_pointer_size_divides_by_eight() {
        let reader = BinaryReader::from_bytes(vec![0; 16], true);
        let dump_reader = DumpFileReader::new(reader, 32);
        assert_eq!(dump_reader.get_pointer_size(), 4);

        let reader = BinaryReader::from_bytes(vec![0; 16], true);
        let dump_reader = DumpFileReader::new(reader, 64);
        assert_eq!(dump_reader.get_pointer_size(), 8);
    }

    #[test]
    fn set_pointer_size_updates_size() {
        let reader = BinaryReader::from_bytes(vec![0; 16], true);
        let mut dump_reader = DumpFileReader::new(reader, 32);
        assert_eq!(dump_reader.get_pointer_size(), 4);

        dump_reader.set_pointer_size(64);
        assert_eq!(dump_reader.get_pointer_size(), 8);
    }

    #[test]
    fn read_pointer_32bit() -> io::Result<()> {
        let data = vec![0x34, 0x12, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        let reader = BinaryReader::from_bytes(data, true);
        let dump_reader = DumpFileReader::new(reader, 32);

        let value = dump_reader.read_pointer(0)?;
        assert_eq!(value, 0x1234i64);

        Ok(())
    }

    #[test]
    fn read_pointer_64bit() -> io::Result<()> {
        let data = vec![0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let reader = BinaryReader::from_bytes(data, true);
        let dump_reader = DumpFileReader::new(reader, 64);

        let value = dump_reader.read_pointer(0)?;
        assert_eq!(value, 0x12345678i64);

        Ok(())
    }

    #[test]
    fn read_next_pointer_32bit() -> io::Result<()> {
        let data = vec![0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let reader = BinaryReader::from_bytes(data, true);
        let mut dump_reader = DumpFileReader::new(reader, 32);

        let value = dump_reader.read_next_pointer()?;
        assert_eq!(value, 0x1234i64);
        assert_eq!(dump_reader.get_pointer_index(), 4);

        Ok(())
    }

    #[test]
    fn read_next_pointer_64bit() -> io::Result<()> {
        let data = vec![0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let reader = BinaryReader::from_bytes(data, true);
        let mut dump_reader = DumpFileReader::new(reader, 64);

        let value = dump_reader.read_next_pointer()?;
        assert_eq!(value, 0x12345678i64);
        assert_eq!(dump_reader.get_pointer_index(), 8);

        Ok(())
    }

    #[test]
    fn pointer_size_affects_read_next() -> io::Result<()> {
        let data = vec![
            0x34, 0x12, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
            0x00, 0x00,
        ];
        let reader = BinaryReader::from_bytes(data, true);
        let mut dump_reader = DumpFileReader::new(reader, 32);

        let value = dump_reader.read_next_pointer()?;
        assert_eq!(value, 0x1234i64);
        assert_eq!(dump_reader.get_pointer_index(), 4);

        dump_reader.set_pointer_size(64);
        assert_eq!(dump_reader.read_next_pointer()?, -1i64);
        assert_eq!(dump_reader.get_pointer_index(), 12);

        Ok(())
    }

    #[test]
    fn pointer_operations_preserve_endianness() -> io::Result<()> {
        let data = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = BinaryReader::from_bytes(data, true);
        reader.set_little_endian(false);

        let dump_reader = DumpFileReader::new(reader, 32);
        let value = dump_reader.read_pointer(0)?;
        assert_eq!(value, 0x12340000i64);

        Ok(())
    }

    #[test]
    fn get_and_set_pointer_index() -> io::Result<()> {
        let reader = BinaryReader::from_bytes(vec![0; 16], true);
        let mut dump_reader = DumpFileReader::new(reader, 32);

        assert_eq!(dump_reader.get_pointer_index(), 0);

        let old = dump_reader.set_pointer_index(8);
        assert_eq!(old, 0);
        assert_eq!(dump_reader.get_pointer_index(), 8);

        Ok(())
    }

    #[test]
    fn is_and_set_little_endian() {
        let reader = BinaryReader::from_bytes(vec![0; 16], true);
        let mut dump_reader = DumpFileReader::new(reader, 32);

        assert!(dump_reader.is_little_endian());

        dump_reader.set_little_endian(false);
        assert!(!dump_reader.is_little_endian());
    }

    #[test]
    fn length_returns_provider_length() -> io::Result<()> {
        let reader = BinaryReader::from_bytes(vec![0; 32], true);
        let dump_reader = DumpFileReader::new(reader, 32);

        assert_eq!(dump_reader.length()?, 32);

        Ok(())
    }
}

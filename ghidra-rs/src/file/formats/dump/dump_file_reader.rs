use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Reads pointer values (32-bit or 64-bit) from a binary data source.
///
/// Extends the capabilities of `BinaryReader` to handle architecture-dependent pointer sizes.
/// Mirrors `ghidra.file.formats.dump.DumpFileReader` from the original Ghidra source.
pub struct DumpFileReader {
    reader: Box<dyn BinaryReader>,
    size: u32,
}

impl DumpFileReader {
    /// Creates a new `DumpFileReader` wrapping the given `BinaryReader`.
    ///
    /// # Arguments
    /// * `reader` - The underlying binary reader
    /// * `size` - Pointer size in bits (32 or 64)
    pub fn new(reader: Box<dyn BinaryReader>, size: u32) -> Self {
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
    use std::cell::RefCell;
    use std::rc::Rc;

    struct TestByteProvider {
        data: Vec<u8>,
    }

    impl crate::filesystem::ghidra::g_binary_reader::ByteProvider for TestByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.data.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.data.len()
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            Ok(self.data[index as usize])
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let idx = index as usize;
            Ok(self.data[idx..idx + length].to_vec())
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Ok(())
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }

    struct TestReader {
        provider: Rc<RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(data: Vec<u8>) -> Self {
            let provider = Rc::new(RefCell::new(TestByteProvider { data }));
            Self {
                provider,
                index: 0,
                little_endian: true,
            }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }

        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }

        fn get_pointer_index(&self) -> u64 {
            self.index
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.index;
            self.index = index;
            old
        }

        fn is_little_endian(&self) -> bool {
            self.little_endian
        }

        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }

        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }

        fn get_byte_provider(&self) -> Rc<RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>> {
            self.provider.clone()
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            let mut clone = TestReader {
                provider: self.provider.clone(),
                index: new_index,
                little_endian: self.little_endian,
            };
            clone.index = new_index;
            Box::new(clone)
        }
    }

    #[test]
    fn new_stores_reader_and_size() {
        let reader = Box::new(TestReader::new(vec![0; 16]));
        let dump_reader = DumpFileReader::new(reader, 32);
        assert_eq!(dump_reader.size, 32);
    }

    #[test]
    fn get_pointer_size_divides_by_eight() {
        let reader = Box::new(TestReader::new(vec![0; 16]));
        let dump_reader = DumpFileReader::new(reader, 32);
        assert_eq!(dump_reader.get_pointer_size(), 4);

        let reader = Box::new(TestReader::new(vec![0; 16]));
        let dump_reader = DumpFileReader::new(reader, 64);
        assert_eq!(dump_reader.get_pointer_size(), 8);
    }

    #[test]
    fn set_pointer_size_updates_size() {
        let reader = Box::new(TestReader::new(vec![0; 16]));
        let mut dump_reader = DumpFileReader::new(reader, 32);
        assert_eq!(dump_reader.get_pointer_size(), 4);

        dump_reader.set_pointer_size(64);
        assert_eq!(dump_reader.get_pointer_size(), 8);
    }

    #[test]
    fn read_pointer_32bit() -> io::Result<()> {
        let data = vec![0x34, 0x12, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        let reader = Box::new(TestReader::new(data));
        let dump_reader = DumpFileReader::new(reader, 32);

        let value = dump_reader.read_pointer(0)?;
        assert_eq!(value, 0x1234i64);

        Ok(())
    }

    #[test]
    fn read_pointer_64bit() -> io::Result<()> {
        let data = vec![0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let reader = Box::new(TestReader::new(data));
        let dump_reader = DumpFileReader::new(reader, 64);

        let value = dump_reader.read_pointer(0)?;
        assert_eq!(value, 0x12345678i64);

        Ok(())
    }

    #[test]
    fn read_next_pointer_32bit() -> io::Result<()> {
        let data = vec![0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let reader = Box::new(TestReader::new(data));
        let mut dump_reader = DumpFileReader::new(reader, 32);

        let value = dump_reader.read_next_pointer()?;
        assert_eq!(value, 0x1234i64);
        assert_eq!(dump_reader.get_pointer_index(), 4);

        Ok(())
    }

    #[test]
    fn read_next_pointer_64bit() -> io::Result<()> {
        let data = vec![0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let reader = Box::new(TestReader::new(data));
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
        let reader = Box::new(TestReader::new(data));
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
        let mut reader = Box::new(TestReader::new(data));
        reader.set_little_endian(false);

        let dump_reader = DumpFileReader::new(reader, 32);
        let value = dump_reader.read_pointer(0)?;
        assert_eq!(value, 0x12340000i64);

        Ok(())
    }

    #[test]
    fn get_and_set_pointer_index() -> io::Result<()> {
        let reader = Box::new(TestReader::new(vec![0; 16]));
        let mut dump_reader = DumpFileReader::new(reader, 32);

        assert_eq!(dump_reader.get_pointer_index(), 0);

        let old = dump_reader.set_pointer_index(8);
        assert_eq!(old, 0);
        assert_eq!(dump_reader.get_pointer_index(), 8);

        Ok(())
    }

    #[test]
    fn is_and_set_little_endian() {
        let reader = Box::new(TestReader::new(vec![0; 16]));
        let mut dump_reader = DumpFileReader::new(reader, 32);

        assert!(dump_reader.is_little_endian());

        dump_reader.set_little_endian(false);
        assert!(!dump_reader.is_little_endian());
    }

    #[test]
    fn length_returns_provider_length() -> io::Result<()> {
        let reader = Box::new(TestReader::new(vec![0; 32]));
        let dump_reader = DumpFileReader::new(reader, 32);

        assert_eq!(dump_reader.length()?, 32);

        Ok(())
    }
}

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents an Object Module Format (OMF) directory entry.
///
/// Mirrors the `OMFDirEntry` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfDirEntry {
    /// Subsection type (sst...).
    subsection: i16,
    /// Module index.
    imod: i16,
    /// Large file offset of subsection.
    lfo: i32,
    /// Number of bytes in subsection.
    cb: i32,
}

impl OmfDirEntry {
    /// The size of an OMF directory entry structure in bytes.
    pub const SIZE: usize = 12;

    /// Creates a new `OmfDirEntry` by reading from the given binary reader at the
    /// specified index.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `index` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &dyn BinaryReader, index: u64) -> io::Result<Self> {
        let subsection = reader.read_short(index)?;
        let imod = reader.read_short(index + 2)?;
        let lfo = reader.read_int(index + 4)?;
        let cb = reader.read_int(index + 8)?;

        Ok(OmfDirEntry {
            subsection,
            imod,
            lfo,
            cb,
        })
    }

    /// Returns the subsection type.
    pub fn subsection_type(&self) -> i16 {
        self.subsection
    }

    /// Returns the module index.
    pub fn module_index(&self) -> i16 {
        self.imod
    }

    /// Returns the large file offset of the subsection.
    pub fn large_file_offset(&self) -> i32 {
        self.lfo
    }

    /// Returns the number of bytes in the subsection.
    pub fn number_of_bytes(&self) -> i32 {
        self.cb
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
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
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }

        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }

        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
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

        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    #[test]
    fn read_structure_little_endian() {
        let data = vec![
            0x02, 0x00,             // subsection = 2 (little endian)
            0x05, 0x00,             // imod = 5 (little endian)
            0x00, 0x10, 0x00, 0x00, // lfo = 0x1000 (little endian)
            0x20, 0x03, 0x00, 0x00, // cb = 0x320 (little endian)
        ];

        let reader = MockReader::new(data, true);
        let entry = OmfDirEntry::new(&reader, 0).expect("failed to read");

        assert_eq!(entry.subsection_type(), 2);
        assert_eq!(entry.module_index(), 5);
        assert_eq!(entry.large_file_offset(), 0x1000);
        assert_eq!(entry.number_of_bytes(), 0x320);
    }

    #[test]
    fn read_structure_big_endian() {
        let data = vec![
            0x00, 0x03,             // subsection = 3 (big endian)
            0x00, 0x07,             // imod = 7 (big endian)
            0x00, 0x00, 0x20, 0x00, // lfo = 0x2000 (big endian)
            0x00, 0x00, 0x04, 0x00, // cb = 0x400 (big endian)
        ];

        let reader = MockReader::new(data, false);
        let entry = OmfDirEntry::new(&reader, 0).expect("failed to read");

        assert_eq!(entry.subsection_type(), 3);
        assert_eq!(entry.module_index(), 7);
        assert_eq!(entry.large_file_offset(), 0x2000);
        assert_eq!(entry.number_of_bytes(), 0x400);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, // Padding
            0x01, 0x00,             // subsection = 1 at offset 4
            0x02, 0x00,             // imod = 2
            0x00, 0x08, 0x00, 0x00, // lfo = 0x800
            0x10, 0x01, 0x00, 0x00, // cb = 0x110
        ];

        let reader = MockReader::new(data, true);
        let entry = OmfDirEntry::new(&reader, 4).expect("failed to read");

        assert_eq!(entry.subsection_type(), 1);
        assert_eq!(entry.module_index(), 2);
        assert_eq!(entry.large_file_offset(), 0x800);
        assert_eq!(entry.number_of_bytes(), 0x110);
    }

    #[test]
    fn zero_values() {
        let data = vec![
            0x00, 0x00, // subsection = 0
            0x00, 0x00, // imod = 0
            0x00, 0x00, 0x00, 0x00, // lfo = 0
            0x00, 0x00, 0x00, 0x00, // cb = 0
        ];

        let reader = MockReader::new(data, true);
        let entry = OmfDirEntry::new(&reader, 0).expect("failed to read");

        assert_eq!(entry.subsection_type(), 0);
        assert_eq!(entry.module_index(), 0);
        assert_eq!(entry.large_file_offset(), 0);
        assert_eq!(entry.number_of_bytes(), 0);
    }

    #[test]
    fn max_values() {
        let data = vec![
            0xFF, 0x7F,             // subsection = 32767 (max i16)
            0xFF, 0x7F,             // imod = 32767
            0xFF, 0xFF, 0xFF, 0x7F, // lfo = 0x7FFFFFFF (max i32, little endian)
            0xFF, 0xFF, 0xFF, 0x7F, // cb = 0x7FFFFFFF (max i32, little endian)
        ];

        let reader = MockReader::new(data, true);
        let entry = OmfDirEntry::new(&reader, 0).expect("failed to read");

        assert_eq!(entry.subsection_type(), i16::MAX);
        assert_eq!(entry.module_index(), i16::MAX);
        assert_eq!(entry.large_file_offset(), i32::MAX);
        assert_eq!(entry.number_of_bytes(), i32::MAX);
    }

    #[test]
    fn negative_values() {
        let data = vec![
            0xFF, 0xFF,             // subsection = -1 (little endian)
            0xFE, 0xFF,             // imod = -2 (little endian)
            0xFF, 0xFF, 0xFF, 0xFF, // lfo = -1 (little endian)
            0x00, 0xFF, 0xFF, 0xFF, // cb = -256 (little endian)
        ];

        let reader = MockReader::new(data, true);
        let entry = OmfDirEntry::new(&reader, 0).expect("failed to read");

        assert_eq!(entry.subsection_type(), -1);
        assert_eq!(entry.module_index(), -2);
        assert_eq!(entry.large_file_offset(), -1);
        assert_eq!(entry.number_of_bytes(), -256);
    }

    #[test]
    fn clone_equality() {
        let data = vec![
            0x04, 0x00, // subsection = 4
            0x06, 0x00, // imod = 6
            0x00, 0x20, 0x00, 0x00, // lfo = 0x2000
            0x00, 0x02, 0x00, 0x00, // cb = 0x200
        ];

        let reader = MockReader::new(data, true);
        let entry1 = OmfDirEntry::new(&reader, 0).expect("failed to read");
        let entry2 = entry1.clone();

        assert_eq!(entry1, entry2);
    }

    #[test]
    fn size_constant() {
        assert_eq!(OmfDirEntry::SIZE, 12);
    }
}

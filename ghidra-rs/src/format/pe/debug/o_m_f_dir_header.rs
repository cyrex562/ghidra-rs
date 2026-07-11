use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents the Object Module Format (OMF) directory header.
///
/// Mirrors the `OMFDirHeader` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```
/// typedef struct OMFDirHeader {
///     unsigned short cbDirHeader; // length of this structure
///     unsigned short cbDirEntry;  // number of bytes in each directory entry
///     unsigned long  cDir;        // number of directory entries
///     long           lfoNextDir;  // offset from base of next directory
///     unsigned long  flags;       // status flags
/// } OMFDirHeader;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfDirHeader {
    /// Length of this structure.
    cb_dir_header: i16,
    /// Number of bytes in each directory entry.
    cb_dir_entry: i16,
    /// Number of directory entries.
    c_dir: i32,
    /// Offset from base of next directory.
    lfo_next_dir: i32,
    /// Status flags.
    flags: i32,
}

impl OmfDirHeader {
    /// The size of an OMF directory header structure in bytes.
    pub const SIZE: usize = 16;

    /// Creates a new `OmfDirHeader` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
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
        let cb_dir_header = reader.read_short(index)?;
        let cb_dir_entry = reader.read_short(index + 2)?;
        let c_dir = reader.read_int(index + 4)?;
        let lfo_next_dir = reader.read_int(index + 8)?;
        let flags = reader.read_int(index + 12)?;

        Ok(OmfDirHeader {
            cb_dir_header,
            cb_dir_entry,
            c_dir,
            lfo_next_dir,
            flags,
        })
    }

    /// Returns the length of this structure in bytes.
    pub fn length_in_bytes(&self) -> i16 {
        self.cb_dir_header
    }

    /// Returns the number of bytes in each directory entry.
    pub fn number_of_bytes_in_entries(&self) -> i16 {
        self.cb_dir_entry
    }

    /// Returns the number of directory entries.
    pub fn number_of_entries(&self) -> i32 {
        self.c_dir
    }

    /// Returns the offset from base of next directory.
    pub fn base_of_next_entry(&self) -> i32 {
        self.lfo_next_dir
    }

    /// Returns the status flags.
    pub fn flags(&self) -> i32 {
        self.flags
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
            0x10, 0x00, // cb_dir_header = 16 (little endian)
            0x0C, 0x00, // cb_dir_entry = 12 (little endian)
            0x05, 0x00, 0x00, 0x00, // c_dir = 5
            0x00, 0x10, 0x00, 0x00, // lfo_next_dir = 4096
            0x01, 0x00, 0x00, 0x00, // flags = 1
        ];

        let reader = MockReader::new(data, true);
        let header = OmfDirHeader::new(&reader, 0).expect("failed to read");

        assert_eq!(header.length_in_bytes(), 16);
        assert_eq!(header.number_of_bytes_in_entries(), 12);
        assert_eq!(header.number_of_entries(), 5);
        assert_eq!(header.base_of_next_entry(), 4096);
        assert_eq!(header.flags(), 1);
    }

    #[test]
    fn read_structure_big_endian() {
        let data = vec![
            0x00, 0x10, // cb_dir_header = 16 (big endian)
            0x00, 0x0C, // cb_dir_entry = 12 (big endian)
            0x00, 0x00, 0x00, 0x05, // c_dir = 5
            0x00, 0x00, 0x10, 0x00, // lfo_next_dir = 4096
            0x00, 0x00, 0x00, 0x01, // flags = 1
        ];

        let reader = MockReader::new(data, false);
        let header = OmfDirHeader::new(&reader, 0).expect("failed to read");

        assert_eq!(header.length_in_bytes(), 16);
        assert_eq!(header.number_of_bytes_in_entries(), 12);
        assert_eq!(header.number_of_entries(), 5);
        assert_eq!(header.base_of_next_entry(), 4096);
        assert_eq!(header.flags(), 1);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, // Padding
            0x20, 0x00, // cb_dir_header = 32 at offset 4
            0x0C, 0x00, // cb_dir_entry = 12
            0x0A, 0x00, 0x00, 0x00, // c_dir = 10
            0x00, 0x20, 0x00, 0x00, // lfo_next_dir = 8192
            0x02, 0x00, 0x00, 0x00, // flags = 2
        ];

        let reader = MockReader::new(data, true);
        let header = OmfDirHeader::new(&reader, 4).expect("failed to read");

        assert_eq!(header.length_in_bytes(), 32);
        assert_eq!(header.number_of_bytes_in_entries(), 12);
        assert_eq!(header.number_of_entries(), 10);
        assert_eq!(header.base_of_next_entry(), 8192);
        assert_eq!(header.flags(), 2);
    }

    #[test]
    fn read_zero_entries() {
        let data = vec![
            0x10, 0x00, // cb_dir_header = 16
            0x0C, 0x00, // cb_dir_entry = 12
            0x00, 0x00, 0x00, 0x00, // c_dir = 0
            0x00, 0x00, 0x00, 0x00, // lfo_next_dir = 0
            0x00, 0x00, 0x00, 0x00, // flags = 0
        ];

        let reader = MockReader::new(data, true);
        let header = OmfDirHeader::new(&reader, 0).expect("failed to read");

        assert_eq!(header.length_in_bytes(), 16);
        assert_eq!(header.number_of_bytes_in_entries(), 12);
        assert_eq!(header.number_of_entries(), 0);
        assert_eq!(header.base_of_next_entry(), 0);
        assert_eq!(header.flags(), 0);
    }

    #[test]
    fn read_negative_offsets() {
        let data = vec![
            0x10, 0x00, // cb_dir_header = 16
            0x0C, 0x00, // cb_dir_entry = 12
            0x05, 0x00, 0x00, 0x00, // c_dir = 5
            0xFF, 0xFF, 0xFF, 0xFF, // lfo_next_dir = -1
            0xFF, 0xFF, 0xFF, 0xFF, // flags = -1
        ];

        let reader = MockReader::new(data, true);
        let header = OmfDirHeader::new(&reader, 0).expect("failed to read");

        assert_eq!(header.length_in_bytes(), 16);
        assert_eq!(header.number_of_bytes_in_entries(), 12);
        assert_eq!(header.number_of_entries(), 5);
        assert_eq!(header.base_of_next_entry(), -1);
        assert_eq!(header.flags(), -1);
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x10, 0x00, // cb_dir_header = 16
            0x0C, 0x00, // cb_dir_entry = 12
            0x05, 0x00, 0x00, 0x00, // c_dir = 5
            0x00, 0x10, 0x00, 0x00, // lfo_next_dir = 4096
            0x01, 0x00, 0x00, 0x00, // flags = 1
        ];

        let reader = MockReader::new(data, true);
        let header1 = OmfDirHeader::new(&reader, 0).expect("failed to read");
        let header2 = header1.clone();

        assert_eq!(header1, header2);
    }

    #[test]
    fn size_constant() {
        assert_eq!(OmfDirHeader::SIZE, 16);
    }
}

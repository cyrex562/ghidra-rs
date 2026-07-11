use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents the Object Module Format (OMF) File Index data structure.
///
/// Mirrors the `OMFFileIndex` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// short cMod        - Count or number of modules in the executable.
/// short cRef         - Count or number of file name references.
/// short [] modStart - array of indices into the nameoffset table for each module.  Each
///                     index is the start of the file name references for each module.
/// short cRefCnt     - number of file name references per module.
/// int [] nameRef     - array of offsets in to the names table.  For each module the offset
///                     to the first references file name is at nameRef[modStart] and
///                     continues for cRefCnt entries.
/// String names     - file names.
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfFileIndex {
    /// The number of modules in the executable.
    c_mod: i16,
    /// The number of file name references in the executable.
    c_ref: i16,
    /// The array of indices into the nameoffset table for each module.
    mod_start: Vec<i16>,
    /// The number of file name references per module.
    c_ref_cnt: Vec<i16>,
    /// The array of offsets into the names table.
    name_ref: Vec<i32>,
    /// The file names referenced in the executable.
    names: Vec<String>,
}

impl OmfFileIndex {
    /// Creates a new `OmfFileIndex` by reading from the given binary reader at the
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
        let mut index = index;

        let c_mod = reader.read_short(index)?;
        index += 2;
        let c_ref = reader.read_short(index)?;
        index += 2;

        let mut mod_start = vec![0i16; c_mod as u16 as usize];
        for slot in mod_start.iter_mut().take(c_mod.max(0) as usize) {
            *slot = reader.read_short(index)?;
            index += 2;
        }

        let mut c_ref_cnt = vec![0i16; c_mod as u16 as usize];
        for slot in c_ref_cnt.iter_mut().take(c_mod.max(0) as usize) {
            *slot = reader.read_short(index)?;
            index += 2;
        }

        let mut name_ref = vec![0i32; c_ref as u16 as usize];
        for slot in name_ref.iter_mut().take(c_ref.max(0) as usize) {
            *slot = reader.read_int(index)?;
            index += 4;
        }

        let mut names = Vec::new();
        for &offset in name_ref.iter().take(c_ref as u16 as usize) {
            let name_index = (index as i64 + offset as i64) as u64;

            let len = reader.read_byte(name_index)?;
            let name_index = name_index + 1;
            let length = len as usize;

            let name = reader.read_ascii_string_fixed(name_index, length)?;
            names.push(name);
        }

        Ok(OmfFileIndex {
            c_mod,
            c_ref,
            mod_start,
            c_ref_cnt,
            name_ref,
            names,
        })
    }

    /// Returns the number of modules in the executable.
    pub fn c_mod(&self) -> i16 {
        self.c_mod
    }

    /// Returns the number of file name references in the executable.
    pub fn c_ref(&self) -> i16 {
        self.c_ref
    }

    /// Returns the array of offsets into the names table.
    pub fn name_ref(&self) -> &[i32] {
        &self.name_ref
    }

    /// Returns the file names referenced in the executable.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Returns the indices into the nameoffset table for each file.
    pub fn c_ref_cnt(&self) -> &[i16] {
        &self.c_ref_cnt
    }

    /// Returns the array of indices into the nameoffset table for each module.
    pub fn mod_start(&self) -> &[i16] {
        &self.mod_start
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
        // 2 modules, 3 file name references.
        let data = vec![
            0x02, 0x00, // c_mod = 2
            0x03, 0x00, // c_ref = 3
            0x00, 0x00, // mod_start[0] = 0
            0x02, 0x00, // mod_start[1] = 2
            0x02, 0x00, // c_ref_cnt[0] = 2
            0x01, 0x00, // c_ref_cnt[1] = 1
            // name_ref array starts at offset 12, 3 entries of 4 bytes = 12 bytes,
            // so names table starts at offset 24.
            0x00, 0x00, 0x00, 0x00, // name_ref[0] = 0 -> offset 24
            0x04, 0x00, 0x00, 0x00, // name_ref[1] = 4 -> offset 28
            0x08, 0x00, 0x00, 0x00, // name_ref[2] = 8 -> offset 32
            // names table (offset 24)
            0x03, b'a', b'b', b'c', // len=3, "abc"
            0x02, b'x', b'y', 0x00, // len=2, "xy" (padded)
            0x01, b'z', 0x00, 0x00, // len=1, "z"
        ];

        let reader = MockReader::new(data, true);
        let file_index = OmfFileIndex::new(&reader, 0).expect("failed to read");

        assert_eq!(file_index.c_mod(), 2);
        assert_eq!(file_index.c_ref(), 3);
        assert_eq!(file_index.mod_start(), &[0, 2]);
        assert_eq!(file_index.c_ref_cnt(), &[2, 1]);
        assert_eq!(file_index.name_ref(), &[0, 4, 8]);
        assert_eq!(file_index.names(), &["abc".to_string(), "xy".to_string(), "z".to_string()]);
    }

    #[test]
    fn read_structure_big_endian() {
        let data = vec![
            0x00, 0x01, // c_mod = 1
            0x00, 0x01, // c_ref = 1
            0x00, 0x00, // mod_start[0] = 0
            0x00, 0x01, // c_ref_cnt[0] = 1
            0x00, 0x00, 0x00, 0x00, // name_ref[0] = 0 -> offset 12
            0x02, b'h', b'i', // len=2, "hi"
        ];

        let reader = MockReader::new(data, false);
        let file_index = OmfFileIndex::new(&reader, 0).expect("failed to read");

        assert_eq!(file_index.c_mod(), 1);
        assert_eq!(file_index.c_ref(), 1);
        assert_eq!(file_index.mod_start(), &[0]);
        assert_eq!(file_index.c_ref_cnt(), &[1]);
        assert_eq!(file_index.name_ref(), &[0]);
        assert_eq!(file_index.names(), &["hi".to_string()]);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, // padding
            0x01, 0x00, // c_mod = 1 at offset 4
            0x01, 0x00, // c_ref = 1
            0x00, 0x00, // mod_start[0] = 0
            0x01, 0x00, // c_ref_cnt[0] = 1
            0x00, 0x00, 0x00, 0x00, // name_ref[0] = 0 -> offset 16
            0x03, b'f', b'o', b'o', // len=3, "foo"
        ];

        let reader = MockReader::new(data, true);
        let file_index = OmfFileIndex::new(&reader, 4).expect("failed to read");

        assert_eq!(file_index.c_mod(), 1);
        assert_eq!(file_index.c_ref(), 1);
        assert_eq!(file_index.names(), &["foo".to_string()]);
    }

    #[test]
    fn zero_modules_and_references() {
        let data = vec![
            0x00, 0x00, // c_mod = 0
            0x00, 0x00, // c_ref = 0
        ];

        let reader = MockReader::new(data, true);
        let file_index = OmfFileIndex::new(&reader, 0).expect("failed to read");

        assert_eq!(file_index.c_mod(), 0);
        assert_eq!(file_index.c_ref(), 0);
        assert!(file_index.mod_start().is_empty());
        assert!(file_index.c_ref_cnt().is_empty());
        assert!(file_index.name_ref().is_empty());
        assert!(file_index.names().is_empty());
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x01, 0x00, // c_mod = 1
            0x01, 0x00, // c_ref = 1
            0x00, 0x00, // mod_start[0] = 0
            0x01, 0x00, // c_ref_cnt[0] = 1
            0x00, 0x00, 0x00, 0x00, // name_ref[0] = 0 -> offset 12
            0x01, b'a', // len=1, "a"
        ];

        let reader = MockReader::new(data, true);
        let file_index1 = OmfFileIndex::new(&reader, 0).expect("failed to read");
        let file_index2 = file_index1.clone();

        assert_eq!(file_index1, file_index2);
    }
}

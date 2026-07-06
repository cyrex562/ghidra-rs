use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::length_string_set::LengthStringSet;
use std::io;

/// Represents the imported name table in a new-executable (NE) format file.
///
/// The imported name table stores names of functions/procedures imported from
/// DLLs. This struct provides access to names at specific offsets within the table.
///
/// Mirrors `ImportedNameTable` from the original Ghidra Java source.
pub struct ImportedNameTable {
    reader: Box<dyn BinaryReader>,
    index: u64,
}

impl ImportedNameTable {
    /// Constructs a new imported name table.
    ///
    /// # Arguments
    /// * `reader` - The binary reader used to read from the underlying data
    /// * `index` - The absolute file offset where the table begins
    pub fn new(reader: Box<dyn BinaryReader>, index: u64) -> Self {
        ImportedNameTable { reader, index }
    }

    /// Returns the length/string set at the given offset.
    ///
    /// # Arguments
    /// * `offset` - The offset from the beginning of the Imported Name Table
    ///              to the length/string set
    ///
    /// # Errors
    /// Returns an error if there is an IO-related error reading from the reader.
    pub fn get_name_at(&self, offset: i16) -> io::Result<LengthStringSet> {
        let new_index = self.index + (offset as u16) as u64;
        let mut reader = self.reader.clone_at(new_index);
        LengthStringSet::new(&mut *reader)
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
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
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
    fn creates_table_with_index() {
        let data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        let reader = Box::new(MockReader::new(data));
        let table = ImportedNameTable::new(reader, 0);
        assert_eq!(table.index, 0);
    }

    #[test]
    fn gets_name_at_zero_offset() {
        let data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        let reader = Box::new(MockReader::new(data));
        let table = ImportedNameTable::new(reader, 0);

        let name_set = table.get_name_at(0).unwrap();
        assert_eq!(name_set.length(), 5);
        assert_eq!(name_set.name(), Some("hello"));
    }

    #[test]
    fn gets_name_at_positive_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 10]);
        data.push(3);
        data.extend_from_slice(b"abc");

        let reader = Box::new(MockReader::new(data));
        let table = ImportedNameTable::new(reader, 0);

        let name_set = table.get_name_at(10).unwrap();
        assert_eq!(name_set.length(), 3);
        assert_eq!(name_set.name(), Some("abc"));
    }

    #[test]
    fn gets_name_at_different_table_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xffu8; 5]);
        data.push(4);
        data.extend_from_slice(b"test");
        data.extend_from_slice(&[0u8; 10]);

        let reader = Box::new(MockReader::new(data));
        let table = ImportedNameTable::new(reader, 5);

        let name_set = table.get_name_at(0).unwrap();
        assert_eq!(name_set.length(), 4);
        assert_eq!(name_set.name(), Some("test"));
    }

    #[test]
    fn gets_zero_length_name() {
        let data = vec![0];
        let reader = Box::new(MockReader::new(data));
        let table = ImportedNameTable::new(reader, 0);

        let name_set = table.get_name_at(0).unwrap();
        assert_eq!(name_set.length(), 0);
        assert_eq!(name_set.name(), None);
    }

    #[test]
    fn handles_offset_conversion_from_signed() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 50]);
        data.push(2);
        data.extend_from_slice(b"xy");

        let reader = Box::new(MockReader::new(data));
        let table = ImportedNameTable::new(reader, 0);

        let name_set = table.get_name_at(50).unwrap();
        assert_eq!(name_set.length(), 2);
        assert_eq!(name_set.name(), Some("xy"));
    }

    #[test]
    fn works_with_table_offset_and_name_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 100]);
        data.push(6);
        data.extend_from_slice(b"import");
        data.extend_from_slice(&[0u8; 50]);

        let reader = Box::new(MockReader::new(data));
        let table = ImportedNameTable::new(reader, 20);

        let name_set = table.get_name_at(80).unwrap();
        assert_eq!(name_set.length(), 6);
        assert_eq!(name_set.name(), Some("import"));
    }

    #[test]
    fn multiple_gets_independent() {
        let mut data = Vec::new();
        data.push(3);
        data.extend_from_slice(b"foo");
        data.push(3);
        data.extend_from_slice(b"bar");
        data.push(3);
        data.extend_from_slice(b"baz");

        let reader = Box::new(MockReader::new(data));
        let table = ImportedNameTable::new(reader, 0);

        let first = table.get_name_at(0).unwrap();
        let second = table.get_name_at(4).unwrap();
        let third = table.get_name_at(8).unwrap();

        assert_eq!(first.name(), Some("foo"));
        assert_eq!(second.name(), Some("bar"));
        assert_eq!(third.name(), Some("baz"));
    }
}
